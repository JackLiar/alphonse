use anyhow::Result;
use fnv::FnvHashMap;
use hyperscan::pattern;
use serde_json::json;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager, Rule, RuleID, RuleType};
use api::packet::Packet;
use api::parsers::ParserID;
use api::session::Session;

use super::MatchCallBack;

pub fn register_classify_rules(
    id: ParserID,
    manager: &mut ClassifierManager,
    match_cbs: &mut FnvHashMap<RuleID, MatchCallBack>,
) -> Result<()> {
    let mut dpi_rule = dpi::Rule::new(pattern! {r"^\x03\x00"});
    dpi_rule.protocol = dpi::Protocol::TCP;
    let mut rule = Rule::new(id);
    rule.rule_type = RuleType::DPI(dpi_rule);
    let rule_id = manager.add_rule(&mut rule)?;
    match_cbs.insert(rule_id, MatchCallBack::Func(classify));

    Ok(())
}

fn classify(ses: &mut Session, pkt: &Box<dyn Packet>) {
    let payload = pkt.payload();
    if payload.len() > 5
        && payload[3] < payload.len() as u8
        && payload[4] == payload[3] - 5
        && payload[5] == 0xe0
    {
        ses.add_protocol("rdp");
        if payload.len() > 30 && &payload[11..28] == b"Cookie: mstshash=" {
            match payload[28..].windows(2).position(|win| win == b"\r\n") {
                Some(pos) => ses.add_field(
                    &"user",
                    &json!(String::from_utf8_lossy(&payload[28..28 + pos]).to_string()),
                ),
                None => {}
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::session::Session;
    use api::{parsers::ProtocolParserTrait, utils::packet::Packet as TestPacket};

    use crate::ProtocolParser;

    #[test]
    fn rdp() {
        let mut manager = ClassifierManager::new();
        let mut parser = ProtocolParser::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(
            b"\x03\x00\x00\x05\x00\xe0\x00\x00\x00\x00\x00Cookie: mstshash=user\r\n".to_vec(),
        );
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser.parse_pkt(&pkt, &pkt.rules()[0], &mut ses).unwrap();
        assert!(ses.has_protocol("rdp"));
        assert_eq!(ses.fields.as_object().unwrap().get("user").unwrap(), "user");
    }
}
