use anyhow::Result;
use fnv::FnvHashMap;
use hyperscan::pattern;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager, Rule, RuleID, RuleType};
use api::parsers::ParserID;

use super::MatchCallBack;

pub fn register_classify_rules(
    id: ParserID,
    manager: &mut ClassifierManager,
    match_cbs: &mut FnvHashMap<RuleID, MatchCallBack>,
) -> Result<()> {
    let mut dpi_rule = dpi::Rule::new(pattern! {r"^\x13BitTorrent protocol"});
    dpi_rule.protocol = dpi::Protocol::TCP;
    let mut rule = Rule::new(id);
    rule.rule_type = RuleType::DPI(dpi_rule);
    let rule_id = manager.add_rule(&mut rule)?;
    match_cbs.insert(
        rule_id,
        MatchCallBack::ProtocolName("bittorrent".to_string()),
    );

    let mut dpi_rule = dpi::Rule::new(pattern! {r"^Bsync\x00"});
    dpi_rule.protocol = dpi::Protocol::TCP;
    let mut rule = Rule::new(id);
    rule.rule_type = RuleType::DPI(dpi_rule);
    let rule_id = manager.add_rule(&mut rule)?;
    match_cbs.insert(
        rule_id,
        MatchCallBack::ProtocolName("bittorrent".to_string()),
    );

    let mut dpi_rule = dpi::Rule::new(pattern! {r"^d1:[arq]"});
    dpi_rule.protocol = dpi::Protocol::UDP;
    let mut rule = Rule::new(id);
    rule.rule_type = RuleType::DPI(dpi_rule);
    let rule_id = manager.add_rule(&mut rule)?;
    match_cbs.insert(
        rule_id,
        MatchCallBack::ProtocolName("bittorrent".to_string()),
    );

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::parsers::ProtocolParserTrait;
    use api::session::Session;
    use api::utils::packet::Packet as TestPacket;

    use crate::ProtocolParser;

    #[test]
    fn bittorrent() {
        let mut manager = ClassifierManager::new();
        let mut parser = ProtocolParser::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // rule 1
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x13BitTorrent protocol".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser.parse_pkt(&pkt, &pkt.rules()[0], &mut ses).unwrap();
        assert!(ses.has_protocol("bittorrent"));

        // rule 2
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"Bsync\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser.parse_pkt(&pkt, &pkt.rules()[0], &mut ses).unwrap();
        assert!(ses.has_protocol("bittorrent"));

        // rule 3
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"d1:r".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser.parse_pkt(&pkt, &pkt.rules()[0], &mut ses).unwrap();
        assert!(ses.has_protocol("bittorrent"));
    }
}