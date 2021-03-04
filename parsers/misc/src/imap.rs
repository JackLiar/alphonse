use anyhow::Result;
use hyperscan::pattern;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager, Rule, RuleType};
use api::packet::Packet;
use api::session::Session;

use super::{add_dpi_rule_with_func, add_dpi_tcp_rule_with_func, MatchCallBack, ProtocolParser};

pub fn register_classify_rules(
    parser: &mut ProtocolParser,
    manager: &mut ClassifierManager,
) -> Result<()> {
    add_dpi_tcp_rule_with_func!(r"^\*\sOK\s", classify, parser, manager);

    Ok(())
}

fn classify(ses: &mut Session, pkt: &Box<dyn Packet>) {
    match &pkt.payload()[5..].windows(4).position(|win| win == b"IMAP") {
        Some(_) => ses.add_protocol(&"imap"),
        None => {}
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
    fn imap() {
        let mut manager = ClassifierManager::new();
        let mut parser = ProtocolParser::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"* OK \r\n IMAP".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(&pkt, Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"imap"));
    }
}
