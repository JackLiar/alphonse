use anyhow::Result;
use hyperscan::pattern;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager, Rule, RuleType};

use crate::{add_simple_dpi_rule, add_simple_dpi_tcp_rule, MatchCallBack, ProtocolParser};

pub fn register_classify_rules(
    parser: &mut ProtocolParser,
    manager: &mut ClassifierManager,
) -> Result<()> {
    add_simple_dpi_tcp_rule!(
        r"^\x00\x00\x00\x25\x80\x01\x00\x01\x00\x00\x00\x0c\x73\x65\x74\x5f",
        "cassandra",
        parser,
        manager
    );

    add_simple_dpi_tcp_rule!(
        r"^\x00\x00\x00\x1d\x80\x01\x00\x01\x00\x00\x00\x10\x64\x65\x73\x63",
        "cassandra",
        parser,
        manager
    );

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::session::Session;
    use api::{parsers::ProtocolParserTrait, utils::packet::Packet as TestPacket};

    use crate::ProtocolParser;

    #[test]
    fn areospike() {
        let mut manager = ClassifierManager::new();
        let mut parser = ProtocolParser::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // rule 1
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw =
            Box::new(b"\x00\x00\x00\x25\x80\x01\x00\x01\x00\x00\x00\x0c\x73\x65\x74\x5f".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser.parse_pkt(&pkt, Some(rule), &mut ses).unwrap();
        }
        assert!(ses.has_protocol(&"cassandra"));

        // rule 2
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw =
            Box::new(b"\x00\x00\x00\x1d\x80\x01\x00\x01\x00\x00\x00\x10\x64\x65\x73\x63".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser.parse_pkt(&pkt, Some(rule), &mut ses).unwrap();
        }
        assert!(ses.has_protocol(&"cassandra"));
    }
}
