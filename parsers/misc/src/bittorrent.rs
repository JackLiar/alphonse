use anyhow::Result;
use hyperscan::pattern;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager, Rule, RuleType};

use crate::{
    add_simple_dpi_rule, add_simple_dpi_tcp_rule, add_simple_dpi_udp_rule, MatchCallBack,
    ProtocolParser,
};

pub fn register_classify_rules(
    parser: &mut ProtocolParser,
    manager: &mut ClassifierManager,
) -> Result<()> {
    add_simple_dpi_tcp_rule!(r"^\x13BitTorrent protocol", "bittorrent", parser, manager);

    add_simple_dpi_tcp_rule!(r"^Bsync\x00", "bittorrent", parser, manager);

    add_simple_dpi_udp_rule!(r"^d1:[arq]", "bittorrent", parser, manager);

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
        parser
            .parse_pkt(&pkt, Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"bittorrent"));

        // rule 2
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"Bsync\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(&pkt, Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"bittorrent"));

        // rule 3
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"d1:r".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(&pkt, Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"bittorrent"));
    }
}
