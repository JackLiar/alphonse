use anyhow::Result;
use hyperscan::pattern;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager, Rule, RuleType};
use api::packet::Packet;
use api::session::Session;

use crate::{add_dpi_rule_with_func, add_dpi_udp_rule_with_func, MatchCallBack, ProtocolParser};

pub fn register_classify_rules(
    parser: &mut ProtocolParser,
    manager: &mut ClassifierManager,
) -> Result<()> {
    add_dpi_udp_rule_with_func!(r"^.host_int", classify, parser, manager);

    Ok(())
}

fn classify(ses: &mut Session, pkt: &Box<dyn Packet>) {
    unsafe {
        if pkt.src_port() == 17500 || pkt.dst_port() == 17500 {
            ses.add_protocol(&"dropbox-lan-sync");
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
    fn test() {
        let mut manager = ClassifierManager::new();
        let mut parser = ProtocolParser::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(vec![
            0x44, 0x5c, 0x00, 0x31, 0x39, 0x83, 0x1f, 0x05, 0x6d, 0x2e, 0xaf, 0x30, 0x50, 0x10,
            0x10, 0x20, 0x49, 0x93, 0x00, 0x00, 0x20, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x69, 0x6e,
            0x74,
        ]);
        pkt.layers.trans.protocol = Protocol::UDP;
        pkt.layers.app.offset = 20;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(&pkt, Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"dropbox-lan-sync"));
    }
}
