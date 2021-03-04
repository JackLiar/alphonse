use anyhow::Result;
use hyperscan::pattern;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager, Rule, RuleType};
use api::packet::Packet;
use api::session::Session;

use crate::{add_dpi_rule_with_func, add_dpi_tcp_rule_with_func, MatchCallBack, ProtocolParser};

pub fn register_classify_rules(
    parser: &mut ProtocolParser,
    manager: &mut ClassifierManager,
) -> Result<()> {
    add_dpi_tcp_rule_with_func!(r"^\x00\x00", classify, parser, manager);

    Ok(())
}

fn classify(ses: &mut Session, pkt: &Box<dyn Packet>) {
    let payload = pkt.payload();
    if payload.len() < 10 || payload[4] != 0 || payload[5] > 6 || payload[7] != 0 {
        return;
    }
    let flen = 4 + ((payload[2] as u16) << 8 | payload[3] as u16) as usize;
    if payload.len() != flen {
        return;
    }
    ses.add_protocol(&"kafka");
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
            0x00, 0x00, 0x00, 0x4b, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x23, 0x69, 0x6e, 0x74, 0x65,
            0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74,
            0x6f, 0x70, 0x69, 0x63, 0x31, 0x34, 0x37, 0x35, 0x30, 0x30, 0x37, 0x30, 0x36, 0x39,
            0x33, 0x35, 0x32, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
        ]);
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(&pkt, Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"kafka"));
    }
}
