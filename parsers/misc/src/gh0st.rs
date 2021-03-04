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
    add_dpi_tcp_rule_with_func!(
        r"^[a-zA-z0-9:]{5}..\x00\x00....\x78\x9c",
        classify_windows,
        parser,
        manager
    );
    add_dpi_tcp_rule_with_func!(
        r"^[a-zA-z0-9:]{5}\x00\x00.{6}\x78\x9c",
        classify_mac,
        parser,
        manager
    );

    Ok(())
}

fn classify_windows(ses: &mut Session, pkt: &Box<dyn Packet>) {
    let payload = pkt.payload();
    if payload.len() < 15 {
        return;
    }

    if ((payload[6] as u16 & 0xff) << 8 | (payload[5] as u16 & 0xff)) == payload.len() as u16 {
        ses.add_protocol(&"gh0st");
    } else if payload[11] == 0 && payload[12] == 0 {
        ses.add_protocol(&"gh0st");
    }
}

fn classify_mac(ses: &mut Session, pkt: &Box<dyn Packet>) {
    let payload = pkt.payload();
    if payload.len() < 15 {
        return;
    }

    if ((payload[7] as u16 & 0xff) << 8 | (payload[8] as u16 & 0xff)) == payload.len() as u16 {
        ses.add_protocol(&"gh0st");
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
    fn gh0st() {
        let mut manager = ClassifierManager::new();
        let mut parser = ProtocolParser::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // Windows branch 1
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"Gh0st\x0f\x00\x00\x00\x09\x10\x11\x12\x78\x9c".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(&pkt, Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"gh0st"));

        // Windows branch 2
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"Gh0st\x05\x06\x00\x00\x09\x10\x00\x00\x78\x9c".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(&pkt, Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"gh0st"));

        // mac
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"Gh0st\x00\x00\x00\x0f\x09\x10\x11\x12\x78\x9c".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(&pkt, Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"gh0st"));
    }
}
