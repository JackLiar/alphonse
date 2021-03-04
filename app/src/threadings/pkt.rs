use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::Receiver;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::{Packet, PacketHashKey};
use api::parsers::ProtocolParserTrait;
use api::utils::timeval::TimeVal;

use crate::config::Config;
use crate::rx::{SessionData, SessionTable};

pub struct PktThread {
    id: u8,
    exit: Arc<AtomicBool>,
    classifier: Arc<ClassifierManager>,
    receiver: Receiver<Box<dyn Packet>>,
}

impl PktThread {
    pub fn new(
        id: u8,
        exit: Arc<AtomicBool>,
        classifier: Arc<ClassifierManager>,
        receiver: Receiver<Box<dyn Packet>>,
    ) -> Self {
        Self {
            id,
            exit,
            classifier,
            receiver,
        }
    }

    pub fn name(&self) -> String {
        format!("alphonse-pkt{}", self.id)
    }

    #[inline]
    fn parse_pkt(
        &self,
        scratch: &mut api::classifiers::ClassifyScratch,
        protocol_parsers: &mut Box<Vec<Box<dyn ProtocolParserTrait>>>,
        pkt: &mut Box<dyn Packet>,
        ses_data: &mut SessionData,
    ) -> Result<()> {
        self.classifier.classify(pkt, scratch)?;

        for rule in pkt.rules().iter() {
            for parser_id in rule.parsers.iter() {
                match ses_data.parsers.get_mut(parser_id) {
                    Some(_) => {}
                    None => {
                        let parser = protocol_parsers
                            .get_mut(*parser_id as usize)
                            .unwrap()
                            .box_clone();
                        ses_data.parsers.insert(parser.id(), parser);
                    }
                };
            }
        }

        for (_, parser) in ses_data.parsers.iter_mut() {
            let mut matched = false;
            for rule in pkt.rules().iter() {
                // If parser has bind a rule this packet matches, parse with this rule
                // otherwise this pkt belongs to the same flow, parse witout rule information
                for parser_id in rule.parsers.iter() {
                    if *parser_id == parser.id() {
                        parser.parse_pkt(pkt, Some(rule), ses_data.info.as_mut())?;
                        matched = true;
                    }
                }
            }

            if !matched {
                parser.parse_pkt(pkt, None, ses_data.info.as_mut())?;
            }
        }

        Ok(())
    }

    pub fn spawn(
        &self,
        cfg: Arc<Config>,
        session_table: Arc<SessionTable>,
        mut protocol_parsers: Box<Vec<Box<dyn ProtocolParserTrait>>>,
    ) -> Result<()> {
        let parser = crate::packet::Parser::new(crate::packet::link::ETHERNET);
        let mut classify_scratch = match self.classifier.alloc_scratch() {
            Ok(scratch) => scratch,
            Err(_) => todo!(),
        };
        println!("{} started", self.name());

        while !self.exit.load(Ordering::Relaxed) {
            let mut pkt = match self.receiver.recv() {
                Err(_) => break,
                Ok(s) => s,
            };

            match parser.parse_pkt(pkt.as_mut()) {
                Ok(_) => {}
                Err(e) => match e {
                    crate::packet::parser::Error::UnsupportProtocol(_) => {}
                    _ => todo!(),
                },
            };

            let key = PacketHashKey::from(pkt.as_ref());
            match session_table.get_mut(&key) {
                Some(mut ses) => {
                    ses.info.update(&pkt);
                    self.parse_pkt(
                        &mut classify_scratch,
                        &mut protocol_parsers,
                        &mut pkt,
                        ses.as_mut(),
                    )
                    .unwrap();
                }
                None => {
                    let mut ses = Box::new(SessionData::default());
                    ses.info.start_time = TimeVal::new(*pkt.ts());
                    ses.info.save_time = pkt.ts().tv_sec as u64 + cfg.ses_save_timeout as u64;
                    ses.info.update(&pkt);
                    self.parse_pkt(
                        &mut classify_scratch,
                        &mut protocol_parsers,
                        &mut pkt,
                        ses.as_mut(),
                    )
                    .unwrap();

                    &mut session_table.insert(key, ses);
                }
            };
        }

        println!("{} exit", self.name());

        Ok(())
    }
}
