use std::iter::FromIterator;

use anyhow::{anyhow, Result};
use hyperscan::Builder;

use super::{matched, packet};

bitflags! {
    pub struct Protocol: u8 {
        const TCP = 0b00000001;
        const UDP = 0b00000010;
        const SCTP = 0b00000100;
    }
}

impl From<packet::Protocol> for Protocol {
    fn from(protocol: packet::Protocol) -> Self {
        match protocol {
            packet::Protocol::TCP => Protocol::TCP,
            packet::Protocol::UDP => Protocol::UDP,
            packet::Protocol::SCTP => Protocol::SCTP,
            _ => Protocol::all(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    hs_pattern: hyperscan::Pattern,
    pub protocol: Protocol,
}

impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        (self.hs_pattern.expression == other.hs_pattern.expression)
            && (self.hs_pattern.flags == other.hs_pattern.flags)
            && (self.hs_pattern.ext == self.hs_pattern.ext)
            && (self.hs_pattern.som == self.hs_pattern.som)
            && (self.protocol == self.protocol)
    }
}

impl Eq for Rule {}

impl Rule {
    /// Crate a new DPI rule, matching all protocol(TCP/UDP/SCTP)
    pub fn new(hs_pattern: hyperscan::Pattern) -> Self {
        Rule {
            hs_pattern,
            protocol: Protocol::all(),
        }
    }
}

#[derive(Default)]
pub struct Classifier {
    /// DPI rules
    dpi_rules: Vec<Rule>,
    /// Rule for packet classification assignment
    rules: Vec<matched::Rule>,
    hs_db: Option<hyperscan::BlockDatabase>,
}

impl super::Classifier for Classifier {
    fn add_rule(&mut self, rule: &super::Rule) -> Result<&matched::Rule> {
        let mut dpi_rule = match &rule.rule_type {
            super::RuleType::DPI(r) => r.clone(),
            r => {
                return Err(anyhow!(
                    "Mismatched rule type, expecting DPI Rule, get {:?}",
                    r
                ))
            }
        };

        // reset rule's id to None
        dpi_rule.hs_pattern.id = None;

        let mut same_pattern_index: Option<usize> = None;
        for (i, drule) in (&*self.dpi_rules).iter().enumerate() {
            if dpi_rule == *drule {
                same_pattern_index = Some(i)
            }
        }

        match same_pattern_index {
            None => {
                self.rules.push(matched::Rule::from(rule));
                self.dpi_rules.push(dpi_rule.clone());
                Ok(&self.rules[self.rules.len() - 1])
            }
            Some(i) => Ok(&self.rules[i]),
        }
    }
}

impl Classifier {
    pub fn classify(
        &self,
        pkt: &mut Box<dyn packet::Packet>,
        scratch: &mut ClassifyScratch,
    ) -> Result<()> {
        match (&self.hs_db, &scratch.hs_scratch) {
            (Some(db), Some(s)) => {
                let mut ids = Vec::new();
                db.scan(pkt.payload(), s, |id, _from, _to, _flags| {
                    ids.push(id as usize);
                    hyperscan::Matching::Continue
                })?;

                for id in ids {
                    let proto = Protocol::from(pkt.layers().trans.protocol);
                    if self.dpi_rules[id].protocol.contains(proto) {
                        pkt.rules_mut().push(self.rules[id].clone());
                    }
                }

                Ok(())
            }
            (None, None) => Ok(()), // no dpi rule is registered
            (None, _) => Err(anyhow!("DPI classifier's hs db is None")),
            (_, None) => Err(anyhow!("DPI classifier's hs scratch is None")),
        }
    }

    /// Allocate a protocol classifier scratch
    pub fn alloc_scratch(&self) -> Result<ClassifyScratch> {
        let scratch = match &self.hs_db {
            Some(db) => Some(db.alloc_scratch()?),
            None => None,
        };
        Ok(ClassifyScratch {
            hs_scratch: scratch,
        })
    }

    pub fn prepare(&mut self) -> Result<()> {
        if self.dpi_rules.len() == 0 {
            self.hs_db = None;
        } else {
            let patterns =
                hyperscan::Patterns::from_iter(self.dpi_rules.iter().map(|r| r.hs_pattern.clone()));
            self.hs_db = Some(patterns.build()?);
        }
        Ok(())
    }
}

pub struct ClassifyScratch {
    hs_scratch: Option<hyperscan::Scratch>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::classifiers::Classifier as ClassifierTrait;
    use crate::packet::Packet as PacketTrait;

    #[test]
    fn add_same_dpi_rule() {
        let mut classifier = Classifier::default();
        let expression = String::from("regex");
        let dpi_rule = Rule::new(hyperscan::Pattern::new(expression.clone()).unwrap());
        let rule = super::super::Rule {
            id: 0,
            priority: 0,
            parsers: Vec::new(),
            rule_type: super::super::RuleType::DPI(dpi_rule),
        };

        assert!(matches!(classifier.add_rule(&rule), Ok(_)));

        let mut rule = rule.clone();
        rule.parsers.push(1);
        assert!(matches!(classifier.add_rule(&rule), Ok(rule) if rule.id == 0));
    }

    #[test]
    fn add_invalid_rule_type_rule() {
        let mut classifier = Classifier::default();
        let mut rule = super::super::Rule::new(0);
        rule.rule_type = super::super::RuleType::All;
        assert!(matches!(classifier.add_rule(&rule), Err(_)));
    }

    #[test]
    fn classify() {
        let mut classifier = Classifier::default();
        let expression = String::from("regex");
        let dpi_rule = Rule::new(hyperscan::Pattern::new(expression.clone()).unwrap());
        let rule = super::super::Rule {
            id: 10,
            priority: 100,
            parsers: vec![0],
            rule_type: super::super::RuleType::DPI(dpi_rule),
        };

        assert!(matches!(classifier.add_rule(&rule), Ok(_)));

        classifier.prepare().unwrap();
        let mut scratch = classifier.alloc_scratch().unwrap();

        // matched
        let mut pkt = Box::new(packet::test::Packet::default());
        let buf = b"a sentence contains word regex";
        pkt.raw = Box::new(buf.iter().cloned().collect());
        let mut pkt: Box<dyn PacketTrait> = pkt;
        classifier.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);
        assert_eq!(pkt.rules()[0].id(), 10);
        assert_eq!(pkt.rules()[0].priority, 100);
        assert_eq!(pkt.rules()[0].parsers.len(), 1);
        assert_eq!(pkt.rules()[0].parsers[0], 0);

        // unmatched
        let mut pkt = Box::new(packet::test::Packet::default());
        let buf = b"a sentence does not contains the word";
        pkt.raw = Box::new(buf.iter().cloned().collect());
        let mut pkt: Box<dyn PacketTrait> = pkt;
        classifier.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 0);
    }

    #[test]
    fn classify_protocol_mismatch() {
        let mut classifier = Classifier::default();
        let expression = String::from("regex");
        let mut dpi_rule = Rule::new(hyperscan::Pattern::new(expression.clone()).unwrap());
        dpi_rule.protocol = Protocol::SCTP;
        let rule = super::super::Rule {
            id: 10,
            priority: 100,
            parsers: vec![0],
            rule_type: super::super::RuleType::DPI(dpi_rule),
        };

        assert!(matches!(classifier.add_rule(&rule), Ok(_)));

        classifier.prepare().unwrap();
        let mut scratch = classifier.alloc_scratch().unwrap();

        // matched
        let mut pkt = Box::new(packet::test::Packet::default());
        let buf = b"a sentence contains word regex";
        pkt.raw = Box::new(buf.iter().cloned().collect());
        pkt.layers_mut().trans.protocol = packet::Protocol::TCP;
        let mut pkt: Box<dyn PacketTrait> = pkt;
        classifier.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 0);
    }
}
