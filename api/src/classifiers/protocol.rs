use std::hash::Hash;

use anyhow::{anyhow, Result};

use crate::packet;

use super::matched;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Rule(pub packet::Protocol);

pub struct Classifier {
    /// Port rules
    rules: Vec<matched::Rule>,
}

impl Default for Classifier {
    fn default() -> Self {
        Classifier {
            rules: vec![matched::Rule::new(matched::RuleType::Protocol); u8::MAX as usize],
        }
    }
}

impl super::Classifier for Classifier {
    fn add_rule(&mut self, rule: &super::Rule) -> Result<super::Rule> {
        let proto_rule = match &rule.rule_type {
            super::RuleType::Protocol(r) => r,
            r => {
                return Err(anyhow!(
                    "Mismatched rule type, expecting Protocol Rule, get {:?}",
                    r
                ))
            }
        };

        let i = proto_rule.0 as u8 as usize;
        self.rules[i].id = rule.id;
        self.rules[i].parsers.push(rule.parsers[0]);
        Ok(super::Rule {
            id: self.rules[i].id(),
            priority: self.rules[i].priority,
            rule_type: rule.rule_type.clone(),
            parsers: self.rules[i].parsers.clone(),
        })
    }
}

impl Classifier {
    pub fn classify(&self, pkt: &mut Box<dyn packet::Packet>) {
        macro_rules! classify_layer {
            ($layer:ident) => {
                let i = pkt.layers().$layer.protocol as usize;
                if self.rules[i].parsers.len() > 0 {
                    pkt.rules_mut().push(self.rules[i].clone());
                }
                match pkt.layers().$layer.protocol {
                    packet::Protocol::UNKNOWN => return,
                    _ => {}
                };
            };
        }

        classify_layer!(data_link);
        classify_layer!(network);
        classify_layer!(trans);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::classifiers::Classifier as ClassifierTrait;
    use crate::packet::Packet as PacketTrait;
    use crate::utils;

    #[test]
    fn add_same_protocol_rule() {
        let mut classifier = Box::new(Classifier::default());
        let proto_rule = Rule(packet::Protocol::TCP);
        let mut rule = crate::classifiers::Rule::new(1);
        rule.rule_type = crate::classifiers::RuleType::Protocol(proto_rule);
        assert!(matches!(classifier.add_rule(&mut rule), Ok(_)));

        let rule = &classifier.rules[proto_rule.0 as usize];
        assert_eq!(rule.parsers.len(), 1);
        assert_eq!(rule.parsers[0], 1);

        // Add a same rule only ID is different, we expected the same
        let proto_rule = Rule(packet::Protocol::TCP);
        let mut rule = crate::classifiers::Rule::new(2);
        rule.rule_type = crate::classifiers::RuleType::Protocol(proto_rule);
        assert!(matches!(classifier.add_rule(&mut rule), Ok(rule) if rule.id == 0));

        let rule = &classifier.rules[proto_rule.0 as usize];
        assert_eq!(rule.parsers.len(), 2);
        assert_eq!(rule.parsers[1], 2);
    }

    #[test]
    fn add_invalid_rule_type_rule() {
        let mut classifier = Classifier::default();
        let mut rule = super::super::Rule::new(0);
        rule.rule_type = super::super::RuleType::All;
        assert!(matches!(classifier.add_rule(&mut rule), Err(_)));
    }

    /// Classify a normal TCP/IP stack packet
    #[test]
    fn classify() {
        let mut classifier = Box::new(Classifier::default());
        let proto_rule = Rule(packet::Protocol::TCP);
        let mut rule = crate::classifiers::Rule::new(1);
        rule.rule_type = crate::classifiers::RuleType::Protocol(proto_rule);
        classifier.add_rule(&mut rule).unwrap();

        let mut pkt = Box::new(utils::packet::Packet::default());
        pkt.layers_mut().data_link = packet::Layer {
            offset: 0,
            protocol: packet::Protocol::ETHERNET,
        };
        pkt.layers_mut().network = packet::Layer {
            offset: 14,
            protocol: packet::Protocol::IPV4,
        };
        pkt.layers_mut().trans = packet::Layer {
            offset: 34,
            protocol: packet::Protocol::TCP,
        };
        let mut pkt: Box<dyn PacketTrait> = pkt;
        classifier.classify(&mut pkt);
        assert_eq!(pkt.rules().len(), 1);
        assert_eq!(pkt.rules()[0].rule_type, matched::RuleType::Protocol);
        assert_eq!(pkt.rules()[0].parsers[0], 1);
        assert_eq!(pkt.rules()[0].parsers.len(), 1);
    }
}
