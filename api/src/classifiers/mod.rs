use anyhow::Result;
use tinyvec::TinyVec;

use crate::packet;
use crate::parsers::ParserID;

pub mod all;
pub mod dpi;
pub mod macros;
pub mod port;
pub mod protocol;

pub type RuleID = u32;
pub type Parsers = TinyVec<[ParserID; 4]>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    // Get packets by dpi rule
    DPI(dpi::Rule),
    // Get packets by transport layer port
    Port(port::Rule),
    // Get packets by protocol
    Protocol(protocol::Rule),
    // Get all packets
    All,
}

/// Rule struct use for rule binding
#[derive(Debug, Clone)]
pub struct Rule {
    /// Rule ID
    id: RuleID,
    /// Rule priority, 255 is the highest, 0 is the lowest
    pub priority: u8,
    /// Rule type, see details in RuleType
    pub rule_type: RuleType,
    /// Matched protocol parsers
    parsers: Parsers,
}

impl Rule {
    /// Get rule's id
    pub fn id(&self) -> RuleID {
        self.id
    }

    /// Create a new classify rule
    pub fn new(parser_id: ParserID) -> Self {
        let mut parsers = Parsers::default();
        parsers.push(parser_id);
        Rule {
            id: 0,
            priority: 0,
            rule_type: RuleType::All,
            parsers,
        }
    }
}

impl PartialEq for Rule {
    fn eq(&self, other: &Rule) -> bool {
        match (&self.rule_type, &other.rule_type) {
            (RuleType::All, RuleType::All) => true,
            (RuleType::All, _) => false,
            (_, RuleType::All) => false,
            _ => (self.priority == other.priority) && (self.rule_type == other.rule_type),
        }
    }
}

pub mod matched {
    use super::{Parsers, RuleID};
    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Primitive)]
    pub enum RuleType {
        // Get all packets
        All = 0,
        // Get packets by dpi rule
        DPI = 1,
        // Get packets by transport layer port
        Port = 2,
        // Get packets by protocol
        Protocol = 3,
    }

    impl Default for RuleType {
        fn default() -> Self {
            Self::All
        }
    }

    impl From<&super::RuleType> for RuleType {
        #[inline]
        fn from(rule_type: &super::RuleType) -> Self {
            match rule_type {
                super::RuleType::All => RuleType::All,
                super::RuleType::Port(_) => RuleType::Port,
                super::RuleType::DPI(_) => RuleType::DPI,
                super::RuleType::Protocol(_) => RuleType::Protocol,
            }
        }
    }

    #[derive(Debug, Default, Clone, PartialEq)]
    /// Data struct used by Packet trait, only contains necessary information about matched rule
    ///
    /// General Rule struct is quite huge, since it contains the real classify rule information,
    /// but most of the time we don't need that information for every packet.
    ///
    /// For example, we want to process a http stream, we only need to know that one of
    /// the tcp packets of this session matched the HTTP Request rule. But we do not need to know
    /// which method it matches, just leave it to the http parser.
    ///
    /// So for performance reason(reduce bytes to copy and heap allocation),
    /// we use a simplified `RuleType` & `Rule`. This is enough for parsers to work.
    ///
    pub struct Rule {
        pub id: RuleID,
        pub priority: u8,
        pub rule_type: RuleType,
        pub parsers: Parsers,
        pub from_to: Option<(u16, u16)>,
    }

    impl From<&super::Rule> for Rule {
        fn from(rule: &super::Rule) -> Self {
            Rule {
                id: rule.id,
                priority: rule.priority,
                rule_type: RuleType::from(&rule.rule_type),
                parsers: rule.parsers.clone(),
                from_to: None,
            }
        }
    }

    impl Rule {
        /// Create a new match rule
        pub fn new(rule_type: RuleType) -> Self {
            let mut rule = Self::default();
            rule.rule_type = rule_type;
            rule
        }

        /// Get rule's id
        pub fn id(&self) -> RuleID {
            self.id
        }
    }
}

pub trait Classifier {
    /// Add a classify rule for this classifier
    ///
    /// # Arguments
    ///
    /// * `rule` - Rule information
    ///
    /// # Returns
    ///
    /// * `Result<&Rule>` - Rule
    fn add_rule(&mut self, rule: &Rule) -> Result<Rule>;
}

/// Protocol Classifier
pub struct ClassifierManager {
    /// Store rule detail information
    rules: Vec<Rule>,
    /// Receive all pkts rules
    all_pkt_classifier: all::Classifier,
    /// Port classifier
    port_classifier: port::Classifier,
    /// DPI classifier
    dpi_classifier: dpi::Classifier,
    /// Protocol classifier
    proto_classifier: protocol::Classifier,
}

pub type ClassifyScratch = dpi::ClassifyScratch;

impl ClassifierManager {
    pub fn new() -> ClassifierManager {
        ClassifierManager {
            rules: vec![Rule {
                id: 0,
                priority: 255,
                rule_type: RuleType::All,
                parsers: Parsers::default(),
            }], // first rule is always the receive all pkt rule
            all_pkt_classifier: all::Classifier::default(),
            port_classifier: port::Classifier::default(),
            dpi_classifier: dpi::Classifier::default(),
            proto_classifier: protocol::Classifier::default(),
        }
    }

    /// Find whether there specific rule is already registerd
    ///
    /// # Arguments
    ///
    /// * `rule` - Rule information
    ///
    /// # Returns
    ///
    /// * `Option<&Rule>` - Find result
    fn find(&self, rule: &Rule) -> Option<&Rule> {
        self.rules.iter().find(|r| *r == rule)
    }

    /// Get rule by ID
    #[inline]
    pub fn get_rule(&self, id: RuleID) -> Option<&Rule> {
        self.rules.get(id as usize)
    }

    /// Add a classify rule
    pub fn add_rule(&mut self, rule: &mut Rule) -> Result<RuleID> {
        // Find existing rule first, let individual classifiers handle same rule situation
        let rule = match self.find(rule) {
            Some(r) => {
                rule.id = r.id;
                match rule.rule_type {
                    RuleType::All => self.all_pkt_classifier.add_rule(rule)?,
                    RuleType::DPI(_) => self.dpi_classifier.add_rule(rule)?,
                    RuleType::Port(_) => self.port_classifier.add_rule(rule)?,
                    RuleType::Protocol(_) => self.proto_classifier.add_rule(rule)?,
                }
            }
            None => {
                rule.id = self.rules.len() as RuleID;
                let match_rule = match rule.rule_type {
                    RuleType::All => self.all_pkt_classifier.add_rule(rule)?,
                    RuleType::DPI(_) => self.dpi_classifier.add_rule(rule)?,
                    RuleType::Port(_) => self.port_classifier.add_rule(rule)?,
                    RuleType::Protocol(_) => self.proto_classifier.add_rule(rule)?,
                };
                self.rules.push(rule.clone());
                match_rule
            }
        };

        self.rules[rule.id() as usize] = rule.clone();
        // self.rules[rule.id() as usize].parsers = rule.parsers.clone();

        Ok(rule.id())
    }

    pub fn get_dpi_rule_internal_id(&self, rule_id: RuleID) -> usize {
        match &self.get_rule(rule_id).unwrap().rule_type {
            RuleType::DPI(rule) => rule.hs_pattern.id.unwrap(),
            _ => unreachable!(),
        }
    }

    /// Allocate a protocol classifier scratch
    ///
    /// # Returns
    ///
    /// * `Result<ClassifyScratch>` - classifier scratch
    pub fn alloc_scratch(&self) -> Result<ClassifyScratch> {
        self.dpi_classifier.alloc_scratch()
    }

    pub fn prepare(&mut self) -> Result<()> {
        self.dpi_classifier.prepare()
    }

    /// Classify protocol
    #[inline]
    pub fn classify(
        &self,
        pkt: &mut Box<dyn packet::Packet>,
        scratch: &mut dpi::ClassifyScratch,
    ) -> Result<()> {
        self.all_pkt_classifier.classify(pkt);

        self.proto_classifier.classify(pkt);

        self.port_classifier.classify(pkt);

        self.dpi_classifier.classify(pkt, scratch)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_all_pkt_rule() {
        let mut classifier = ClassifierManager::new();
        // add a regular receive all pkt rule
        let mut rule = Rule::new(1);

        classifier.add_rule(&mut rule).unwrap();
        assert_eq!(classifier.rules.len(), 1);
        assert_eq!(classifier.rules[0].id(), 0);
        assert_eq!(classifier.rules[0].priority, 0);
        assert_eq!(classifier.rules[0].parsers.len(), 1);
        assert_eq!(classifier.rules[0].parsers[0], 1);
        assert!(matches!(classifier.rules[0].rule_type, RuleType::All));

        // add a rule that has different id and priority
        let mut rule = Rule::new(2);
        classifier.add_rule(&mut rule).unwrap();
        assert_eq!(classifier.rules.len(), 1);
        assert_eq!(classifier.rules[0].id(), 0);
        assert_eq!(classifier.rules[0].priority, 0);
        assert_eq!(classifier.rules[0].parsers.len(), 2);
        assert_eq!(classifier.rules[0].parsers[0], 1);
        assert_eq!(classifier.rules[0].parsers[1], 2);
    }

    #[test]
    fn add_port_rule() {
        let mut classifier = ClassifierManager::new();
        // add a regular port rule
        let mut rule = Rule::new(1);
        rule.rule_type = RuleType::Port(port::Rule {
            port: 80,
            protocol: packet::Protocol::TCP,
        });
        classifier.add_rule(&mut rule).unwrap();
        assert_eq!(classifier.rules.len(), 2);
        assert_eq!(classifier.rules[1].id(), 1);
        assert_eq!(classifier.rules[1].priority, 0);
        assert_eq!(classifier.rules[1].parsers.len(), 1);
        assert_eq!(classifier.rules[1].parsers[0], 1);
        assert!(matches!(classifier.rules[1].rule_type, RuleType::Port(r) if r.port == 80));
        match classifier.rules[1].rule_type {
            RuleType::Port(r) => {
                assert!(matches!(r.protocol, packet::Protocol::TCP));
            }
            _ => unreachable!(),
        };
    }

    #[test]
    fn classifier_add_dpi_rule() {
        // let mut classifier = ClassifierManager::new();
        // let expression = String::from("regex");
        // let pattern = hyperscan::Pattern::new(expression.clone()).unwrap();
        // classifier.add_dpi_rule(pattern, 100);
        // assert_eq!(classifier.dpi_rules[0].hs_pattern.expression, expression);
        // assert_eq!(classifier.dpi_rules[0].protocols[0], 100);

        // classifier.prepare();
        // let scratch = classifier.alloc_scratch().unwrap();
        // let mut protocols = Vec::new();
        // let mut pkt = packet::Packet::default();

        // classifier.classify(&pkt, &mut protocols, &scratch).unwrap();
        // assert_eq!(protocols.len(), 0);

        // pkt.data = Box::new(Vec::from(String::from("regex").as_bytes()));
        // classifier.classify(&pkt, &mut protocols, &scratch).unwrap();
        // assert_eq!(protocols.len(), 1);
        // println!("result: {:?}", protocols);
        // assert_eq!(protocols[0], 100);
    }

    #[test]
    fn classifier_add_dpi_rule_with_existing_expression() {
        // let mut classifier = ClassifierManager::new();
        // let expression = String::from("regex");
        // let pattern = hyperscan::Pattern::new(expression.clone()).unwrap();
        // classifier.add_dpi_rule(pattern, 100);
        // assert_eq!(classifier.dpi_rules[0].hs_pattern.expression, expression);
        // assert_eq!(classifier.dpi_rules[0].protocols[0], 100);

        // let expression = String::from("regex");
        // let pattern = hyperscan::Pattern::new(expression.clone()).unwrap();
        // classifier.add_dpi_rule(pattern, 8);
        // assert_eq!(classifier.dpi_rules[0].hs_pattern.expression, expression);
        // assert_eq!(classifier.dpi_rules[0].protocols[1], 8);
    }

    #[test]
    fn rule_type_size() {
        // assert_eq!(std::mem::size_of::<RuleType>(), 1);
        // assert_eq!(std::mem::size_of::<Rule>(), 1);
        // assert_eq!(std::mem::size_of::<hyperscan::Pattern>(), 1);
        // assert_eq!(std::mem::size_of::<Result<()>>(), 1);
    }
}
