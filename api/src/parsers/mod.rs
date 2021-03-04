use std::ops::{Deref, DerefMut};

use anyhow::Result;

use crate::classifiers::ClassifierManager;
use crate::{packet, session};

pub type ParserID = u8;

/// Create a Box of the protocol parser
pub type NewProtocolParserFunc = extern "C" fn() -> Box<Box<dyn ProtocolParserTrait>>;
/// Create a Vector of Box of the protocol parser
pub type NewProtocolParserBoxesFunc = extern "C" fn() -> Box<Vec<Box<dyn ProtocolParserTrait>>>;

// Initialize parser required global resources
pub type ParserInitFunc = fn() -> Result<()>;

// Release parser required global resources
pub type ParserExitFunc = fn() -> Result<()>;

pub struct ProtocolParser {
    parser: Box<Box<dyn ProtocolParserTrait>>,
}

impl ProtocolParser {
    pub fn new(parser: Box<Box<dyn ProtocolParserTrait>>) -> Self {
        ProtocolParser { parser }
    }
}

impl Deref for ProtocolParser {
    type Target = Box<dyn ProtocolParserTrait>;
    fn deref(&self) -> &Self::Target {
        &self.parser
    }
}

impl DerefMut for ProtocolParser {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.parser
    }
}

pub trait ProtocolParserTrait: Send + Sync {
    /// Clone a Protocol Parser
    fn box_clone(&self) -> Box<dyn ProtocolParserTrait>;

    /// Get parser id
    fn id(&self) -> ParserID;

    /// Set parser id
    fn set_id(&mut self, id: ParserID);

    /// Get parser name
    fn name(&self) -> &str;

    /// Initialize parser required global resources
    fn init(&mut self) -> Result<()> {
        Ok(())
    }

    // Release parser required global resources
    fn exit(&mut self) -> Result<()> {
        Ok(())
    }

    /// Register protocol classify rules
    fn register_classify_rules(&mut self, manager: &mut ClassifierManager) -> Result<()>;

    /// Parse a single packet and maybe update session information
    fn parse_pkt(
        &mut self,
        _pkt: &Box<dyn packet::Packet>,
        _rule: Option<&super::classifiers::matched::Rule>,
        ses: &mut session::Session,
    ) -> Result<()> {
        if !self.is_classified() {
            // If this session is already classified as this protocol, skip
            self.classified_as_this_protocol()?;
            ses.add_protocol(&self.name());
        }

        Ok(())
    }

    /// Check whether the session is classfied as this protocol
    fn is_classified(&self) -> bool;

    /// Change this protocol parser's internal state to indicate this session is classfied as this protocol
    fn classified_as_this_protocol(&mut self) -> Result<()>;

    /// Cleanup operations
    fn finish(&mut self, _: &mut session::Session) {}
}
