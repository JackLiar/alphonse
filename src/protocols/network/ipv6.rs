use super::ParserError;
use super::{Layer, SimpleProtocolParser};

pub struct Parser {}

impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(_buf: &[u8]) -> Result<Layer, ParserError> {
        return Err(ParserError::UnsupportProtocol(format!(
            "Unsupport protocol: IPV6"
        )));
    }
}
