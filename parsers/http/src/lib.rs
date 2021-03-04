use anyhow::{anyhow, Result};
use hyperscan::pattern;
use once_cell::sync::OnceCell;

use alphonse_api as api;
use api::classifiers;
use api::classifiers::{dpi, Rule, RuleID, RuleType};
use api::parsers::ParserID;
use api::session::Session;
use api::{add_simple_dpi_rule, add_simple_dpi_tcp_rule};

static SETTINGS: OnceCell<llhttp::Settings> = OnceCell::new();

#[derive(Clone)]
struct ProtocolParser<'a> {
    id: ParserID,
    name: String,
    classified: bool,
    parsers: [llhttp::Parser<'a>; 2],
}

fn on_url(parser: &mut llhttp::Parser, at: *const libc::c_char, length: usize) -> libc::c_int {
    let http = match parser.data::<HTTP>() {
        Some(h) => h,
        None => return 0,
    };

    let url = unsafe { std::slice::from_raw_parts(at as *const u8, length) };
    http.url.push(String::from_utf8_lossy(url).to_string());
    0
}

#[derive(Clone, Default)]
struct HTTP {
    url: Vec<String>,
    host: String,
    cookie: String,
    auth: String,
    value: [String; 2],
    header: [String; 2],
    checksum: String,
}

unsafe impl Send for ProtocolParser<'_> {}
unsafe impl Sync for ProtocolParser<'_> {}

impl<'a> ProtocolParser<'a> {
    fn new() -> Self {
        ProtocolParser {
            id: 0,
            name: String::from("http"),
            classified: false,
            parsers: [llhttp::Parser::default(), llhttp::Parser::default()],
        }
    }
}

impl<'a> api::parsers::ProtocolParserTrait for ProtocolParser<'static> {
    fn box_clone(&self) -> Box<dyn api::parsers::ProtocolParserTrait> {
        Box::new(self.clone())
    }

    /// Get parser id
    fn id(&self) -> ParserID {
        self.id
    }

    /// Get parser id
    fn set_id(&mut self, id: ParserID) {
        self.id = id
    }

    /// Get parser name
    fn name(&self) -> &str {
        &self.name.as_str()
    }

    fn register_classify_rules(
        &mut self,
        manager: &mut classifiers::ClassifierManager,
    ) -> Result<()> {
        let methods = vec![
            "DELETE",
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "CONNECT",
            "OPTIONS",
            "TRACE",
            "COPY",
            "LOCK",
            "MKCOL",
            "MOVE",
            "PROPFIND",
            "PROPPATCH",
            "SEARCH",
            "UNLOCK",
            "BIND",
            "REBIND",
            "UNBIND",
            "ACL",
            "REPORT",
            "MKACTIVITY",
            "CHECKOUT",
            "MERGE",
            "MSEARCH",
            "NOTIFY",
            "SUBSCRIBE",
            "UNSUBSCRIBE",
            "PATCH",
            "PURGE",
            "MKCALENDAR",
            "LINK",
            "UNLINK",
            "SOURCE",
            "PRI",
            "DESCRIBE",
            "ANNOUNCE",
            "SETUP",
            "PLAY",
            "PAUSE",
            "TEARDOWN",
            "GET_PARAMETER",
            "SET_PARAMETER",
            "REDIRECT",
            "RECORD",
            "FLUSH",
        ];
        for method in methods {
            let mut expression = String::from("^");
            expression.push_str(method);
            let pattern = hyperscan::Pattern {
                expression,
                id: None,
                flags: hyperscan::PatternFlags::empty(),
                ext: hyperscan::ExprExt::default(),
                som: None,
            };
            let dpi_rule = dpi::Rule::new(pattern);
            let mut rule = classifiers::Rule::new(self.id());
            rule.rule_type = classifiers::RuleType::DPI(dpi_rule);
            manager.add_rule(&mut rule)?;
        }

        let dpi_rule = classifiers::dpi::Rule::new(pattern! {"^HTTP"});
        let mut rule = classifiers::Rule::new(self.id());
        rule.rule_type = classifiers::RuleType::DPI(dpi_rule);
        manager.add_rule(&mut rule)?;

        Ok(())
    }

    fn is_classified(&self) -> bool {
        self.classified
    }

    fn classified_as_this_protocol(&mut self) -> Result<()> {
        self.classified = true;
        Ok(())
    }

    fn parse_pkt(
        &mut self,
        pkt: &Box<dyn api::packet::Packet>,
        _rule: Option<&api::classifiers::matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        if !self.is_classified() {
            // If this session is already classified as this protocol, skip
            self.classified_as_this_protocol()?;
            ses.add_protocol(&self.name());
            let settings = match SETTINGS.get() {
                Some(s) => s,
                None => return Err(anyhow!("Global llhttp sttings is empty or initializing")),
            };
            let http = Box::into_raw(Box::new(HTTP::default()));
            for parser in &mut self.parsers {
                parser.init(settings, llhttp::Type::BOTH);
                parser.set_data(http);
            }
        }

        let direction = pkt.direction() as u8 as usize;

        match self.parsers[direction].parse(pkt.payload()) {
            llhttp::Error::Ok => {}
            llhttp::Error::Paused | llhttp::Error::PausedUpgrade => {}
            _ => {
                let data = self.parsers[direction].set_data::<HTTP>(std::ptr::null_mut());
                let settings = match SETTINGS.get() {
                    Some(s) => s,
                    None => {
                        return Err(anyhow!(
                            "Global llhttp sttings is empty or being initialized"
                        ))
                    }
                };
                self.parsers[direction].init(settings, llhttp::Type::BOTH);
                self.parsers[direction].set_data(data);
            }
        };

        Ok(())
    }

    fn finish(&mut self, ses: &mut Session) {
        self.parsers[0].set_data::<HTTP>(std::ptr::null_mut());
        let http = self.parsers[1].set_data::<HTTP>(std::ptr::null_mut());
        let http = if http.is_null() {
            return;
        } else {
            unsafe { Box::from_raw(http) }
        };

        ses.add_field(&"http.uri", &serde_json::json!(http.url));
    }
}

#[no_mangle]
pub extern "C" fn al_new_protocol_parser() -> Box<Box<dyn api::parsers::ProtocolParserTrait>> {
    // initialize global llhttp settings
    let mut settings = llhttp::Settings::default();

    llhttp::data_cb_wrapper!(_on_url, on_url);
    settings.on_url(Some(_on_url));

    SETTINGS.set(settings).unwrap();

    Box::new(Box::new(ProtocolParser::new()))
}
