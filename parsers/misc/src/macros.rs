/// Add a simple DPI rule
#[macro_export]
macro_rules! add_simple_dpi_rule {
    ($hs_pattern:literal, $protocol_name:literal, $trans_protocol: expr, $parser: expr, $manager: expr) => {
        let mut dpi_rule = dpi::Rule::new(pattern! {$hs_pattern});
        dpi_rule.protocol = $trans_protocol;
        let mut rule = Rule::new($parser.id);
        rule.rule_type = RuleType::DPI(dpi_rule);
        let rule_id = $manager.add_rule(&mut rule)?;
        $parser.match_cbs.insert(
            rule_id,
            MatchCallBack::ProtocolName($protocol_name.to_string()),
        );
    };
}

/// Add a simple TCP DPI rule
#[macro_export]
macro_rules! add_simple_dpi_tcp_rule {
    ($hs_pattern:literal, $protocol:literal, $parser: expr, $manager: expr) => {
        add_simple_dpi_rule!(
            $hs_pattern,
            $protocol,
            dpi::Protocol::TCP,
            $parser,
            $manager
        )
    };
}

/// Add a simple UDP DPI rule
#[macro_export]
macro_rules! add_simple_dpi_udp_rule {
    ($hs_pattern:literal, $protocol:literal, $parser: expr, $manager: expr) => {
        add_simple_dpi_rule!(
            $hs_pattern,
            $protocol,
            dpi::Protocol::UDP,
            $parser,
            $manager
        )
    };
}

#[macro_export]
macro_rules! add_simple_dpi_tcp_udp_rule {
    ($hs_pattern:literal, $protocol:literal, $parser: expr, $manager: expr) => {
        add_simple_dpi_rule!(
            $hs_pattern,
            $protocol,
            dpi::Protocol::TCP | dpi::Protocol::UDP,
            $parser,
            $manager
        )
    };
}

#[macro_export]
macro_rules! add_dpi_rule_with_func {
    ($hs_pattern:literal, $func:ident, $trans_protocol: expr, $parser: expr, $manager: expr) => {
        let mut dpi_rule = dpi::Rule::new(pattern! {$hs_pattern});
        dpi_rule.protocol = $trans_protocol;
        let mut rule = Rule::new($parser.id);
        rule.rule_type = RuleType::DPI(dpi_rule);
        let rule_id = $manager.add_rule(&mut rule)?;
        $parser
            .match_cbs
            .insert(rule_id, MatchCallBack::Func($func));
    };
    ($hs_pattern:expr, $func:ident, $trans_protocol: expr, $parser: expr, $manager: expr) => {
        let mut dpi_rule = dpi::Rule::new($hs_pattern);
        dpi_rule.protocol = $trans_protocol;
        let mut rule = Rule::new($parser.id);
        rule.rule_type = RuleType::DPI(dpi_rule);
        let rule_id = $manager.add_rule(&mut rule)?;
        $parser
            .match_cbs
            .insert(rule_id, MatchCallBack::Func($func));
    };
}

#[macro_export]
macro_rules! add_dpi_tcp_rule_with_func {
    ($hs_pattern:literal, $func:ident, $parser: expr, $manager: expr) => {
        add_dpi_rule_with_func!($hs_pattern, $func, dpi::Protocol::TCP, $parser, $manager)
    };
    ($hs_pattern:expr, $func:ident, $parser: expr, $manager: expr) => {
        add_dpi_rule_with_func!($hs_pattern, $func, dpi::Protocol::TCP, $parser, $manager)
    };
}

#[macro_export]
macro_rules! add_dpi_udp_rule_with_func {
    ($hs_pattern:literal, $func:ident, $parser: expr, $manager: expr) => {
        add_dpi_rule_with_func!($hs_pattern, $func, dpi::Protocol::UDP, $parser, $manager)
    };
}

#[macro_export]
macro_rules! add_dpi_tcp_udp_rule_with_func {
    ($hs_pattern:literal, $func:ident, $parser: expr, $manager: expr) => {
        add_dpi_rule_with_func!(
            $hs_pattern,
            $func,
            dpi::Protocol::TCP | dpi::Protocol::UDP,
            $parser,
            $manager
        )
    };
    ($hs_pattern:expr, $func:ident, $parser: expr, $manager: expr) => {
        add_dpi_rule_with_func!(
            $hs_pattern,
            $func,
            dpi::Protocol::TCP | dpi::Protocol::UDP,
            $parser,
            $manager
        )
    };
}

#[macro_export]
macro_rules! add_none_dpi_rule {
    ($hs_pattern:literal, $trans_protocol: expr, $parser: expr, $manager: expr) => {{
        let mut dpi_rule = dpi::Rule::new(pattern! {$hs_pattern});
        dpi_rule.protocol = $trans_protocol;
        let mut rule = Rule::new($parser.id);
        rule.rule_type = RuleType::DPI(dpi_rule);
        let rule_id = $manager.add_rule(&mut rule)?;
        $parser.match_cbs.insert(rule_id, MatchCallBack::None);
        match &$manager.get_rule(rule_id).unwrap().rule_type {
            RuleType::DPI(rule) => rule.hs_pattern.id.unwrap(),
            _ => unreachable!(),
        }
    }};
}

#[macro_export]
macro_rules! add_none_dpi_tcp_rule {
    ($hs_pattern:literal, $parser: expr, $manager: expr) => {
        add_none_dpi_rule!($hs_pattern, dpi::Protocol::TCP, $parser, $manager)
    };
}

#[macro_export]
macro_rules! add_none_dpi_udp_rule {
    ($hs_pattern:literal, $parser: expr, $manager: expr) => {
        add_none_dpi_rule!($hs_pattern, dpi::Protocol::UDP, $parser, $manager)
    };
}
