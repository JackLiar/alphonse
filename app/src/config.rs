use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Result};
use yaml_rust::{Yaml, YamlLoader};

use super::commands::CliArg;

#[derive(Default, Clone)]
pub struct Config {
    pub rx_backend: String,
    pub verbose_mode: bool,
    pub pkt_channel_size: u32,
    pub default_timeout: u16,
    pub delete: bool,
    pub dpdk_eal_args: Vec<String>,
    pub dry_run: bool,
    pub interfaces: Vec<String>,
    pub output_threads: u8,
    pub parsers: Vec<String>,
    pub pcap_file: String,
    pub pcap_dir: String,
    pub pkt_threads: u8,
    pub quiet: bool,
    pub recursive: bool,
    pub rx_stat_log_interval: u64,
    pub rx_threads: u8,
    /// Max single session packets
    pub ses_max_packets: u16,
    /// Max session connection duration
    pub ses_save_timeout: u16,
    pub ses_threads: u8,
    pub sctp_timeout: u16,
    pub tags: Vec<String>,
    pub tcp_timeout: u16,
    pub timeout_interval: u64,
    pub udp_timeout: u16,
    pub docs: Vec<Yaml>,
}

fn get_str(doc: &Yaml, key: &str, default: &str) -> String {
    match &doc[key] {
        Yaml::String(s) => s.clone(),
        Yaml::BadValue => {
            println!(
                "Option {} not found or bad string value, set {} to {}",
                key, key, default
            );
            default.to_string()
        }
        _ => {
            println!(
                "Wrong value type for {}, expecting string, set {} to {}",
                key, key, default
            );
            default.to_string()
        }
    }
}

fn get_integer(doc: &Yaml, key: &str, default: i64, min: i64, max: i64) -> i64 {
    match doc[key] {
        Yaml::Integer(i) => {
            if i < min || i > max {
                println!(
                    "Option {} is less/greater than min/max value {}/{}, set {} to {}",
                    key, min, max, key, default
                );
                default
            } else {
                i
            }
        }
        Yaml::BadValue => {
            println!(
                "Option {} not found or bad integer value, set {} to {}",
                key, key, default
            );
            default
        }
        _ => {
            println!(
                "Wrong value type for {}, expecting string, set {} to {}",
                key, key, default
            );
            default
        }
    }
}

fn get_str_arr(doc: &Yaml, key: &str) -> Vec<String> {
    let mut result = vec![];
    match &doc[key] {
        Yaml::Array(a) => {
            for parser in a {
                match parser {
                    Yaml::String(s) => result.push(String::from(s)),
                    Yaml::BadValue => println!("Bad string value for {}'s element", key),
                    _ => println!("Wrong value type for {}' element, expecting string", key),
                }
            }
        }
        Yaml::BadValue => println!(
            "Option {} not found or bad array value, set {} to empty array",
            key, key
        ),
        _ => println!(
            "Wrong value type for {}, expecting array, set {} to empty array",
            key, key
        ),
    }
    result
}

impl Config {
    pub fn get_integer(&self, key: &str, default: i64, min: i64, max: i64) -> i64 {
        get_integer(&self.docs[0], key, default, min, max)
    }

    pub fn get_str(&self, key: &str, default: &str) -> String {
        get_str(&self.docs[0], key, default)
    }

    pub fn get_str_arr(&self, key: &str) -> Vec<String> {
        get_str_arr(&self.docs[0], key)
    }
}

/// Parse command line arguments and set configuration
pub fn parse_args(root_cmd: clap::App) -> Result<Config> {
    let mut config: Config = Default::default();
    let matches = root_cmd.get_matches();

    if let Some(config_file) = matches.value_of("config") {
        parse_config_file(config_file, &mut config)?;
    }

    set_config_by_cli_args(&mut config, &matches);

    if (config.pcap_dir.is_empty() || config.pcap_file.is_empty()) && config.interfaces.is_empty() {
        return Err(anyhow!(
            "Launched without specify network interface nor pcap file/dir"
        ));
    }

    Ok(config)
}

fn parse_config_file(config_file: &str, config: &mut Config) -> Result<()> {
    let cfg_path = Path::new(config_file);
    if !cfg_path.exists() {
        eprintln!(
            "\"{}\" does not exist! Use default configuration file instead",
            config_file
        );
    }

    let mut s = String::new();
    File::open(cfg_path)?.read_to_string(&mut s)?;

    let docs = YamlLoader::load_from_str(&s)?;
    let doc = &docs[0];
    config.docs = docs.clone();

    config.pkt_channel_size =
        get_integer(doc, "channel.pkt.size", 1000000, 100000, 10000000) as u32;
    config.timeout_interval = get_integer(doc, "timeout.interval", 1, 1, 10) as u64;
    config.default_timeout = get_integer(doc, "timeout.default", 60, 10, 180) as u16;
    config.tcp_timeout = get_integer(doc, "timeout.tcp", 60, 10, 180) as u16;
    config.udp_timeout = get_integer(doc, "timeout.udp", 60, 10, 180) as u16;
    config.sctp_timeout = get_integer(doc, "timeout.sctp", 60, 10, 180) as u16;
    config.ses_save_timeout = get_integer(doc, "timeout.ses.save", 180, 60, 360) as u16;

    config.ses_max_packets =
        get_integer(doc, "ses.max.packets", 10000, 1000, u16::MAX as i64) as u16;

    config.pkt_threads = get_integer(doc, "threads.pkt", 1, 1, 24) as u8;
    config.rx_threads = get_integer(doc, "threads.rx", 1, 1, 24) as u8;
    config.ses_threads = get_integer(doc, "threads.session", 1, 1, 24) as u8;
    config.output_threads = get_integer(doc, "threads.output", 1, 1, 24) as u8;

    let backend = get_str(doc, "rx.backend", "libpcap");
    match backend.as_str() {
        "dpdk" | "libpcap" => {
            config.rx_backend = backend;
        }
        _ => {
            println!(
                "Invalid rx.backend option: {}, set rx.backend to {}",
                s, "libpcap"
            );
        }
    };

    config.parsers = get_str_arr(doc, "parsers");
    config.interfaces = get_str_arr(doc, "interfaces");

    config.rx_stat_log_interval =
        get_integer(doc, "rx.stats.log.interval", 10000, 10000, i64::MAX) as u64;

    #[cfg(all(target_os = "linux", feature = "dpdk"))]
    {
        // parse DPDK EAL intialize arguments
        let args = doc["dpdk.eal.args"]
            .as_vec()
            .ok_or(anyhow!("Invalid type/bad value for dpdk.eal.args"))?;
        for arg in args {
            let arg = arg
                .as_str()
                .ok_or(anyhow!("Failed to convert Yaml into &str"))?
                .to_string();
            config.dpdk_eal_args.push(arg);
        }
    }
    Ok(())
}

/// Use command arguments overrides config file settings
fn set_config_by_cli_args(config: &mut Config, matches: &clap::ArgMatches) {
    config.delete = matches.is_present(CliArg::Delete.as_str());
    config.dry_run = matches.is_present(CliArg::DryRun.as_str());
    config.quiet = matches.is_present(CliArg::Quiet.as_str());
    config.recursive = matches.is_present(CliArg::Recursive.as_str());
    config.verbose_mode = matches.is_present(CliArg::Verbose.as_str());

    if let Some(pcap_file) = matches.value_of(CliArg::PcapFile.as_str()) {
        config.pcap_file = String::from(pcap_file);
    }

    if let Some(pcap_dir) = matches.value_of(CliArg::PcapDir.as_str()) {
        config.pcap_dir = String::from(pcap_dir);
    }

    if let Some(tags) = matches.values_of(CliArg::Tags.as_str()) {
        config.tags = tags.map(|x| String::from(x)).collect::<Vec<_>>();
    }
}
