use clap::{App, Arg};

/// Avaliable command line arguments
pub enum CliArg {
    Config,
    Delete,
    DryRun,
    PcapDir,
    PcapFile,
    Quiet,
    Recursive,
    Tags,
    Verbose,
}

impl CliArg {
    pub fn as_str(&self) -> &str {
        match self {
            &CliArg::Config => "config",
            &CliArg::Delete => "delete",
            &CliArg::DryRun => "dryrun",
            &CliArg::PcapDir => "pcap-dir",
            &CliArg::PcapFile => "pcap-file",
            &CliArg::Quiet => "quiet",
            &CliArg::Recursive => "recursive",
            &CliArg::Tags => "tags",
            &CliArg::Verbose => "verbose",
        }
    }
}

/// Construct a new clap root command
pub fn new_root_command<'a>() -> clap::App<'a, 'static> {
    let root_cmd = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .args(&[
            Arg::with_name(CliArg::Config.as_str())
                .short("c")
                .value_name("FILE")
                .help("Use a specific config file")
                .takes_value(true),
            Arg::with_name(CliArg::Delete.as_str())
                .long("delete")
                .help("In offline mode delete files once processed"),
            Arg::with_name(CliArg::DryRun.as_str())
                .long("dryrun")
                .help("In dry run mode, nothing would be written to databases or filesystem"),
            Arg::with_name(CliArg::PcapDir.as_str())
                .short("R")
                .value_name("PCAP-DIR")
                .help("Offline pcap directory, all *.pcap files will be processed")
                .takes_value(true)
                .conflicts_with(CliArg::PcapFile.as_str()),
            Arg::with_name(CliArg::PcapFile.as_str())
                .short("r")
                .value_name("PCAP-FILE")
                .help("Offline pcap file")
                .takes_value(true)
                .conflicts_with(CliArg::PcapDir.as_str()),
            Arg::with_name(CliArg::Quiet.as_str())
                .short("q")
                .long("quiet")
                .help("Turn off info level logging"),
            Arg::with_name(CliArg::Recursive.as_str())
                .long("recursive")
                .help("In offline pcap directory mode, recurse sub directories"),
            Arg::with_name(CliArg::Tags.as_str())
                .short("t")
                .long("tags")
                .help("Extra tags to add to all packets")
                .takes_value(true)
                .multiple(true),
            Arg::with_name(CliArg::Verbose.as_str())
                .short("v")
                .long("verbose")
                .help("Turn on all debugging"),
        ]);

    return root_cmd;
}
