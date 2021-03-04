use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;
use path_absolutize::Absolutize;
use signal_hook::low_level::raise;

use alphonse_api as api;
use api::packet::Packet as PacketTrait;

use crate::config::Config;
use crate::rx::libpcap::Packet;
use crate::rx::RxUtility;
use crate::stats::CaptureStat;

pub const UTILITY: RxUtility = RxUtility {
    init: |_| Ok(()),
    start,
    cleanup: |_| Ok(()),
};

fn start(
    exit: Arc<AtomicBool>,
    cfg: Arc<Config>,
    sender: Sender<Box<dyn PacketTrait>>,
) -> Result<Vec<JoinHandle<Result<()>>>> {
    let mut handles = vec![];
    let mut thread = RxThread {
        exit: exit.clone(),
        files: get_pcap_files(cfg.as_ref()),
        sender: sender.clone(),
    };
    let builder = std::thread::Builder::new().name(thread.name());
    let handle = builder.spawn(move || thread.spawn(cfg))?;
    handles.push(handle);
    Ok(handles)
}

/// get pcap files according to command line arguments/configuration file
fn get_pcap_files(cfg: &Config) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !cfg.pcap_file.is_empty() {
        files.push(PathBuf::from(&cfg.pcap_file));
    } else if !cfg.pcap_dir.is_empty() {
        let path_buf = PathBuf::from(&cfg.pcap_dir);
        let pcap_dir = path_buf.absolutize().unwrap();
        for entry in pcap_dir.read_dir().expect("read_dir call failed") {
            if let Ok(entry) = entry {
                let buf = entry.path();
                if buf.is_dir() {
                    continue;
                }

                match buf.extension() {
                    None => continue,
                    Some(s) => {
                        let ext = std::ffi::OsString::from(s);
                        let pcap_ext = OsString::from("pcap");
                        let pcapng_ext = OsString::from("pcapng");
                        match ext {
                            _ if ext == pcap_ext => files.push(entry.path()),
                            _ if ext == pcapng_ext => files.push(entry.path()),
                            _ => {} // if file is not pcap or pcapng, skip
                        };
                    }
                };
            }
        }
    }

    return files;
}

struct RxThread {
    exit: Arc<AtomicBool>,
    sender: Sender<Box<dyn PacketTrait>>,
    files: Vec<PathBuf>,
}

impl RxThread {
    fn spawn(&mut self, _cfg: Arc<Config>) -> Result<()> {
        if self.files.is_empty() {
            return Ok(());
        }

        println!("{} started", self.name());

        for file in &self.files {
            if !file.exists() {
                return Err(anyhow!("File does not exist"));
            }

            let mut cap = Offline::try_from_path(file)?;
            let mut overflow_cnt = 0;

            while !self.exit.load(Ordering::Relaxed) {
                let pkt = match cap.next() {
                    Ok(pkt) => pkt,
                    Err(err) => {
                        if err.to_string().as_str() == "no more packets to read from the file" {
                        } else {
                            eprintln!("{}", err);
                        }
                        break;
                    }
                };

                match self.sender.try_send(pkt) {
                    Ok(_) => {}
                    Err(err) => match err {
                        crossbeam_channel::TrySendError::Full(_) => {
                            overflow_cnt += 1;
                            if overflow_cnt % 10000 == 0 {
                                println!(
                                    "{} overflowing, total overflow {}",
                                    self.name(),
                                    overflow_cnt
                                );
                            }
                        }
                        crossbeam_channel::TrySendError::Disconnected(_) => {
                            println!("{} channel is closed, exit", self.name());
                            break;
                        }
                    },
                };
            }
        }

        // terminate alphonse
        raise(signal_hook::consts::SIGTERM)?;

        println!("{} exit", self.name());

        Ok(())
    }

    fn name(&self) -> String {
        String::from("alphonse-replay")
    }
}

struct Offline {
    cap: Box<pcap::Capture<pcap::Offline>>,
}

impl Offline {
    pub fn try_from_path<P: AsRef<Path>>(path: P) -> Result<Offline> {
        if !path.as_ref().exists() {
            return Err(anyhow!("File does not exist"));
        }

        let result = pcap::Capture::from_file(path);
        let pcap_file;
        match result {
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(-1);
            }
            Ok(v) => pcap_file = v,
        }

        Ok(Offline {
            cap: Box::new(pcap_file),
        })
    }
}

impl Offline {
    #[inline]
    fn next(&mut self) -> Result<Box<dyn PacketTrait>> {
        let raw = self.cap.as_mut().next()?;
        let pkt = Box::new(Packet::from(&raw));
        Ok(pkt)
    }

    fn stats(&mut self) -> Result<CaptureStat> {
        let mut stats = CaptureStat::default();
        let cap_stats = self.cap.as_mut().stats()?;
        stats.rx_pkts = cap_stats.received as u64;
        stats.dropped = cap_stats.dropped as u64;
        stats.if_dropped = cap_stats.if_dropped as u64;
        Ok(stats)
    }
}
