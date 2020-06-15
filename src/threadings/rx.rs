use std::ffi::OsString;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crossbeam_channel::Sender;
use path_absolutize::Absolutize;

use super::capture::{Capture, NetworkInterface, Offline};
use super::config;
use super::error::Error;
use super::packet::{Packet, Parser};

/// 收包线程
pub struct RxThread {
    /// 线程ID
    id: u8,
    exit: Arc<AtomicBool>,
    /// 收包总数
    pub rx_count: u64,
    // 基本协议解析器
    parser: Parser,
    senders: Vec<Sender<Box<Packet>>>,
}

impl RxThread {
    /// 创建一个新的收包线程结构体
    pub fn new(
        id: u8,
        link_type: u16,
        senders: Vec<Sender<Box<Packet>>>,
        exit: Arc<AtomicBool>,
    ) -> RxThread {
        RxThread {
            id,
            exit,
            rx_count: 0,
            parser: Parser::new(link_type),
            senders,
        }
    }
}

impl RxThread {
    /// get pcap files according to command line arguments/configuration file
    fn get_pcap_files(cfg: &config::Config) -> Vec<PathBuf> {
        let mut files = Vec::new();
        if !cfg.pcap_file.is_empty() {
            files.push(PathBuf::from(&cfg.pcap_file));
        } else if !cfg.pcap_dir.is_empty() {
            let pcap_dir = PathBuf::from(&cfg.pcap_dir).absolutize().unwrap();
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

    #[inline]
    fn rx<C: Capture>(&mut self, cap: &mut C) -> Result<(), Error> {
        while let Ok(mut pkt) = cap.next() {
            match self.parser.parse_pkt(&mut pkt) {
                Ok(_) => {}
                Err(e) => {
                    return Err(Error::ParserError(e));
                }
            };
            // TODO: inline with_seed function
            let mut hasher = twox_hash::Xxh3Hash64::with_seed(0);
            pkt.hash(&mut hasher);
            pkt.hash = hasher.finish();

            let thread = (pkt.hash % self.senders.len() as u64) as usize;
            self.senders[thread].send(Box::from(pkt)).unwrap() // pkt move happens here, could be optimized
        }
        Ok(())
    }

    fn process_files(&mut self, files: &Vec<PathBuf>) -> Result<(), Error> {
        while !self.exit.load(Ordering::Relaxed) {
            for file in files {
                let result = Offline::try_from_path(file);
                let mut cap;
                match result {
                    Err(e) => {
                        return Err(e);
                    }
                    Ok(c) => cap = c,
                }

                self.rx(&mut cap)?;
            }
            break;
        }
        Ok(())
    }

    fn listen_network_interface(&mut self, cfg: &Arc<config::Config>) -> Result<(), Error> {
        let interface = match cfg.interfaces.get(self.id as usize) {
            Some(i) => i,
            None => todo!(),
        };

        let result = NetworkInterface::try_from_str(interface);
        let mut cap;
        match result {
            Err(e) => {
                return Err(e);
            }
            Ok(c) => cap = c,
        }

        while !self.exit.load(Ordering::Relaxed) {
            self.rx(&mut cap)?;
        }

        Ok(())
    }

    pub fn spawn(&mut self, cfg: Arc<config::Config>) -> Result<(), Error> {
        let files = RxThread::get_pcap_files(cfg.as_ref());
        if !files.is_empty() {
            return self.process_files(&files);
        } else {
            return self.listen_network_interface(&cfg);
        }
    }
}
