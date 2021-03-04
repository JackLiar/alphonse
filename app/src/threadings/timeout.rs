use std::os::raw::c_long;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use crossbeam_channel::Sender;
use rayon::iter::{ParallelBridge, ParallelIterator};

use alphonse_api as api;
use api::packet::Protocol;
use api::session::Session;

use crate::config::Config;
use crate::rx::SessionTable;

/// Session table timeout thread
pub struct TimeoutThread {
    exit: Arc<AtomicBool>,
    sender: Sender<Box<Session>>,
}

impl TimeoutThread {
    pub fn new(exit: Arc<AtomicBool>, sender: Sender<Box<Session>>) -> Self {
        Self { exit, sender }
    }

    pub fn name(&self) -> String {
        "alphonse-timeout".to_string()
    }

    pub fn spawn(&self, cfg: Arc<Config>, session_table: Arc<SessionTable>) -> Result<()> {
        let now: u64 = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut next_timeout_check_time: u64 = now + cfg.timeout_interval;
        println!("{} started", self.name());

        while !self.exit.load(Ordering::Relaxed) {
            let now: u64 = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now <= next_timeout_check_time {
                continue;
            }

            next_timeout_check_time = now + cfg.timeout_interval;
            session_table
                .shards()
                .iter()
                .par_bridge()
                .for_each(|shard| {
                    shard.write().retain(|key, ses| {
                        let ses = ses.get_mut();
                        let timeout = match key.trans_proto {
                            Protocol::TCP => {
                                ses.info.timeout(cfg.tcp_timeout as c_long, now as c_long)
                            }
                            Protocol::UDP => {
                                ses.info.timeout(cfg.udp_timeout as c_long, now as c_long)
                            }
                            Protocol::SCTP => {
                                ses.info.timeout(cfg.sctp_timeout as c_long, now as c_long)
                            }
                            _ => ses
                                .info
                                .timeout(cfg.default_timeout as c_long, now as c_long),
                        };

                        if ses.info.need_mid_save(cfg.ses_max_packets as u32, now) {
                            self.sender.try_send(ses.info.clone()).unwrap();
                            ses.info.mid_save_reset(now + cfg.ses_save_timeout as u64);
                        } else if timeout {
                            for (_, parser) in ses.parsers.iter_mut() {
                                parser.finish(ses.info.as_mut());
                            }
                            self.sender.try_send(ses.info.clone()).unwrap();
                        }
                        !timeout
                    })
                });
        }

        session_table
            .shards()
            .iter()
            .par_bridge()
            .for_each(|shard| {
                shard.write().retain(|_, ses| {
                    let ses = ses.get_mut();
                    for (_, parser) in ses.parsers.iter_mut() {
                        parser.finish(ses.info.as_mut());
                    }
                    self.sender.try_send(ses.info.clone()).unwrap();
                    false
                })
            });

        println!("{} exit", self.name());

        Ok(())
    }
}
