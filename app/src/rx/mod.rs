use std::sync::{atomic::AtomicBool, Arc};
use std::thread::JoinHandle;

use anyhow::Result;
use crossbeam_channel::Sender;
use dashmap::DashMap;
use fnv::{FnvBuildHasher, FnvHashMap};

use alphonse_api as api;
use api::packet::{Packet, PacketHashKey};
use api::parsers::{ParserID, ProtocolParserTrait};
use api::session::Session;

use crate::config::Config;

#[cfg(all(target_os = "linux", feature = "dpdk"))]
pub mod dpdk;
pub mod files;
pub mod libpcap;

pub struct RxUtility {
    pub init: fn(cfg: &mut Config) -> Result<()>,
    pub start: fn(
        exit: Arc<AtomicBool>,
        cfg: Arc<Config>,
        sender: Sender<Box<dyn Packet>>,
    ) -> Result<Vec<JoinHandle<Result<()>>>>,
    pub cleanup: fn(cfg: &Config) -> Result<()>,
}

pub struct SessionData {
    pub info: Box<Session>,
    pub parsers: Box<FnvHashMap<ParserID, Box<dyn ProtocolParserTrait>>>,
}

impl Default for SessionData {
    fn default() -> SessionData {
        SessionData {
            // Here we use Session::new(), since default() doesn't generate the struct we need
            info: Box::new(Session::new()),
            parsers: Box::new(FnvHashMap::default()),
        }
    }
}

pub type SessionTable = DashMap<PacketHashKey, Box<SessionData>, FnvBuildHasher>;
