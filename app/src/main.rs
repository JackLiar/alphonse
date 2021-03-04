#[macro_use]
extern crate clap;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::Result;
use crossbeam_channel::{bounded, Sender};

use alphonse_api as api;
use api::packet::Packet;
use api::parsers::NewProtocolParserFunc;
use api::{classifiers, parsers::ParserID};

mod commands;
mod config;
mod packet;
mod rx;
mod stats;
mod threadings;

fn start_rx<'a>(
    exit: Arc<AtomicBool>,
    cfg: Arc<config::Config>,
    sender: Sender<Box<dyn Packet>>,
) -> Result<Vec<JoinHandle<Result<()>>>> {
    if !cfg.pcap_file.is_empty() {
        return (rx::files::UTILITY.start)(exit, cfg, sender);
    }

    match cfg.rx_backend.as_str() {
        "libpcap" => return (rx::libpcap::UTILITY.start)(exit, cfg, sender),
        #[cfg(all(target_os = "linux", feature = "dpdk"))]
        "dpdk" => return (rx::dpdk::UTILITY.start)(exit, cfg, sender),
        _ => unreachable!(),
    };
}

fn main() -> Result<()> {
    let root_cmd = commands::new_root_command();
    let mut cfg = config::parse_args(root_cmd)?;
    let exit = Arc::new(AtomicBool::new(false));

    let session_table = Arc::new(dashmap::DashMap::with_capacity_and_hasher(
        1000000,
        fnv::FnvBuildHasher::default(),
    ));
    match cfg.rx_backend.as_str() {
        "libpcap" => {
            (rx::libpcap::UTILITY.init)(&mut cfg)?;
        }
        #[cfg(all(target_os = "linux", feature = "dpdk"))]
        "dpdk" => {
            (rx::dpdk::UTILITY.init)(&mut cfg)?;
        }
        _ => unreachable!(),
    };

    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&exit))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&exit))?;

    let cfg = Arc::new(cfg);

    let mut handles = vec![];

    // keep share library 'alive' so that the vtable of trait object pointer is not pointing to an invalid position
    let mut parser_libraries = HashMap::new();
    let mut protocol_parsers = Vec::new();

    for p in &cfg.as_ref().parsers {
        let lib = unsafe { libloading::Library::new(p)? };
        parser_libraries.insert(p.clone(), lib);
        let lib = parser_libraries.get(p).unwrap();

        unsafe {
            match lib.get::<NewProtocolParserFunc>(b"al_new_protocol_parser\0") {
                Ok(func) => {
                    let mut parser = func();
                    parser.set_id(protocol_parsers.len() as ParserID);
                    let parser = api::parsers::ProtocolParser::new(parser);
                    protocol_parsers.push(parser);
                }
                Err(e) => {
                    eprintln!("{:?}", e);
                }
            }
        }
    }

    let mut classifier_manager = classifiers::ClassifierManager::new();
    for parser in &mut protocol_parsers {
        parser.register_classify_rules(&mut classifier_manager)?;
        parser.init()?;
    }

    classifier_manager.prepare()?;
    let classifier_manager = Arc::new(classifier_manager);

    let (ses_sender, ses_receiver) = bounded(cfg.pkt_channel_size as usize);
    let mut output_thread = threadings::output::Thread::new(ses_receiver.clone());

    // initialize pkt threads
    let (pkt_sender, pkt_receiver) = bounded(cfg.pkt_channel_size as usize);
    let mut pkt_threads = Vec::new();

    for i in 0..cfg.pkt_threads {
        let thread = threadings::PktThread::new(
            i,
            exit.clone(),
            classifier_manager.clone(),
            pkt_receiver.clone(),
        );
        pkt_threads.push(thread);
    }

    let timeout_thread = threadings::TimeoutThread::new(exit.clone(), ses_sender.clone());

    // start all output threads
    {
        let cfg = cfg.clone();
        let builder = std::thread::Builder::new().name(output_thread.name());
        let handle = builder.spawn(move || output_thread.spawn(cfg)).unwrap();
        handles.push(handle);
    }

    // start all pkt threads
    for thread in pkt_threads {
        let cfg = cfg.clone();
        let session_table = session_table.clone();
        let parsers = Box::new(protocol_parsers.iter().map(|p| p.box_clone()).collect());
        let builder = std::thread::Builder::new().name(thread.name());
        let handle = builder.spawn(move || thread.spawn(cfg, session_table, parsers))?;
        handles.push(handle);
    }

    // start session timeout thread
    {
        let cfg = cfg.clone();
        let builder = std::thread::Builder::new().name(timeout_thread.name());
        let handle = builder
            .spawn(move || timeout_thread.spawn(cfg, session_table.clone()))
            .unwrap();
        handles.push(handle);
    }

    let rx_handles = start_rx(exit.clone(), cfg.clone(), pkt_sender.clone())?;
    for h in rx_handles {
        handles.push(h);
    }

    drop(pkt_sender);
    drop(pkt_receiver);
    drop(ses_sender);
    drop(ses_receiver);

    for handle in handles {
        match handle.join() {
            Ok(_) => {}
            Err(e) => println!("{:?}", e),
        };
    }

    match cfg.rx_backend.as_str() {
        "libpcap" => {
            (rx::libpcap::UTILITY.cleanup)(&cfg)?;
        }
        #[cfg(all(target_os = "linux", feature = "dpdk"))]
        "dpdk" => {
            (rx::dpdk::UTILITY.cleanup)(&cfg)?;
        }
        _ => unreachable!(),
    };

    Ok(())
}
