use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::Result;
use crossbeam_channel::Sender;

use alphonse_api as api;
use api::packet::Packet as PacketTrait;
use rte::ethdev::EthDevice;

use crate::config::Config;
use crate::rx::RxUtility;

mod device;
mod mempool;

use device::{Device, Packet};

pub const UTILITY: RxUtility = RxUtility {
    init,
    start,
    cleanup,
};

fn init(cfg: &mut Config) -> Result<()> {
    rte::eal::init(cfg.dpdk_eal_args.as_slice())?;
    Ok(())
}

fn start(
    exit: Arc<AtomicBool>,
    cfg: Arc<Config>,
    sender: Sender<Box<dyn PacketTrait>>,
) -> Result<Vec<JoinHandle<Result<()>>>> {
    let mempool = mempool::create_pktmbuf_pool(&cfg)?;

    {
        let ptr = mempool.as_ref() as *const _ as *mut rte::mempool::MemoryPool;
        let mb_pool = unsafe { &mut (*ptr) };
        device::init_ports(&cfg, mb_pool)?;
    }

    let mut handles = vec![];
    for (_, device) in device::devices(&cfg)? {
        let cfg = cfg.clone();
        let mut thread = RxThread {
            exit: exit.clone(),
            _sender: sender.clone(),
            device: device.clone(),
        };
        let builder = std::thread::Builder::new().name(thread.name());
        let handle = builder.spawn(move || thread.spawn(cfg))?;
        handles.push(handle);
    }

    Ok(handles)
}

fn cleanup(_: &Config) -> Result<()> {
    rte::eal::cleanup()
}

struct RxThread {
    exit: Arc<AtomicBool>,
    device: Device,
    _sender: Sender<Box<dyn PacketTrait>>,
}

impl RxThread {
    pub fn spawn(&mut self, _cfg: Arc<Config>) -> Result<()> {
        let mut mbufs = vec![None; 8];
        let mut rx_count: u64 = 0;
        let mut overflow_cnt = 0;
        println!("{} started", self.name());

        while !self.exit.load(Ordering::Relaxed) {
            for queue in &self.device.rx_queues {
                let cnt = self.device.port.rx_burst(*queue, &mut mbufs);
                rx_count += cnt as u64;
                for mbuf in mbufs.iter() {
                    match mbuf {
                        Some(m) => {
                            let pkt = Box::new(Packet::new(m.clone()));
                            match self._sender.try_send(pkt) {
                                Ok(_) => {}
                                Err(e) => match e {
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
                            }
                        }
                        None => break,
                    }
                }
            }
        }

        println!("{} exit", self.name());
        Ok(())
    }

    pub fn name(&self) -> String {
        format!("alphonse-{}-{:?}", self.device.port, self.device.rx_queues)
    }
}
