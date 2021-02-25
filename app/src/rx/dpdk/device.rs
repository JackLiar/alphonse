use std::collections::HashMap;
use std::ffi::CStr;
use std::ops::Deref;

use anyhow::{anyhow, Result};
use rte::ethdev::EthDevice;
use yaml_rust::Yaml;

use alphonse_api as api;
use api::classifiers::matched::Rule;
use api::packet::{Layers, Packet as PacketTrait, Rules, Tunnel};
use api::utils::timeval::{precision, TimeVal};

use crate::config::Config;
use crate::stats::CaptureStat;

/// Minimium DPDK rx unit
#[derive(Clone, Debug)]
pub struct Device {
    /// DPDK port ID
    pub port: rte::PortId,
    /// Rx queues
    pub rx_queues: Vec<rte::QueueId>,
}

impl Device {
    pub fn new(port: rte::PortId, rx_queues: &Vec<rte::QueueId>) -> Self {
        Self {
            port,
            rx_queues: rx_queues.clone(),
        }
    }

    pub fn pci_address(&self) -> String {
        let info = self.port.info();
        unsafe {
            CStr::from_ptr((*info.device).name)
                .to_str()
                .unwrap()
                .to_string()
        }
    }

    pub fn configure(&mut self, _: &Config) -> Result<()> {
        Ok(())
    }

    pub fn next(&mut self) -> Result<Box<dyn PacketTrait>> {
        unimplemented!("dpdk::Device::next not implemented")
    }

    pub fn stats(&mut self) -> Result<CaptureStat> {
        Ok(CaptureStat::default())
    }
}

/// Get all avaliable DPDK devices
pub fn devices(cfg: &Config) -> Result<Vec<(rte::lcore::Id, Device)>> {
    if rte::ethdev::count() == 0 {
        return Err(anyhow!("no avaiable port found"));
    }

    let mut devices = vec![];
    let ports: HashMap<String, rte::PortId> = rte::ethdev::devices()
        .map(|port| {
            let info = port.info();
            let name = unsafe { CStr::from_ptr((*info.device).name).to_str().unwrap() };
            (name.to_string(), port)
        })
        .collect();

    let doc = &cfg.docs[0];
    let rx_ports = doc["dpdk.rx.ports"]
        .as_hash()
        .ok_or(anyhow!("dpdk.rx.ports is not hash"))?;
    for (k, v) in rx_ports.iter() {
        let pci = k.as_str().ok_or(anyhow!("key is not a string"))?;
        let port = match ports.get(pci) {
            Some(port) => *port,
            None => {
                eprintln!("specific port {} doesn't exist or is not available", pci);
                eprintln!("available ports: {:?}", ports.keys());
                continue;
            }
        };

        let cores = v.as_vec().ok_or(anyhow!("cores is not an array"))?;
        let mut nb_rx_queue = 0;
        for core in cores {
            let core = core.as_hash().ok_or(anyhow!("core is not a hash"))?;
            let queues = core
                .get(&Yaml::String("queue".to_string()))
                .ok_or(anyhow!("no queue found"))?
                .as_i64()
                .ok_or(anyhow!("queue is not i64"))?;
            let lcore = core
                .get(&Yaml::String("core".to_string()))
                .ok_or(anyhow!("no core found"))?
                .as_i64()
                .ok_or(anyhow!("core is not i64"))? as u32;
            devices.push((
                rte::lcore::Id::from(lcore),
                Device::new(
                    port,
                    &(nb_rx_queue as u16..(nb_rx_queue + queues) as u16).collect(),
                ),
            ));
            nb_rx_queue += queues;
        }
    }

    Ok(devices)
}

fn configure(
    port: rte::PortId,
    nb_rx_queue: u16,
    mb_pool: &mut rte::mempool::MemoryPool,
) -> Result<()> {
    let rss_key = [
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D,
        0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    ];

    let rss_conf = rte::ethdev::EthRssConf {
        key: Some(rss_key),
        // hash: rte::ethdev::RssHashFunc::ETH_RSS_PROTO_MASK,
        hash: rte::ethdev::RssHashFunc::ETH_RSS_UNKNOWN,
    };
    let mut rx_adv_conf = rte::ethdev::RxAdvConf::default();
    rx_adv_conf.rss_conf = Some(rss_conf);

    let mut rx_mode = rte::ethdev::EthRxMode::default();
    rx_mode.mq_mode = rte::ffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS;

    let mut conf = rte::ethdev::EthConf::default();
    conf.rx_adv_conf = Some(rx_adv_conf);
    conf.rxmode = Some(rx_mode);

    port.configure(nb_rx_queue, 0, &conf)?;
    rx_queue_setup(port, nb_rx_queue, mb_pool)?;

    Ok(())
}

fn rx_queue_setup(
    port: rte::PortId,
    nb_rx_queue: u16,
    mb_pool: &mut rte::mempool::MemoryPool,
) -> Result<()> {
    for i in 0..nb_rx_queue {
        let mut rx_conf = rte::ffi::rte_eth_rxconf::default();
        rx_conf.rx_thresh.pthresh = 8;
        rx_conf.rx_thresh.hthresh = 0;
        rx_conf.rx_thresh.wthresh = 4;
        rx_conf.rx_free_thresh = 0;
        rx_conf.rx_drop_en = 0;
        rx_conf.rx_deferred_start = 0;
        port.rx_queue_setup(i, 4096, Some(rx_conf), mb_pool)?;
    }
    Ok(())
}

/// Initialize all ports
pub fn init_ports(cfg: &Config, mb_pool: &mut rte::mempool::MemoryPool) -> Result<()> {
    if rte::ethdev::count() == 0 {
        return Err(anyhow!("no avaiable port found"));
    }

    println!("available port count: {}", rte::ethdev::count());

    let devices = devices(cfg)?;

    let mut ports: HashMap<rte::PortId, u16> = HashMap::new();
    for dev in &devices {
        let dev = &dev.1;
        let port = dev.port;
        let nb_rx_queues = dev.rx_queues.len() as u16;
        match ports.get_mut(&port) {
            Some(nb) => *nb += nb_rx_queues,
            None => {
                ports.insert(port, nb_rx_queues);
            }
        };
    }

    let mtu = cfg.get_integer(&"dpdk.rx.mtu", 1500, 1500, 4096) as u16;
    for (port, nb_rx_queue) in ports {
        let name = unsafe { CStr::from_ptr((*port.info().device).name).to_str().unwrap() };
        println!("configuring port {}", name);
        configure(port, nb_rx_queue, mb_pool)?;

        port.set_mtu(mtu)?;
        port.promiscuous_enable();
        port.start()?;
    }

    Ok(())
}

pub struct PacketMetaData {
    ts: TimeVal<precision::Millisecond>,
    layers: Layers,
    rules: Rules,
    tunnel: Tunnel,
}

#[derive(Clone, Debug)]
pub struct Packet(rte::mbuf::MBuf);

impl Packet {
    pub fn new(mbuf: rte::mbuf::MBuf) -> Self {
        Self(mbuf)
    }

    fn metadata(&self) -> &PacketMetaData {
        unsafe { &*(self.0.priv_addr().as_ptr() as *mut PacketMetaData) }
    }

    fn metadata_mut(&self) -> &mut PacketMetaData {
        unsafe { &mut *(self.0.priv_addr().as_ptr() as *mut PacketMetaData) }
    }
}

unsafe impl Send for Packet {}

impl PacketTrait for Packet {
    fn raw(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.mtod().as_ptr(), self.0.pkt_len()) }
    }

    fn caplen(&self) -> u32 {
        self.0.pkt_len() as u32
    }

    fn ts(&self) -> &libc::timeval {
        self.metadata().ts.deref()
    }

    fn layers(&self) -> &Layers {
        &self.metadata().layers
    }

    fn layers_mut(&mut self) -> &mut Layers {
        &mut self.metadata_mut().layers
    }

    fn rules(&self) -> &[Rule] {
        self.metadata().rules.as_slice()
    }

    fn rules_mut(&mut self) -> &mut Rules {
        &mut self.metadata_mut().rules
    }

    fn tunnel(&self) -> Tunnel {
        self.metadata().tunnel
    }

    fn tunnel_mut(&mut self) -> &mut Tunnel {
        &mut self.metadata_mut().tunnel
    }

    fn clone_box(&self) -> Box<dyn PacketTrait + '_> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn packet_metadata_size_is_aligned() {
        let priv_size = std::mem::size_of::<PacketMetaData>() as u32;
        assert_eq!(
            priv_size + (rte::ffi::RTE_MBUF_PRIV_ALIGN - 1)
                & (!(rte::ffi::RTE_MBUF_PRIV_ALIGN - 1)),
            priv_size
        );
    }
}
