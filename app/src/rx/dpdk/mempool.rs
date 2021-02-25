use std::sync::Arc;

use anyhow::{anyhow, Result};
use rte::mbuf::RTE_MBUF_PRIV_ALIGN;

use super::device::PacketMetaData;
use crate::config::Config;

fn is_power_of_two<T: Into<u64>>(x: T) -> bool {
    let x: u64 = x.into();
    x != 0 && ((x & (x - 1)) == 0)
}

fn is_cache_size_valid<T: Into<u64>>(cache_size: T, pool_size: u32) -> bool {
    let x: u64 = cache_size.into();
    if x == 0 {
        return true;
    }

    if x > rte::ffi::RTE_MEMPOOL_CACHE_MAX_SIZE as u64 {
        return false;
    }

    if x as f64 > pool_size as f64 / 1.5 {
        return false;
    }

    if (pool_size + 1) as u64 % x != 0 {
        eprintln!(
            "dpdk.pkt.pool.cache.size {} is not optimal,\
                 it is advised to choose cache_size to have: pool_size modulo cache_size == 0",
            x
        );
    }

    true
}

pub fn create_pktmbuf_pool(cfg: &Config) -> Result<Box<rte::mempool::MemoryPool>> {
    let pool_size = cfg.get_integer(
        &"dpdk.pkt.pool.size",
        2i64.pow(22) - 1,
        2i64.pow(16) - 1,
        2i64.pow(24) - 1,
    ) as u32;

    if !is_power_of_two(pool_size + 1) {
        eprintln!(
            "dpdk.pkt.pool.size {} is not optimal, consider make it a power of two minus one",
            pool_size
        );
    }

    let cache_size = cfg.get_integer(&"dpdk.pkt.pool.cache.size", 512, 32, 2048) as u32;
    if !is_cache_size_valid(cache_size, pool_size) {
        anyhow!("Invalid dpdk.pkt.pool.cache.size: {}", cache_size);
    }

    let mtu = cfg.get_integer(&"dpdk.rx.mtu", 1500, 1500, 4096) as u16;

    let priv_size = std::mem::size_of::<PacketMetaData>() as u16;

    let data_room_size = mtu + priv_size;
    Ok(Box::new(rte::mbuf::pool_create(
        &"alphonse-pkt-pool",
        pool_size,
        cache_size,
        priv_size,
        data_room_size,
        rte::socket_id() as i32,
    )?))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_is_power_of_two() {
        assert!(!is_power_of_two(0u32));
        assert!(is_power_of_two(2u32));
        assert!(is_power_of_two(4194304u32));
    }
}
