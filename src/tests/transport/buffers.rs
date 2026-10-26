// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Transport buffer tests.

use super::*;

#[test]
fn allocates_zeroed_buffers_with_configured_sizes() {
    let buffers = Buffers::new(4);

    assert_eq!(&*buffers.get_tcp_buffer(), &vec![0; 4]);
}

#[test]
fn reuses_released_buffers() {
    let buffers = Buffers::new(4);
    {
        let mut buffer = buffers.get_tcp_buffer();
        buffer[0] = 7;
    }

    assert_eq!(&*buffers.get_tcp_buffer(), &vec![7, 0, 0, 0]);
}

impl Buffers {
    pub(crate) fn cached_tcp_buffers(&self) -> usize {
        self.tcp.cached.lock().unwrap().len()
    }
}

#[test]
fn udp_pool_is_lazy_bounded_and_reuses_full_size_buffers() {
    let pool = Arc::new(BufferPool::new(UDP_BUFFER_SIZE, UDP_CACHE_LIMIT));
    assert!(pool.cached.lock().unwrap().is_empty());
    let leases = (0..32)
        .map(|_| BufferPool::acquire(&pool))
        .collect::<Vec<_>>();
    assert!(leases.iter().all(|buffer| buffer.len() == UDP_BUFFER_SIZE));
    assert!(pool.cached.lock().unwrap().is_empty());
    drop(leases);
    assert_eq!(pool.cached.lock().unwrap().len(), UDP_CACHE_LIMIT);
    let buffer = BufferPool::acquire(&pool);
    let pointer = buffer.as_ptr();
    drop(buffer);
    assert_eq!(BufferPool::acquire(&pool).as_ptr(), pointer);
}

impl BufferLease {
    pub(crate) fn isolated_udp() -> (Self, impl Fn() -> usize) {
        let pool = Arc::new(BufferPool::new(UDP_BUFFER_SIZE, UDP_CACHE_LIMIT));
        let buffer = BufferPool::acquire(&pool);
        (buffer, move || pool.cached.lock().unwrap().len())
    }
}

#[test]
fn udp_leases_share_one_process_pool_with_a_fixed_cache_limit() {
    let first = get_udp_buffer();
    let second = get_udp_buffer();
    assert!(Arc::ptr_eq(&first.pool, &second.pool));
    assert_eq!(first.pool.size, UDP_BUFFER_SIZE);
    assert_eq!(first.pool.cache_limit, UDP_CACHE_LIMIT);
}
