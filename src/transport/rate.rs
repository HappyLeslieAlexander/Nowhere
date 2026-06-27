// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bidirectional rate-limiter facade over token buckets.

#[path = "rate_bucket.rs"]
mod rate_bucket;

pub use self::rate_bucket::TokenBucket;
use self::rate_bucket::token_bucket_now;

/// Optional read/write rate limiter shared by relay paths.
#[derive(Debug)]
pub struct RateLimiter {
    read: Option<TokenBucket>,
    write: Option<TokenBucket>,
}

impl RateLimiter {
    /// Creates a limiter; returns `None` when both directions are unlimited.
    pub fn new(read_bytes_per_second: i64, write_bytes_per_second: i64) -> Option<Self> {
        if read_bytes_per_second <= 0 && write_bytes_per_second <= 0 {
            return None;
        }
        Some(Self {
            read: (read_bytes_per_second > 0).then(|| TokenBucket::new(read_bytes_per_second, 0)),
            write: (write_bytes_per_second > 0)
                .then(|| TokenBucket::new(write_bytes_per_second, 0)),
        })
    }

    /// Waits until the inbound direction can accept `bytes`.
    pub async fn wait_read(&self, bytes: i64) {
        if bytes <= 0 {
            return;
        }
        if let Some(read) = &self.read {
            read.wait(bytes).await;
        }
    }

    /// Waits until the outbound direction can accept `bytes`.
    pub async fn wait_write(&self, bytes: i64) {
        if bytes <= 0 {
            return;
        }
        if let Some(write) = &self.write {
            write.wait(bytes).await;
        }
    }

    /// Resets active bucket budgets to their configured capacity.
    pub fn reset(&self) {
        let now = token_bucket_now();
        if let Some(read) = &self.read {
            read.reset(now);
        }
        if let Some(write) = &self.write {
            write.reset(now);
        }
    }
}

#[cfg(test)]
#[path = "../tests/transport/rate.rs"]
mod tests;
