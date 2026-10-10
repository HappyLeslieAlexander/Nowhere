// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Validated Egress configuration and shared target-forwarding construction.

use super::Egress;
use crate::common::{DialPolicy, Logger, OutboundDialer, query_first};
use crate::portal::forward::{Forwarder, Outlet};
use crate::protocol::Credentials;
use crate::telemetry::{InstanceRole, TelemetryHub};
use crate::transport::{Buffers, RateLimiter, Stats};
use crate::vector::{PortalClientConfig, tls::ClientTls};
use anyhow::{Context, Result, bail};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use url::Url;

impl Egress {
    pub fn new(url: Url, logger: Logger) -> Result<Self> {
        if url.scheme() != "egress" {
            bail!("Egress configuration: URL scheme must be egress");
        }
        let query = query_first(
            &url,
            &[
                "sni", "pin", "morph", "dial", "dial4", "dial6", "rate", "etar", "log",
            ],
        )?;
        if query
            .get("log")
            .is_some_and(|s| !matches!(s.as_str(), "none" | "debug" | "info" | "warn" | "error"))
        {
            bail!("invalid log level");
        }
        let config =
            PortalClientConfig::parse(&url, &query, crate::vector::config::CarrierMode::Udp)?;
        let credentials = Credentials::new(&url)?;
        let tls = ClientTls::new(&config)?;
        let dial = DialPolicy::from_query(&query)?;
        let rate = |name: &str| -> Result<i32> {
            query.get(name).map_or(Ok(0), |s| {
                s.parse::<i32>()
                    .ok()
                    .filter(|n| *n >= 0)
                    .context("invalid rate limit")
            })
        };
        let upload = rate("rate")?;
        let download = rate("etar")?;
        let summary = format!(
            "portal={} {} {dial} rate={upload} etar={download} log={}",
            config.endpoint(),
            config
                .effective_route()
                .split_whitespace()
                .filter(|s| !s.starts_with("net="))
                .collect::<Vec<_>>()
                .join(" "),
            query.get("log").map(String::as_str).unwrap_or("info")
        );
        let effective = format!(
            "egress://{}?sni={}&pin={}&{}&morph={}&rate={upload}&etar={download}&log={}",
            config.endpoint(),
            config.sni.as_deref().unwrap_or(config.host()),
            config.pin.as_deref().unwrap_or("none"),
            dial.to_string().replace(' ', "&"),
            u8::from(config.morph),
            query.get("log").map(String::as_str).unwrap_or("info")
        );
        let telemetry = TelemetryHub::for_current_process(
            InstanceRole::Egress,
            config.endpoint(),
            summary,
            crate::common::telemetry_interval()?,
        );
        telemetry.set_egress_online(Some(false));
        let runtime = crate::portal::config::PortalRuntimeConfig::from_env()?;
        let forward = Arc::new(Forwarder {
            runtime,
            outbound: Outlet::Network(Arc::new(OutboundDialer::new(dial, None))),
            logger,
            telemetry,
            stats: Arc::new(Stats::default()),
            buffers: Buffers::new(
                crate::common::tcp_data_buf_size(),
                crate::common::udp_data_buf_size(),
            ),
            rate: RateLimiter::new(
                crate::common::rate_limit_bytes_per_second(upload) as i64,
                crate::common::rate_limit_bytes_per_second(download) as i64,
            )
            .map(Arc::new),
            flows: Arc::new(Semaphore::new(1024)),
            shutdown: CancellationToken::new(),
        });
        Ok(Self {
            config,
            credentials,
            forward,
            tls,
            effective,
        })
    }
}

#[cfg(test)]
#[path = "../tests/egress/setup.rs"]
mod tests;
