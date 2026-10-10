// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Validated `vector://` URL parsing with first-value query semantics.

use crate::common::{
    CarrierEndpoint, DialPolicy, ServiceEndpoint, SocksCredentials, first_raw_query_value,
    format_host_port, parse_host_port, parse_socks_value, query_first,
};
use crate::transport::MorphKeys;
use anyhow::{Result, anyhow, bail};
use std::collections::HashMap;
use std::fmt;
use url::Url;

const VECTOR_QUERY_KEYS: &[&str] = &["in", "net", "sni", "pin", "rate", "etar", "morph", "log"];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierMode {
    Tcp,
    Udp,
}
impl CarrierMode {
    pub(crate) const fn carrier(self) -> crate::protocol::Carrier {
        match self {
            Self::Tcp => crate::protocol::Carrier::TlsTcp,
            Self::Udp => crate::protocol::Carrier::Quic,
        }
    }
}
impl fmt::Display for CarrierMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) struct PortalClientConfig {
    pub(crate) remote: ServiceEndpoint,
    pub(crate) net: CarrierMode,
    pub(crate) morph: bool,
    pub(crate) morph_keys: Option<MorphKeys>,
    pub(crate) sni: Option<String>,
    pub(crate) pin: Option<String>,
    pub(crate) dial_policy: DialPolicy,
}
impl PortalClientConfig {
    pub(crate) fn parse(
        url: &Url,
        query: &HashMap<String, String>,
        net: CarrierMode,
    ) -> Result<Self> {
        let context = "Portal endpoint";
        if url.password().is_some() || url.fragment().is_some() {
            bail!("invalid URL password or fragment");
        }
        let remote = ServiceEndpoint::parse(url, false, context)?;
        if (net == CarrierMode::Tcp && !remote.has_tcp())
            || (net == CarrierMode::Udp && !remote.has_udp())
        {
            bail!("net selects an unavailable carrier");
        }
        let morph = match query.get("morph").map(String::as_str) {
            None | Some("0") => false,
            Some("1") => true,
            Some(_) => bail!("{context}: morph must be 0 or 1"),
        };
        let morph_keys = morph.then(|| MorphKeys::from_url(url)).transpose()?;
        let sni = query
            .get("sni")
            .filter(|value| !value.is_empty() && value.as_str() != "none")
            .map(|value| {
                if !value.is_ascii()
                    || value.len() > 253
                    || value.contains([':', '[', ']'])
                    || value.parse::<std::net::IpAddr>().is_ok()
                {
                    bail!("{context}: sni must be an ASCII DNS name");
                }
                Ok(value.to_owned())
            })
            .transpose()?;
        let pin = query
            .get("pin")
            .filter(|value| !value.is_empty() && value.as_str() != "none")
            .cloned();
        if pin.as_ref().is_some_and(|pin| {
            pin.len() != 64
                || !pin
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        }) {
            bail!("pin must be 64 lowercase hex characters");
        }
        Ok(Self {
            remote,
            net,
            morph,
            morph_keys,
            sni,
            pin,
            dial_policy: DialPolicy::default(),
        })
    }
    pub(crate) fn from_probe_url(url: &Url) -> Result<(Self, crate::protocol::Credentials)> {
        if url.scheme() != "vector" {
            bail!("probe requires vector://");
        }
        let query = query_first(url, VECTOR_QUERY_KEYS)?;
        validate_options(&query)?;
        let net = match query.get("net").map(String::as_str) {
            None | Some("tcp") => CarrierMode::Tcp,
            Some("udp") => CarrierMode::Udp,
            _ => bail!("net must be tcp or udp"),
        };
        if first_raw_query_value(url, "in").is_some() {
            SocksListenConfig::from_url(url)?;
        }
        Ok((
            Self::parse(url, &query, net)?,
            crate::protocol::Credentials::new(url)?,
        ))
    }
    pub(crate) fn from_fingerprint_url(url: &Url) -> Result<Self> {
        if url.scheme() != "nowhere" {
            bail!("fingerprint requires a nowhere:// share link");
        }
        crate::protocol::Credentials::decode_shared_key(url)?;
        if url
            .path()
            .split('/')
            .skip(1)
            .any(|s| !matches!(s.split_once(':').map(|(c, _)| c), Some("tcp" | "udp")))
        {
            bail!("share link paths support only tcp and udp");
        }
        let mut clean = url.clone();
        clean.set_fragment(None);
        let endpoint = ServiceEndpoint::parse(&clean, false, "fingerprint endpoint")?;
        Self::parse(
            &clean,
            &query_first(&clean, &["morph", "sni"])?,
            if endpoint.has_tcp() {
                CarrierMode::Tcp
            } else {
                CarrierMode::Udp
            },
        )
    }
    pub(crate) fn endpoint(&self) -> String {
        self.remote.canonical()
    }
    pub(crate) fn host(&self) -> &str {
        &self.remote.host
    }
    pub(crate) fn tcp_endpoint(&self) -> Option<CarrierEndpoint> {
        self.remote.tcp
    }
    pub(crate) fn udp_endpoint(&self) -> Option<CarrierEndpoint> {
        self.remote.udp
    }
    pub(crate) fn effective_route(&self) -> String {
        format!(
            "net={} sni={} pin={} morph={}",
            self.net,
            self.sni.as_deref().unwrap_or(self.host()),
            self.pin.as_deref().unwrap_or("none"),
            u8::from(self.morph)
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SocksListenConfig {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) credentials: Option<SocksCredentials>,
}
impl SocksListenConfig {
    fn from_url(url: &Url) -> Result<Self> {
        let raw = first_raw_query_value(url, "in")
            .ok_or_else(|| anyhow!("Vector configuration: in parameter is required"))?;
        let (endpoint, credentials) = parse_socks_value(raw)?;
        let (host, port) = parse_host_port(&endpoint, "SOCKS ingress", true)?;
        Ok(Self {
            host,
            port,
            credentials,
        })
    }
    pub(super) fn endpoint(&self) -> String {
        format_host_port(&self.host, self.port)
    }
    pub(super) fn authenticated(&self) -> bool {
        self.credentials.is_some()
    }
}
#[derive(Clone, Debug)]
pub(crate) struct VectorConfig {
    pub(crate) portal: PortalClientConfig,
    pub(super) rate_mbps: i32,
    pub(super) etar_mbps: i32,
    pub(super) socks: SocksListenConfig,
    pub(super) log: String,
}
impl std::ops::Deref for VectorConfig {
    type Target = PortalClientConfig;
    fn deref(&self) -> &Self::Target {
        &self.portal
    }
}
impl VectorConfig {
    pub(super) fn from_url(url: &Url) -> Result<Self> {
        let (portal, _) = PortalClientConfig::from_probe_url(url)?;
        let query = query_first(url, VECTOR_QUERY_KEYS)?;
        Ok(Self {
            portal,
            rate_mbps: parse_rate(query.get("rate").map(String::as_str), "rate")?,
            etar_mbps: parse_rate(query.get("etar").map(String::as_str), "etar")?,
            socks: SocksListenConfig::from_url(url)?,
            log: query.get("log").cloned().unwrap_or_else(|| "info".into()),
        })
    }
    pub(crate) fn portal_client_config(&self) -> PortalClientConfig {
        self.portal.clone()
    }
    pub(super) fn portal_endpoint(&self) -> String {
        self.endpoint()
    }
    pub(super) fn effective_url(&self) -> String {
        format!(
            "vector://{}?in={}&net={}&sni={}&pin={}&morph={}&rate={}&etar={}&log={}",
            self.endpoint(),
            self.socks.endpoint(),
            self.net,
            self.sni.as_deref().unwrap_or(self.host()),
            self.pin.as_deref().unwrap_or("none"),
            u8::from(self.morph),
            self.rate_mbps,
            self.etar_mbps,
            self.log
        )
    }
}
fn validate_options(query: &HashMap<String, String>) -> Result<()> {
    if query
        .get("log")
        .is_some_and(|s| !matches!(s.as_str(), "none" | "debug" | "info" | "warn" | "error"))
    {
        bail!("invalid log level");
    }
    parse_rate(query.get("rate").map(String::as_str), "rate")?;
    parse_rate(query.get("etar").map(String::as_str), "etar")?;
    Ok(())
}
fn parse_rate(value: Option<&str>, name: &str) -> Result<i32> {
    match value {
        None => Ok(0),
        Some(s) => s
            .parse()
            .ok()
            .filter(|v| *v >= 0)
            .ok_or_else(|| anyhow!("{name} must be a non-negative integer")),
    }
}
#[cfg(test)]
#[path = "../tests/vector/config.rs"]
mod tests;
