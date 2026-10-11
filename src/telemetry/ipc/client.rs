// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Local telemetry client connections and subscription requests.

use std::time::Duration;

use anyhow::{Context, Result, bail};

use super::frame::{FrameReader, TelemetryReader, write_frame};
use super::registry::{DiscoveredInstance, RegistryEntry, registry_path, valid_instance};
use crate::telemetry::local;
use crate::telemetry::{ClientMessage, Hello, ServerMessage, Subscription, TELEMETRY_PROTOCOL};

pub(crate) struct TelemetryClient {
    hello: Hello,
    reader: TelemetryReader,
}

impl TelemetryClient {
    pub(crate) async fn connect(
        discovered: &DiscoveredInstance,
        subscription: Subscription,
    ) -> Result<Self> {
        if !valid_instance(discovered) {
            bail!("invalid registry name");
        }
        let payload = local::read_registry(&registry_path(&discovered.registry_name))
            .context("telemetry: discovered registry disappeared")?;
        let entry: RegistryEntry =
            serde_json::from_slice(&payload).context("telemetry: invalid discovered registry")?;
        if entry.instance != *discovered
            || entry.transport != local::TRANSPORT
            || entry.protocol != TELEMETRY_PROTOCOL
            || entry.namespace != local::namespace()
            || !valid_instance(discovered)
            || entry.endpoint
                != local::endpoint(
                    discovered
                        .registry_name
                        .strip_prefix("nowhere.")
                        .expect("valid name"),
                )
        {
            bail!("telemetry: discovered registry identity mismatch");
        }
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            local::connect(&entry.endpoint, discovered.pid),
        )
        .await??;
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = FrameReader::new(reader);
        let message = tokio::time::timeout(Duration::from_secs(5), reader.next::<ServerMessage>())
            .await
            .context("telemetry: hello timed out")??;
        let mut hello = match message {
            ServerMessage::Hello(hello) => hello,
            _ => bail!("telemetry: service did not begin with hello"),
        };
        validate_hello(&hello, discovered)?;
        hello.instance.uid = discovered.uid;
        hello.instance.incarnation = discovered.incarnation;
        write_frame(&mut writer, &ClientMessage::Subscribe { subscription }).await?;
        Ok(Self {
            hello,
            reader: TelemetryReader { inner: reader },
        })
    }

    pub(crate) fn into_parts(self) -> (Hello, TelemetryReader) {
        (self.hello, self.reader)
    }
}

fn validate_hello(hello: &Hello, discovered: &DiscoveredInstance) -> Result<()> {
    let instance = &hello.instance;
    if instance.telemetry_protocol != TELEMETRY_PROTOCOL
        || instance.pid != discovered.pid
        || instance.registry_name() != discovered.registry_name
    {
        bail!("telemetry: hello identity does not match discovered registry");
    }
    Ok(())
}
