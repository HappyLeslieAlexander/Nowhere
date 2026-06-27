// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! URL input decoding and length validation for protocol spec fields.

use anyhow::{Context, Result, bail};
use percent_encoding::percent_decode_str;
use url::Url;

use super::MAX_INPUT_LEN;

pub(in crate::protocol) fn decode_username(parsed_url: &Url) -> Result<Vec<u8>> {
    let username = parsed_url.username();
    percent_decode_str(username)
        .decode_utf8()
        .with_context(|| "protocol::spec::decode_username: invalid percent-encoded username")
        .map(|decoded| decoded.as_bytes().to_vec())
}

pub(super) fn validate_required(name: &str, value: &[u8]) -> Result<()> {
    if value.is_empty() {
        bail!("protocol::spec::validate_required: missing {name}");
    }
    if value.len() > MAX_INPUT_LEN {
        bail!("protocol::spec::validate_required: {name} exceeds {MAX_INPUT_LEN} bytes");
    }
    Ok(())
}

pub(super) fn validate_optional(name: &str, value: &[u8]) -> Result<()> {
    if value.len() > MAX_INPUT_LEN {
        bail!("protocol::spec::validate_optional: {name} exceeds {MAX_INPUT_LEN} bytes");
    }
    Ok(())
}

pub(super) fn query_value(parsed_url: &Url, key: &str) -> Result<Option<String>> {
    let Some(query) = parsed_url.query() else {
        return Ok(None);
    };

    for pair in query.split('&') {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded_key = percent_decode_str(raw_key)
            .decode_utf8()
            .with_context(|| "protocol::spec::query_value: invalid percent-encoded query key")?;
        if decoded_key != key {
            continue;
        }
        let decoded_value = percent_decode_str(raw_value)
            .decode_utf8()
            .with_context(|| {
                format!("protocol::spec::query_value: invalid percent-encoded {key}")
            })?;
        return Ok(Some(decoded_value.into_owned()));
    }

    Ok(None)
}
