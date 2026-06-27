// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TLS configuration tests.

use super::*;
use crate::common::{LogLevel, Logger};

#[test]
fn server_tls_config_explicitly_disables_early_data() {
    let (_, tls, _quic) = new_server_configs(
        &Url::parse("portal://secret@127.0.0.1:2077?tls=1").unwrap(),
        "now/1",
        Logger::new(LogLevel::None, false),
    )
    .unwrap();

    assert_eq!(tls.max_early_data_size, 0);
    assert!(!tls.send_half_rtt_data);
}
