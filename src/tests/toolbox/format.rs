// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Status display value formatting tests.

use super::*;

#[test]
fn formats_byte_totals_with_iec_units() {
    assert_eq!(bytes(0), "0 B");
    assert_eq!(bytes(1_536), "1.50 KiB");
    assert_eq!(bytes(10 * (1 << 20)), "10.0 MiB");
    assert_eq!(bytes(u64::MAX), "16384 PiB");
}

#[test]
fn formats_uptime_across_unit_boundaries() {
    for (input, expected) in [
        (0, "0ms"),
        (999, "999ms"),
        (1_000, "1.0s"),
        (59_999, "60.0s"),
        (60_000, "1m 00s"),
        (3_599_999, "59m 59s"),
        (3_600_000, "1h 00m"),
        (86_399_999, "23h 59m"),
        (86_400_000, "1d 00h"),
        (90_000_000, "1d 01h"),
    ] {
        assert_eq!(duration_ms(input), expected);
    }
}

#[test]
fn panel_aligns_labels_and_values() {
    assert_eq!(
        panel(
            "NOWHERE PROBE",
            &[("Result", "OK".to_owned()), ("Setup", "1.2 ms".to_owned()),],
        ),
        "NOWHERE PROBE\n─────────────\nResult  OK\n Setup  1.2 ms"
    );
}

#[test]
fn duration_uses_compact_consistent_precision() {
    assert_eq!(format_duration(Duration::from_micros(1_250)), "1.2 ms");
    assert_eq!(format_duration(Duration::from_millis(25)), "25 ms");
}
