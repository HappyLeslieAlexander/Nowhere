// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Compact, allocation-light display formatting.

use std::time::Duration;

pub(super) fn bytes(value: u64) -> String {
    const UNITS: [(&str, u64); 6] = [
        ("PiB", 1 << 50),
        ("TiB", 1 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
        ("B", 1),
    ];
    for (unit, divisor) in UNITS {
        if value >= divisor {
            if divisor == 1 {
                return format!("{value} B");
            }
            let scaled = value as f64 / divisor as f64;
            return if scaled >= 100.0 {
                format!("{scaled:.0} {unit}")
            } else if scaled >= 10.0 {
                format!("{scaled:.1} {unit}")
            } else {
                format!("{scaled:.2} {unit}")
            };
        }
    }
    "0 B".to_owned()
}

pub(super) fn duration_ms(value: u64) -> String {
    if value < 1_000 {
        return format!("{value}ms");
    }
    let duration = Duration::from_millis(value);
    let seconds = duration.as_secs();
    if seconds < 60 {
        return format!("{:.1}s", value as f64 / 1_000.0);
    }
    let minutes = seconds / 60;
    let remaining_seconds = seconds % 60;
    if minutes < 60 {
        return format!("{minutes}m {remaining_seconds:02}s");
    }
    let hours = minutes / 60;
    let remaining_minutes = minutes % 60;
    if hours < 24 {
        return format!("{hours}h {remaining_minutes:02}m");
    }
    let days = hours / 24;
    format!("{days}d {:02}h", hours % 24)
}

pub(super) fn panel(title: &str, rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(label, _)| label.len()).max().unwrap_or(0);
    let mut output = format!("{title}\n{}\n", "─".repeat(title.chars().count()));
    for (label, value) in rows {
        output.push_str(&format!("{label:>width$}  {value}\n"));
    }
    output.pop();
    output
}

pub(super) fn format_duration(value: Duration) -> String {
    let milliseconds = value.as_secs_f64() * 1_000.0;
    if milliseconds < 10.0 {
        format!("{milliseconds:.1} ms")
    } else {
        format!("{milliseconds:.0} ms")
    }
}

#[cfg(test)]
#[path = "../tests/toolbox/format.rs"]
mod tests;
