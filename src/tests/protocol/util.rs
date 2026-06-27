// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Protocol utility tests.

use super::*;

#[test]
fn validates_host_port_forms() {
    assert!(validate_target("example.com:443").is_ok());
    assert!(validate_target("93.184.216.34:443").is_ok());
    assert!(validate_target("[::1]:443").is_ok());
    assert!(validate_target(":443").is_ok());
    assert!(validate_target("example.com:").is_err());
    assert!(validate_target("::1:443").is_err());
}

#[test]
fn checks_target_length_boundaries() {
    let max_len_target = format!("{}:1", "a".repeat(TARGET_LEN_MAX - 2));
    let too_long_target = format!("{}:1", "a".repeat(TARGET_LEN_MAX - 1));

    assert!(check_target_len("test", "").is_err());
    assert!(check_target_len("test", &max_len_target).is_ok());
    assert!(check_target_len("test", &too_long_target).is_err());
}
