// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Morph key derivation and interoperability vectors tests.

use super::*;

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

#[test]
fn derives_fixed_hkdf_sha256_keys() {
    let keys = MorphKeys::derive(b"test portal key");
    assert_eq!(
        keys.tcp_c2s,
        hex("90df47db82553ab6b0489ea77a085593475a70c6a61e957ad3ffe0824bd2126a")
    );
    assert_eq!(
        keys.tcp_s2c,
        hex("20bc17a22d08469e60efd4c6bdda76f190c33946599a0797bab2d52007b97e27")
    );
    assert_eq!(
        keys.udp_c2s,
        hex("6837a1f0de5a70baf35de9ba7a77174a665d577bde4000386ddf0e5206b56773")
    );
    assert_eq!(
        keys.udp_s2c,
        hex("798c97f634139bb467919fbbcd705e0eeffe9294164981dc34a72e274d449b79")
    );
}
