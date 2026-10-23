// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Independent prelude vectors, mutation coverage, identity lifetime and allocation limits.

use std::collections::HashSet;
use std::sync::Arc;

use super::*;

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    std::array::from_fn(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap())
}

fn vector() -> (MorphKeys, [u8; 64], [u8; 12], AuthenticatedPrelude) {
    let keys = MorphKeys::derive(b"0123456789abcdef0123456789abcdef");
    let mut prelude = [0; 64];
    for (index, byte) in prelude[..32].iter_mut().enumerate() {
        *byte = index as u8;
    }
    let high = 0xf00f_aa55u32;
    for (index, byte) in prelude[32..].iter_mut().enumerate() {
        *byte = (((high >> (31 - index)) & 1) << 7) as u8;
    }
    (
        keys,
        prelude,
        hex("000102030405060708090a0b"),
        AuthenticatedPrelude {
            identity: 0x0123_4567_89ab_cdef,
            counter: 1,
        },
    )
}

fn encode_reference_payload(
    keys: &MorphKeys,
    header: [u8; 48],
    payload: [u8; 28],
) -> ([u8; 64], [u8; 12]) {
    let mask = hmac_sha256(&keys.tcp_prelude_mask, &header);
    let masked: [u8; 28] = std::array::from_fn(|index| payload[index] ^ mask[index]);
    let mut prelude = [0; 64];
    prelude[..32].copy_from_slice(&header[12..44]);
    for index in 0..32 {
        let high = ((header[44 + index / 8] >> (7 - index % 8)) & 1) << 7;
        let low = (0..7).fold(0, |value, bit| {
            let offset = index * 7 + bit;
            (value << 1) | ((masked[offset / 8] >> (7 - offset % 8)) & 1)
        });
        prelude[32 + index] = high | low;
    }
    (prelude, header[..12].try_into().unwrap())
}

#[test]
fn independent_fixed_tag_and_encoded_tail_match() {
    let (keys, mut prelude, nonce, authentication) = vector();
    let mut input = authentication_input(&prelude, &nonce);
    input[48..56].copy_from_slice(&authentication.identity.to_be_bytes());
    input[56..].copy_from_slice(&authentication.counter.to_be_bytes()[2..]);
    assert_eq!(&input[44..48], &hex::<4>("f00faa55"));
    assert_eq!(
        hmac_sha256(&keys.tcp_prelude_auth, &input)[..14],
        hex::<14>("abb825c613d58ecda8d6489ea975")
    );
    keys.encode_prelude(&mut prelude, &nonce, authentication);
    assert_eq!(
        prelude[32..],
        hex::<32>("898f9c840e570537225e187fb7e4c990df489547d61b9e515bad2a8f4dd84d86")
    );
    assert!(keys.decode_prelude(&prelude, &nonce) == Some(authentication));
}

#[test]
fn extreme_field_encodings_match_independent_vectors() {
    let keys = MorphKeys::derive(b"0123456789abcdef0123456789abcdef");
    for (prefix, nonce, high, identity, counter, tag, tail) in [
        (
            [255; 32],
            [255; 12],
            [255; 4],
            u64::MAX,
            MAX_COUNTER,
            "fe74232711614dce0c60a6a4832f",
            "b2eac9c5c3fcb0e5a3f3a7c8febed9bca7aec3a1c4b0a3a5cf879c8edf8ffce8",
        ),
        (
            [0; 32],
            [0; 12],
            [0; 4],
            0,
            0,
            "4568be962a1b259cf44db132261c",
            "245b016f7d7e2b4c125f3e33445f0d2a103f225860664d0c7465093120367212",
        ),
        (
            std::array::from_fn(|index| 31 - index as u8),
            std::array::from_fn(|index| 11 - index as u8),
            hex("80000001"),
            0x8000_0000_0000_0001,
            0x8000_0000_0001,
            "37d8bc3e65c0ebc5b93bbabb9d76",
            "b57508160f6c2d312c50315572780903206a301662675c472f676d701b032ab8",
        ),
    ] {
        let authentication = AuthenticatedPrelude { identity, counter };
        let mut header = [0; 48];
        header[..12].copy_from_slice(&nonce);
        header[12..44].copy_from_slice(&prefix);
        header[44..].copy_from_slice(&high);
        let mut payload = [0; 28];
        payload[..8].copy_from_slice(&identity.to_be_bytes());
        payload[8..14].copy_from_slice(&counter.to_be_bytes()[2..]);
        payload[14..].copy_from_slice(&hex::<14>(tag));
        let (mut prelude, _) = encode_reference_payload(&keys, header, payload);
        assert_eq!(prelude[32..], hex::<32>(tail));
        assert!(keys.decode_prelude(&prelude, &nonce) == Some(authentication));
        prelude[32..].iter_mut().for_each(|byte| *byte &= 0x80);
        keys.encode_prelude(&mut prelude, &nonce, authentication);
        assert_eq!(prelude[32..], hex::<32>(tail));
    }
}

#[test]
fn every_bootstrap_bit_is_authenticated() {
    let (keys, mut prelude, nonce, authentication) = vector();
    keys.encode_prelude(&mut prelude, &nonce, authentication);
    for bit in 0..64 * 8 {
        let mut modified = prelude;
        modified[bit / 8] ^= 1 << (bit % 8);
        assert!(
            keys.decode_prelude(&modified, &nonce).is_none(),
            "prelude bit {bit}"
        );
    }
    for bit in 0..12 * 8 {
        let mut modified = nonce;
        modified[bit / 8] ^= 1 << (bit % 8);
        assert!(
            keys.decode_prelude(&prelude, &modified).is_none(),
            "nonce bit {bit}"
        );
    }
}

#[test]
fn every_tag_input_and_payload_bit_is_bound_after_independent_remasking() {
    let (keys, prelude, nonce, authentication) = vector();
    let mut header = [0; 48];
    header[..12].copy_from_slice(&nonce);
    header[12..44].copy_from_slice(&prelude[..32]);
    header[44..].copy_from_slice(&hex::<4>("f00faa55"));
    let payload = hex::<28>("0123456789abcdef000000000001abb825c613d58ecda8d6489ea975");
    let (encoded, nonce) = encode_reference_payload(&keys, header, payload);
    assert!(keys.decode_prelude(&encoded, &nonce) == Some(authentication));
    for bit in 0..(48 + 28) * 8 {
        let mut modified_header = header;
        let mut modified_payload = payload;
        if bit < 48 * 8 {
            modified_header[bit / 8] ^= 1 << (bit % 8);
        } else {
            let bit = bit - 48 * 8;
            modified_payload[bit / 8] ^= 1 << (bit % 8);
        }
        let (encoded, nonce) = encode_reference_payload(&keys, modified_header, modified_payload);
        assert!(
            keys.decode_prelude(&encoded, &nonce).is_none(),
            "remasked mutation bit {bit}"
        );
    }
}

#[test]
fn auth_mask_and_directional_keys_are_isolated() {
    let (keys, mut prelude, nonce, authentication) = vector();
    let all = [
        keys.tcp_c2s,
        keys.tcp_s2c,
        keys.udp_c2s,
        keys.udp_s2c,
        keys.tcp_prelude_auth,
        keys.tcp_prelude_mask,
    ];
    assert_eq!(all.into_iter().collect::<HashSet<_>>().len(), 6);
    keys.encode_prelude(&mut prelude, &nonce, authentication);
    let mut swapped = keys.clone();
    std::mem::swap(&mut swapped.tcp_prelude_auth, &mut swapped.tcp_prelude_mask);
    assert!(swapped.decode_prelude(&prelude, &nonce).is_none());
    assert!(
        MorphKeys::derive(b"ffffffffffffffffffffffffffffffff")
            .decode_prelude(&prelude, &nonce)
            .is_none()
    );
}

#[test]
fn masks_change_with_nonce_and_roundtrip_all_counter_byte_boundaries() {
    let (keys, prelude, mut nonce, _) = vector();
    let mut seen = HashSet::new();
    for identity in [0, 1, u64::MAX] {
        for counter in [0, 1, 127, 128, 255, 256, 65535, 65536, 1 << 32, MAX_COUNTER] {
            let authentication = AuthenticatedPrelude { identity, counter };
            let mut encoded = prelude;
            keys.encode_prelude(&mut encoded, &nonce, authentication);
            assert!(keys.decode_prelude(&encoded, &nonce) == Some(authentication));
            assert_eq!(authentication.is_valid(), counter != 0);
            seen.insert(encoded);
            nonce[0] = nonce[0].wrapping_add(1);
        }
    }
    assert_eq!(seen.len(), 30);
    let authentication = AuthenticatedPrelude {
        identity: 0,
        counter: 1,
    };
    let mut first = prelude;
    let mut second = prelude;
    keys.encode_prelude(&mut first, &[0; 12], authentication);
    keys.encode_prelude(&mut second, &[1; 12], authentication);
    assert_ne!(first[32..], second[32..]);
    assert!(
        !AuthenticatedPrelude {
            identity: 0,
            counter: MAX_COUNTER + 1
        }
        .is_valid()
    );
}

#[test]
fn fixed_sample_low7_distribution_has_no_visible_marker() {
    let (keys, prelude, _, _) = vector();
    let mut counts = [0usize; 128];
    let mut position_bits = [0u8; 32];
    for sample in 0..4096u64 {
        let mut nonce = [0; 12];
        nonce[..8].copy_from_slice(&sample.to_be_bytes());
        let mut encoded = prelude;
        keys.encode_prelude(
            &mut encoded,
            &nonce,
            AuthenticatedPrelude {
                identity: sample.wrapping_mul(0x9e37_79b9_7f4a_7c15),
                counter: sample + 1,
            },
        );
        for (index, byte) in encoded[32..].iter().enumerate() {
            counts[usize::from(byte & 0x7f)] += 1;
            position_bits[index] |= byte & 0x7f;
        }
    }
    assert!(counts.iter().all(|&count| (800..1250).contains(&count)));
    assert_eq!(position_bits, [127; 32]);
}

#[test]
fn concurrent_allocation_uses_one_identity_and_never_reuses_counters() {
    let state = Arc::new(ClientPrelude::default());
    let workers: Vec<_> = (0..16)
        .map(|_| {
            let state = state.clone();
            std::thread::spawn(move || {
                (0..1024)
                    .map(|_| state.allocate().unwrap())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut identities = HashSet::new();
    let mut counters = HashSet::new();
    for worker in workers {
        for authentication in worker.join().unwrap() {
            identities.insert(authentication.identity);
            assert!(counters.insert(authentication.counter));
        }
    }
    assert_eq!(identities.len(), 1);
    assert_eq!(counters.len(), 16 * 1024);
    assert!(counters.contains(&1));
    assert!(counters.contains(&(16 * 1024)));
}

#[test]
fn counter_exhaustion_is_permanent_including_concurrent_last_allocation() {
    let state = Arc::new(ClientPrelude::for_test(0, MAX_COUNTER - 1));
    let workers: Vec<_> = (0..16)
        .map(|_| {
            let state = state.clone();
            std::thread::spawn(move || state.allocate())
        })
        .collect();
    let mut successes = 0;
    for worker in workers {
        if let Ok(authentication) = worker.join().unwrap() {
            successes += 1;
            assert_eq!(authentication.counter, MAX_COUNTER);
        }
    }
    assert_eq!(successes, 1);
    assert!(state.allocate().is_err());
    assert_eq!(
        state
            .identity
            .get()
            .unwrap()
            .as_ref()
            .unwrap()
            .counter
            .load(Ordering::Relaxed),
        MAX_COUNTER
    );
}

#[test]
fn identity_initialization_failure_never_allocates_or_logs_identity() {
    let state = ClientPrelude {
        identity: OnceLock::from(Err(io::Error::other("unavailable"))),
    };
    assert_eq!(
        state.allocate().err().unwrap().to_string(),
        "Morph identity randomness unavailable"
    );
    let first = ClientPrelude::default();
    let second = ClientPrelude::default();
    assert!(first.allocate().unwrap().identity != second.allocate().unwrap().identity);
}

impl ClientPrelude {
    pub(crate) fn for_test(identity: u64, previous_counter: u64) -> Self {
        Self {
            identity: OnceLock::from(Ok(Identity {
                value: identity,
                counter: AtomicU64::new(previous_counter),
            })),
        }
    }

    pub(crate) fn allocated_for_test(&self) -> u64 {
        self.identity.get().map_or(0, |identity| {
            identity.as_ref().unwrap().counter.load(Ordering::Relaxed)
        })
    }
}
