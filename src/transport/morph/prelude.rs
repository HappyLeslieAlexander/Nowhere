// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated TCP prelude encoding and shared client identity allocation.

use std::io;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use subtle::ConstantTimeEq;

use super::{MorphKeys, NONCE_LEN, TCP_PRELUDE_LEN, hmac_sha256};

const MAX_COUNTER: u64 = (1 << 48) - 1;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AuthenticatedPrelude {
    pub(crate) identity: u64,
    pub(crate) counter: u64,
}

struct Identity {
    value: u64,
    counter: AtomicU64,
}

#[derive(Default)]
pub(crate) struct ClientPrelude {
    identity: OnceLock<io::Result<Identity>>,
}

impl AuthenticatedPrelude {
    pub(crate) fn is_valid(self) -> bool {
        (1..=MAX_COUNTER).contains(&self.counter)
    }
}

impl ClientPrelude {
    pub(super) fn allocate(&self) -> io::Result<AuthenticatedPrelude> {
        let identity = self.identity.get_or_init(|| {
            let mut bytes = [0; 8];
            getrandom::fill(&mut bytes).map_err(io::Error::other)?;
            Ok(Identity {
                value: u64::from_be_bytes(bytes),
                counter: AtomicU64::new(0),
            })
        });
        let identity = identity
            .as_ref()
            .map_err(|_| io::Error::other("Morph identity randomness unavailable"))?;
        let mut previous = identity.counter.load(Ordering::Relaxed);
        loop {
            if previous >= MAX_COUNTER {
                return Err(io::Error::other("Morph prelude counter exhausted"));
            }
            match identity.counter.compare_exchange_weak(
                previous,
                previous + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(AuthenticatedPrelude {
                        identity: identity.value,
                        counter: previous + 1,
                    });
                }
                Err(current) => previous = current,
            }
        }
    }
}

impl MorphKeys {
    pub(super) fn encode_prelude(
        &self,
        prelude: &mut [u8; TCP_PRELUDE_LEN],
        nonce: &[u8; NONCE_LEN],
        authentication: AuthenticatedPrelude,
    ) {
        let mut input = authentication_input(prelude, nonce);
        input[48..56].copy_from_slice(&authentication.identity.to_be_bytes());
        input[56..].copy_from_slice(&authentication.counter.to_be_bytes()[2..]);
        let tag = hmac_sha256(&self.tcp_prelude_auth, &input);
        let mask = hmac_sha256(&self.tcp_prelude_mask, &input[..48]);
        let mut payload = [0; 28];
        payload[..14].copy_from_slice(&input[48..]);
        payload[14..].copy_from_slice(&tag[..14]);
        for (byte, mask) in payload.iter_mut().zip(mask) {
            *byte ^= mask;
        }
        let mut accumulator = 0u16;
        let mut bits = 0;
        let mut tail = prelude[32..].iter_mut();
        for byte in payload {
            accumulator = (accumulator << 8) | u16::from(byte);
            bits += 8;
            while bits >= 7 {
                bits -= 7;
                let output = tail.next().unwrap();
                *output = (*output & 0x80) | ((accumulator >> bits) as u8 & 0x7f);
            }
        }
    }

    pub(super) fn decode_prelude(
        &self,
        prelude: &[u8; TCP_PRELUDE_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> Option<AuthenticatedPrelude> {
        let mut input = authentication_input(prelude, nonce);
        let mask = hmac_sha256(&self.tcp_prelude_mask, &input[..48]);
        let mut payload = [0; 28];
        let mut accumulator = 0u16;
        let mut bits = 0;
        let mut output = payload.iter_mut();
        for byte in &prelude[32..] {
            accumulator = (accumulator << 7) | u16::from(byte & 0x7f);
            bits += 7;
            if bits >= 8 {
                bits -= 8;
                *output.next().unwrap() = (accumulator >> bits) as u8;
            }
        }
        for (byte, mask) in payload.iter_mut().zip(mask) {
            *byte ^= mask;
        }
        input[48..].copy_from_slice(&payload[..14]);
        let tag = hmac_sha256(&self.tcp_prelude_auth, &input);
        if !bool::from(tag[..14].ct_eq(&payload[14..])) {
            return None;
        }
        let identity = u64::from_be_bytes(payload[..8].try_into().unwrap());
        let mut counter = [0; 8];
        counter[2..].copy_from_slice(&payload[8..14]);
        Some(AuthenticatedPrelude {
            identity,
            counter: u64::from_be_bytes(counter),
        })
    }
}

fn authentication_input(prelude: &[u8; TCP_PRELUDE_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; 62] {
    let mut input = [0; 62];
    input[..12].copy_from_slice(nonce);
    input[12..44].copy_from_slice(&prelude[..32]);
    for (index, byte) in prelude[32..].iter().enumerate() {
        input[44 + index / 8] |= (byte >> 7) << (7 - index % 8);
    }
    input
}

#[cfg(test)]
#[path = "../../tests/transport/morph/prelude.rs"]
mod tests;
