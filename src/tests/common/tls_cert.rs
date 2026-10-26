// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! PEM loading and certificate reload compatibility tests.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::tls_test_support::server_certificate_der;

use super::*;

const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBdTCCARugAwIBAgIJAPzMghCcbEntMAoGCCqGSM49BAMCMBkxFzAVBgNVBAMM
Dk5XMyBBdWRpdCBSb290MB4XDTI2MTAyNjA4MDgxMloXDTI2MTAyODA4MDgxMlow
FDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
G4qgDmk9suVM/YsU6dO0Xx/Va0Y76pd+tf6KM3NKiv4mNusso6BvG2EK1eo6xgT+
pvDTMCWJb2rXh3y/3+djZKNRME8wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMC
B4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/
AAABMAoGCCqGSM49BAMCA0gAMEUCIQDdagyHXJ/7Xi6PFeB6CVFS3jgad5D4wqi+
JU99MAlxbgIgOTJmiwnEnWbovdj1r2aAGeM3AdX361oaKJRU09TmSfE=
-----END CERTIFICATE-----
";

const ROTATED_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBbTCCAROgAwIBAgIBAjAKBggqhkjOPQQDAjAZMRcwFQYDVQQDDA5OVzMgQXVk
aXQgUm9vdDAeFw0yNjEwMjYwODEwMTFaFw0yNjEwMjgwODEwMTFaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBuKoA5pPbLl
TP2LFOnTtF8f1WtGO+qXfrX+ijNzSor+JjbrLKOgbxthCtXqOsYE/qbw0zAliW9q
14d8v9/nY2SjUTBPMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAKBggq
hkjOPQQDAgNIADBFAiAHE42bW3c11tOHSCpQReqq5U2spiLDChmwEZLEDwK6EgIh
ANbr+aKth65Ejf1pZfkHDqfM0yVicW/gCwR8aTfNdgjH
-----END CERTIFICATE-----
";

const KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgk0OfoN7+3VtvL1Bh
wl2uKDN91jU0EY624cd7uce3cqihRANCAAQbiqAOaT2y5Uz9ixTp07RfH9VrRjvq
l361/oozc0qK/iY26yyjoG8bYQrV6jrGBP6m8NMwJYlvateHfL/f52Nk
-----END PRIVATE KEY-----
";

struct PemFiles(std::path::PathBuf);

impl PemFiles {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nowhere-pem-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let files = Self(path);
        files.write(CERT, KEY);
        files
    }

    fn write(&self, cert: &str, key: &str) {
        fs::write(self.0.join("cert.pem"), cert).unwrap();
        fs::write(self.0.join("key.pem"), key).unwrap();
    }

    fn load(&self) -> Result<CertifiedKey> {
        load_certified_key(
            self.0.join("cert.pem").to_str().unwrap(),
            self.0.join("key.pem").to_str().unwrap(),
            &rustls::crypto::ring::default_provider(),
        )
    }
}

impl Drop for PemFiles {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn pem_loading_preserves_chain_order_and_uses_the_first_private_key() {
    let files = PemFiles::new();
    files.write(
        &format!("ignored text\n{KEY}{CERT}{ROTATED_CERT}"),
        &format!("{CERT}{KEY}-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"),
    );
    let loaded = files.load().unwrap();
    assert_eq!(
        loaded.cert,
        [CERT, ROTATED_CERT].map(|pem| CertificateDer::from_pem_slice(pem.as_bytes()).unwrap())
    );
}

#[test]
fn pem_loading_rejects_missing_and_malformed_material() {
    let files = PemFiles::new();
    for (cert, key, expected) in [
        ("", KEY, "no certificates found"),
        (CERT, "", "no private keys found"),
        (
            "-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n",
            KEY,
            "invalid PEM certificate",
        ),
        (
            CERT,
            "-----BEGIN PRIVATE KEY-----\n!\n-----END PRIVATE KEY-----\n",
            "invalid PEM private key",
        ),
    ] {
        files.write(cert, key);
        assert!(format!("{:#}", files.load().unwrap_err()).contains(expected));
    }
}

#[test]
fn pem_reload_replaces_valid_material_and_retains_the_last_valid_certificate() {
    let files = PemFiles::new();
    let mut url = url::Url::parse("portal://secret@127.0.0.1:2000").unwrap();
    url.query_pairs_mut()
        .append_pair("tls", "2")
        .append_pair("crt", files.0.join("cert.pem").to_str().unwrap())
        .append_pair("key", files.0.join("key.pem").to_str().unwrap());
    let (_, tls, _) =
        super::super::new_server_configs_with_reload_interval(&url, Duration::ZERO, Logger)
            .unwrap();
    assert_eq!(
        server_certificate_der(&tls),
        CertificateDer::from_pem_slice(CERT.as_bytes()).unwrap()
    );
    files.write(ROTATED_CERT, KEY);
    let expected = CertificateDer::from_pem_slice(ROTATED_CERT.as_bytes()).unwrap();
    assert_eq!(server_certificate_der(&tls), expected);
    files.write("malformed", KEY);
    assert_eq!(server_certificate_der(&tls), expected);
}
