// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! TCP request frame tests.

use super::*;
use url::Url;

fn protocol_spec(spec: &str) -> EffectiveProtocolSpec {
    let url = Url::parse(&format!("portal://secret@127.0.0.1:443?spec={spec}")).unwrap();
    EffectiveProtocolSpec::new(&url, b"secret").unwrap()
}

#[test]
fn writes_versioned_target_in_derived_order() {
    let spec = protocol_spec("edge-a");
    let frame = write_request_frame("example.com:443", &spec).unwrap();
    assert_eq!(
        frame.len(),
        1 + 2 + "example.com:443".len() + 1 + spec.tcp_padding_len as usize
    );

    let fields = decode_fields(&frame, &spec);
    assert_eq!(fields.version, PROXY_FRAME_VERSION);
    assert_eq!(fields.target, "example.com:443");
    assert_eq!(
        fields.padding,
        tcp_request_padding_bytes(&spec, "example.com:443")
    );
}

#[test]
fn tcp_request_fixed_vectors() {
    let cases = [
        (
            "auto",
            "000f6578616d706c652e636f6d3a343433013c1526b9b947228779cfc539fe4681bcb5d1e20efa2bcb9f89eda5b473625c3c6b7fb12499fd33edfefb1934c9ae0bfc0e849f4c94814f4f2f9ae782e8",
        ),
        (
            "edge-a",
            "321e7800dfe8345ac8f3c1897d243ec10cea6218a101531221c227da14f0242f079004bf8575f00e6a2ff9c48a932410fe434601000f6578616d706c652e636f6d3a343433",
        ),
    ];

    for (spec_name, expected_hex) in cases {
        let spec = protocol_spec(spec_name);
        let frame = write_request_frame("example.com:443", &spec).unwrap();

        assert_eq!(hex(&frame), expected_hex);
    }
}

#[tokio::test]
async fn reads_request_frame() {
    let spec = protocol_spec("edge-a");
    let frame = write_request_frame("example.com:443", &spec).unwrap();
    let mut reader = frame.as_slice();

    assert_eq!(
        read_request(&mut reader, &spec).await.unwrap(),
        "example.com:443"
    );
}

#[tokio::test]
async fn rejects_invalid_request_targets() {
    let spec = protocol_spec("edge-a");
    let mut frame = Vec::new();
    for element in spec.frame_layout.tcp {
        match element {
            TcpFrameElement::Version => frame.push(PROXY_FRAME_VERSION),
            TcpFrameElement::Target => {
                frame.extend_from_slice(&12u16.to_be_bytes());
                frame.extend_from_slice(b"example.com:");
            }
            TcpFrameElement::Padding => {
                frame.push(spec.tcp_padding_len);
                frame.extend_from_slice(&tcp_request_padding_bytes(&spec, "example.com:"));
            }
        }
    }
    let mut reader = frame.as_slice();

    assert!(read_request(&mut reader, &spec).await.is_err());
}

#[tokio::test]
async fn rejects_invalid_version() {
    let spec = protocol_spec("edge-a");
    let mut frame = write_request_frame("example.com:443", &spec).unwrap();
    let offset = field_offset(&frame, &spec, TcpFrameElement::Version);
    frame[offset] = PROXY_FRAME_VERSION + 1;
    let mut reader = frame.as_slice();

    assert!(read_request(&mut reader, &spec).await.is_err());
}

#[tokio::test]
async fn rejects_invalid_padding_length_and_bytes() {
    let spec = protocol_spec("edge-a");
    let mut bad_len = write_request_frame("example.com:443", &spec).unwrap();
    let padding_offset = field_offset(&bad_len, &spec, TcpFrameElement::Padding);
    bad_len[padding_offset] = bad_len[padding_offset].wrapping_add(1);
    let mut reader = bad_len.as_slice();
    assert!(read_request(&mut reader, &spec).await.is_err());

    if spec.tcp_padding_len > 0 {
        let mut bad_padding = write_request_frame("example.com:443", &spec).unwrap();
        bad_padding[padding_offset + 1] ^= 1;
        let mut reader = bad_padding.as_slice();
        assert!(read_request(&mut reader, &spec).await.is_err());
    }
}

struct DecodedFields {
    version: u8,
    target: String,
    padding: Vec<u8>,
}

fn decode_fields(frame: &[u8], spec: &EffectiveProtocolSpec) -> DecodedFields {
    let mut offset = 0;
    let mut version = None;
    let mut target = None;
    let mut padding = None;
    for element in spec.frame_layout.tcp {
        match element {
            TcpFrameElement::Version => {
                version = Some(frame[offset]);
                offset += 1;
            }
            TcpFrameElement::Target => {
                let len = u16::from_be_bytes(
                    frame[offset..offset + 2]
                        .try_into()
                        .expect("target length slice"),
                ) as usize;
                offset += 2;
                target = Some(
                    std::str::from_utf8(&frame[offset..offset + len])
                        .expect("target utf8")
                        .to_string(),
                );
                offset += len;
            }
            TcpFrameElement::Padding => {
                let len = frame[offset] as usize;
                offset += 1;
                padding = Some(frame[offset..offset + len].to_vec());
                offset += len;
            }
        }
    }
    assert_eq!(offset, frame.len());

    DecodedFields {
        version: version.expect("version"),
        target: target.expect("target"),
        padding: padding.expect("padding"),
    }
}

fn field_offset(
    frame: &[u8],
    spec: &EffectiveProtocolSpec,
    target_element: TcpFrameElement,
) -> usize {
    let mut offset = 0;
    for element in spec.frame_layout.tcp {
        if element == target_element {
            return offset;
        }
        offset += match element {
            TcpFrameElement::Version => 1,
            TcpFrameElement::Target => {
                let len = u16::from_be_bytes(
                    frame[offset..offset + 2]
                        .try_into()
                        .expect("target length slice"),
                ) as usize;
                2 + len
            }
            TcpFrameElement::Padding => 1 + frame[offset] as usize,
        };
    }
    unreachable!("field must exist in TCP frame layout")
}

fn hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
