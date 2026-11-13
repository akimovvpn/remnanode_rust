//! These are normal bounded regression tests and coverage-guided cargo-bolero targets.
use crate::{config, mux, reality, reality_probe, sniff, socks, vision, vless};
use std::sync::{Arc, Mutex};

#[test]
fn fuzz_config() {
    bolero::check!()
        .with_max_len(8192)
        .with_iterations(512)
        .for_each(|data: &[u8]| {
            if let Ok(text) = std::str::from_utf8(data) {
                let _ = config::Config::parse(text);
                let _ = config::parse_uuid(text);
            }
        });
}

#[test]
fn fuzz_tls_handshakes() {
    bolero::check!()
        .with_max_len(16384)
        .with_iterations(512)
        .for_each(|data: &[u8]| {
            let _ = reality::ClientHello::parse(data);
            let _ = reality_probe::extensions(data);
            let _ = reality_probe::certificates(data);
            let _ = reality_probe::server_hello(data, &[0; 32]);
            let _ = reality_probe::validate_certificate_request(data);
            let _ = sniff::sniff_tcp(data);
        });
}

#[test]
fn fuzz_vless_and_udp_headers() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let users = vless::Users::default();
    users
        .add(config::User {
            email: "fuzz".into(),
            level: 0,
            id: [1; 16],
            flow: String::new(),
        })
        .unwrap();
    bolero::check!()
        .with_max_len(8192)
        .with_iterations(512)
        .for_each(|data: &[u8]| {
            let _ = socks::udp_decode(data);
            let _ = mux::read_address_port(data);
            runtime.block_on(async {
                let mut raw = data;
                let _ = vless::read_request(&mut raw, &users).await;
                // Reach addons/command parsing even when random UUIDs would be rejected first.
                let mut request = vec![0];
                request.extend_from_slice(&[1; 16]);
                request.extend_from_slice(data);
                let mut raw = request.as_slice();
                let _ = vless::read_request(&mut raw, &users).await;
            });
        });
}

#[test]
fn fuzz_vision_frames() {
    bolero::check!()
        .with_max_len(16384)
        .with_iterations(512)
        .for_each(|data: &[u8]| {
            let mut wire = vec![1; 16];
            wire.extend_from_slice(data);
            for chunk in [1, 7, 257] {
                let mut decoder =
                    vision::Decoder::new([1; 16], Arc::new(Mutex::new(vision::State::new())));
                for bytes in wire.chunks(chunk) {
                    if decoder.decode(bytes).is_err() {
                        break;
                    }
                }
                let _ = decoder.finish();
            }
        });
}
