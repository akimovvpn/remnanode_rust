use base64::{Engine, engine::general_purpose::STANDARD};
use remnanode_rust::{
    auth::{Auth, derive_sni},
    config::{NodePayload, normalize_pem},
};
use serde_json::json;

#[test]
fn sni_matches_upstream_hkdf_vector() {
    assert_eq!(
        derive_sni(
            "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----",
            "-----BEGIN PUBLIC KEY-----\nZGVm\n-----END PUBLIC KEY-----"
        ),
        "c08a4a89981573a561cd041a620ebcce.5ce2e41a9e.net"
    );
}
#[test]
fn escaped_pem_is_normalized() {
    assert_eq!(
        normalize_pem("  -----BEGIN PUBLIC KEY-----ABC\\nDEF-----END PUBLIC KEY----- "),
        "-----BEGIN PUBLIC KEY-----\nABC\nDEF\n-----END PUBLIC KEY-----"
    );
}
#[test]
fn secret_payload_rejects_missing_fields_and_invalid_certificates() {
    assert!(NodePayload::decode("not-base64").is_err());
    let secret = STANDARD.encode(
        json!({"caCertPem":"bad","nodeCertPem":"bad","nodeKeyPem":"bad","jwtPublicKey":"bad"})
            .to_string(),
    );
    assert!(NodePayload::decode(&secret).is_err());
    assert!(NodePayload::decode(&STANDARD.encode("{}")).is_err());
}
#[test]
fn invalid_rsa_key_rejected_at_startup() {
    assert!(Auth::new("not-a-pem").is_err());
}

#[test]
fn rs256_auth_rejects_wrong_algorithm_signature_expiry_and_future_nbf() {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("jwt.pem");
    let public = dir.path().join("jwt.pub");
    assert!(
        Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out"
            ])
            .arg(&key)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        Command::new("openssl")
            .args(["pkey", "-in"])
            .arg(&key)
            .args(["-pubout", "-out"])
            .arg(&public)
            .output()
            .unwrap()
            .status
            .success()
    );
    let auth = Auth::new(&std::fs::read_to_string(public).unwrap()).unwrap();
    let signing = EncodingKey::from_rsa_pem(&std::fs::read(key).unwrap()).unwrap();
    let token = |claims| {
        format!(
            "Bearer {}",
            encode(&Header::new(Algorithm::RS256), &claims, &signing).unwrap()
        )
    };
    let now = chrono::Utc::now().timestamp();
    assert!(auth.verify(&token(json!({"exp":now+60}))));
    assert!(auth.verify(&token(json!({"sub":"panel"}))));
    assert!(!auth.verify(&token(json!({"exp":now-1}))));
    assert!(!auth.verify(&token(json!({"exp":now+100,"nbf":now+60}))));
    assert!(!auth.verify("Bearer malformed.token.value"));
    assert!(!auth.verify(&token(json!({"exp":now+60})).replace("Bearer", "Basic")));
    let hs = encode(
        &Header::new(Algorithm::HS256),
        &json!({"exp":now+60}),
        &EncodingKey::from_secret(b"secret"),
    )
    .unwrap();
    assert!(!auth.verify(&format!("Bearer {hs}")));
    let valid = token(json!({"exp":now+60}));
    let parts: Vec<_> = valid.split('.').collect();
    assert!(!auth.verify(&format!(
        "{}.{}.{}",
        parts[0],
        STANDARD.encode("{\"exp\":9999999999}"),
        parts[2]
    )));
}
