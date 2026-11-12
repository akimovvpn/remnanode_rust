use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use serde::Deserialize;
use std::{env, io::BufReader, path::PathBuf, sync::Arc};
use x509_parser::prelude::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodePayload {
    pub ca_cert_pem: String,
    pub jwt_public_key: String,
    pub node_cert_pem: String,
    pub node_key_pem: String,
}

pub fn normalize_pem(pem: &str) -> String {
    let mut value = pem.replace("\\n", "\n").replace("\r\n", "\n");
    let mut at = 0;
    while let Some(start) = value[at..].find("-----BEGIN ") {
        let start = at + start;
        let Some(end) = value[start + 11..].find("-----") else {
            break;
        };
        let end = start + 11 + end + 5;
        value.insert(end, '\n');
        at = end + 1;
    }
    value = value.replace("-----END ", "\n-----END ");
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

impl NodePayload {
    pub fn decode(secret: &str) -> Result<Self> {
        ensure!(secret.len() <= 128 * 1024, "SECRET_KEY exceeds size limit");
        let mut payload: Self = serde_json::from_slice(
            &STANDARD
                .decode(secret)
                .context("SECRET_KEY must be base64")?,
        )
        .context("SECRET_KEY must contain the panel certificate payload")?;
        for pem in [
            &mut payload.ca_cert_pem,
            &mut payload.jwt_public_key,
            &mut payload.node_cert_pem,
            &mut payload.node_key_pem,
        ] {
            *pem = normalize_pem(pem);
        }
        let (_, ca_pem) = parse_x509_pem(payload.ca_cert_pem.as_bytes())
            .map_err(|_| anyhow::anyhow!("Invalid CA certificate"))?;
        let (_, node_pem) = parse_x509_pem(payload.node_cert_pem.as_bytes())
            .map_err(|_| anyhow::anyhow!("Invalid node certificate"))?;
        let ca = ca_pem.parse_x509().context("Invalid CA certificate")?;
        let node = node_pem.parse_x509().context("Invalid node certificate")?;
        ensure!(
            ca.validity().is_valid() && node.validity().is_valid(),
            "Certificate expired or not yet valid"
        );
        ca.verify_signature(None)
            .context("Invalid CA self-signature")?;
        node.verify_signature(Some(ca.public_key()))
            .context("Node certificate is not signed by this CA")?;
        crate::auth::Auth::new(&payload.jwt_public_key)?;
        payload.tls_config()?;
        Ok(payload)
    }

    pub fn tls_config(&self) -> Result<ServerConfig> {
        let certs = rustls_pemfile::certs(&mut BufReader::new(self.node_cert_pem.as_bytes()))
            .collect::<std::io::Result<Vec<_>>>()?;
        ensure!(!certs.is_empty(), "Missing node certificate");
        let key = rustls_pemfile::private_key(&mut BufReader::new(self.node_key_pem.as_bytes()))?
            .context("Missing node private key")?;
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut BufReader::new(self.ca_cert_pem.as_bytes())) {
            roots.add(cert?)?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()?;
        Ok(ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?)
    }
}

pub struct Config {
    pub port: u16,
    pub payload: NodePayload,
    pub verify_sni: bool,
    pub xray_binary: PathBuf,
    pub state_dir: PathBuf,
    pub endpoint: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let port = env::var("NODE_PORT")
            .context("NODE_PORT is required")?
            .parse::<u16>()
            .context("Invalid NODE_PORT")?;
        ensure!(port != 0, "NODE_PORT must be greater than zero");
        let verify_sni = match env::var("SNI_VERIFICATION").as_deref() {
            Ok("true") => true,
            Ok("false" | "") | Err(_) => false,
            _ => bail!("SNI_VERIFICATION must be true or false"),
        };
        let endpoint =
            env::var("XRAY_API_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:61000".into());
        let url = reqwest::Url::parse(&endpoint).context("Invalid XRAY_API_ENDPOINT")?;
        ensure!(
            url.scheme() == "http"
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "XRAY_API_ENDPOINT must be a plain loopback HTTP address"
        );
        let host = url.host_str().context("Missing Xray API host")?;
        ensure!(
            host.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()),
            "Xray API must listen on a loopback IP"
        );
        ensure!(
            url.port().is_some_and(|port| port != 0),
            "Xray API requires an explicit port"
        );
        Ok(Self {
            port,
            payload: NodePayload::decode(
                &env::var("SECRET_KEY").context("SECRET_KEY is required")?,
            )?,
            verify_sni,
            xray_binary: env::var_os("XRAY_BINARY")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/usr/local/bin/xray".into()),
            state_dir: env::var_os("STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/var/lib/remnanode".into()),
            endpoint,
        })
    }
}
