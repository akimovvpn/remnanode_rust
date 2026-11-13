//! Port of the server side of xray-core transport/internet/tls (Go crypto/tls under it).
//! rustls runs the handshake with Go's server choices: certificate by SNI (rejectUnknownSni
//! answers unrecognized_name), ALPN in server order with the http/1.1 fallback, cipher suites in
//! Go's order (ChaCha20 first when the client prefers it), X25519MLKEM768, signature schemes in
//! the client's order and no session tickets unless enabled. TLS 1.3 sessions then continue on
//! rcore's record layer, which writes records like Go and lets Vision switch to direct copy.
use crate::config::{keys, string_list, unsupported};
use crate::tls13::{self, Cipher, DirectControl, Suite};
use crate::transport::BoxIo;
use anyhow::{Context, Result, bail, ensure};
use rustls::{
    CipherSuite, NamedGroup, ProtocolVersion, SignatureScheme, SupportedCipherSuite,
    crypto::{
        ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
        ring as provider,
    },
    server::{ClientHello, ResolvesServerCert, ServerConfig},
    sign::{CertifiedKey, Signer, SigningKey},
};
use serde_json::Value;
use std::{
    collections::HashMap,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// What the handshake settled, for the transport and VLESS on top.
pub struct Accepted {
    pub io: BoxIo,
    /// Vision's switch, for TLS 1.3 (Go refuses Vision over older outer TLS).
    pub direct: Option<DirectControl>,
    pub version: u16,
}

/// A certificate with the names getNewGetCertificateFunc matches against.
struct Pair {
    key: Arc<CertifiedKey>,
    common_name: String,
    dns_names: Vec<String>,
}

/// A configured certificate (Certificate in transport/internet/tls/config.proto).
struct Entry {
    cert_path: String,
    key_path: String,
    cert: Vec<u8>,
    key: Vec<u8>,
    one_time: bool,
}

pub struct Server {
    entries: Mutex<Vec<Entry>>,
    /// The usable pairs, by entry index (invalid pairs are skipped, as Go ignores them).
    pairs: RwLock<Vec<(usize, Pair)>>,
    reject_unknown_sni: bool,
    /// Whether maxVersion allows TLS 1.3.
    tls13: bool,
    alpn: Vec<Vec<u8>>,
    /// ServerConfig with AES-GCM preferred, and with ChaCha20 preferred.
    aes: Arc<ServerConfig>,
    chacha: Arc<ServerConfig>,
    key_log: Option<Arc<Mutex<std::fs::File>>>,
    /// Warnings Go logs while building the listener, printed once logging is up.
    warnings: Vec<String>,
}

/// platform.GetCertLocation for relative certificate paths.
fn cert_path(file: &str) -> PathBuf {
    if Path::new(file).is_absolute() {
        return file.into();
    }
    if let Some(dir) =
        std::env::var_os("XRAY_LOCATION_CERT").or_else(|| std::env::var_os("xray.location.cert"))
    {
        return Path::new(&dir).join(file);
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(file)))
        .unwrap_or_else(|| file.into())
}

/// readFileOrString.
fn file_or_string(file: &str, lines: &[String]) -> Result<Vec<u8>> {
    if !file.is_empty() {
        return std::fs::read(cert_path(file)).with_context(|| format!("open {file}"));
    }
    ensure!(
        !lines.is_empty(),
        "infra/conf: both file and bytes are empty."
    );
    Ok(lines.join("\n").into_bytes())
}

/// Signs in the client's preference order (Go's selectSignatureScheme) instead of rustls's.
#[derive(Debug)]
struct ClientOrder(Arc<dyn SigningKey>);

impl SigningKey for ClientOrder {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .iter()
            .find_map(|scheme| self.0.choose_scheme(std::slice::from_ref(scheme)))
    }
    fn public_key(&self) -> Option<rustls::pki_types::SubjectPublicKeyInfoDer<'_>> {
        self.0.public_key()
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
}

/// tls.X509KeyPair plus the leaf's names.
fn key_pair(cert: &[u8], key: &[u8]) -> Result<Pair> {
    let chain: Vec<_> = rustls_pemfile::certs(&mut &cert[..])
        .collect::<Result<_, _>>()
        .context("tls: failed to find any PEM data in certificate input")?;
    ensure!(
        !chain.is_empty(),
        "tls: failed to find any PEM data in certificate input"
    );
    let der = rustls_pemfile::private_key(&mut &key[..])
        .ok()
        .flatten()
        .context("tls: failed to find any PEM data in key input")?;
    let signer = provider::sign::any_supported_type(&der)
        .map_err(|e| anyhow::anyhow!("tls: failed to parse private key: {e}"))?;
    let certified = CertifiedKey::new(chain.clone(), Arc::new(ClientOrder(signer)));
    certified
        .keys_match()
        .map_err(|_| anyhow::anyhow!("tls: private key does not match public key"))?;
    let (_, leaf) =
        x509_parser::parse_x509_certificate(&chain[0]).map_err(|e| anyhow::anyhow!("x509: {e}"))?;
    let common_name = leaf
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or_default()
        .to_owned();
    let dns_names = leaf
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    x509_parser::extensions::GeneralName::DNSName(d) => Some((*d).to_owned()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Pair {
        key: Arc::new(certified),
        common_name,
        dns_names,
    })
}

/// X25519MLKEM768 (0x11ec) for the server side, which ring's provider lacks.
#[derive(Debug)]
struct X25519MlKem768;

const MLKEM768_EK: usize = 1184;

impl SupportedKxGroup for X25519MlKem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        Err(rustls::Error::General(
            "X25519MLKEM768 is server-only here".into(),
        ))
    }

    fn start_and_complete(&self, share: &[u8]) -> Result<CompletedKeyExchange, rustls::Error> {
        use ml_kem::ml_kem_768::EncapsulationKey;
        use ring::rand::SecureRandom;
        let bad = || rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare);
        if share.len() != MLKEM768_EK + 32 {
            return Err(bad());
        }
        let key = share[..MLKEM768_EK].try_into().map_err(|_| bad())?;
        let ek = EncapsulationKey::new(key).map_err(|_| bad())?;
        let rng = ring::rand::SystemRandom::new();
        let (mut m, mut eph) = ([0u8; 32], [0u8; 32]);
        rng.fill(&mut m)
            .and_then(|_| rng.fill(&mut eph))
            .map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        let (ciphertext, kem_shared) = ek.encapsulate_deterministic(&m.into());
        let eph = x25519_dalek::StaticSecret::from(eph);
        let peer: [u8; 32] = share[MLKEM768_EK..].try_into().map_err(|_| bad())?;
        let x_shared = eph.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        if !x_shared.was_contributory() {
            return Err(bad());
        }
        let public = x25519_dalek::PublicKey::from(&eph);
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: [ciphertext.as_slice(), public.as_bytes()].concat(),
            secret: SharedSecret::from(&[kem_shared.as_slice(), x_shared.as_bytes()].concat()[..]),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

static X25519_MLKEM768: X25519MlKem768 = X25519MlKem768;

/// crypto/tls cipher suite IDs, and those that are AES-GCM (isAESGCMPreferred).
const GO_SUITES: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0xc012, 0x000a, 0xc023, 0xc027, 0x003c, 0xc007, 0xc011,
    0x0005,
];
const AES_GCM: &[u16] = &[
    0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0x009c, 0x009d,
];

/// isAESGCMPreferred (assuming AES hardware, as on the servers rcore targets).
fn aes_preferred(suites: &[CipherSuite]) -> bool {
    suites
        .iter()
        .map(|s| u16::from(*s))
        .find(|id| GO_SUITES.contains(id))
        .is_some_and(|id| AES_GCM.contains(&id))
}

/// negotiateALPN: the server's first protocol the client offers; an http/1.1 client of an h2
/// server gets no ALPN instead of an error.
fn negotiate_alpn(server: &[Vec<u8>], client: Option<Vec<Vec<u8>>>) -> Result<Option<Vec<u8>>> {
    let Some(client) = client.filter(|c| !c.is_empty()) else {
        return Ok(None);
    };
    if server.is_empty() {
        return Ok(None);
    }
    let mut http11_fallback = false;
    for s in server {
        for c in &client {
            if s == c {
                return Ok(Some(s.clone()));
            }
            if s == b"h2" && c == b"http/1.1" {
                http11_fallback = true;
            }
        }
    }
    if http11_fallback {
        return Ok(None);
    }
    let names: Vec<String> = client
        .iter()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    bail!(
        "tls: client requested unsupported application protocols ([{}])",
        names.join(" ")
    )
}

/// Serves the certificate chosen before the handshake started.
#[derive(Debug)]
struct Chosen(Arc<CertifiedKey>);

impl ResolvesServerCert for Chosen {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Captures this connection's TLS 1.3 traffic secrets and feeds masterKeyLog.
#[derive(Debug, Default)]
struct Capture {
    secrets: Mutex<HashMap<String, Vec<u8>>>,
    file: Option<Arc<Mutex<std::fs::File>>>,
}

impl rustls::KeyLog for Capture {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if let Some(file) = &self.file {
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            let line = format!("{label} {} {}\n", hex(client_random), hex(secret));
            let _ = file.lock().unwrap().write_all(line.as_bytes());
        }
        if label.ends_with("_TRAFFIC_SECRET_0") {
            self.secrets
                .lock()
                .unwrap()
                .insert(label.to_owned(), secret.to_vec());
        }
    }
}

/// Reads one TLS record (header and body) as rustls frames it.
async fn read_record(tcp: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut record = vec![0u8; 5];
    tcp.read_exact(&mut record).await?;
    let len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if len > 16384 + 2048 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tls: oversized record received",
        ));
    }
    record.resize(5 + len, 0);
    tcp.read_exact(&mut record[5..]).await?;
    Ok(record)
}

/// Go's fingerprint names (tls.GetFingerprint), which the server config still validates.
const FINGERPRINTS: &[&str] = &[
    "",
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
    "randomizednoalpn",
    "unsafe",
    "hellofirefox_120",
    "hellofirefox_148",
    "hellochrome_120",
    "hellochrome_131",
    "hellochrome_133",
    "hellochrome_155",
    "helloios_13",
    "helloios_14",
    "helloedge_106",
    "hellosafari_26_3",
    "hello360_11_0",
    "helloqq_11_1",
    "hellogolang",
    "hellorandomized",
    "hellorandomizedalpn",
    "hellorandomizednoalpn",
    "hellofirefox_auto",
    "hellofirefox_55",
    "hellofirefox_56",
    "hellofirefox_63",
    "hellofirefox_65",
    "hellofirefox_99",
    "hellofirefox_102",
    "hellofirefox_105",
    "hellochrome_auto",
    "hellochrome_58",
    "hellochrome_62",
    "hellochrome_70",
    "hellochrome_72",
    "hellochrome_83",
    "hellochrome_87",
    "hellochrome_96",
    "hellochrome_100",
    "hellochrome_102",
    "hellochrome_106_shuffle",
    "helloios_auto",
    "helloios_11_1",
    "helloios_12_1",
    "helloandroid_11_okhttp",
    "helloedge_85",
    "helloedge_auto",
    "hellosafari_16_0",
    "hellosafari_auto",
    "hello360_auto",
    "hello360_7_5",
    "helloqq_auto",
    "hellochrome_100_psk",
    "hellochrome_112_psk_shuf",
    "hellochrome_114_padding_psk_shuf",
    "hellochrome_115_pq",
    "hellochrome_115_pq_psk",
    "hellochrome_120_pq",
];

impl Server {
    /// TLSConfig.Build plus the server half of Config.GetTLSConfig.
    pub fn parse(v: &Value, path: &str) -> Result<Self> {
        keys(
            v,
            &[
                "allowInsecure",
                "certificates",
                "serverName",
                "alpn",
                "enableSessionResumption",
                "disableSystemRoot",
                "minVersion",
                "maxVersion",
                "cipherSuites",
                "fingerprint",
                "rejectUnknownSni",
                "curvePreferences",
                "masterKeyLog",
                "pinnedPeerCertSha256",
                "verifyPeerCertByName",
                "echServerKeys",
                "echConfigList",
                "echSockopt",
                "useSystemCA",
            ],
            path,
        )?;
        let text = |k: &str| -> Result<&str> {
            match &v[k] {
                Value::Null => Ok(""),
                Value::String(s) => Ok(s),
                _ => bail!("{path}.{k} must be a string"),
            }
        };
        let flag = |k: &str| -> Result<bool> {
            match &v[k] {
                Value::Null => Ok(false),
                Value::Bool(b) => Ok(*b),
                _ => bail!("{path}.{k} must be a boolean"),
            }
        };
        if flag("allowInsecure")? {
            bail!(
                "The feature \"allowInsecure\" has been removed and migrated to \"pinnedPeerCertSha256\"(pcs) and \"verifyPeerCertByName\"(vcn). Please update your config(s) according to release note and documentation."
            );
        }
        let fingerprint = text("fingerprint")?.to_lowercase();
        ensure!(
            FINGERPRINTS.contains(&fingerprint.as_str()),
            "unknown \"fingerprint\": {fingerprint}"
        );
        for pin in text("pinnedPeerCertSha256")?.split(',') {
            let pin = pin.trim().replace(':', "");
            if pin.is_empty() {
                continue;
            }
            ensure!(
                pin.len() % 2 == 0 && pin.bytes().all(|b| b.is_ascii_hexdigit()),
                "encoding/hex: invalid byte in {pin}"
            );
            ensure!(
                pin.len() == 64,
                "incorrect pinnedPeerCertSha256 length: {pin}"
            );
        }
        ensure!(
            text("echServerKeys")?.is_empty(),
            "{}",
            unsupported(&format!("{path}.echServerKeys"))
        );
        let mut entries = Vec::new();
        for (i, c) in v["certificates"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let p = format!("{path}.certificates[{i}]");
            keys(
                c,
                &[
                    "certificateFile",
                    "certificate",
                    "keyFile",
                    "key",
                    "usage",
                    "ocspStapling",
                    "oneTimeLoading",
                    "buildChain",
                ],
                &p,
            )?;
            let s = |k: &str| c[k].as_str().unwrap_or_default().to_owned();
            let lines = |k: &str| string_list(&c[k], &format!("{p}.{k}"));
            let (cert_file, key_file) = (s("certificateFile"), s("keyFile"));
            let cert = file_or_string(&cert_file, &lines("certificate")?)
                .context("infra/conf: failed to parse certificate")?;
            let key_lines = lines("key")?;
            let key = if key_file.is_empty() && key_lines.is_empty() {
                Vec::new()
            } else {
                file_or_string(&key_file, &key_lines).context("infra/conf: failed to parse key")?
            };
            match s("usage").to_lowercase().as_str() {
                "issue" => return Err(unsupported(&format!("{p}.usage issue"))),
                // A verify certificate only checks peers; servers do not present it.
                "verify" => continue,
                _ => {}
            }
            ensure!(
                c["ocspStapling"].as_u64().unwrap_or(0) == 0,
                "{}",
                unsupported(&format!("{p}.ocspStapling"))
            );
            entries.push(Entry {
                one_time: (cert_file.is_empty() && key_file.is_empty())
                    || c["oneTimeLoading"].as_bool().unwrap_or(false),
                cert_path: cert_file,
                key_path: key_file,
                cert,
                key,
            });
        }
        let mut warnings = Vec::new();
        let mut pairs = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            match key_pair(&e.cert, &e.key) {
                Ok(pair) => pairs.push((i, pair)),
                Err(error) => warnings.push(format!(
                    "transport/internet/tls: ignoring invalid X509 key pair > {error:#}"
                )),
            }
        }
        let alpn: Vec<Vec<u8>> = match string_list(&v["alpn"], &format!("{path}.alpn"))? {
            list if list.is_empty() => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            list => {
                ensure!(
                    !list.iter().any(|p| p.eq_ignore_ascii_case("frommitm")),
                    "{}",
                    unsupported(&format!("{path}.alpn fromMitm"))
                );
                list.into_iter().map(String::into_bytes).collect()
            }
        };
        // Versions: crypto/tls defaults to 1.2-1.3; rustls has nothing older, so 1.0/1.1 minimums
        // behave like 1.2.
        let max = match text("maxVersion")? {
            "1.0" | "1.1" => return Err(unsupported(&format!("{path}.maxVersion below 1.2"))),
            "1.2" => 0x0303,
            _ => 0x0304,
        };
        let min = if text("minVersion")? == "1.3" {
            0x0304
        } else {
            0x0303
        };
        let versions: Vec<&'static rustls::SupportedProtocolVersion> = [
            (0x0304, &rustls::version::TLS13),
            (0x0303, &rustls::version::TLS12),
        ]
        .into_iter()
        .filter(|(v, _)| (min..=max).contains(v))
        .map(|(_, v)| v)
        .collect();
        ensure!(
            !versions.is_empty(),
            "tls: no supported versions satisfy MinVersion and MaxVersion"
        );
        // CipherSuites only narrows TLS 1.2 in Go (its order is ignored); CBC and RSA-kex
        // suites have no rustls counterpart.
        use provider::cipher_suite as cs;
        let tls12_names: [(&str, SupportedCipherSuite); 6] = [
            (
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ),
            (
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ),
            (
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            ),
            (
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ),
            (
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ),
            (
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ),
        ];
        let configured: Vec<String> = text("cipherSuites")?
            .split(':')
            .map(|n| n.trim().to_owned())
            .filter(|n| !n.is_empty())
            .collect();
        let known_go = |n: &str| n.starts_with("TLS_");
        let enabled: Vec<&str> = if configured.iter().any(|n| known_go(n)) {
            for n in &configured {
                if known_go(n)
                    && !tls12_names.iter().any(|(m, _)| m == n)
                    && !matches!(
                        n.as_str(),
                        "TLS_AES_128_GCM_SHA256"
                            | "TLS_AES_256_GCM_SHA384"
                            | "TLS_CHACHA20_POLY1305_SHA256"
                    )
                {
                    warnings.push(format!(
                        "transport/internet/tls: cipher suite {n} is not available in rcore"
                    ));
                }
            }
            tls12_names
                .iter()
                .map(|(n, _)| *n)
                .filter(|n| configured.iter().any(|c| c == n))
                .collect()
        } else {
            tls12_names.iter().map(|(n, _)| *n).collect()
        };
        let tls12 = |names: &[usize]| -> Vec<SupportedCipherSuite> {
            names
                .iter()
                .map(|i| tls12_names[*i])
                .filter(|(n, _)| enabled.contains(n))
                .map(|(_, s)| s)
                .collect()
        };
        let mut aes_suites = vec![
            cs::TLS13_AES_128_GCM_SHA256,
            cs::TLS13_AES_256_GCM_SHA384,
            cs::TLS13_CHACHA20_POLY1305_SHA256,
        ];
        aes_suites.extend(tls12(&[0, 1, 2, 3, 4, 5]));
        let mut chacha_suites = vec![
            cs::TLS13_CHACHA20_POLY1305_SHA256,
            cs::TLS13_AES_128_GCM_SHA256,
            cs::TLS13_AES_256_GCM_SHA384,
        ];
        chacha_suites.extend(tls12(&[4, 5, 0, 1, 2, 3]));
        // Go 1.26 curve order; SecP256r1MLKEM768, SecP384r1MLKEM1024 and P-521 are not in ring.
        let all_groups: [(&str, &'static dyn SupportedKxGroup); 4] = [
            ("x25519mlkem768", &X25519_MLKEM768),
            ("x25519", provider::kx_group::X25519),
            ("curvep256", provider::kx_group::SECP256R1),
            ("curvep384", provider::kx_group::SECP384R1),
        ];
        let curves = string_list(&v["curvePreferences"], &format!("{path}.curvePreferences"))?;
        let kx_groups: Vec<&'static dyn SupportedKxGroup> = if curves.is_empty() {
            all_groups.iter().map(|(_, g)| *g).collect()
        } else {
            let mut groups = Vec::new();
            for name in &curves {
                match all_groups
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(name))
                {
                    Some((_, g)) => groups.push(*g),
                    None if matches!(
                        name.to_lowercase().as_str(),
                        "curvep521" | "secp256r1mlkem768" | "secp384r1mlkem1024"
                    ) =>
                    {
                        return Err(unsupported(&format!("{path}.curvePreferences {name}")));
                    }
                    None => warnings.push(format!(
                        "transport/internet/tls: unsupported curve name: {name}"
                    )),
                }
            }
            groups
        };
        let resumption = flag("enableSessionResumption")?;
        let build = |suites: Vec<SupportedCipherSuite>| -> Result<Arc<ServerConfig>> {
            let provider = CryptoProvider {
                cipher_suites: suites,
                kx_groups: kx_groups.clone(),
                ..provider::default_provider()
            };
            let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&versions)
                .map_err(|e| anyhow::anyhow!("{path}: {e}"))?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(NoCert));
            config.ignore_client_order = true;
            config.enable_secret_extraction = true;
            config.max_early_data_size = 0;
            if resumption {
                config.ticketer = provider::Ticketer::new()
                    .map_err(|e| anyhow::anyhow!("session tickets: {e}"))?;
                config.send_tls13_tickets = 1;
            } else {
                config.send_tls13_tickets = 0;
            }
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            Ok(Arc::new(config))
        };
        let key_log = match text("masterKeyLog")? {
            "" | "none" => None,
            file => match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(file)
            {
                Ok(f) => Some(Arc::new(Mutex::new(f))),
                Err(error) => {
                    warnings.push(format!(
                        "transport/internet/tls: failed to open {file} as master key log > {error}"
                    ));
                    None
                }
            },
        };
        Ok(Self {
            entries: Mutex::new(entries),
            pairs: RwLock::new(pairs),
            reject_unknown_sni: flag("rejectUnknownSni")?,
            tls13: max == 0x0304,
            alpn,
            aes: build(aes_suites)?,
            chacha: build(chacha_suites)?,
            key_log,
            warnings,
        })
    }

    pub fn alpn(&self) -> &[Vec<u8>] {
        &self.alpn
    }

    /// Logs build warnings and starts the hourly certificate reload (setupOcspTicker).
    pub fn start(self: &Arc<Self>) {
        for warning in &self.warnings {
            tracing::warn!("{warning}");
        }
        let reloadable = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .any(|e| !e.one_time && !e.cert_path.is_empty() && !e.key_path.is_empty());
        if !reloadable {
            return;
        }
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                let Some(me) = me.upgrade() else {
                    return;
                };
                if !me.reload() {
                    return;
                }
            }
        });
    }

    /// One reload pass; false stops the ticker, as a read failure does in Go.
    fn reload(&self) -> bool {
        let mut entries = self.entries.lock().unwrap();
        for (i, e) in entries.iter_mut().enumerate() {
            if e.one_time || e.cert_path.is_empty() || e.key_path.is_empty() {
                continue;
            }
            let cert = match std::fs::read(cert_path(&e.cert_path)) {
                Ok(c) => c,
                Err(error) => {
                    tracing::error!(
                        "transport/internet/tls: failed to parse certificate > {error}"
                    );
                    return false;
                }
            };
            let key = match std::fs::read(cert_path(&e.key_path)) {
                Ok(k) => k,
                Err(error) => {
                    tracing::error!("transport/internet/tls: failed to parse key > {error}");
                    return false;
                }
            };
            if cert == e.cert && key == e.key {
                continue;
            }
            e.cert = cert;
            e.key = key;
            match key_pair(&e.cert, &e.key) {
                Ok(pair) => {
                    let mut pairs = self.pairs.write().unwrap();
                    match pairs.iter_mut().find(|(j, _)| *j == i) {
                        Some(slot) => slot.1 = pair,
                        None => {
                            pairs.push((i, pair));
                            pairs.sort_by_key(|(j, _)| *j);
                        }
                    }
                }
                Err(error) => tracing::warn!(
                    "transport/internet/tls: ignoring invalid X509 key pair > {error:#}"
                ),
            }
        }
        true
    }

    /// getNewGetCertificateFunc.
    fn certificate(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        let pairs = self.pairs.read().unwrap();
        let first = pairs.first()?;
        let sni = sni.to_lowercase();
        if !self.reject_unknown_sni && (pairs.len() == 1 || sni.is_empty()) {
            return Some(first.1.key.clone());
        }
        let wildcard = match sni.find('.') {
            Some(i) => format!("*{}", &sni[i..]),
            None => "*".to_owned(),
        };
        for (_, p) in pairs.iter() {
            if p.common_name == sni
                || p.common_name == wildcard
                || p.dns_names.iter().any(|n| *n == sni || *n == wildcard)
            {
                return Some(p.key.clone());
            }
        }
        (!self.reject_unknown_sni).then(|| first.1.key.clone())
    }

    /// tls.Server and its handshake; `http_hub` adds net/http's reply to plain HTTP.
    pub async fn accept(&self, mut tcp: TcpStream, http_hub: bool) -> Result<Accepted> {
        let mut acceptor = rustls::server::Acceptor::default();
        let mut hello_message = Vec::new();
        let accepted = loop {
            let first = hello_message.is_empty();
            let record = match read_record(&mut tcp).await {
                Err(e) if first && e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(crate::vless::EmptyRequest.into());
                }
                record => record?,
            };
            if first && record[0] != 22 {
                // net/http answers an HTTP request on its TLS listener before closing.
                if http_hub
                    && matches!(
                        &record[..5],
                        b"GET /" | b"HEAD " | b"POST " | b"PUT /" | b"OPTIO"
                    )
                {
                    let _ = tcp
                        .write_all(b"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n")
                        .await;
                }
                bail!("tls: first record does not look like a TLS handshake");
            }
            hello_message.extend_from_slice(&record[5..]);
            acceptor.read_tls(&mut &record[..])?;
            match acceptor.accept() {
                Ok(Some(accepted)) => break accepted,
                Ok(None) => continue,
                Err((error, mut alert)) => {
                    let mut out = Vec::new();
                    let _ = alert.write_all(&mut out);
                    let _ = tcp.write_all(&out).await;
                    return Err(error.into());
                }
            }
        };
        let hello = accepted.client_hello();
        let client_alpn = hello
            .alpn()
            .map(|a| a.map(<[u8]>::to_vec).collect::<Vec<_>>());
        let alpn = match negotiate_alpn(&self.alpn, client_alpn) {
            Ok(alpn) => alpn,
            Err(error) => {
                // alertNoApplicationProtocol
                let _ = tcp.write_all(&[21, 3, 3, 0, 2, 2, 120]).await;
                return Err(error);
            }
        };
        let Some(key) = self.certificate(hello.server_name().unwrap_or_default()) else {
            // errNoCertificates answers unrecognized_name.
            let _ = tcp.write_all(&[21, 3, 3, 0, 2, 2, 112]).await;
            bail!("tls: no certificates configured");
        };
        let base = if aes_preferred(hello.cipher_suites()) {
            &self.aes
        } else {
            &self.chacha
        };
        let capture = Arc::new(Capture {
            secrets: Mutex::default(),
            file: self.key_log.clone(),
        });
        let mut config = (**base).clone();
        config.alpn_protocols = alpn.into_iter().collect();
        config.cert_resolver = Arc::new(Chosen(key));
        config.key_log = capture.clone();
        let config = Arc::new(config);
        // rustls takes TLS 1.3 whenever both sides allow it.
        let tls13 = self.tls13
            && crate::reality::ClientHello::parse(&hello_message).is_some_and(|h| h.tls13);
        if !tls13 {
            let tls = tokio_rustls::StartHandshake::from_parts(accepted, tcp)
                .into_stream(config)
                .await?;
            return Ok(Accepted {
                io: Box::new(tls),
                direct: None,
                version: 0x0303,
            });
        }
        // TLS 1.3: drive the handshake one record at a time, so nothing after the client's
        // Finished is read into rustls, then continue on rcore's record layer.
        let mut conn = match accepted.into_connection(config) {
            Ok(conn) => conn,
            Err((error, mut alert)) => {
                let mut out = Vec::new();
                let _ = alert.write_all(&mut out);
                let _ = tcp.write_all(&out).await;
                return Err(error.into());
            }
        };
        let mut sent = 0u64;
        loop {
            while conn.wants_write() {
                let mut out = Vec::new();
                conn.write_tls(&mut out)?;
                tcp.write_all(&out).await?;
                sent += out.len() as u64;
            }
            if !conn.is_handshaking() {
                break;
            }
            let record = read_record(&mut tcp).await?;
            conn.read_tls(&mut &record[..])?;
            if let Err(error) = conn.process_new_packets() {
                let mut out = Vec::new();
                let _ = conn.write_tls(&mut out);
                let _ = tcp.write_all(&out).await;
                return Err(error.into());
            }
        }
        let suite = conn
            .negotiated_cipher_suite()
            .and_then(|s| Suite::by_id(u16::from(s.suite())))
            .context("tls: no TLS 1.3 cipher suite")?;
        let secrets = conn
            .dangerous_extract_secrets()
            .map_err(|e| anyhow::anyhow!("tls: {e}"))?;
        let captured = capture.secrets.lock().unwrap().clone();
        let secret = |label: &str| {
            captured
                .get(label)
                .cloned()
                .with_context(|| format!("tls: missing {label}"))
        };
        let mut read = Cipher::new(suite, secret("CLIENT_TRAFFIC_SECRET_0")?);
        read.seq = secrets.rx.0;
        let mut write = Cipher::new(suite, secret("SERVER_TRAFFIC_SECRET_0")?);
        write.seq = secrets.tx.0;
        let (reader, writer) = tcp.into_split();
        let (mut stream, direct) = tls13::stream(reader, writer, read, write, sent);
        // crypto/tls maxUselessRecords.
        stream.set_max_ignored(16);
        Ok(Accepted {
            io: Box::new(stream),
            direct: Some(direct),
            version: 0x0304,
        })
    }
}

/// The resolver the shared configs carry; every connection installs its chosen certificate.
#[derive(Debug)]
struct NoCert;

impl ResolvesServerCert for NoCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_follows_go_negotiation() {
        let server = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let ask = |c: &[&str]| {
            negotiate_alpn(
                &server,
                Some(c.iter().map(|s| s.as_bytes().to_vec()).collect()),
            )
        };
        assert_eq!(ask(&["http/1.1", "h2"]).unwrap(), Some(b"h2".to_vec()));
        assert_eq!(ask(&["http/1.1"]).unwrap(), Some(b"http/1.1".to_vec()));
        assert!(ask(&["h3"]).is_err());
        let h2_only = vec![b"h2".to_vec()];
        assert_eq!(
            negotiate_alpn(&h2_only, Some(vec![b"http/1.1".to_vec()])).unwrap(),
            None
        );
        assert_eq!(negotiate_alpn(&server, None).unwrap(), None);
    }

    #[test]
    fn aes_preference_reads_the_first_known_suite() {
        let ids = |v: &[u16]| v.iter().map(|i| CipherSuite::from(*i)).collect::<Vec<_>>();
        assert!(aes_preferred(&ids(&[0x0a0a, 0x1301, 0x1303])));
        assert!(!aes_preferred(&ids(&[0x1a1a, 0x1303, 0x1301])));
        assert!(!aes_preferred(&ids(&[0x00ff])));
    }

    /// A self-signed certificate for `name` in `dir` as (cert path, key path).
    fn self_signed(dir: &Path, name: &str) -> (String, String) {
        let (cert, key) = (
            dir.join(format!("{name}.pem")),
            dir.join(format!("{name}.key")),
        );
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-days",
                "2",
                "-subj",
                &format!("/CN={name}"),
            ])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .output()
            .expect("openssl");
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        (cert.display().to_string(), key.display().to_string())
    }

    #[test]
    fn reload_picks_up_renewed_certificate_files() {
        let dir = std::env::temp_dir().join(format!("rcore-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a_cert, a_key) = self_signed(&dir, "a.test");
        let (b_cert, b_key) = self_signed(&dir, "b.test");
        let (live_cert, live_key) = (dir.join("live.pem"), dir.join("live.key"));
        std::fs::copy(&a_cert, &live_cert).unwrap();
        std::fs::copy(&a_key, &live_key).unwrap();
        let server = Server::parse(
            &serde_json::json!({"certificates": [
                {"certificateFile": live_cert, "keyFile": live_key},
                {"certificateFile": b_cert, "keyFile": b_key, "oneTimeLoading": true}
            ]}),
            "tls",
        )
        .unwrap();
        let leaf = |sni: &str| server.certificate(sni).unwrap().cert[0].to_vec();
        let der = |path: &str| {
            rustls_pemfile::certs(&mut &std::fs::read(path).unwrap()[..])
                .next()
                .unwrap()
                .unwrap()
                .to_vec()
        };
        assert_eq!(leaf("a.test"), der(&a_cert));
        assert_eq!(leaf("b.test"), der(&b_cert));
        // A renewal rewrites both files; the next tick serves the new pair.
        std::fs::copy(&b_cert, &live_cert).unwrap();
        std::fs::copy(&b_key, &live_key).unwrap();
        assert!(server.reload());
        assert_eq!(leaf("a.test"), der(&b_cert));
        // A missing file stops the reload ticker, keeping the last good pair.
        std::fs::remove_file(&live_key).unwrap();
        assert!(!server.reload());
        assert_eq!(leaf(""), der(&b_cert));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_removed_and_unported_options() {
        for bad in [
            serde_json::json!({"allowInsecure": true}),
            serde_json::json!({"fingerprint": "nope"}),
            serde_json::json!({"pinnedPeerCertSha256": "abcd"}),
            serde_json::json!({"echServerKeys": "AAAA"}),
            serde_json::json!({"maxVersion": "1.1"}),
            serde_json::json!({"curvePreferences": ["CurveP521"]}),
            serde_json::json!({"certificates": [{"usage": "issue", "certificate": ["x"]}]}),
            serde_json::json!({"certificates": [{}]}),
        ] {
            assert!(Server::parse(&bad, "tls").is_err(), "{bad}");
        }
        assert!(Server::parse(&serde_json::json!({"fingerprint": "Chrome"}), "tls").is_ok());
    }
}
