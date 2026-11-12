use anyhow::Result;
use hkdf::Hkdf;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use sha2::Sha256;

pub struct Auth {
    key: DecodingKey,
    validation: Validation,
}

impl Auth {
    pub fn new(public_key: &str) -> Result<Self> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.required_spec_claims.clear();
        validation.validate_nbf = true;
        validation.validate_aud = false;
        validation.leeway = 0;
        Ok(Self {
            key: DecodingKey::from_rsa_pem(public_key.as_bytes())?,
            validation,
        })
    }

    pub fn verify(&self, authorization: &str) -> bool {
        let Some((scheme, token)) = authorization.split_once(' ') else {
            return false;
        };
        scheme.eq_ignore_ascii_case("bearer")
            && decode::<serde_json::Value>(token, &self.key, &self.validation).is_ok()
    }
}

pub fn derive_sni(ca: &str, jwt: &str) -> String {
    fn canon(pem: &str) -> String {
        crate::config::normalize_pem(pem)
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .flat_map(str::chars)
            .filter(|c| c.is_ascii_alphanumeric() || "+/=".contains(*c))
            .collect()
    }
    let ikm = format!("{}{}", canon(jwt), canon(ca));
    let mut output = [0; 22];
    Hkdf::<Sha256>::new(None, ikm.as_bytes())
        .expand(b"rw-v1", &mut output)
        .expect("valid HKDF length");
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "{}.{}.{}",
        hex(&output[..16]),
        hex(&output[16..21]),
        ["com", "net", "org", "io", "dev", "app"][output[21] as usize % 6]
    )
}
