//! TLS 1.3 with self-signed certificates and certificate pinning.
//!
//! Trust = SHA-256 of the peer's end-entity certificate (DER) being in the
//! configured allowlist. No CA, no names, no validity period are consulted;
//! the handshake signature is still verified, so a pin alone cannot be
//! replayed without the private key. Both directions authenticate (mTLS).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::Error;

pub const ALPN: &[u8] = b"pantsume-repl/1";

pub type Pin = [u8; 32];

pub fn pin_of(cert: &CertificateDer<'_>) -> Pin {
    Sha256::digest(cert.as_ref()).into()
}

pub fn pin_hex(pin: &Pin) -> String {
    pin.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_pin(s: &str) -> Result<Pin, Error> {
    let hex = s.strip_prefix("sha256:").unwrap_or(s);
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(Error::Config(format!("pin `{s}`: expected 64 hex chars (sha256)")));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::Config(format!("pin `{s}`: not hex")))?;
    }
    Ok(out)
}

/// Cluster allowlist: node name ↔ certificate pin. Several pins per name are
/// allowed (rotation: old and new certificate side by side).
#[derive(Debug, Clone, Default)]
pub struct Peers {
    by_pin: HashMap<Pin, String>,
}

impl Peers {
    /// `node-a=sha256:<hex>,node-b=sha256:<hex>`
    pub fn parse(spec: &str) -> Result<Self, Error> {
        let mut by_pin = HashMap::new();
        for item in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (name, pin) = item
                .split_once('=')
                .ok_or_else(|| Error::Config(format!("peer `{item}`: expected name=sha256:<hex>")))?;
            by_pin.insert(parse_pin(pin.trim())?, name.trim().to_owned());
        }
        if by_pin.is_empty() {
            return Err(Error::Config("REPL_PEERS is empty: replication needs pinned peers".into()));
        }
        Ok(Self { by_pin })
    }

    pub fn names(&self) -> HashSet<&str> {
        self.by_pin.values().map(String::as_str).collect()
    }

    pub fn contains_name(&self, name: &str) -> bool {
        self.by_pin.values().any(|n| n == name)
    }

    pub fn contains_pin(&self, pin: &Pin) -> bool {
        self.by_pin.contains_key(pin)
    }

    fn pins(&self) -> HashSet<Pin> {
        self.by_pin.keys().copied().collect()
    }
}

pub struct Identity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl Identity {
    pub fn load(cert_path: &str, key_path: &str) -> Result<Self, Error> {
        let chain = CertificateDer::pem_file_iter(cert_path)
            .map_err(|e| Error::Config(format!("{cert_path}: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Config(format!("{cert_path}: {e}")))?;
        if chain.is_empty() {
            return Err(Error::Config(format!("{cert_path}: no certificate")));
        }
        let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| Error::Config(format!("{key_path}: {e}")))?;
        Ok(Self { chain, key })
    }

    pub fn pin(&self) -> Pin {
        pin_of(&self.chain[0])
    }
}

/// Freshly generated self-signed identity (Ed25519).
pub struct Generated {
    pub cert_pem: String,
    pub key_pem: String,
    pub pin: Pin,
}

pub fn generate(node_id: &str) -> Result<Generated, Error> {
    let tls = |e: rcgen::Error| Error::Tls(e.to_string());
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(tls)?;
    let mut params = rcgen::CertificateParams::new(vec![node_id.to_owned()]).map_err(tls)?;
    params.distinguished_name.push(rcgen::DnType::CommonName, node_id);
    let cert = params.self_signed(&key).map_err(tls)?;
    Ok(Generated { cert_pem: cert.pem(), key_pem: key.serialize_pem(), pin: pin_of(cert.der()) })
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[derive(Debug)]
struct PinVerifier {
    pins: HashSet<Pin>,
    algs: WebPkiSupportedAlgorithms,
}

impl PinVerifier {
    fn check(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        if self.pins.contains(&pin_of(end_entity)) {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))
        }
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity).map(|()| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is disabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

impl ClientCertVerifier for PinVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity).map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is disabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// TLS 1.3-only server and client configs that trust exactly `peers`.
pub fn configs(identity: &Identity, peers: &Peers) -> Result<(Arc<ServerConfig>, Arc<ClientConfig>), Error> {
    let provider = provider();
    let verifier = Arc::new(PinVerifier { pins: peers.pins(), algs: provider.signature_verification_algorithms });

    let mut server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(identity.chain.clone(), identity.key.clone_key())?;
    server.alpn_protocols = vec![ALPN.to_vec()];
    server.send_tls13_tickets = 0;

    let mut client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(identity.chain.clone(), identity.key.clone_key())?;
    client.alpn_protocols = vec![ALPN.to_vec()];
    client.resumption = rustls::client::Resumption::disabled();

    Ok((Arc::new(server), Arc::new(client)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_parse_and_reject_garbage() {
        let g = generate("n1").unwrap();
        let spec = format!("n1=sha256:{}", pin_hex(&g.pin));
        let p = Peers::parse(&spec).unwrap();
        assert!(p.contains_name("n1") && !p.contains_name("n2"));
        assert!(Peers::parse("n1=zz").is_err());
        assert!(Peers::parse("").is_err());
        assert!(Peers::parse("n1").is_err());
    }

    #[test]
    fn generated_identity_builds_tls13_configs() {
        let dir = std::env::temp_dir().join(format!("repl_tls_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let g = generate("n1").unwrap();
        let (c, k) = (dir.join("c.pem"), dir.join("k.pem"));
        std::fs::write(&c, &g.cert_pem).unwrap();
        std::fs::write(&k, &g.key_pem).unwrap();
        let id = Identity::load(c.to_str().unwrap(), k.to_str().unwrap()).unwrap();
        assert_eq!(id.pin(), g.pin);
        let peers = Peers::parse(&format!("n1=sha256:{}", pin_hex(&g.pin))).unwrap();
        configs(&id, &peers).unwrap();
    }
}
