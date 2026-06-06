//! TLS client config with certificate pinning.
//!
//! Hysteria links carry `sni`, `insecure`, and `pinSHA256`. The pinning rules:
//!
//! - a `pinSHA256` is present ⇒ accept iff the server's end-entity certificate
//!   hashes to it (stronger than CA trust, and the only secure path for
//!   self-signed servers — honored even when `insecure=1`);
//! - `insecure=1` without a pin ⇒ rejected;
//! - no pin, not insecure ⇒ ordinary CA verification (against a supplied CA;
//!   system roots arrive with the platform verifier later).
//!
//! The handshake-signature checks are always delegated to the crypto provider,
//! so a pinned connection still proves the server holds the cert's private key.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::DigitallySignedStruct;
use rustls::Error as RustlsError;
use rustls::RootCertStore;
use rustls::SignatureScheme;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::verify_tls12_signature;
use rustls::crypto::verify_tls13_signature;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::ServerName;
use rustls_pki_types::UnixTime;
use sha2::Digest as _;
use sha2::Sha256;

use crate::client::config::TlsConfig;
use crate::errors::ConfigError;

/// The ALPN protocol Hysteria 2 negotiates (it speaks HTTP/3 for auth).
const ALPN_H3: &[u8] = b"h3";

/// A `ServerCertVerifier` that accepts a connection iff the end-entity
/// certificate's SHA-256 matches a pinned value. Certificate chain, name, and
/// expiry are intentionally not checked: the pin *is* the server's identity.
#[derive(Debug)]
struct PinnedServerCertVerifier {
    pin: [u8; 32],
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let digest = Sha256::digest(end_entity.as_ref());
        if digest.as_slice() == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General(
                "pinned certificate hash mismatch".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Build the rustls `ClientConfig` (TLS 1.3, ALPN `h3`) for the given TLS
/// settings, applying the pinning rules described in the module docs.
pub fn build_rustls_client_config(tls: &TlsConfig) -> Result<ClientConfig, ConfigError> {
    let provider = Arc::new(default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ConfigError {
            field: "TLSConfig".into(),
            reason: e.to_string(),
        })?;

    let mut config = match (&tls.pin_sha256, tls.insecure) {
        (Some(pin), _) => {
            // Pinned: accept any chain whose end-entity hashes to the pin.
            let verifier = Arc::new(PinnedServerCertVerifier {
                pin: *pin,
                supported_algs: provider.signature_verification_algorithms,
            });
            builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        },
        (None, true) => {
            return Err(ConfigError {
                field: "TLSConfig".into(),
                reason: "insecure requires a pinSHA256".into(),
            });
        },
        (None, false) => {
            // CA-trust path: requires a supplied CA (no system roots yet).
            let ca = tls.ca.as_ref().ok_or_else(|| ConfigError {
                field: "TLSConfig".into(),
                reason: "no pinSHA256 and no CA certificate".into(),
            })?;
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from(ca.clone()))
                .map_err(|e| ConfigError {
                    field: "TLSConfig".into(),
                    reason: e.to_string(),
                })?;
            builder.with_root_certificates(roots).with_no_client_auth()
        },
    };
    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn verifier_for(cert: &[u8]) -> PinnedServerCertVerifier {
        PinnedServerCertVerifier {
            pin: Sha256::digest(cert).into(),
            supported_algs: default_provider().signature_verification_algorithms,
        }
    }

    #[test]
    fn matching_pin_is_accepted() -> anyhow::Result<()> {
        let cert = b"a stand-in for a DER certificate";
        let verifier = verifier_for(cert);
        let name = ServerName::try_from("localhost")?;
        verifier
            .verify_server_cert(
                &CertificateDer::from(cert.to_vec()),
                &[],
                &name,
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(1)),
            )
            .map_err(|e| anyhow::anyhow!("matching pin should verify: {e}"))?;
        Ok(())
    }

    #[test]
    fn mismatched_pin_is_rejected() -> anyhow::Result<()> {
        let verifier = verifier_for(b"the certificate we pinned");
        let name = ServerName::try_from("localhost")?;
        let result = verifier.verify_server_cert(
            &CertificateDer::from(b"a different certificate".to_vec()),
            &[],
            &name,
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(1)),
        );
        assert!(
            result.is_err(),
            "a non-matching certificate must be rejected"
        );
        Ok(())
    }

    #[test]
    fn insecure_without_pin_is_rejected() {
        let tls = TlsConfig {
            insecure: true,
            ..TlsConfig::default()
        };
        let result = build_rustls_client_config(&tls);
        assert!(result.is_err(), "insecure=1 without a pin must be rejected");
    }

    #[test]
    fn pinned_config_negotiates_h3() -> anyhow::Result<()> {
        let tls = TlsConfig {
            pin_sha256: Some([7u8; 32]),
            insecure: true,
            ..TlsConfig::default()
        };
        let config = build_rustls_client_config(&tls).map_err(|e| anyhow::anyhow!("{e}"))?;
        assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()], "ALPN is h3");
        Ok(())
    }
}
