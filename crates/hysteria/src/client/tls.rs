//! TLS client config: TLS 1.3, ALPN `h3`, server-cert verification against the
//! OS trust store.
//!
//! A Hysteria link carries only the SNI; the server's certificate is verified
//! against the platform trust store, so the server must present a
//! publicly-trusted (e.g. ACME) certificate. A specific CA can be supplied out
//! of band — not via a link — to trust a private CA; the conformance tests use
//! this to reach the self-signed reference server.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls_pki_types::CertificateDer;
use rustls_platform_verifier::BuilderVerifierExt as _;

use crate::client::config::TlsConfig;
use crate::errors::ConfigError;

/// The ALPN protocol Hysteria 2 negotiates (it speaks HTTP/3 for auth).
const ALPN_H3: &[u8] = b"h3";

/// Build the rustls `ClientConfig` (TLS 1.3, ALPN `h3`). The server certificate
/// is verified against `tls.ca` when one is supplied, otherwise against the OS
/// trust store (the platform verifier). The handshake-signature checks are the
/// crypto provider's, so either path still proves the server holds the cert's
/// private key.
pub fn build_rustls_client_config(tls: &TlsConfig) -> Result<ClientConfig, ConfigError> {
    let cfg_err = |reason: String| ConfigError {
        field: "TLSConfig".into(),
        reason,
    };

    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| cfg_err(e.to_string()))?;

    let mut config = match &tls.ca {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from(ca.clone()))
                .map_err(|e| cfg_err(e.to_string()))?;
            builder.with_root_certificates(roots).with_no_client_auth()
        },
        None => builder
            .with_platform_verifier()
            .map_err(|e| cfg_err(e.to_string()))?
            .with_no_client_auth(),
    };
    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn platform_verifier_config_negotiates_h3() -> anyhow::Result<()> {
        let config = build_rustls_client_config(&TlsConfig {
            server_name: "example.com".into(),
            ca: None,
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()], "ALPN is h3");
        Ok(())
    }

    #[test]
    fn invalid_ca_is_rejected() {
        let result = build_rustls_client_config(&TlsConfig {
            server_name: "example.com".into(),
            ca: Some(b"not a certificate".to_vec()),
        });
        assert!(result.is_err(), "a non-certificate CA must be rejected");
    }
}
