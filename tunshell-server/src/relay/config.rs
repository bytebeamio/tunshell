use anyhow::{Error, Result};
use rustls::server::NoClientAuth;
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::fs;
use std::io;
use std::{env, sync::Arc, time::Duration};

const DEFAULT_CLIENT_KEY_TIMEOUT_MS: u64 = 3000;
const DEFAULT_CLEAN_EXPIRED_CONNECTION_INTERVAL_MS: u64 = 60_000;
const DEFAULT_WAITING_CONNECTION_EXPIRY_MS: u64 = 3_600_000;
const DEFAULT_CONNECTED_CONNECTION_EXPIRY_MS: u64 = 3_600_000;

#[derive(Clone)]
pub struct Config {
    pub tls_port: u16,
    pub api_port: u16,
    pub tls_config: Arc<ServerConfig>,
    pub tls_key_path: String,
    pub tls_cert_path: String,
    pub client_key_timeout: Duration,
    pub expired_connection_clean_interval: Duration,
    pub waiting_connection_expiry: Duration,
    pub paired_connection_expiry: Duration,
}

impl Config {
    pub fn from_env() -> Result<Config> {
        let tls_port = env::var("TUNSHELL_RELAY_TLS_PORT")?.parse::<u16>()?;
        let api_port = env::var("TUNSHELL_API_PORT")?.parse::<u16>()?;

        let tls_cert_path = env::var("TLS_RELAY_CERT")?;
        let tls_key_path = env::var("TLS_RELAY_PRIVATE_KEY")?;

        let cert_verifier = Arc::new(NoClientAuth);
        let tls_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(cert_verifier)
            .with_single_cert(
                Self::parse_tls_cert(tls_cert_path.clone())?,
                Self::parse_tls_private_key(tls_key_path.clone())?,
            )?;
        let tls_config = Arc::new(tls_config);

        Ok(Config {
            tls_port,
            api_port,
            tls_config,
            tls_cert_path,
            tls_key_path,
            client_key_timeout: Duration::from_millis(DEFAULT_CLIENT_KEY_TIMEOUT_MS),
            expired_connection_clean_interval: Duration::from_millis(
                DEFAULT_CLEAN_EXPIRED_CONNECTION_INTERVAL_MS,
            ),
            waiting_connection_expiry: Duration::from_millis(DEFAULT_WAITING_CONNECTION_EXPIRY_MS),
            paired_connection_expiry: Duration::from_millis(DEFAULT_CONNECTED_CONNECTION_EXPIRY_MS),
        })
    }

    pub(super) fn parse_tls_cert(path: String) -> Result<Vec<Certificate>> {
        let file = fs::File::open(path)?;
        let mut reader = io::BufReader::new(file);

        let certs = rustls_pemfile::certs(&mut reader)?;

        Ok(certs.into_iter().map(Certificate).collect())
    }

    pub(super) fn parse_tls_private_key(path: String) -> Result<PrivateKey> {
        let file = fs::File::open(path)?;
        let mut reader = io::BufReader::new(file);

        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;

        match keys.len() {
            0 => Err(Error::msg("No PKCS8-encoded private key found in {path}")),
            1 => Ok(PrivateKey(keys.remove(0))),
            _ => Err(Error::msg(
                "More than one PKCS8-encoded private key found in {path}",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env() {
        env::remove_var("TUNSHELL_RELAY_TLS_PORT");
        env::remove_var("TUNSHELL_API_PORT");
        env::remove_var("TLS_RELAY_CERT");
        env::remove_var("TLS_RELAY_PRIVATE_KEY");

        assert!(Config::from_env().is_err());

        env::set_var("TUNSHELL_RELAY_TLS_PORT", "1234");
        env::set_var("TUNSHELL_API_PORT", "1235");
        env::set_var("TLS_RELAY_CERT", "certs/development.cert");
        env::set_var("TLS_RELAY_PRIVATE_KEY", "certs/development.key");

        let config = Config::from_env().unwrap();

        std::io::stdin().lock();

        assert_eq!(config.tls_port, 1234);
        assert_eq!(config.api_port, 1235);
    }
}
