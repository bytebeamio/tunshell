#![allow(unexpected_cfgs)]
use crate::Config;
use anyhow::{bail, Context as AnyhowContext, Result};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::{
    convert::TryInto,
    io,
    net::ToSocketAddrs,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::net::TcpStream;
use tokio_rustls::{
    client::TlsStream,
    rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore},
    TlsConnector,
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

pub struct TlsServerStream {
    pub(crate) inner: Compat<TlsStream<TcpStream>>,
}

impl TlsServerStream {
    pub async fn connect(config: &Config, port: u16) -> Result<Self> {
        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .map(|ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject.as_ref(),
                        ta.subject_public_key_info.as_ref(),
                        ta.name_constraints.as_deref(),
                    )
                })
                .collect(),
        };
        let tls_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        // tls_config
        //     .root_store
        //     .add_server_trust_anchors();

        // if config.dangerous_disable_relay_server_verification() {
        //     use tokio_rustls::rustls;

        //     struct NullCertVerifier {}

        //     impl rustls::client::ServerCertVerifier for NullCertVerifier {
        //         fn verify_server_cert(
        //             &self,
        //             _end_entity: &Certificate,
        //             _intermediates: &[Certificate],
        //             _server_name: &ServerName,
        //             _scts: &mut dyn Iterator<Item = &[u8]>,
        //             _ocsp_response: &[u8],
        //             _now: SystemTime,
        //         ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        //             Ok(rustls::client::ServerCertVerified::assertion())
        //         }
        //     }

        //     log::warn!("disabling TLS verification");
        //     tls_config
        //         .dangerous()
        //         .set_certificate_verifier(Arc::new(NullCertVerifier {}));
        // }

        // For targeting CPUs without native SSE2 support (iSH emulated CPU)
        // =================================================================
        // The underlying crypto lib (ring) emits custom assembly for the
        // Poly1305 authentication algorithm (https://github.com/briansmith/ring/blob/main/crypto/poly1305/asm/poly1305-x86.pl).
        // Fortunately the AES-GCM ciphers has fallbacks in rust and can be compiled
        // for every target (https://github.com/briansmith/ring/issues/104).
        // So when targeting CPUs without SSE2 support we only support AES-GCM TLS ciphers.
        #[cfg(tls_only_aes_gcm)]
        {
            use tokio_rustls::rustls::BulkAlgorithm;

            tls_config.ciphersuites = tls_config
                .ciphersuites
                .iter()
                .filter(|s| {
                    s.bulk == BulkAlgorithm::AES_128_GCM || s.bulk == BulkAlgorithm::AES_256_GCM
                })
                .map(|s| *s)
                .collect();
        }

        let connector = TlsConnector::from(Arc::new(tls_config));

        let relay_dns_name = config.relay_host().try_into()?;

        let network_stream = if let Ok(http_proxy) = std::env::var("HTTP_PROXY") {
            log::info!("Connecting to relay server via http proxy {}", http_proxy);

            connect_via_http_proxy(config, port, http_proxy).await?
        } else {
            log::info!("Connecting to relay server over TCP");
            let relay_addr = (config.relay_host(), port)
                .to_socket_addrs()?
                .next()
                .unwrap();

            TcpStream::connect(relay_addr).await?
        };

        // if let Err(err) = network_stream.set_keepalive(true) {
        //     log::warn!("failed to set tcp keepalive: {}", err);
        // }

        let transport_stream = connector.connect(relay_dns_name, network_stream).await?;

        Ok(Self {
            inner: transport_stream.compat(),
        })
    }
}

async fn connect_via_http_proxy(
    config: &Config,
    port: u16,
    http_proxy: String,
) -> Result<TcpStream> {
    let proxy_addr = http_proxy.to_socket_addrs()?.next().unwrap();
    let mut proxy_stream = TcpStream::connect(proxy_addr).await?.compat();

    proxy_stream
        .write_all(format!("CONNECT {}:{} HTTP/1.1\n\n", config.relay_host(), port).as_bytes())
        .await?;
    let mut read_buff = [0u8; 1024];

    let read = match proxy_stream.read(&mut read_buff).await? {
        0 => bail!("Failed to read response from http proxy"),
        read => read,
    };

    let response =
        String::from_utf8(read_buff[..read].to_vec()).context("failed to parse proxy response")?;
    if !response.contains("HTTP/1.1 200") && !response.contains("HTTP/1.0 200") {
        bail!(format!(
            "invalid response returned from http proxy: {}",
            response
        ));
    }

    Ok(proxy_stream.into_inner())
}

impl AsyncRead for TlsServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

impl super::AsyncIO for TlsServerStream {}
