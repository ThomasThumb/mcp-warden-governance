use axum::{body::Body, Router};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

pub async fn serve_app(
    bind_addr: &str,
    app: Router,
    tls_paths: Option<(PathBuf, PathBuf)>,
) -> anyhow::Result<()> {
    if let Some((cert_path, key_path)) = tls_paths {
        serve_tls(bind_addr, app, &cert_path, &key_path).await
    } else {
        tracing::info!("warden-cp listening on plaintext {bind_addr}");
        let listener = TcpListener::bind(bind_addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn serve_tls(
    bind_addr: &str,
    app: Router,
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls ring crypto provider"))?;

    let certs = load_certificates(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!("warden-cp listening with built-in TLS on {bind_addr}");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let service = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::warn!(error = %e, "TLS handshake failed");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let service = service.map_request(|req: hyper::Request<Incoming>| req.map(Body::new));
            let hyper_service = TowerToHyperService::new(service);
            if let Err(e) = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, hyper_service)
                .await
            {
                tracing::warn!(peer = %peer_addr, error = %e, "HTTPS connection failed");
            }
        });
    }
}

fn load_certificates(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read_to_string(path)?;
    let certs: Vec<_> = pem_blocks(&pem, "CERTIFICATE")?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    if certs.is_empty() {
        anyhow::bail!("TLS certificate file {path:?} does not contain a CERTIFICATE block");
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let pem = std::fs::read_to_string(path)?;
    if let Some(key) = pem_blocks(&pem, "PRIVATE KEY")?.into_iter().next() {
        return Ok(PrivatePkcs8KeyDer::from(key).into());
    }
    if let Some(key) = pem_blocks(&pem, "RSA PRIVATE KEY")?.into_iter().next() {
        return Ok(PrivatePkcs1KeyDer::from(key).into());
    }
    anyhow::bail!("TLS private key file {path:?} must contain PRIVATE KEY or RSA PRIVATE KEY PEM")
}

fn pem_blocks(text: &str, label: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after_begin = &rest[start + begin.len()..];
        let Some(end_pos) = after_begin.find(&end) else {
            anyhow::bail!("unterminated PEM block: {label}");
        };
        let body = after_begin[..end_pos]
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<String>();
        blocks.push(BASE64_STANDARD.decode(body)?);
        rest = &after_begin[end_pos + end.len()..];
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_block_decoder_reads_multiple_blocks() {
        let pem = "\
-----BEGIN CERTIFICATE-----\n\
AQID\n\
-----END CERTIFICATE-----\n\
-----BEGIN CERTIFICATE-----\n\
BAUG\n\
-----END CERTIFICATE-----\n";
        let blocks = pem_blocks(pem, "CERTIFICATE").unwrap();
        assert_eq!(blocks, vec![vec![1, 2, 3], vec![4, 5, 6]]);
    }

    #[test]
    fn pem_block_decoder_rejects_unterminated_block() {
        let pem = "-----BEGIN CERTIFICATE-----\nAQID\n";
        assert!(pem_blocks(pem, "CERTIFICATE").is_err());
    }
}
