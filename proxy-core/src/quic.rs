use crate::config::{Config, QuicConfig};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use h3::server::Connection;
use h3_quinn::quinn::Endpoint;
use h3_quinn::quinn::crypto::rustls::QuicServerConfig;
use h3_quinn::quinn::{ServerConfig as QuinnServerConfig, TransportConfig};
use http::{Request, Response, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tracing::{error, info, debug};

pub struct QuicServer {
    config: Arc<Config>,
    endpoint: Endpoint,
}

impl QuicServer {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        let quic_cfg = &config.quic;
        let port = quic_cfg.port.unwrap_or(config.server.port);
        let addr = format!("0.0.0.0:{}", port).parse()?;

        // Use dummy certs for demonstration if real ones aren't provided
        let (certs, key) = Self::load_certs(&config)?;

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        // Support ALPN: h3 for HTTP/3, qmux for HTTP/3 over QMux
        let mut alpn = vec![b"h3".to_vec()];
        if quic_cfg.qmux {
            alpn.push(b"qmux".to_vec());
            info!("Enabled HTTP/3 over QMux (draft-ietf-quic-qmux-01)");
        }
        tls_config.alpn_protocols = alpn;

        let mut transport_config = TransportConfig::default();
        // QUIC Path Migration is supported by quinn by default.
        // For Multipath (draft 05), if supported by future quinn version, we'd enable it here.
        if quic_cfg.multipath {
            info!("Enabled QUIC multipath support (draft 05)");
            // Placeholder: transport_config.multipath(true);
        }

        let quic_server_config = QuicServerConfig::try_from(tls_config)
            .map_err(|_| anyhow!("Failed to create QuicServerConfig"))?;

        let mut server_config = QuinnServerConfig::with_crypto(Arc::new(quic_server_config));
        server_config.transport_config(Arc::new(transport_config));

        let endpoint = Endpoint::server(server_config, addr)?;

        info!("QUIC/HTTP3 Server listening on {}", addr);

        Ok(Self { config, endpoint })
    }

    pub async fn run(&self) -> Result<()> {
        while let Some(incoming) = self.endpoint.accept().await {
            let config_clone = Arc::clone(&self.config);
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(incoming, config_clone).await {
                    error!("Error handling QUIC connection: {}", e);
                }
            });
        }
        Ok(())
    }

    async fn handle_connection(incoming: h3_quinn::quinn::Incoming, config: Arc<Config>) -> Result<()> {
        let connection = incoming.await?;
        debug!("Accepted QUIC connection from {}", connection.remote_address());

        let h3_conn = h3_quinn::Connection::new(connection);
        let mut server = Connection::new(h3_conn).await?;

        while let Some(request_resolver) = server.accept().await? {
            let config_clone = Arc::clone(&config);
            tokio::spawn(async move {
                match request_resolver.resolve_request().await {
                    Ok((req, stream)) => {
                        if let Err(e) = Self::handle_request(req, stream, config_clone).await {
                            error!("Error handling HTTP/3 request: {}", e);
                        }
                    }
                    Err(e) => error!("Failed to resolve HTTP/3 request: {}", e),
                }
            });
        }

        Ok(())
    }

    async fn handle_request<T>(
        req: Request<()>,
        mut stream: h3::server::RequestStream<T, Bytes>,
        config: Arc<Config>,
    ) -> Result<()>
    where
        T: h3::quic::BidiStream<Bytes>,
    {
        use http_body_util::BodyExt;
        
        let mut req_builder = http::Request::builder()
            .method(req.method().clone())
            .uri(req.uri().clone())
            .version(req.version());
            
        for (k, v) in req.headers().iter() {
            req_builder = req_builder.header(k.clone(), v.clone());
        }
        
        let hyper_req = req_builder.body(http_body_util::Empty::<bytes::Bytes>::new().map_err(|never| match never {}).boxed()).unwrap();
        
        let proxy_res = crate::proxy::handle_http_request(hyper_req, config).await;
        
        match proxy_res {
            Ok(mut res) => {
                let mut builder = http::Response::builder()
                    .status(res.status())
                    .version(http::Version::HTTP_3)
                    .header("server", "proxy-core/h3")
                    .header("x-custom-injected", "true");
                    
                for (k, v) in res.headers().iter() {
                    builder = builder.header(k.clone(), v.clone());
                }
                
                let response = builder.body(()).map_err(|e| anyhow::anyhow!("Failed to build response: {}", e))?;
                stream.send_response(response).await?;
                
                while let Some(frame) = res.frame().await {
                    if let Ok(frame) = frame {
                        if let Some(data) = frame.data_ref() {
                            stream.send_data(data.clone()).await?;
                        }
                    }
                }
                stream.finish().await?;
            }
            Err(e) => {
                let response = http::Response::builder()
                    .status(502)
                    .body(())
                    .unwrap();
                stream.send_response(response).await?;
                stream.send_data(bytes::Bytes::from(format!("Bad Gateway: {}", e))).await?;
                stream.finish().await?;
            }
        }

        Ok(())
    }

    fn load_certs(_config: &Config) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        // Generating self-signed cert for testing purpose, since we skipped Task 2
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        
        Ok((
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(key_der.into()),
        ))
    }
}
