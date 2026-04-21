use anyhow::Result;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, UPGRADE};
use hyper::upgrade::Upgraded;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioIo, TokioExecutor};
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{error, info};

use crate::config::Config;

static HTTP_CLIENT: OnceLock<Client<HttpConnector, Incoming>> = OnceLock::new();

fn get_client() -> &'static Client<HttpConnector, Incoming> {
    HTTP_CLIENT.get_or_init(|| {
        Client::builder(TokioExecutor::new()).build(HttpConnector::new())
    })
}

pub fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Handle a single HTTP request (including reverse proxy and WSS upgrade)
pub async fn handle_http_request(
    mut req: Request<Incoming>,
    config: Arc<Config>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    
    // Find matching route
    let upstream = config.routes.iter()
        .find(|r| host.contains(&r.domain))
        .map(|r| r.upstream.clone())
        .unwrap_or_else(|| "127.0.0.1:8080".to_string()); // Default upstream or error

    // Handle WebSocket Upgrade
    if req.headers().get(UPGRADE).map(|v| v.as_bytes()).unwrap_or(b"") == b"websocket" {
        info!("Handling WebSocket upgrade for {}", host);
        let upstream_clone = upstream.clone();
        
        tokio::task::spawn(async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    if let Err(e) = handle_ws_connection(upgraded, upstream_clone).await {
                        error!("WebSocket proxy error: {}", e);
                    }
                }
                Err(e) => error!("Upgrade error: {}", e),
            }
        });

        let mut res = Response::new(empty_body());
        *res.status_mut() = hyper::StatusCode::SWITCHING_PROTOCOLS;
        res.headers_mut().insert(UPGRADE, HeaderValue::from_static("websocket"));
        res.headers_mut().insert("Connection", HeaderValue::from_static("Upgrade"));
        return Ok(res);
    }

    // Normal HTTP reverse proxy
    info!("Proxying HTTP request to {}", upstream);
    
    let uri_string = format!("http://{}{}", upstream, req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/"));
    *req.uri_mut() = uri_string.parse().unwrap();

    let client = get_client();
    match client.request(req).await {
        Ok(res) => Ok(res.map(|b| b.boxed())),
        Err(e) => {
            error!("Error forwarding request: {}", e);
            // Return 502 Bad Gateway
            let mut res = Response::new(empty_body());
            *res.status_mut() = hyper::StatusCode::BAD_GATEWAY;
            Ok(res)
        }
    }
}

async fn handle_ws_connection(upgraded: Upgraded, upstream: String) -> Result<()> {
    let mut server_stream = TcpStream::connect(&upstream).await?;
    let mut client_stream = TokioIo::new(upgraded);
    
    copy_bidirectional(&mut client_stream, &mut server_stream).await?;
    Ok(())
}

pub async fn run_tcp_proxy(listen_port: u16, upstream: String) -> Result<()> {
    let addr = format!("0.0.0.0:{}", listen_port);
    let listener = TcpListener::bind(&addr).await?;
    info!("TCP proxy listening on {} -> {}", addr, upstream);

    loop {
        match listener.accept().await {
            Ok((mut client_stream, peer_addr)) => {
                info!("TCP connection from {}", peer_addr);
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    match TcpStream::connect(&upstream).await {
                        Ok(mut server_stream) => {
                            if let Err(e) = copy_bidirectional(&mut client_stream, &mut server_stream).await {
                                error!("TCP proxy error: {}", e);
                            }
                        }
                        Err(e) => error!("Failed to connect to upstream {}: {}", upstream, e),
                    }
                });
            }
            Err(e) => error!("TCP accept error: {}", e),
        }
    }
}

pub async fn run_udp_proxy(listen_port: u16, upstream: String) -> Result<()> {
    let addr = format!("0.0.0.0:{}", listen_port);
    let socket = UdpSocket::bind(&addr).await?;
    info!("UDP proxy listening on {} -> {}", addr, upstream);
    let socket = Arc::new(socket);

    let mut buf = vec![0; 65535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer_addr)) => {
                let upstream = upstream.clone();
                let data = buf[..len].to_vec();
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    if let Ok(upstream_socket) = UdpSocket::bind("0.0.0.0:0").await {
                        if let Ok(_) = upstream_socket.send_to(&data, &upstream).await {
                            let mut resp_buf = vec![0; 65535];
                            if let Ok((resp_len, _)) = upstream_socket.recv_from(&mut resp_buf).await {
                                let _ = socket.send_to(&resp_buf[..resp_len], peer_addr).await;
                            }
                        }
                    }
                });
            }
            Err(e) => error!("UDP recv error: {}", e),
        }
    }
}

