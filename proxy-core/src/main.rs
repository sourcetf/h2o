use http::{HeaderName, HeaderValue, Request, Response};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use tokio::net::TcpStream;
use tokio::time::timeout;
use std::time::Duration;
use std::convert::Infallible;
use http_body_util::Full;
use hyper::body::Bytes;

pub async fn middleware_handler(
    mut req: Request<Incoming>,
    sni_name: &str,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // 2. Domain fronting
    let host = req.headers().get("Host")
        .or_else(|| req.headers().get(":authority"))
        .and_then(|h| h.to_str().ok());

    if host != Some(sni_name) {
        if let Ok(val) = HeaderValue::from_str(sni_name) {
            req.headers_mut().insert("Host", val);
        }
    }

    // 3. Eliminate .unwrap() panics on HTTP header parsing
    let k = "x-backend-header";
    let v = "backend-value";
    if let Ok(name) = HeaderName::from_bytes(k.as_bytes()) {
        if let Ok(val) = HeaderValue::from_str(v) {
            req.headers_mut().insert(name, val);
        }
    }

    Ok(Response::new(Full::new(Bytes::from("OK"))))
}

pub async fn handle_stream(stream: TcpStream) {
    let mut buf = [0; 1024];

    // 1. stream.peek slow attack
    if let Err(_) = timeout(Duration::from_secs(3), stream.peek(&mut buf)).await {
        return; // timed out
    }

    // 4. Hyper frontend timeout
    let mut b1 = http1::Builder::new();
    b1.header_read_timeout(Duration::from_secs(10));

    let mut b2 = http2::Builder::new(hyper_util::rt::TokioExecutor::new());
    b2.keep_alive_timeout(Duration::from_secs(30));
}

#[tokio::main]
async fn main() {
    println!("Proxy core started.");
}
