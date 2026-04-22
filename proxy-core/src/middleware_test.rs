use hyper::{Request, Response, body::Bytes};
use http_body_util::Full;
use std::convert::Infallible;

pub async fn middleware(
    mut req: Request<hyper::body::Incoming>,
    client_ip: std::net::IpAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from_static(b"HTTP OK"))))
}
