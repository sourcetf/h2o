use hyper::{Request, Response, body::Bytes};
use http_body_util::Full;
use std::convert::Infallible;
use std::io::Write;
use brotli::CompressorWriter;
use flate2::write::GzEncoder;
use flate2::Compression;

pub async fn backend_handler() -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from_static(b"HTTP OK"))))
}

pub async fn proxy_middleware<B>(
    mut req: Request<B>,
    client_ip: std::net::IpAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // 3. Add X-Real-IP-75fe608c to proxied requests
    req.headers_mut().insert(
        "X-Real-IP-75fe608c",
        hyper::header::HeaderValue::from_str(&client_ip.to_string()).unwrap(),
    );

    let path = req.uri().path().to_string();
    let accept_encoding = req.headers().get(hyper::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut response = backend_handler().await?;

    // 2. Add X-XSS-Protection
    response.headers_mut().insert(
        "X-XSS-Protection",
        hyper::header::HeaderValue::from_static("1; mode=block"),
    );

    let (mut parts, body) = response.into_parts();
    // For Full<Bytes>, we can just get the bytes
    // In a real proxy we would read the body, but here it's Full<Bytes>
    // To make it simple, let's just assume we can get the bytes from the body
    // wait, Full<Bytes> doesn't have an easy way to get the inner Bytes without consuming it,
    // but we can convert it into bytes.
    use http_body_util::BodyExt;
    let body_bytes = body.collect().await.unwrap().to_bytes();

    let size = body_bytes.len();
    let is_compressible_ext = path.ends_with(".html") || path.ends_with(".js") || path.ends_with(".css");

    if size > 1024 && is_compressible_ext {
        if accept_encoding.contains("br") {
            let mut writer = CompressorWriter::new(Vec::new(), 4096, 11, 22);
            writer.write_all(&body_bytes).unwrap();
            let compressed = writer.into_inner();
            parts.headers.insert(hyper::header::CONTENT_ENCODING, hyper::header::HeaderValue::from_static("br"));
            return Ok(Response::from_parts(parts, Full::new(Bytes::from(compressed))));
        } else if accept_encoding.contains("gzip") {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&body_bytes).unwrap();
            let compressed = encoder.finish().unwrap();
            parts.headers.insert(hyper::header::CONTENT_ENCODING, hyper::header::HeaderValue::from_static("gzip"));
            return Ok(Response::from_parts(parts, Full::new(Bytes::from(compressed))));
        }
    }

    Ok(Response::from_parts(parts, Full::new(body_bytes)))
}
