mod config;
mod server;
mod quic;
pub mod tls;
pub mod proxy;
// pub mod ech_test; // commented out to fix compile error

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::Result;
use config::Config;
use server::Server;
use quic::QuicServer;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use std::thread;

fn main() -> Result<()> {
    // Initialize tracing for logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    // Install default crypto provider
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // For demonstration, create a default config if file is missing
    let config_path = "config.toml";
    let config = Config::load(config_path).unwrap_or_else(|_| {
        info!("Failed to load {}, using default configuration", config_path);
        Config {
            server: config::ServerConfig {
                port: 8080,
                tls: None,
            },
            routes: vec![],
            quic: config::QuicConfig {
                enable: true,
                port: Some(8443),
                multipath: true,
                qmux: true,
            },
            proxy: config::ProxyConfig::default(),
        }
    });

    info!("Starting high-performance reverse proxy...");

    let config_arc = Arc::new(config.clone());
    
    // Spawn QUIC Server thread
    if config_arc.quic.enable {
        let quic_config = Arc::clone(&config_arc);
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                match QuicServer::new(quic_config) {
                    Ok(quic_server) => {
                        if let Err(e) = quic_server.run().await {
                            tracing::error!("QUIC server error: {}", e);
                        }
                    }
                    Err(e) => tracing::error!("Failed to start QUIC server: {}", e),
                }
            });
        });
    }

    // Advanced Multi-Core architecture: Thread-per-core with SO_REUSEPORT
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    info!("Spawning {} worker threads for HTTP/HTTPS...", cores);

    let mut handles = vec![];
    for i in 0..cores {
        let cfg = config.clone();
        let handle = thread::spawn(move || {
            // Each thread gets its own single-threaded Tokio runtime
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async move {
                let srv = Server::new(cfg);
                if let Err(e) = srv.run().await {
                    tracing::error!("Worker {} failed: {}", i, e);
                }
            });
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }

    Ok(())
}
