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

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing for logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

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
    
    // Start QUIC Server if enabled
    if config_arc.quic.enable {
        let quic_config = Arc::clone(&config_arc);
        tokio::spawn(async move {
            match QuicServer::new(quic_config) {
                Ok(quic_server) => {
                    if let Err(e) = quic_server.run().await {
                        tracing::error!("QUIC server error: {}", e);
                    }
                }
                Err(e) => tracing::error!("Failed to start QUIC server: {}", e),
            }
        });
    }

    let srv = Server::new(config);
    srv.run().await?;

    Ok(())
}
