use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteConfig {
    pub path: String,
    pub target: String,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file from {}", path))?;
        let config: Config = serde_yaml::from_str(&content)
            .with_context(|| "Failed to parse YAML config")?;
        Ok(config)
    }
}
