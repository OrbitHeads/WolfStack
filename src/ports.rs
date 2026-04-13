// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Persistent port configuration.
//!
//! WolfStack listens on three ports:
//! - `api` — main HTTP(S) API and dashboard (default 8553)
//! - `inter_node` — plain HTTP for inter-node calls when TLS is on (default api+1)
//! - `status` — public status pages (default 8550)
//!
//! Per-node config lives in `/etc/wolfstack/ports.json`. A CLI `--port` flag
//! still overrides the API port for one-off launches. The status port has an
//! auto-fallback (`reserve_status_port`) so a colliding service (e.g. WolfDisk
//! grabbing 8550) doesn't stop the daemon from starting.

use serde::{Deserialize, Serialize};
use std::net::TcpListener;
use tracing::warn;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PortConfig {
    #[serde(default = "default_api")]
    pub api: u16,
    #[serde(default = "default_inter_node")]
    pub inter_node: u16,
    #[serde(default = "default_status")]
    pub status: u16,
}

fn default_api() -> u16 { 8553 }
fn default_inter_node() -> u16 { 8554 }
fn default_status() -> u16 { 8550 }

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            api: default_api(),
            inter_node: default_inter_node(),
            status: default_status(),
        }
    }
}

impl PortConfig {
    pub fn load() -> Self {
        let path = crate::paths::get().ports_config.clone();
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                warn!("ports.json parse error ({}), using defaults", e);
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = crate::paths::get().ports_config.clone();
        if let Some(parent) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())
    }
}

/// Try to reserve the preferred status port. If it's taken, scan upward through
/// the range and pick the first free one — persists the choice back to ports.json
/// so subsequent restarts use the same port. Returns the chosen port, or the
/// preferred port unchanged if nothing else is free (caller will then surface
/// the bind error like before).
pub fn reserve_status_port(bind: &str, preferred: u16, range: std::ops::RangeInclusive<u16>) -> u16 {
    if port_is_free(bind, preferred) {
        return preferred;
    }
    for p in range {
        if p == preferred { continue; }
        if port_is_free(bind, p) {
            warn!("status port {} taken, falling back to {}", preferred, p);
            let mut cfg = PortConfig::load();
            if cfg.status != p {
                cfg.status = p;
                if let Err(e) = cfg.save() {
                    warn!("failed to persist new status port to ports.json: {}", e);
                }
            }
            return p;
        }
    }
    warn!("no free status port found in scan range, leaving as {}", preferred);
    preferred
}

fn port_is_free(bind: &str, port: u16) -> bool {
    TcpListener::bind((bind, port)).is_ok()
}
