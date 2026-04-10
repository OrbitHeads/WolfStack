// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Unifi Controller connector — manage devices, clients, and networks.
//!
//! Unifi uses cookie-based auth: POST `/api/login` with `{username, password}`,
//! then carry the returned session cookies on all subsequent requests.
//! Since reqwest's `cookies` feature is not enabled, we extract the
//! `Set-Cookie` header manually and replay it.

use crate::integrations::{
    AuthMethod, ConfigField, Connector, ConnectorCapability, ConnectorInfo,
    HealthStatus, IntegrationInstance, ServiceStatus,
};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub struct UnifiConnector;

impl UnifiConnector {
    /// Build a base HTTP client (no cookies yet).
    fn base_client() -> Result<reqwest::Client, String> {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))
    }

    /// Login to the Unifi controller and return the session cookie string.
    async fn login(
        base_url: &str,
        credentials: &serde_json::Value,
    ) -> Result<(reqwest::Client, String), String> {
        let username = credentials.get("username")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'username' in credentials")?;
        let password = credentials.get("password")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'password' in credentials")?;

        let client = Self::base_client()?;
        let url = format!("{}/api/login", base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "username": username,
            "password": password,
        });

        let resp = client.post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Login request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Unifi login failed: {}", resp.status()));
        }

        // Extract all Set-Cookie headers and combine them
        let cookies: Vec<String> = resp.headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|v| {
                // Take only the cookie name=value part (before first ';')
                v.split(';').next().unwrap_or(v).to_string()
            })
            .collect();

        if cookies.is_empty() {
            return Err("Unifi login returned no cookies".to_string());
        }

        let cookie_header = cookies.join("; ");
        Ok((client, cookie_header))
    }

    /// GET request with session cookies.
    async fn api_get(
        base_url: &str,
        credentials: &serde_json::Value,
        path: &str,
    ) -> Result<serde_json::Value, String> {
        let (client, cookies) = Self::login(base_url, credentials).await?;
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);

        let resp = client.get(&url)
            .header("Cookie", &cookies)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Unifi API error: {} {}", resp.status(), url));
        }

        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }

    /// POST request with session cookies.
    async fn api_post(
        base_url: &str,
        credentials: &serde_json::Value,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let (client, cookies) = Self::login(base_url, credentials).await?;
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);

        let resp = client.post(&url)
            .header("Cookie", &cookies)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(format!("Unifi API error: {} {} — {}", status, url, body_text));
        }

        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }

    /// Resolve the site name from config, defaulting to "default".
    fn site(instance: &IntegrationInstance) -> String {
        instance.config.get("site")
            .cloned()
            .unwrap_or_else(|| "default".to_string())
    }
}

impl Connector for UnifiConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            id: "unifi".to_string(),
            name: "Unifi Controller".to_string(),
            icon: "fa-wifi".to_string(),
            description: "Manage Unifi network devices, clients, and networks".to_string(),
            auth_methods: vec![AuthMethod::Cookie],
            config_schema: vec![
                ConfigField {
                    name: "base_url".to_string(),
                    label: "Controller URL".to_string(),
                    field_type: "url".to_string(),
                    required: true,
                    default_value: None,
                    placeholder: Some("https://unifi.local:8443".to_string()),
                },
                ConfigField {
                    name: "site".to_string(),
                    label: "Site Name".to_string(),
                    field_type: "text".to_string(),
                    required: false,
                    default_value: Some("default".to_string()),
                    placeholder: Some("default".to_string()),
                },
            ],
        }
    }

    fn capabilities(&self) -> Vec<ConnectorCapability> {
        vec![
            ConnectorCapability {
                id: "devices".to_string(),
                label: "Devices".to_string(),
                icon: "fa-tower-broadcast".to_string(),
            },
            ConnectorCapability {
                id: "clients".to_string(),
                label: "Clients".to_string(),
                icon: "fa-laptop".to_string(),
            },
            ConnectorCapability {
                id: "networks".to_string(),
                label: "Networks".to_string(),
                icon: "fa-diagram-project".to_string(),
            },
        ]
    }

    fn health_check<'a>(
        &'a self,
        instance: &'a IntegrationInstance,
        credentials: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + 'a>> {
        Box::pin(async move {
            let now = chrono::Utc::now().to_rfc3339();
            let start = std::time::Instant::now();

            match Self::api_get(&instance.base_url, credentials, "/api/self/sites").await {
                Ok(data) => {
                    // Try to extract controller version from site info
                    let version = data.get("data")
                        .and_then(|d| d.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|site| site.get("desc"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    HealthStatus {
                        status: ServiceStatus::Online,
                        message: "Connected".to_string(),
                        latency_ms: Some(start.elapsed().as_millis() as u64),
                        last_checked: now,
                        version,
                    }
                }
                Err(e) => HealthStatus {
                    status: ServiceStatus::Offline,
                    message: e,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    last_checked: now,
                    version: None,
                },
            }
        })
    }

    fn execute<'a>(
        &'a self,
        instance: &'a IntegrationInstance,
        credentials: &'a serde_json::Value,
        operation: &'a str,
        params: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + 'a>> {
        Box::pin(async move {
            let base = &instance.base_url;
            let site = Self::site(instance);

            match operation {
                "list_clients" => {
                    Self::api_get(base, credentials, &format!("/api/s/{}/stat/sta", site)).await
                }

                "list_devices" => {
                    Self::api_get(base, credentials, &format!("/api/s/{}/stat/device", site)).await
                }

                "list_networks" => {
                    Self::api_get(base, credentials, &format!("/api/s/{}/rest/networkconf", site)).await
                }

                "block_client" => {
                    let mac = params.get("mac").and_then(|v| v.as_str())
                        .ok_or("Missing 'mac' parameter")?;
                    let body = serde_json::json!({
                        "cmd": "block-sta",
                        "mac": mac,
                    });
                    Self::api_post(base, credentials, &format!("/api/s/{}/cmd/stamgr", site), &body).await
                }

                "unblock_client" => {
                    let mac = params.get("mac").and_then(|v| v.as_str())
                        .ok_or("Missing 'mac' parameter")?;
                    let body = serde_json::json!({
                        "cmd": "unblock-sta",
                        "mac": mac,
                    });
                    Self::api_post(base, credentials, &format!("/api/s/{}/cmd/stamgr", site), &body).await
                }

                "reconnect_client" => {
                    let mac = params.get("mac").and_then(|v| v.as_str())
                        .ok_or("Missing 'mac' parameter")?;
                    let body = serde_json::json!({
                        "cmd": "kick-sta",
                        "mac": mac,
                    });
                    Self::api_post(base, credentials, &format!("/api/s/{}/cmd/stamgr", site), &body).await
                }

                "restart_device" => {
                    let mac = params.get("mac").and_then(|v| v.as_str())
                        .ok_or("Missing 'mac' parameter")?;
                    let body = serde_json::json!({
                        "cmd": "restart",
                        "mac": mac,
                    });
                    Self::api_post(base, credentials, &format!("/api/s/{}/cmd/devmgr", site), &body).await
                }

                _ => Err(format!("Unknown operation: {}", operation)),
            }
        })
    }

    fn dashboard_data<'a>(
        &'a self,
        instance: &'a IntegrationInstance,
        credentials: &'a serde_json::Value,
        capability_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + 'a>> {
        Box::pin(async move {
            let empty = serde_json::json!({});
            match capability_id {
                "devices" => self.execute(instance, credentials, "list_devices", &empty).await,
                "clients" => self.execute(instance, credentials, "list_clients", &empty).await,
                "networks" => self.execute(instance, credentials, "list_networks", &empty).await,
                _ => Err(format!("Unknown capability: {}", capability_id)),
            }
        })
    }
}
