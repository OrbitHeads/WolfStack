// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! NetBird VPN connector — manage peers, groups, routes, and users via the
//! NetBird Management API.

use crate::integrations::{
    AuthMethod, ConfigField, Connector, ConnectorCapability, ConnectorInfo,
    HealthStatus, IntegrationInstance, ServiceStatus,
};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

pub struct NetBirdConnector;

impl NetBirdConnector {
    /// Build a reqwest client with the Bearer token set.
    fn client(
        credentials: &serde_json::Value,
    ) -> Result<(reqwest::Client, String), String> {
        let token = credentials.get("token")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'token' in credentials")?;

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        Ok((client, format!("Token {}", token)))
    }

    async fn api_get(
        base_url: &str,
        credentials: &serde_json::Value,
        path: &str,
    ) -> Result<serde_json::Value, String> {
        let (client, auth) = Self::client(credentials)?;
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        let resp = client.get(&url)
            .header("Authorization", &auth)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("NetBird API error: {} {}", resp.status(), url));
        }

        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }

    async fn api_post(
        base_url: &str,
        credentials: &serde_json::Value,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let (client, auth) = Self::client(credentials)?;
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        let resp = client.post(&url)
            .header("Authorization", &auth)
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("NetBird API error: {} {}", resp.status(), url));
        }

        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }

    async fn api_put(
        base_url: &str,
        credentials: &serde_json::Value,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let (client, auth) = Self::client(credentials)?;
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        let resp = client.put(&url)
            .header("Authorization", &auth)
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("NetBird API error: {} {}", resp.status(), url));
        }

        resp.json().await.map_err(|e| format!("JSON parse error: {}", e))
    }
}

impl Connector for NetBirdConnector {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            id: "netbird".to_string(),
            name: "NetBird VPN".to_string(),
            icon: "fa-shield-halved".to_string(),
            description: "Manage NetBird VPN peers, groups, routes, and users".to_string(),
            auth_methods: vec![AuthMethod::Bearer],
            config_schema: vec![
                ConfigField {
                    name: "base_url".to_string(),
                    label: "Management URL".to_string(),
                    field_type: "url".to_string(),
                    required: true,
                    default_value: Some("https://api.netbird.io".to_string()),
                    placeholder: Some("https://api.netbird.io".to_string()),
                },
            ],
        }
    }

    fn capabilities(&self) -> Vec<ConnectorCapability> {
        vec![
            ConnectorCapability {
                id: "peers".to_string(),
                label: "Peers".to_string(),
                icon: "fa-network-wired".to_string(),
            },
            ConnectorCapability {
                id: "groups".to_string(),
                label: "Groups".to_string(),
                icon: "fa-layer-group".to_string(),
            },
            ConnectorCapability {
                id: "routes".to_string(),
                label: "Routes".to_string(),
                icon: "fa-route".to_string(),
            },
            ConnectorCapability {
                id: "users".to_string(),
                label: "Users".to_string(),
                icon: "fa-users".to_string(),
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

            match Self::api_get(&instance.base_url, credentials, "/api/peers").await {
                Ok(_) => HealthStatus {
                    status: ServiceStatus::Online,
                    message: "Connected".to_string(),
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    last_checked: now,
                    version: None,
                },
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
            match operation {
                "list_peers" => Self::api_get(base, credentials, "/api/peers").await,

                "get_peer" => {
                    let peer_id = params.get("peer_id").and_then(|v| v.as_str())
                        .ok_or("Missing 'peer_id' parameter")?;
                    Self::api_get(base, credentials, &format!("/api/peers/{}", peer_id)).await
                }

                "disable_peer" => {
                    let peer_id = params.get("peer_id").and_then(|v| v.as_str())
                        .ok_or("Missing 'peer_id' parameter")?;
                    let body = serde_json::json!({ "enabled": false });
                    Self::api_put(base, credentials, &format!("/api/peers/{}", peer_id), &body).await
                }

                "enable_peer" => {
                    let peer_id = params.get("peer_id").and_then(|v| v.as_str())
                        .ok_or("Missing 'peer_id' parameter")?;
                    let body = serde_json::json!({ "enabled": true });
                    Self::api_put(base, credentials, &format!("/api/peers/{}", peer_id), &body).await
                }

                "list_groups" => Self::api_get(base, credentials, "/api/groups").await,

                "list_routes" => Self::api_get(base, credentials, "/api/routes").await,

                "list_users" => Self::api_get(base, credentials, "/api/users").await,

                "create_group" => {
                    Self::api_post(base, credentials, "/api/groups", params).await
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
                "peers" => self.execute(instance, credentials, "list_peers", &empty).await,
                "groups" => self.execute(instance, credentials, "list_groups", &empty).await,
                "routes" => self.execute(instance, credentials, "list_routes", &empty).await,
                "users" => self.execute(instance, credentials, "list_users", &empty).await,
                _ => Err(format!("Unknown capability: {}", capability_id)),
            }
        })
    }
}
