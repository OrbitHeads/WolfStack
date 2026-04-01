// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfNote Integration — connect to WolfNote (https://app.wolfnote.org)
//!
//! Allows WolfStack users to:
//! - Authenticate with their WolfNote account
//! - Create notes and folders from the WolfStack dashboard
//! - Use the AI chat to create notes automatically
//! - Toggle integration features on/off

use serde::{Deserialize, Serialize};

fn wolfnote_config_path() -> String { crate::paths::get().wolfnote_config }

/// Default WolfNote instance URL
const DEFAULT_WOLFNOTE_URL: &str = "https://app.wolfnote.org";

// ─── Configuration ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNoteConfig {
    #[serde(default = "default_url")]
    pub url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub company: String,
    /// Feature toggles
    #[serde(default)]
    pub features: WolfNoteFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNoteFeatures {
    /// Allow AI chat to create notes
    #[serde(default = "default_true")]
    pub ai_create_notes: bool,
    /// Auto-log server events as notes
    #[serde(default)]
    pub auto_log_events: bool,
    /// Auto-create incident notes from status page incidents
    #[serde(default)]
    pub incident_notes: bool,
    /// Auto-log backup results as notes
    #[serde(default)]
    pub backup_notes: bool,
    /// Auto-log alert events as notes
    #[serde(default)]
    pub alert_notes: bool,
}

impl Default for WolfNoteFeatures {
    fn default() -> Self {
        Self {
            ai_create_notes: true,
            auto_log_events: false,
            incident_notes: false,
            backup_notes: false,
            alert_notes: false,
        }
    }
}

fn default_url() -> String { DEFAULT_WOLFNOTE_URL.to_string() }
fn default_true() -> bool { true }

impl Default for WolfNoteConfig {
    fn default() -> Self {
        Self {
            url: default_url(),
            token: String::new(),
            username: String::new(),
            company: String::new(),
            features: WolfNoteFeatures::default(),
        }
    }
}

impl WolfNoteConfig {
    pub fn load() -> Self {
        let path = wolfnote_config_path();
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = wolfnote_config_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())
    }

    pub fn is_connected(&self) -> bool {
        !self.token.is_empty()
    }
}

// ─── WolfNote API Client ───

/// Login response from WolfNote
#[derive(Debug, Deserialize)]
pub struct WolfNoteLoginResponse {
    pub token: String,
    pub user: WolfNoteUser,
}

#[derive(Debug, Deserialize)]
pub struct WolfNoteUser {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub email: String,
}

/// Folder from WolfNote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNoteFolder {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
}

/// Note from WolfNote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNoteNote {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub note_type: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// WolfNote API client — all calls go through WolfStack backend to avoid CORS
pub struct WolfNoteClient {
    client: reqwest::Client,
    base_url: String,
    token: String,
}

impl WolfNoteClient {
    pub fn new(base_url: &str, token: &str) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
        }
    }

    /// Login to WolfNote and get a JWT token
    pub async fn login(base_url: &str, username: &str, password: &str, company: &str) -> Result<WolfNoteLoginResponse, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| e.to_string())?;

        let url = format!("{}/api/auth/login", base_url.trim_end_matches('/'));
        let resp = client.post(&url)
            .json(&serde_json::json!({
                "username": username,
                "password": password,
                "company": company,
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to connect to WolfNote: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("WolfNote login failed ({}): {}", status, body));
        }

        resp.json::<WolfNoteLoginResponse>()
            .await
            .map_err(|e| format!("Invalid WolfNote response: {}", e))
    }

    /// List folders
    pub async fn list_folders(&self) -> Result<Vec<WolfNoteFolder>, String> {
        let url = format!("{}/api/folders", self.base_url);
        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("WolfNote request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("WolfNote error: {}", resp.status()));
        }

        resp.json().await.map_err(|e| format!("Invalid response: {}", e))
    }

    /// List notes (optionally filtered by folder)
    pub async fn list_notes(&self) -> Result<Vec<WolfNoteNote>, String> {
        let url = format!("{}/api/notes", self.base_url);
        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| format!("WolfNote request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("WolfNote error: {}", resp.status()));
        }

        resp.json().await.map_err(|e| format!("Invalid response: {}", e))
    }

    /// Create a note
    pub async fn create_note(&self, title: &str, content: &str, folder_id: Option<&str>) -> Result<WolfNoteNote, String> {
        let url = format!("{}/api/notes", self.base_url);
        let mut body = serde_json::json!({
            "title": title,
            "content": content,
        });
        if let Some(fid) = folder_id {
            body["folder_id"] = serde_json::Value::String(fid.to_string());
        }

        let resp = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("WolfNote request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("WolfNote error ({}): {}", status, body));
        }

        resp.json().await.map_err(|e| format!("Invalid response: {}", e))
    }

    /// Create a folder
    pub async fn create_folder(&self, name: &str, parent_id: Option<&str>, color: Option<&str>) -> Result<WolfNoteFolder, String> {
        let url = format!("{}/api/folders", self.base_url);
        let mut body = serde_json::json!({ "name": name });
        if let Some(pid) = parent_id {
            body["parent_id"] = serde_json::Value::String(pid.to_string());
        }
        if let Some(c) = color {
            body["color"] = serde_json::Value::String(c.to_string());
        }

        let resp = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("WolfNote request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("WolfNote error ({}): {}", status, body));
        }

        resp.json().await.map_err(|e| format!("Invalid response: {}", e))
    }
}
