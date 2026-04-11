// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! AI Agent — LLM-powered monitoring and chat assistant
//!
//! Each WolfStack node runs an AI agent that:
//! - Answers questions about WolfStack, WolfNet, WolfDisk, WolfProxy, WolfServe
//! - Monitors server health hourly and alerts on issues
//! - Coordinates with agents on other cluster nodes
//! - Supports Claude and Gemini as LLM backends
//! - Can execute read-only commands locally and across the cluster

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tracing::warn;
use std::process::Command as StdCommand;
use std::time::Duration;

fn ai_config_path() -> String { crate::paths::get().ai_config }
const KNOWLEDGE_DIR: &str = "/opt/wolfscale/web";
const KNOWLEDGE_DIR_DEV: &str = "../wolfscale/web";

// ─── Configuration ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    pub provider: String,         // "claude", "gemini", "openrouter", or "local"
    pub claude_api_key: String,
    pub gemini_api_key: String,
    /// OpenRouter API key (https://openrouter.ai — access hundreds of models via one API)
    #[serde(default)]
    pub openrouter_api_key: String,
    /// URL of a local/self-hosted AI server (OpenAI-compatible API)
    /// Supports: Ollama (http://localhost:11434/v1), LM Studio (http://localhost:1234/v1),
    /// LocalAI, vLLM, text-generation-webui, or any OpenAI-compatible endpoint
    #[serde(default)]
    pub local_url: String,
    /// Optional API key for the local server (some require it, most don't)
    #[serde(default)]
    pub local_api_key: String,
    pub model: String,            // e.g. "claude-sonnet-4-20250514", "gemini-2.0-flash", "llama3", "mistral"
    pub email_enabled: bool,
    pub email_to: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    #[serde(default)]
    pub smtp_tls: String,         // "none", "starttls", or "tls"
    pub check_interval_minutes: u32,
    #[serde(default = "default_scan_schedule")]
    pub scan_schedule: String,    // "off", "hourly", "6h", "12h", "daily"
}

fn default_scan_schedule() -> String { "off".to_string() }

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            provider: "claude".to_string(),
            claude_api_key: String::new(),
            gemini_api_key: String::new(),
            openrouter_api_key: String::new(),
            local_url: String::new(),
            local_api_key: String::new(),
            model: "claude-sonnet-4-20250514".to_string(),
            email_enabled: false,
            email_to: String::new(),
            smtp_host: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            smtp_user: String::new(),
            smtp_pass: String::new(),
            smtp_tls: "starttls".to_string(),
            check_interval_minutes: 60,
            scan_schedule: "off".to_string(),
        }
    }
}

impl AiConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(&ai_config_path()) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = ai_config_path();
        let dir = std::path::Path::new(&path).parent().unwrap();
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())
    }

    /// Return config with API keys masked for frontend display
    pub fn masked(&self) -> serde_json::Value {
        serde_json::json!({
            "provider": self.provider,
            "claude_api_key": mask_key(&self.claude_api_key),
            "gemini_api_key": mask_key(&self.gemini_api_key),
            "openrouter_api_key": mask_key(&self.openrouter_api_key),
            "local_url": self.local_url,
            "local_api_key": mask_key(&self.local_api_key),
            "model": self.model,
            "email_enabled": self.email_enabled,
            "email_to": self.email_to,
            "smtp_host": self.smtp_host,
            "smtp_port": self.smtp_port,
            "smtp_user": self.smtp_user,
            "smtp_pass": mask_key(&self.smtp_pass),
            "check_interval_minutes": self.check_interval_minutes,
            "scan_schedule": self.scan_schedule,
            "has_claude_key": !self.claude_api_key.is_empty(),
            "has_gemini_key": !self.gemini_api_key.is_empty(),
            "has_openrouter_key": !self.openrouter_api_key.is_empty(),
            "has_local_url": !self.local_url.is_empty(),
            "has_smtp_pass": !self.smtp_pass.is_empty(),
        })
    }

    fn active_key(&self) -> &str {
        match self.provider.as_str() {
            "local" => if self.local_api_key.is_empty() { "local" } else { &self.local_api_key },
            "openrouter" => &self.openrouter_api_key,
            "gemini" => &self.gemini_api_key,
            _ => &self.claude_api_key,
        }
    }

    pub fn is_configured(&self) -> bool {
        match self.provider.as_str() {
            "local" => !self.local_url.is_empty(),
            "openrouter" => !self.openrouter_api_key.is_empty(),
            _ => !self.active_key().is_empty(),
        }
    }
}

fn mask_key(key: &str) -> String {
    if key.len() <= 8 {
        return if key.is_empty() { String::new() } else { "••••••••".to_string() };
    }
    format!("{}••••{}", &key[..4], &key[key.len()-4..])
}

// ─── Chat Messages ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,     // "user" or "assistant"
    pub content: String,
    pub timestamp: i64,
}

// ─── Alerts ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAlert {
    pub timestamp: i64,
    pub severity: String,  // "info", "warning", "critical"
    pub message: String,
    pub hostname: String,
}

// ─── AI Actions (propose-then-execute) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAction {
    pub id: String,
    pub title: String,
    pub command: String,
    pub risk: String,           // "low", "medium", "high"
    pub explanation: String,
    #[serde(default)]
    pub node_target: String,    // "local", "all", or a specific node hostname
    pub status: String,         // "pending", "approved", "rejected", "executed", "failed"
    pub created_at: i64,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub approved_by: String,
}

// ─── AI Agent State ───

pub struct AiAgent {
    pub config: Mutex<AiConfig>,
    pub chat_history: Mutex<Vec<ChatMessage>>,
    pub alerts: Mutex<Vec<AiAlert>>,
    pub pending_actions: Mutex<Vec<AiAction>>,
    pub last_health_check: Mutex<Option<String>>,
    pub knowledge_base: String,
    client: reqwest::Client,
}

impl AiAgent {
    pub fn new() -> Self {
        let config = AiConfig::load();
        let knowledge_base = load_knowledge_base();


        Self {
            config: Mutex::new(config),
            chat_history: Mutex::new(Vec::new()),
            alerts: Mutex::new(Vec::new()),
            pending_actions: Mutex::new(Vec::new()),
            last_health_check: Mutex::new(None),
            knowledge_base,
            client: reqwest::Client::new(),
        }
    }

    /// Chat with the AI — multi-turn with command execution and action proposal support.
    /// Returns (response_text, proposed_actions).
    /// cluster_nodes is a list of (node_id, hostname, base_url) for remote execution
    /// cluster_secret is used to authenticate with remote nodes via X-WolfStack-Secret
    pub async fn chat(
        &self,
        user_message: &str,
        system_context: &str,
        cluster_nodes: &[(String, String, String, String)],  // (id, hostname, base_url_primary, base_url_fallback)
        cluster_secret: &str,
    ) -> Result<(String, Vec<AiAction>), String> {
        let config = self.config.lock().unwrap().clone();
        if !config.is_configured() {
            return Err("AI not configured — please add an API key in AI Settings".to_string());
        }

        // Build conversation history
        let mut history: Vec<ChatMessage> = {
            let h = self.chat_history.lock().unwrap();
            h.iter().rev().take(10).cloned().collect::<Vec<_>>().into_iter().rev().collect()
        };

        let system_prompt = build_system_prompt(&self.knowledge_base, system_context);

        let mut current_msg = user_message.to_string();
        let mut final_response = String::new();
        let mut last_response = String::new();

        // Multi-turn loop: AI can request commands, we execute and feed back
        for _round in 0..3 {
            let response = match config.provider.as_str() {
                "gemini" => {
                    call_gemini(&self.client, &config.gemini_api_key, &config.model, &system_prompt, &history, &current_msg).await?
                }
                "openrouter" => {
                    call_local(&self.client, "https://openrouter.ai/api/v1", &config.openrouter_api_key, &config.model, &system_prompt, &history, &current_msg).await?
                }
                "local" => {
                    call_local(&self.client, &config.local_url, &config.local_api_key, &config.model, &system_prompt, &history, &current_msg).await?
                }
                _ => {
                    call_claude(&self.client, &config.claude_api_key, &config.model, &system_prompt, &history, &current_msg).await?
                }
            };

            last_response = response.clone();

            // Check for [EXEC], [EXEC_ALL], or [WOLFNOTE] tags
            let has_exec = response.contains("[EXEC]") && response.contains("[/EXEC]");
            let has_exec_all = response.contains("[EXEC_ALL]") && response.contains("[/EXEC_ALL]");
            let has_wolfnote = response.contains("[WOLFNOTE") && response.contains("[/WOLFNOTE]");

            if !has_exec && !has_exec_all {
                // Handle [WOLFNOTE] tags if present (fire-and-forget, no multi-turn needed)
                if has_wolfnote {
                    final_response = execute_wolfnote_tags(&response).await;
                } else {
                    final_response = response;
                }
                break;
            }

            // Parse and execute commands
            let mut command_results = String::new();
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "local".to_string());

            // Handle [EXEC]command[/EXEC] — local execution
            let mut search_from = 0;
            while let Some(start) = response[search_from..].find("[EXEC]") {
                let abs_start = search_from + start + 6;
                if let Some(end) = response[abs_start..].find("[/EXEC]") {
                    let cmd = response[abs_start..abs_start + end].trim();

                    let result = execute_safe_command(cmd);
                    command_results.push_str(&format!(
                        "\n=== Command on {} ===\n$ {}\n{}\n",
                        hostname, cmd,
                        match &result {
                            Ok(output) => output.clone(),
                            Err(e) => format!("ERROR: {}", e),
                        }
                    ));
                    search_from = abs_start + end + 7;
                } else {
                    break;
                }
            }

            // Handle [EXEC_ALL]command[/EXEC_ALL] — cluster-wide execution
            search_from = 0;
            while let Some(start) = response[search_from..].find("[EXEC_ALL]") {
                let abs_start = search_from + start + 10;
                if let Some(end) = response[abs_start..].find("[/EXEC_ALL]") {
                    let cmd = response[abs_start..abs_start + end].trim();


                    // Run locally first
                    let local_result = execute_safe_command(cmd);
                    command_results.push_str(&format!(
                        "\n=== {} (local) ===\n$ {}\n{}\n",
                        hostname, cmd,
                        match &local_result {
                            Ok(output) => output.clone(),
                            Err(e) => format!("ERROR: {}", e),
                        }
                    ));

                    // Run on all remote cluster nodes
                    for (node_id, node_hostname, url_primary, url_fallback) in cluster_nodes {
                        // Try primary URL first (port+1 for HTTPS nodes), fall back to original port
                        let urls = [url_primary.as_str(), url_fallback.as_str()];
                        let mut output = String::new();
                        for base_url in &urls {
                            let remote_url = format!("{}/api/ai/exec", base_url);
                            let remote_result = self.client
                                .post(&remote_url)
                                .header("X-WolfStack-Secret", cluster_secret)
                                .json(&serde_json::json!({ "command": cmd }))
                                .timeout(Duration::from_secs(15))
                                .send()
                                .await;

                            match remote_result {
                                Ok(resp) => {
                                    let resp_text = resp.text().await.unwrap_or_default();
                                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp_text) {
                                        if let Some(err) = json["error"].as_str() {
                                            output = format!("ERROR: {}", err);
                                        } else {
                                            output = json["output"].as_str().unwrap_or("(no output)").to_string();
                                        }
                                    } else {
                                        let preview: String = resp_text.chars().take(200).collect();
                                        output = format!("ERROR: Failed to parse response (body: {})", preview);
                                    }
                                    break; // Got a response, don't try fallback
                                }
                                Err(e) => {
                                    output = format!("ERROR: Connection failed — {}", e);
                                    // Try next URL
                                }
                            }
                        }

                        command_results.push_str(&format!(
                            "\n=== {} ({}) ===\n$ {}\n{}\n",
                            node_hostname, node_id, cmd, output
                        ));
                    }

                    search_from = abs_start + end + 11;
                } else {
                    break;
                }
            }

            // Add the AI's response and command results to history for next round
            let now = chrono::Utc::now().timestamp();
            history.push(ChatMessage { role: "assistant".to_string(), content: response.clone(), timestamp: now });
            current_msg = format!(
                "Here are the command results. Please analyze them and provide a clear summary for the user. \
                 Do NOT request more commands unless absolutely necessary.\n\n{}",
                command_results
            );
            history.push(ChatMessage { role: "user".to_string(), content: current_msg.clone(), timestamp: now });
        }

        // Fallback: if the loop exhausted without a clean response, use the last thing the AI said
        if final_response.is_empty() && !last_response.is_empty() {
            final_response = last_response;
        }

        // Parse [ACTION] tags from the final response
        let actions = parse_actions(&final_response);

        // Store pending actions (expire old ones first)
        {
            let mut pa = self.pending_actions.lock().unwrap();
            let now = chrono::Utc::now().timestamp();
            // Expire actions older than 10 minutes
            pa.retain(|a| a.status == "pending" && (now - a.created_at) < 600);
            // Cap at 20 pending
            if pa.len() + actions.len() > 20 {
                let drain = (pa.len() + actions.len()).saturating_sub(20);
                let drain = drain.min(pa.len());
                pa.drain(..drain);
            }
            pa.extend(actions.clone());
        }

        // Strip [ACTION] tags from the displayed response (frontend renders them separately)
        let clean_response = strip_action_tags(&final_response);

        // Store messages in history
        {
            let mut h = self.chat_history.lock().unwrap();
            let now = chrono::Utc::now().timestamp();
            h.push(ChatMessage { role: "user".to_string(), content: user_message.to_string(), timestamp: now });
            h.push(ChatMessage { role: "assistant".to_string(), content: clean_response.clone(), timestamp: now });
            // Keep last 100 messages
            if h.len() > 100 { let drain = h.len() - 100; h.drain(..drain); }
        }

        Ok((clean_response, actions))
    }

    /// Execute an approved action by ID. Returns the command output.
    pub async fn execute_action(
        &self,
        action_id: &str,
        approved_by: &str,
        cluster_nodes: &[(String, String, String, String)],
        cluster_secret: &str,
    ) -> Result<String, String> {
        let mut action = {
            let mut pa = self.pending_actions.lock().unwrap();
            let idx = pa.iter().position(|a| a.id == action_id)
                .ok_or_else(|| "Action not found or expired".to_string())?;
            if pa[idx].status != "pending" {
                return Err(format!("Action already {}", pa[idx].status));
            }
            // Enforce 10-minute expiry
            let now = chrono::Utc::now().timestamp();
            if now - pa[idx].created_at > 600 {
                pa[idx].status = "expired".to_string();
                return Err("Action expired (older than 10 minutes)".to_string());
            }
            pa[idx].status = "approved".to_string();
            pa[idx].approved_by = approved_by.to_string();
            pa[idx].clone()
        };

        // Audit log
        log_action_audit(&action, "approved", approved_by, "");

        // Execute the command
        let result = if action.node_target == "all" {
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "local".to_string());

            let mut output = String::new();

            // Local execution
            match execute_action_command(&action.command) {
                Ok(o) => output.push_str(&format!("=== {} (local) ===\n{}\n\n", hostname, o)),
                Err(e) => output.push_str(&format!("=== {} (local) ===\nERROR: {}\n\n", hostname, e)),
            }

            // Remote execution
            for (_node_id, node_hostname, url_primary, url_fallback) in cluster_nodes {
                let urls = [url_primary.as_str(), url_fallback.as_str()];
                let mut node_output = String::new();
                for base_url in &urls {
                    let remote_url = format!("{}/api/ai/action/exec", base_url);
                    match self.client
                        .post(&remote_url)
                        .header("X-WolfStack-Secret", cluster_secret)
                        .json(&serde_json::json!({ "command": action.command }))
                        .timeout(Duration::from_secs(30))
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            let resp_text = resp.text().await.unwrap_or_default();
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp_text) {
                                node_output = json["output"].as_str()
                                    .or(json["error"].as_str())
                                    .unwrap_or("(no output)")
                                    .to_string();
                            } else {
                                node_output = format!("ERROR: Unexpected response: {}", resp_text.chars().take(200).collect::<String>());
                            }
                            break;
                        }
                        Err(e) => {
                            node_output = format!("ERROR: {}", e);
                        }
                    }
                }
                output.push_str(&format!("=== {} ===\n{}\n\n", node_hostname, node_output));
            }
            Ok(output)
        } else {
            execute_action_command(&action.command)
        };

        // Update action status
        {
            let mut pa = self.pending_actions.lock().unwrap();
            if let Some(a) = pa.iter_mut().find(|a| a.id == action_id) {
                match &result {
                    Ok(output) => {
                        a.status = "executed".to_string();
                        a.result = output.clone();
                        action.result = output.clone();
                    }
                    Err(e) => {
                        a.status = "failed".to_string();
                        a.result = e.clone();
                        action.result = e.clone();
                    }
                }
            }
        }

        // Audit log result
        log_action_audit(&action, &action.status, approved_by, &action.result);

        result
    }

    /// Reject a pending action
    pub fn reject_action(&self, action_id: &str, rejected_by: &str) -> Result<(), String> {
        let mut pa = self.pending_actions.lock().unwrap();
        let action = pa.iter_mut().find(|a| a.id == action_id)
            .ok_or_else(|| "Action not found or expired".to_string())?;
        if action.status != "pending" {
            return Err(format!("Action already {}", action.status));
        }
        action.status = "rejected".to_string();
        log_action_audit(action, "rejected", rejected_by, "");
        Ok(())
    }

    /// List available models for the configured provider
    pub async fn list_models(&self, provider: &str, api_key: &str) -> Result<Vec<String>, String> {
        match provider {
            "openrouter" => {
                // OpenRouter uses the OpenAI-compatible /v1/models endpoint
                let resp = self.client.get("https://openrouter.ai/api/v1/models")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .send().await
                    .map_err(|e| format!("OpenRouter API error: {}", e))?;
                let status = resp.status();
                let text = resp.text().await.map_err(|e| format!("OpenRouter response error: {}", e))?;
                if !status.is_success() {
                    return Err(format!("OpenRouter API {} — {}", status, text));
                }
                let json: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| format!("OpenRouter JSON error: {}", e))?;
                let models = json["data"].as_array()
                    .map(|arr| arr.iter().filter_map(|m| {
                        m["id"].as_str().map(|s| s.to_string())
                    }).collect())
                    .unwrap_or_default();
                Ok(models)
            }
            "gemini" => {
                let url = format!(
                    "https://generativelanguage.googleapis.com/v1beta/models?key={}",
                    api_key
                );
                let resp = self.client.get(&url)
                    .send().await
                    .map_err(|e| format!("Gemini API error: {}", e))?;
                let status = resp.status();
                let text = resp.text().await.map_err(|e| format!("Gemini response error: {}", e))?;
                if !status.is_success() {
                    return Err(format!("Gemini API {} — {}", status, text));
                }
                let json: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| format!("Gemini JSON error: {}", e))?;
                let models = json["models"].as_array()
                    .map(|arr| arr.iter().filter_map(|m| {
                        let name = m["name"].as_str()?;
                        // name is like "models/gemini-2.0-flash" — strip prefix
                        let short = name.strip_prefix("models/").unwrap_or(name);
                        // Only include generateContent-capable models
                        let methods = m["supportedGenerationMethods"].as_array()?;
                        if methods.iter().any(|m| m.as_str() == Some("generateContent")) {
                            Some(short.to_string())
                        } else {
                            None
                        }
                    }).collect())
                    .unwrap_or_default();
                Ok(models)
            }
            _ => {
                // Claude models API
                let resp = self.client.get("https://api.anthropic.com/v1/models")
                    .header("x-api-key", api_key)
                    .header("anthropic-version", "2023-06-01")
                    .send().await
                    .map_err(|e| format!("Claude API error: {}", e))?;
                let status = resp.status();
                let text = resp.text().await.map_err(|e| format!("Claude response error: {}", e))?;
                if !status.is_success() {
                    return Err(format!("Claude API {} — {}", status, text));
                }
                let json: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| format!("Claude JSON error: {}", e))?;
                let models = json["data"].as_array()
                    .map(|arr| arr.iter().filter_map(|m| {
                        m["id"].as_str().map(|s| s.to_string())
                    }).collect())
                    .unwrap_or_default();
                Ok(models)
            }
        }
    }

    /// Run a health check — analyze system metrics and return findings  
    pub async fn health_check(&self, metrics_summary: &str) -> Option<String> {
        let config = self.config.lock().unwrap().clone();
        if !config.is_configured() { return None; }

        let prompt = format!(
            "You are a server monitoring AI for WolfStack. Analyze these metrics and report ONLY if there are concerns. \
             If everything looks healthy, respond with exactly 'ALL_OK'. \
             If there are issues, list them concisely with severity (INFO/WARNING/CRITICAL).\n\
             IMPORTANT: Ignore /boot, /boot/efi, and /etc/pve partition usage — these are managed automatically \
             by the OS or Proxmox. Only flag them if over 99% full.\n\
             When CPU or memory is high, the top processes are included — identify WHICH process is causing the issue \
             by name (e.g. 'mysqld using 85% CPU', 'java consuming 4.2GB RAM'). Don't just say 'CPU is high' — say what's using it.\n\
             For Kubernetes clusters: flag unhealthy/NotReady nodes, failed or pending pods, pods with high restart counts \
             (10+), and any cluster that reports as UNHEALTHY. Include the cluster name and affected pod/node names.\n\n\
             IMPORTANT: If you identify a fixable issue, propose the fix using ACTION tags:\n\
             [ACTION id=\"unique-id\" title=\"Short Title\" risk=\"low|medium|high\" explain=\"Why this fixes it\" target=\"local\"]command[/ACTION]\n\
             The admin will see these actions in the WolfStack dashboard AND in the alert email, and can approve them with one click.\n\n\
             Current server metrics:\n{}",
            metrics_summary
        );

        let system = "You are a WolfStack server health monitoring agent. Be concise and technical. Only flag genuine issues. Propose fixes with [ACTION] tags when possible.";

        let result = match config.provider.as_str() {
            "gemini" => call_gemini(&self.client, &config.gemini_api_key, &config.model, system, &[], &prompt).await,
            "openrouter" => call_local(&self.client, "https://openrouter.ai/api/v1", &config.openrouter_api_key, &config.model, system, &[], &prompt).await,
            "local" => call_local(&self.client, &config.local_url, &config.local_api_key, &config.model, system, &[], &prompt).await,
            _ => call_claude(&self.client, &config.claude_api_key, &config.model, system, &[], &prompt).await,
        };

        match result {
            Ok(response) => {
                // Update last health check
                {
                    let mut lhc = self.last_health_check.lock().unwrap();
                    *lhc = Some(response.clone());
                }

                if response.trim() != "ALL_OK" {
                    let hostname = hostname::get()
                        .map(|h| h.to_string_lossy().to_string())
                        .unwrap_or_else(|_| "unknown".to_string());

                    // Parse proposed actions from the response
                    let actions = parse_actions(&response);
                    let clean_response = strip_action_tags(&response);

                    // Store pending actions
                    if !actions.is_empty() {
                        let mut pa = self.pending_actions.lock().unwrap();
                        let now = chrono::Utc::now().timestamp();
                        pa.retain(|a| a.status == "pending" && (now - a.created_at) < 600);
                        pa.extend(actions.clone());
                    }

                    // Parse severity from response
                    let severity = if response.contains("CRITICAL") {
                        "critical"
                    } else if response.contains("WARNING") {
                        "warning"
                    } else {
                        "info"
                    };

                    let alert = AiAlert {
                        timestamp: chrono::Utc::now().timestamp(),
                        severity: severity.to_string(),
                        message: clean_response.clone(),
                        hostname: hostname.clone(),
                    };

                    // Store alert
                    {
                        let mut alerts = self.alerts.lock().unwrap();
                        alerts.push(alert);
                        // Keep last 200 alerts
                        if alerts.len() > 200 { let drain = alerts.len() - 200; alerts.drain(..drain); }
                    }

                    // Send email if configured — include proposed actions
                    if config.email_enabled && !config.email_to.is_empty() {
                        let subject = format!("[WolfStack {}] {} Alert on {}", severity.to_uppercase(), severity.to_uppercase(), hostname);
                        let email_body = if actions.is_empty() {
                            clean_response.clone()
                        } else {
                            let mut body = clean_response.clone();
                            body.push_str("\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                            body.push_str("PROPOSED FIXES (approve in WolfStack dashboard)\n");
                            body.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
                            for a in &actions {
                                let risk_label = match a.risk.as_str() {
                                    "low" => "LOW RISK",
                                    "high" => "HIGH RISK",
                                    _ => "MEDIUM RISK",
                                };
                                body.push_str(&format!(
                                    "[{}] {}\n  Command: {}\n  {}\n  → Open WolfStack dashboard to approve this action\n\n",
                                    risk_label, a.title, a.command,
                                    if a.explanation.is_empty() { String::new() } else { format!("Reason: {}", a.explanation) }
                                ));
                            }
                            body
                        };
                        if let Err(e) = send_alert_email(&config, &subject, &email_body) {
                            warn!("Failed to send alert email: {}", e);
                        }
                    }

                    // Also send to Discord/Telegram/Slack via the alerting system
                    let alert_config = crate::alerting::AlertConfig::load();
                    if alert_config.enabled && alert_config.has_channels() {
                        let title = format!(
                            "[WolfStack AI {}] Health alert on {}",
                            severity.to_uppercase(), hostname
                        );
                        let body = clean_response.clone();
                        tokio::spawn(async move {
                            crate::alerting::send_alert(&alert_config, &title, &body).await;
                        });
                    }

                    Some(clean_response)
                } else {

                    None
                }
            }
            Err(e) => {
                warn!("AI health check failed: {}", e);
                None
            }
        }
    }

    /// Analyze reboot diagnostics and suggest remediation steps
    pub async fn analyze_reboot(&self, hostname: &str, diagnostics: &str) -> Option<String> {
        self.analyze_issue(
            &format!(
                "Server '{}' has unexpectedly rebooted. Determine the most likely cause \
                 (OOM kill, kernel panic, power loss, unattended upgrade, hardware watchdog, \
                 manual reboot, etc.) and provide 2-3 specific actionable steps to prevent it.\n\n\
                 Diagnostics:\n{}",
                hostname, diagnostics
            )
        ).await
    }

    /// General-purpose issue analysis — takes a description of the problem and returns
    /// AI-powered diagnosis with actionable remediation steps.
    /// Works across different Linux distributions and system types.
    pub async fn analyze_issue(&self, issue_description: &str) -> Option<String> {
        let config = self.config.lock().unwrap().clone();
        if !config.is_configured() { return None; }

        let system = "You are a Linux server administration expert working with WolfStack, a server management platform. \
                       Servers may run different Linux distributions (Ubuntu, Debian, Fedora, RHEL, Arch, etc.) and \
                       different configurations. When suggesting fixes, give commands that work across common distros \
                       or note when a command is distro-specific. Be concise and technical — max 5-6 lines. \
                       Focus on actionable steps the admin can take right now.";

        let result = match config.provider.as_str() {
            "gemini" => call_gemini(&self.client, &config.gemini_api_key, &config.model, system, &[], issue_description).await,
            "openrouter" => call_local(&self.client, "https://openrouter.ai/api/v1", &config.openrouter_api_key, &config.model, system, &[], issue_description).await,
            "local" => call_local(&self.client, &config.local_url, &config.local_api_key, &config.model, system, &[], issue_description).await,
            _ => call_claude(&self.client, &config.claude_api_key, &config.model, system, &[], issue_description).await,
        };

        match result {
            Ok(response) => Some(response),
            Err(e) => {
                warn!("AI issue analysis failed: {}", e);
                None
            }
        }
    }
}

// ─── Knowledge Base ───

fn load_knowledge_base() -> String {
    let mut knowledge = String::new();

    // Load the expert knowledge base first (shipped with WolfStack)
    let kb_paths = [
        "/etc/wolfstack/knowledge/wolfstack-kb.md",
        "knowledge/wolfstack-kb.md",
        "../knowledge/wolfstack-kb.md",
    ];
    for kb_path in &kb_paths {
        if let Ok(content) = std::fs::read_to_string(kb_path) {
            if !content.trim().is_empty() {
                knowledge.push_str(&content);
                tracing::info!("Loaded expert knowledge base from {}", kb_path);
                break;
            }
        }
    }

    // Also load wolfscale web files for additional context
    let dirs = [KNOWLEDGE_DIR, KNOWLEDGE_DIR_DEV, "wolfscale/web", "../wolfscale/web"];
    let mut found_dir = None;

    for dir in &dirs {
        let path = std::path::Path::new(dir);
        if path.exists() && path.is_dir() {
            found_dir = Some(dir.to_string());
            break;
        }
    }

    let dir = match found_dir {
        Some(d) => d,
        None => {
            warn!("AI knowledge base directory not found, AI will have limited knowledge");
            return "WolfStack is a server management platform by Wolf Software Systems Ltd.".to_string();
        }
    };

    // Read all HTML files and extract text
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "html").unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let filename = path.file_stem().unwrap_or_default().to_string_lossy();
                    let text = strip_html_tags(&content);
                    let trimmed = text.trim();
                    if !trimmed.is_empty() && trimmed.len() > 50 {
                        knowledge.push_str(&format!("\n\n=== {} ===\n{}", filename.to_uppercase(), trimmed));
                    }
                }
            }
        }
    }

    if knowledge.is_empty() {
        "WolfStack is a server management platform by Wolf Software Systems Ltd.".to_string()
    } else {
        // Truncate to ~60KB to keep context lean and responses fast
        if knowledge.len() > 60_000 {
            knowledge.truncate(60_000);
        }
        knowledge
    }
}

/// Strip HTML tags and return plain text
fn strip_html_tags(html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;
    let lower = html.to_lowercase();
    let chars: Vec<char> = html.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();

    let mut i = 0;
    while i < chars.len() {
        if !in_tag && i + 7 < lower_chars.len() {
            let slice: String = lower_chars[i..i+7].iter().collect();
            if slice == "<script" { in_script = true; }
            if slice == "<style " || (i + 6 < lower_chars.len() && lower_chars[i..i+6].iter().collect::<String>() == "<style") {
                in_style = true;
            }
        }

        if chars[i] == '<' {
            // Check for end of script/style
            if in_script && i + 9 < lower_chars.len() {
                let slice: String = lower_chars[i..i+9].iter().collect();
                if slice == "</script>" { in_script = false; }
            }
            if in_style && i + 8 < lower_chars.len() {
                let slice: String = lower_chars[i..i+8].iter().collect();
                if slice == "</style>" { in_style = false; }
            }
            in_tag = true;
        } else if chars[i] == '>' {
            in_tag = false;
        } else if !in_tag && !in_script && !in_style {
            result.push(chars[i]);
        }
        i += 1;
    }

    // Clean up excessive whitespace
    let mut cleaned = String::new();
    let mut last_was_space = false;
    let mut newline_count = 0;
    for c in result.chars() {
        if c == '\n' || c == '\r' {
            newline_count += 1;
            if newline_count <= 2 {
                cleaned.push('\n');
            }
            last_was_space = true;
        } else if c.is_whitespace() {
            if !last_was_space {
                cleaned.push(' ');
            }
            last_was_space = true;
            newline_count = 0;
        } else {
            cleaned.push(c);
            last_was_space = false;
            newline_count = 0;
        }
    }

    // Decode common HTML entities
    cleaned
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&mdash;", "—")
        .replace("&ndash;", "–")
        .replace("&nbsp;", " ")
        .replace("&rsquo;", "'")
        .replace("&lsquo;", "'")
        .replace("&rdquo;", "\u{201d}")
        .replace("&ldquo;", "\u{201c}")
}

// ─── Safe Command Execution ───

/// Whitelist of allowed command prefixes for read-only operations
const ALLOWED_COMMANDS: &[&str] = &[
    // System info
    "uname", "hostname", "uptime", "whoami", "id", "lscpu", "lsblk", "lsmem", "lspci", "lsusb",
    "free", "df", "du", "cat /proc/", "cat /etc/os-release", "cat /etc/hostname",
    "cat /etc/hosts", "cat /etc/resolv.conf",
    "arch", "nproc", "getconf", "sysctl",
    // Process/service info
    "ps", "top -bn1", "systemctl status", "systemctl list-units", "systemctl is-active",
    "systemctl show", "journalctl",
    // Network info
    "ip addr", "ip route", "ip link", "ip neigh", "ss", "netstat",
    "ping -c", "dig", "nslookup", "host ", "traceroute", "tracepath",
    "curl -s", "curl --silent", "wget -qO-",
    // Containers
    "docker ps", "docker stats --no-stream", "docker inspect", "docker logs",
    "docker images", "docker info", "docker version", "docker network",
    "lxc-ls", "lxc-info", "lxc-config",
    // Files (read-only)
    "ls", "cat ", "head ", "tail ", "wc ", "file ", "stat ",
    "find ", "locate ", "which ", "whereis ",
    // Wolf suite status
    "wolfnet", "wolfdisk", "wolfproxy", "wolfserve", "wolfscale",
    // Misc read-only
    "date", "cal", "env", "printenv", "timedatectl", "hostnamectl",
    "dmidecode", "lshw", "sensors", "smartctl",
];

/// Commands/patterns that are explicitly blocked (destructive operations)
const BLOCKED_PATTERNS: &[&str] = &[
    "rm ", "rm -", "rmdir", "unlink",
    "dd ", "mkfs", "fdisk", "parted", "gdisk", "cfdisk",
    "shutdown", "reboot", "poweroff", "halt", "init ",
    "kill ", "kill -", "killall", "pkill",
    "mv ", "cp ", "install ",
    "chmod", "chown", "chgrp", "chattr",
    "useradd", "userdel", "usermod", "groupadd", "groupdel", "passwd",
    "visudo", "sudoers",
    "iptables -D", "iptables -F", "iptables -X", "iptables -A", "iptables -I",
    "nft ", "firewall-cmd",
    "systemctl start", "systemctl stop", "systemctl restart",
    "systemctl enable", "systemctl disable", "systemctl mask",
    "apt ", "apt-get", "dpkg -i", "dpkg -r", "dpkg -P",
    "yum ", "dnf ", "rpm -i", "rpm -e", "rpm -U",
    "pip ", "pip3 ", "npm ", "cargo ", "make ", "cmake",
    "docker rm", "docker rmi", "docker stop", "docker kill", "docker exec",
    "docker run", "docker pull", "docker push", "docker build",
    "lxc-stop", "lxc-destroy", "lxc-create", "lxc-start", "lxc-execute",
    "crontab", "at ",
    "mount ", "umount", "swapon", "swapoff",
    "insmod", "rmmod", "modprobe",
    "nano", "vim", "vi ", "emacs", "ed ", "sed -i",
    "tee ", "sponge",
    "wget ", "curl -o", "curl -O", "curl --output",
];

/// Execute a command only if it passes safety checks
pub fn execute_safe_command(cmd: &str) -> Result<String, String> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return Err("Empty command".to_string());
    }

    // Block output redirection
    if cmd.contains(" > ") || cmd.contains(" >> ") || cmd.contains(" 2>") {
        return Err("Output redirection is not allowed (read-only mode)".to_string());
    }

    // Block backtick/subshell command injection
    if cmd.contains('`') || cmd.contains("$(") {
        return Err("Command substitution is not allowed (read-only mode)".to_string());
    }

    // Check each piped segment for safety
    let segments: Vec<&str> = cmd.split('|').collect();
    for segment in &segments {
        let seg = segment.trim();

        // Check blocked patterns
        for blocked in BLOCKED_PATTERNS {
            if seg.starts_with(blocked) || seg.contains(&format!(" {}", blocked)) {
                return Err(format!("Command '{}' is blocked (read-only mode — no destructive operations)", blocked.trim()));
            }
        }
    }

    // The first command must match an allowed prefix
    let first_seg = segments[0].trim();
    let allowed = ALLOWED_COMMANDS.iter().any(|prefix| first_seg.starts_with(prefix));
    if !allowed {
        return Err(format!(
            "Command '{}' is not in the allowed list. I can only run read-only system commands like lscpu, df, ps, docker ps, etc.",
            first_seg.split_whitespace().next().unwrap_or(first_seg)
        ));
    }

    // Execute with timeout
    let output = StdCommand::new("bash")
        .arg("-c")
        .arg(cmd)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let mut result = stdout.to_string();
            if !stderr.is_empty() {
                result.push_str(&format!("\n[stderr]: {}", stderr));
            }
            // Truncate long output
            if result.len() > 10_000 {
                result.truncate(10_000);
                result.push_str("\n[output truncated at 10000 chars]");
            }
            if result.trim().is_empty() {
                result = "(no output)".to_string();
            }
            Ok(result)
        }
        Err(e) => Err(format!("Failed to execute command: {}", e)),
    }
}

// ─── Action Parsing & Execution ───

/// Advance to the next valid UTF-8 char boundary at or after `pos`
fn next_char_boundary(s: &str, pos: usize) -> usize {
    let mut i = pos;
    while i < s.len() && !s.is_char_boundary(i) { i += 1; }
    i
}

/// Parse [ACTION id="..." title="..." risk="..."]command[/ACTION] tags from AI response.
/// Action IDs from the AI are ignored — we generate secure UUIDs server-side.
fn parse_actions(response: &str) -> Vec<AiAction> {
    let mut actions = Vec::new();
    let now = chrono::Utc::now().timestamp();
    let mut search_from = 0;

    while search_from < response.len() {
        let start = match response[search_from..].find("[ACTION ") {
            Some(i) => search_from + i,
            None => break,
        };
        // Find the closing ] of the opening tag
        let tag_end = match response[start..].find(']') {
            Some(i) => start + i,
            None => break,
        };
        // Safe char-boundary advance past the ]
        let after_tag = next_char_boundary(response, tag_end + 1);
        if after_tag >= response.len() { break; }

        // Find [/ACTION]
        let content_end = match response[after_tag..].find("[/ACTION]") {
            Some(i) => after_tag + i,
            None => break,
        };

        let tag_header = &response[start..after_tag];
        let command = response[after_tag..content_end].trim().to_string();

        // Server-generated UUID — never trust AI-supplied IDs
        let id = format!("act-{:08x}", (now as u32).wrapping_mul(actions.len() as u32 + 1).wrapping_add(command.len() as u32));
        let title = extract_attr(tag_header, "title")
            .unwrap_or_else(|| "Fix".to_string());
        let risk = extract_attr(tag_header, "risk")
            .unwrap_or_else(|| "medium".to_string());
        let explanation = extract_attr(tag_header, "explain")
            .unwrap_or_default();
        let target = extract_attr(tag_header, "target")
            .unwrap_or_else(|| "local".to_string());

        if !command.is_empty() {
            actions.push(AiAction {
                id,
                title,
                command,
                risk,
                explanation,
                node_target: target,
                status: "pending".to_string(),
                created_at: now,
                result: String::new(),
                approved_by: String::new(),
            });
        }

        search_from = (content_end + 9).min(response.len());
    }

    actions
}

/// Strip [ACTION ...] ... [/ACTION] tags from text, leaving clean prose
fn strip_action_tags(text: &str) -> String {
    let mut result = text.to_string();
    loop {
        let start = match result.find("[ACTION ") {
            Some(i) => i,
            None => break,
        };
        let end = match result[start..].find("[/ACTION]") {
            Some(i) => start + i + 9,
            None => break,
        };
        result.replace_range(start..end, "");
    }
    // Clean up any double newlines left behind
    while result.contains("\n\n\n") {
        result = result.replace("\n\n\n", "\n\n");
    }
    result
}

/// Commands that are NEVER allowed even with user approval
const CATASTROPHIC_PATTERNS: &[&str] = &[
    "rm -rf /",
    "rm -rf /*",
    "dd if=/dev/zero of=/dev/sd",
    "dd if=/dev/zero of=/dev/nvme",
    "dd if=/dev/urandom of=/dev/sd",
    "mkfs /dev/sd",
    "mkfs /dev/nvme",
    ":(){ :|:&",        // fork bomb
    "> /dev/sd",
    "chmod -R 777 /",
    "chown -R",
    "rm -rf /etc",
    "rm -rf /var",
    "rm -rf /usr",
    "rm -rf /home",
    "rm -rf /root",
    "wget|sh",
    "curl|sh",
    "curl|bash",
    "wget|bash",
];

/// Execute an action command (write-capable, user-approved).
/// This allows commands that execute_safe_command blocks, but still prevents catastrophic ones.
/// Uses a 30-second timeout to prevent hanging.
pub fn execute_action_command(cmd: &str) -> Result<String, String> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return Err("Empty command".to_string());
    }

    // Normalise whitespace for pattern matching (collapse multiple spaces)
    let normalised = cmd.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();

    // Block catastrophic patterns (checked against normalised form)
    for pattern in CATASTROPHIC_PATTERNS {
        if normalised.contains(pattern) {
            return Err(format!("Command contains catastrophic pattern '{}' — blocked for safety", pattern));
        }
    }

    // Block shell injection vectors
    if cmd.contains('`') || cmd.contains("$(") || cmd.contains("<(") || cmd.contains(">(") {
        return Err("Command/process substitution is not allowed in actions".to_string());
    }

    // Execute with a 30-second timeout using `timeout` command wrapper
    let wrapped = format!("timeout 30 bash -c {}", shell_escape(cmd));

    let output = StdCommand::new("bash")
        .arg("-c")
        .arg(&wrapped)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let exit_code = out.status.code().unwrap_or(-1);

            // exit code 124 = timeout killed the command
            if exit_code == 124 {
                return Err("Command timed out after 30 seconds and was killed".to_string());
            }

            let mut result = String::new();
            if !stdout.is_empty() { result.push_str(&stdout); }
            if !stderr.is_empty() {
                if !result.is_empty() { result.push('\n'); }
                result.push_str(&format!("[stderr]: {}", stderr));
            }
            if exit_code != 0 {
                result.push_str(&format!("\n[exit code: {}]", exit_code));
            }
            if result.len() > 10_000 {
                result.truncate(10_000);
                result.push_str("\n[output truncated]");
            }
            if result.trim().is_empty() {
                result = if exit_code == 0 {
                    "(completed successfully)".to_string()
                } else {
                    format!("(no output, exit code: {})", exit_code)
                };
            }
            Ok(result)
        }
        Err(e) => Err(format!("Failed to execute: {}", e)),
    }
}

/// Shell-escape a string for safe embedding in a bash -c argument
fn shell_escape(s: &str) -> String {
    // Wrap in single quotes, escaping any embedded single quotes
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Write an audit log entry for an action
pub fn log_action_audit(action: &AiAction, event: &str, user: &str, output: &str) {
    let log_path = format!("{}/ai-actions.log", crate::paths::get().config_dir);
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Sanitize fields to prevent log injection via newlines
    let safe = |s: &str| s.replace('\n', "\\n").replace('\r', "\\r");
    let entry = format!(
        "[{}] {} | host={} user={} action_id={} title=\"{}\" risk={} target={} command=\"{}\" output_len={}\n",
        timestamp, event.to_uppercase(), hostname, safe(user), safe(&action.id), safe(&action.title),
        safe(&action.risk), safe(&action.node_target), safe(&action.command), output.len()
    );

    // Append to log file (best-effort)
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
        use std::io::Write;
        let _ = f.write_all(entry.as_bytes());
    }
}

// ─── WolfNote Tag Handler ───

/// Parse and execute [WOLFNOTE title="..."]content[/WOLFNOTE] tags in an AI response.
/// Returns the response with tags replaced by confirmation text.
async fn execute_wolfnote_tags(response: &str) -> String {
    let config = crate::wolfnote::WolfNoteConfig::load();
    if !config.is_connected() || !config.features.ai_create_notes {
        // Strip tags and return as-is with a note about not being connected
        let mut result = response.to_string();
        while let Some(start) = result.find("[WOLFNOTE") {
            if let Some(end) = result[start..].find("[/WOLFNOTE]") {
                result.replace_range(start..start + end + 11, "*[WolfNote not connected — note not saved]*");
            } else {
                break;
            }
        }
        return result;
    }

    let client = crate::wolfnote::WolfNoteClient::new(&config.url, &config.token);
    let mut result = response.to_string();

    // Process tags iteratively (can't mutate while finding)
    loop {
        let start_idx = match result.find("[WOLFNOTE") {
            Some(i) => i,
            None => break,
        };
        let end_tag = match result[start_idx..].find("[/WOLFNOTE]") {
            Some(i) => start_idx + i,
            None => break,
        };

        // Extract title from attributes: [WOLFNOTE title="..."]
        let tag_header_end = match result[start_idx..].find(']') {
            Some(i) => start_idx + i,
            None => break,
        };
        let tag_header = &result[start_idx..tag_header_end + 1];
        let title = extract_attr(tag_header, "title").unwrap_or_else(|| "Untitled Note".to_string());

        // Content is between the closing ] of the opening tag and [/WOLFNOTE]
        let raw_content = result[tag_header_end + 1..end_tag].trim().to_string();
        // Wrap with margins for readable formatting in WolfNote
        let content = format!("<div style=\"margin: 16px 20px;\">{}</div>", raw_content);

        // Use the configured AI folder
        let folder_id = if config.features.ai_folder_id.is_empty() {
            None
        } else {
            Some(config.features.ai_folder_id.as_str())
        };

        // Create the note
        let replacement = match client.create_note(&title, &content, folder_id).await {
            Ok(note) => format!("*Note \"{}\" saved to WolfNote (ID: {})*", title, note.id),
            Err(e) => format!("*Failed to save note: {}*", e),
        };

        result.replace_range(start_idx..end_tag + 11, &replacement);
    }

    result
}

/// Extract an attribute value from a tag like `[WOLFNOTE title="value"]`
fn extract_attr(tag: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr_name);
    let start = tag.find(&pattern)?;
    let value_start = start + pattern.len();
    let value_end = tag[value_start..].find('"')?;
    Some(tag[value_start..value_start + value_end].to_string())
}

// ─── System Prompt Builder ───

fn build_system_prompt(knowledge: &str, server_context: &str) -> String {
    format!(
        "You are the AI operations assistant for a WolfStack server node. You are knowledgeable, helpful, and concise.\n\n\
         ## Your Capabilities\n\
         - Answer questions about WolfStack, WolfNet, WolfDisk, WolfProxy, WolfServe, and WolfScale\n\
         - Help with server administration, container management, networking, and storage\n\
         - Explain technical concepts in plain language\n\
         - Help troubleshoot issues based on the current server state\n\
         - **Run read-only commands** on this server and across the WolfStack cluster\n\n\
         ## Command Execution\n\
         You can run commands on the server by using these special tags:\n\
         - `[EXEC]command[/EXEC]` — runs the command on the LOCAL WolfStack node only (the machine running this dashboard)\n\
         - `[EXEC_ALL]command[/EXEC_ALL]` — runs the command on ALL WolfStack nodes in the cluster. Results come back labelled by hostname.\n\n\
         **CRITICAL RULES:**\n\
         - [EXEC] ALWAYS runs on the LOCAL node — even if the user is viewing a different node in the dashboard\n\
         - When the user asks about a SPECIFIC REMOTE node (e.g. 'what is using CPU on pbs?'), you MUST use [EXEC_ALL] and then look at the results for that specific hostname in the output\n\
         - Do NOT use [EXEC] when the user asks about a remote node — [EXEC] cannot reach remote nodes\n\
         - Only read-only commands are allowed (ls, cat, lscpu, df, ps, docker ps, systemctl status, etc.)\n\
         - Destructive commands (rm, kill, reboot, etc.) are blocked and will fail\n\
         - You MUST use these tags when the user asks a question that requires live data\n\
         - Do NOT just tell the user how to run a command — run it yourself and present the results\n\
         - After receiving command output, summarize the results clearly for the user\n\
         - Keep commands simple and focused\n\
         - When showing results from [EXEC_ALL], clearly label which node each result came from\n\n\
         ## Cluster Topology\n\
         - All nodes are **equal peers** — do NOT label any node as 'main', 'primary', or 'secondary'\n\
         - Each node runs whatever components it needs; not all nodes run the same services\n\
         - Some nodes also run Proxmox VE — they are full WolfStack nodes AND Proxmox hypervisors\n\
         - [EXEC_ALL] targets ALL online nodes including Proxmox nodes (they all have WolfStack agents)\n\
         - Do NOT assume a service should be running on a node just because it runs on others\n\n\
         ## Proxmox Nodes\n\
         - Proxmox nodes have WolfStack agents — you CAN execute commands on them via [EXEC_ALL]\n\
         - They appear in both the WolfStack node list and as Proxmox hypervisors\n\
         - Proxmox data (VM/CT counts, per-guest CPU) is shown in the server state below\n\
         - When reporting on the full infrastructure, include Proxmox node health data (CPU, RAM, disk)\n\n\
         ## Proposed Actions (Fix It)\n\
         When you identify a problem and know how to fix it, propose the fix using ACTION tags.\n\
         The user will see each proposed action as a card with an Approve or Dismiss button.\n\
         The command is ONLY executed after the user explicitly approves it.\n\n\
         Format:\n\
         `[ACTION id=\"unique-id\" title=\"Short Title\" risk=\"low|medium|high\" explain=\"Why this fixes it\" target=\"local|all\"]command here[/ACTION]`\n\n\
         Rules:\n\
         - Always explain what the command does and why it will fix the problem\n\
         - Set risk appropriately: low = restarts/reloads, medium = config changes/installs, high = disk/network/user changes\n\
         - Use target=\"all\" only when the fix needs to run on every cluster node\n\
         - You can propose multiple actions — they are independent, user approves each one\n\
         - NEVER tell the user to run a command manually if you can propose it as an action instead\n\
         - Group related commands into a single action when they must run together\n\
         - After diagnosing an issue, ALWAYS offer to fix it with an ACTION if a fix exists\n\n\
         Examples:\n\
         `[ACTION id=\"restart-nginx\" title=\"Restart Nginx\" risk=\"low\" explain=\"Nginx config is valid but the service needs a reload to pick up changes\" target=\"local\"]systemctl restart nginx[/ACTION]`\n\
         `[ACTION id=\"fix-dns\" title=\"Fix DNS Resolver\" risk=\"medium\" explain=\"/etc/resolv.conf is empty, adding Google DNS as a fallback\" target=\"local\"]echo 'nameserver 8.8.8.8' >> /etc/resolv.conf[/ACTION]`\n\n\
         ## WolfNote Integration\n\
         You can create notes in the user's WolfNote account using this tag:\n\
         `[WOLFNOTE title=\"Note Title\"]Note content here (plain text or HTML)[/WOLFNOTE]`\n\n\
         Use this when the user asks you to:\n\
         - Create a note, save something, write it down, or document something\n\
         - Log an event, create a report, or save findings\n\
         - \"Remember this\" or \"note this down\"\n\n\
         Rules:\n\
         - Always include a descriptive title\n\
         - Content can be plain text or simple HTML (paragraphs, lists, bold, etc.)\n\
         - After creating, confirm to the user what was saved\n\
         - Only use this tag when the user explicitly asks to create/save a note\n\n\
         ## Current Server State\n{}\n\n\
         ## Wolf Software Knowledge Base\n\
         Below is comprehensive documentation about the Wolf software suite:\n{}",
        server_context, knowledge
    )
}

// ─── LLM API Calls ───

/// Call a local/self-hosted AI via the OpenAI-compatible chat completions API.
/// Works with: Ollama, LM Studio, LocalAI, vLLM, text-generation-webui, llama.cpp server.
async fn call_local(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    model: &str,
    system: &str,
    history: &[ChatMessage],
    user_msg: &str,
) -> Result<String, String> {
    if base_url.is_empty() {
        return Err("Local AI URL not configured — set it in Settings → AI Agent".to_string());
    }

    // Build the URL — append /chat/completions if not already present
    let url = if base_url.ends_with("/chat/completions") {
        base_url.to_string()
    } else {
        let base = base_url.trim_end_matches('/');
        if base.ends_with("/v1") {
            format!("{}/chat/completions", base)
        } else {
            format!("{}/v1/chat/completions", base)
        }
    };

    let mut messages = vec![
        serde_json::json!({"role": "system", "content": system})
    ];

    for msg in history {
        messages.push(serde_json::json!({
            "role": msg.role,
            "content": msg.content
        }));
    }

    messages.push(serde_json::json!({
        "role": "user",
        "content": user_msg
    }));

    let body = serde_json::json!({
        "model": model,
        "messages": messages,
        "max_tokens": 4096,
        "temperature": 0.7,
    });

    let mut req = client.post(&url)
        .header("content-type", "application/json")
        .json(&body);

    // Add API key if provided (some local servers need it, most don't)
    if !api_key.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", api_key));
    }

    let resp = req.send().await
        .map_err(|e| format!("Local AI connection failed ({}): {}", url, e))?;

    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("Local AI response error: {}", e))?;

    if !status.is_success() {
        return Err(format!("Local AI returned {} — {}", status, text.chars().take(500).collect::<String>()));
    }

    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("Local AI JSON parse error: {}", e))?;

    // OpenAI format: {"choices": [{"message": {"content": "..."}}]}
    json["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Unexpected local AI response format: {}", text.chars().take(200).collect::<String>()))
}

async fn call_claude(
    client: &reqwest::Client,
    api_key: &str,
    model: &str,
    system: &str,
    history: &[ChatMessage],
    user_msg: &str,
) -> Result<String, String> {
    let mut messages = Vec::new();

    // Add conversation history
    for msg in history {
        messages.push(serde_json::json!({
            "role": msg.role,
            "content": msg.content
        }));
    }

    // Add current user message
    messages.push(serde_json::json!({
        "role": "user",
        "content": user_msg
    }));

    let body = serde_json::json!({
        "model": model,
        "max_tokens": 4096,
        "system": system,
        "messages": messages,
    });

    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Claude API error: {}", e))?;

    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("Claude response error: {}", e))?;

    if !status.is_success() {
        let lower = text.to_lowercase();
        if status.as_u16() == 429 || lower.contains("rate_limit") || lower.contains("quota") || lower.contains("resource_exhausted") {
            return Err("Claude API rate limit or quota exceeded. Try switching to Gemini in AI Settings.".to_string());
        }
        if lower.contains("credit") || lower.contains("billing") || lower.contains("insufficient") {
            return Err("Claude API credits exhausted. Try switching to Gemini in AI Settings, or top up your Anthropic account.".to_string());
        }
        if lower.contains("token") && (lower.contains("limit") || lower.contains("exceeded") || lower.contains("too long")) {
            return Err("Claude token limit exceeded — your conversation may be too long. Try starting a fresh chat or switching to Gemini in AI Settings.".to_string());
        }
        return Err(format!("Claude API {} — {}", status, text));
    }

    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("Claude JSON error: {}", e))?;

    json["content"][0]["text"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Unexpected Claude response format: {}", text))
}

async fn call_gemini(
    client: &reqwest::Client,
    api_key: &str,
    model: &str,
    system: &str,
    history: &[ChatMessage],
    user_msg: &str,
) -> Result<String, String> {
    // Map model name — default for Gemini
    let model_name = if model.starts_with("gemini") { model } else { "gemini-2.0-flash" };

    let mut contents = Vec::new();

    // Add conversation history
    for msg in history {
        let role = if msg.role == "assistant" { "model" } else { "user" };
        contents.push(serde_json::json!({
            "role": role,
            "parts": [{"text": msg.content}]
        }));
    }

    // Add current user message
    contents.push(serde_json::json!({
        "role": "user",
        "parts": [{"text": user_msg}]
    }));

    let body = serde_json::json!({
        "system_instruction": {
            "parts": [{"text": system}]
        },
        "contents": contents,
        "generationConfig": {
            "maxOutputTokens": 4096,
        }
    });

    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
        model_name, api_key
    );

    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Gemini API error: {}", e))?;

    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("Gemini response error: {}", e))?;

    if !status.is_success() {
        let lower = text.to_lowercase();
        if status.as_u16() == 429 || lower.contains("rate_limit") || lower.contains("quota") || lower.contains("resource_exhausted") {
            return Err("Gemini API rate limit or quota exceeded. Try switching to Claude in AI Settings.".to_string());
        }
        if lower.contains("billing") || lower.contains("insufficient") {
            return Err("Gemini API quota exhausted. Try switching to Claude in AI Settings, or check your Google Cloud billing.".to_string());
        }
        if lower.contains("token") && (lower.contains("limit") || lower.contains("exceeded") || lower.contains("too long")) {
            return Err("Gemini token limit exceeded — your conversation may be too long. Try starting a fresh chat or switching to Claude in AI Settings.".to_string());
        }
        return Err(format!("Gemini API {} — {}", status, text));
    }

    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("Gemini JSON error: {}", e))?;

    json["candidates"][0]["content"]["parts"][0]["text"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Unexpected Gemini response format: {}", text))
}

// ─── Email Alerts ───

pub fn send_alert_email(config: &AiConfig, subject: &str, body: &str) -> Result<(), String> {
    use lettre::{Message, SmtpTransport, Transport};
    use lettre::transport::smtp::authentication::Credentials;

    let email = Message::builder()
        .from(format!("WolfStack AI <{}>", config.smtp_user).parse().map_err(|e| format!("Email from: {}", e))?)
        .to(config.email_to.parse().map_err(|e| format!("Email to: {}", e))?)
        .subject(subject)
        .body(body.to_string())
        .map_err(|e| format!("Email build: {}", e))?;

    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_pass.clone());

    let mailer = match config.smtp_tls.as_str() {
        "tls" => {
            // Implicit TLS (port 465 typically)
            SmtpTransport::relay(&config.smtp_host)
                .map_err(|e| format!("SMTP relay: {}", e))?
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        }
        "none" => {
            // No encryption
            SmtpTransport::builder_dangerous(&config.smtp_host)
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        }
        _ => {
            // STARTTLS (default, port 587 typically)
            SmtpTransport::starttls_relay(&config.smtp_host)
                .map_err(|e| format!("SMTP STARTTLS: {}", e))?
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        }
    };

    mailer.send(&email).map_err(|e| format!("SMTP send: {}", e))?;

    Ok(())
}

/// Send an HTML email (used for the daily report with tables)
pub fn send_html_email(config: &AiConfig, subject: &str, html_body: &str) -> Result<(), String> {
    use lettre::{Message, SmtpTransport, Transport};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::message::{SinglePart, header::ContentType};

    let email = Message::builder()
        .from(format!("WolfStack AI <{}>", config.smtp_user).parse().map_err(|e| format!("Email from: {}", e))?)
        .to(config.email_to.parse().map_err(|e| format!("Email to: {}", e))?)
        .subject(subject)
        .singlepart(SinglePart::builder()
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string()))
        .map_err(|e| format!("Email build: {}", e))?;

    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_pass.clone());

    let mailer = match config.smtp_tls.as_str() {
        "tls" => {
            SmtpTransport::relay(&config.smtp_host)
                .map_err(|e| format!("SMTP relay: {}", e))?
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        }
        "none" => {
            SmtpTransport::builder_dangerous(&config.smtp_host)
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        }
        _ => {
            SmtpTransport::starttls_relay(&config.smtp_host)
                .map_err(|e| format!("SMTP STARTTLS: {}", e))?
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        }
    };

    mailer.send(&email).map_err(|e| format!("SMTP send: {}", e))?;
    Ok(())
}

// ─── Metrics Summary Builder ───

/// Get the top processes by CPU and memory usage (for AI analysis)
fn get_top_processes() -> Option<String> {
    // ps aux sorted by CPU, top 10 (skip header)
    let output = std::process::Command::new("ps")
        .args(["aux", "--sort=-pcpu"])
        .output()
        .ok()?;

    if !output.status.success() { return None; }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() { return None; }

    let header = lines.remove(0);
    // Take top 10 processes, format as a compact table
    let mut result = format!("  {}\n", header);
    for line in lines.iter().take(10) {
        result.push_str(&format!("  {}\n", line));
    }
    Some(result)
}

pub fn build_metrics_summary(
    hostname: &str,
    cpu_percent: f32,
    memory_used_gb: f64,
    memory_total_gb: f64,
    disk_used_gb: f64,
    disk_total_gb: f64,
    docker_count: u32,
    lxc_count: u32,
    vm_count: u32,
    uptime_secs: u64,
    guest_cpu_stats: Option<&[(&str, &str, u64, &str, f32)]>, // (pve_node, guest_type, vmid, name, cpu_percent)
    k8s_summary: Option<&str>,
) -> String {
    let mem_percent = if memory_total_gb > 0.0 { (memory_used_gb / memory_total_gb * 100.0) as u32 } else { 0 };
    let disk_percent = if disk_total_gb > 0.0 { (disk_used_gb / disk_total_gb * 100.0) as u32 } else { 0 };
    let uptime_hours = uptime_secs / 3600;
    let uptime_days = uptime_hours / 24;
    let version = env!("CARGO_PKG_VERSION");

    let mut summary = format!(
        "Hostname: {}\n\
         WolfStack Version: {}\n\
         CPU Usage: {:.1}%\n\
         Memory: {:.1}/{:.1} GB ({}%)\n\
         Disk: {:.1}/{:.1} GB ({}%)\n\
         Docker Containers: {}\n\
         LXC Containers: {}\n\
         Virtual Machines: {}\n\
         Uptime: {} days {} hours",
        hostname,
        version,
        cpu_percent,
        memory_used_gb, memory_total_gb, mem_percent,
        disk_used_gb, disk_total_gb, disk_percent,
        docker_count,
        lxc_count,
        vm_count,
        uptime_days, uptime_hours % 24,
    );

    // When CPU or memory is elevated, include top processes so the AI can identify the cause
    if cpu_percent > 50.0 || mem_percent > 75 {
        if let Some(top_procs) = get_top_processes() {
            summary.push_str("\n\nTop Processes (by CPU):\n");
            summary.push_str(&top_procs);
        }
    }

    // Append per-guest CPU stats if available (from Proxmox nodes)
    if let Some(stats) = guest_cpu_stats {
        let running: Vec<_> = stats.iter().filter(|(_, _, _, _, cpu)| *cpu > 0.0).collect();
        if !running.is_empty() {
            summary.push_str("\n\nProxmox Guest CPU Usage:");
            for (pve_node, gtype, vmid, name, cpu) in running {
                let label = if *gtype == "lxc" { "LXC" } else { "VM" };
                summary.push_str(&format!(
                    "\n  {} {} ({}) on {}: {:.1}%",
                    label, vmid, name, pve_node, cpu * 100.0
                ));
            }
        }
    }

    // Append Kubernetes cluster health if available
    if let Some(k8s) = k8s_summary {
        summary.push_str("\n\n");
        summary.push_str(k8s);
    }

    summary
}
