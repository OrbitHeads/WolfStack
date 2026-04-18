// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Telegram receiver — long-polls the Bot API for messages in chats
//! bound to WolfAgents and replies with the agent's response.
//!
//! Much simpler than the Discord gateway: Telegram exposes HTTP
//! long-polling (`getUpdates`) so we just issue one outstanding GET
//! per tick, handle whatever comes back, and use `offset` to
//! acknowledge. No gateway, no heartbeat, no session resume.
//!
//! Security posture:
//!
//! * **Bot token** lives in `AlertConfig.telegram_bot_token` — same
//!   field already used for outbound alerts. The receiver will only
//!   run when the operator toggles it on (separate flag so users who
//!   only want outbound alerts don't get surprised inbound flows).
//! * **Abuse guard**: same `chat_with_agent` rate limit as Discord.
//! * **Authorisation model**: chat binding on the agent. Only
//!   messages in the bound chat_id route to the agent. Telegram DMs
//!   and groups both work — the chat_id identifies either.
//! * **Bot reply loop**: we skip messages where `from.is_bot` is
//!   true, same as Discord.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

/// Minimal shape of a Telegram `Message`. Only fields we route on.
#[derive(Debug, Clone, Deserialize)]
struct TgMessage {
    message_id: i64,
    #[serde(default)]
    text: Option<String>,
    chat: TgChat,
    from: Option<TgUser>,
}

#[derive(Debug, Clone, Deserialize)]
struct TgChat {
    id: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct TgUser {
    #[serde(default)]
    is_bot: bool,
}

/// `getUpdates` response envelope.
#[derive(Debug, Deserialize)]
struct TgUpdatesResponse {
    ok: bool,
    #[serde(default)]
    result: Vec<TgUpdate>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TgUpdate {
    update_id: i64,
    #[serde(default)]
    message: Option<TgMessage>,
}

/// Payload sent to `sendMessage`. We only use `chat_id` + `text` — no
/// formatting, no reply markup. Keeps rendering surprises minimal.
#[derive(Debug, Serialize)]
struct TgSendMessage<'a> {
    chat_id: i64,
    text: &'a str,
}

/// One long-polling cycle: issue a `getUpdates` with a 50-second
/// timeout, dispatch any received messages, advance `offset` past
/// the last update, return the new offset.
async fn poll_once(
    http: &reqwest::Client,
    bot_token: &str,
    offset: i64,
) -> Result<i64, String> {
    let url = format!(
        "https://api.telegram.org/bot{}/getUpdates?timeout=50&offset={}",
        bot_token, offset
    );
    let resp = http.get(&url)
        .timeout(Duration::from_secs(65))
        .send().await
        .map_err(|e| format!("http: {}", e))?;
    let status = resp.status();
    let body: TgUpdatesResponse = resp.json().await
        .map_err(|e| format!("decode: {}", e))?;
    if !status.is_success() || !body.ok {
        return Err(format!(
            "Telegram API {}: {}",
            status.as_u16(),
            body.description.unwrap_or_default()
        ));
    }
    let mut next_offset = offset;
    for upd in body.result {
        // Always advance past this update so retries don't replay it,
        // even if we decide not to process it.
        next_offset = next_offset.max(upd.update_id + 1);
        let Some(msg) = upd.message else { continue; };
        let Some(text) = msg.text.clone() else { continue; };
        if let Some(from) = &msg.from {
            if from.is_bot { continue; }
        }
        let chat_id = msg.chat.id;
        // Route to the agent bound to this chat.
        let agents = crate::wolfagents::load_all();
        let Some(agent) = agents.iter().find(|a|
            a.telegram.as_ref().map(|t| t.chat_id.as_str()) == Some(&chat_id.to_string())
        ).cloned() else { continue; };
        let http_reply = http.clone();
        let token = bot_token.to_string();
        let content = text;
        tokio::spawn(async move {
            handle_telegram_chat(http_reply, &token, &agent, chat_id, content, msg.message_id).await;
        });
    }
    Ok(next_offset)
}

/// Run one agent turn for a Telegram message and post the reply back
/// to the same chat. Truncates over-long replies at 4000 chars
/// (Telegram's 4096 cap with a safety margin + a suffix so the user
/// knows it was clipped).
async fn handle_telegram_chat(
    http: reqwest::Client,
    bot_token: &str,
    agent: &crate::wolfagents::Agent,
    chat_id: i64,
    content: String,
    _source_msg_id: i64,
) {
    let content = content.trim();
    if content.is_empty() { return; }
    let reply = match crate::wolfagents::chat_with_agent(&agent.id, content).await {
        Ok(r) => r,
        Err(e) => format!("(agent error) {}", e),
    };
    let out = if reply.len() > 4000 {
        format!("{}\n…(truncated)", &reply[..4000])
    } else {
        reply
    };
    if let Err(e) = send_telegram_message(&http, bot_token, chat_id, &out).await {
        warn!("telegram_bot: reply failed for agent {} chat {}: {}",
            agent.id, chat_id, e);
    }
}

async fn send_telegram_message(
    http: &reqwest::Client,
    bot_token: &str,
    chat_id: i64,
    text: &str,
) -> Result<(), String> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    let payload = TgSendMessage { chat_id, text };
    let resp = http.post(&url)
        .json(&payload)
        .send().await
        .map_err(|e| format!("http: {}", e))?;
    if !resp.status().is_success() {
        let code = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Telegram API {}: {}", code, body.chars().take(200).collect::<String>()));
    }
    Ok(())
}

/// Supervisor: loops forever, (re)starts a long-polling loop whenever
/// the operator has both a bot token AND the receiver flag enabled.
/// When misconfigured or disabled, sleeps and re-checks.
pub async fn supervise_forever() {
    tokio::time::sleep(Duration::from_secs(30)).await;
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("telegram_bot: cannot build http client: {}", e);
            return;
        }
    };
    let mut offset: i64 = 0;
    loop {
        let cfg = crate::alerting::AlertConfig::load();
        if cfg.telegram_bot_token.trim().is_empty() || !cfg.telegram_receiver_enabled {
            // Not enabled — sleep and re-check.
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
        }
        match poll_once(&http, &cfg.telegram_bot_token, offset).await {
            Ok(next) => {
                if next != offset {
                    info!("telegram_bot: advanced offset {} → {}", offset, next);
                }
                offset = next;
            }
            Err(e) => {
                warn!("telegram_bot: poll error — {}", e);
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}
