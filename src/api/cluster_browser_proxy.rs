// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Cluster Browser reverse proxy — tunnels every browser-session
//! HTTP request and WebSocket upgrade through WolfStack's own port
//! (8553) instead of exposing per-session ports (33000-33999) directly.
//!
//! Why: browsers/CDNs/reverse proxies in real deployments routinely
//! restrict ws(s) traffic to 80/443/8080. A selkies stream on
//! ws://host:33001 works on a LAN but falls over behind Cloudflare,
//! corporate HTTP proxies, or any setup that only allows well-known
//! ports through. Routing everything over the same port WolfStack
//! already listens on means the cluster browser works wherever
//! WolfStack does. Same pattern used by /ws/console and /ws/pve-vnc.
//!
//! Route: /api/cluster-browser/session/{id}/{tail:.*}
//!   - auth-gated (cookie session)
//!   - strips the /api/cluster-browser/session/{id}/ prefix
//!   - WebSocket upgrades bridged via tokio-tungstenite
//!   - plain HTTP proxied via reqwest with streaming bodies

use actix_web::{web, HttpRequest, HttpResponse, Error};
use actix_ws::Message;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;
use tracing::{error, warn};

use super::AppState;

/// Headers that must NOT be copied end-to-end (hop-by-hop per RFC 7230).
/// Also strip `host` since reqwest sets it from the target URL.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

/// Look up a session's local (127.0.0.1) port. Returns None if no
/// matching session exists on this node — the caller turns that into
/// a 404.
fn session_port(id: &str) -> Option<u16> {
    crate::cluster_browser::list_sessions()
        .into_iter()
        .find(|s| s.id == id)
        .map(|s| s.web_port)
}

/// Unified entry point: same URL serves HTTP assets, SPA JS, and the
/// selkies /websocket upgrade — actix routes both through here. We
/// peek at the `Upgrade` header to pick the bridge vs the HTTP path.
pub async fn cluster_browser_proxy(
    req: HttpRequest,
    state: web::Data<AppState>,
    payload: web::Payload,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_auth(&req, &state) {
        return Ok(resp);
    }

    let (id, tail) = path.into_inner();
    let port = match session_port(&id) {
        Some(p) => p,
        None => {
            return Ok(HttpResponse::NotFound()
                .json(serde_json::json!({ "error": "Session not found on this node" })));
        }
    };

    let upgrade_is_ws = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if upgrade_is_ws {
        proxy_websocket(req, payload, port, tail).await
    } else {
        proxy_http(req, payload, port, tail).await
    }
}

/// HTTP proxy leg — reissues the client's request against
/// http://127.0.0.1:{port}/{tail}?{query} and streams the upstream
/// response back. Selkies asset bundles are chunked/streaming, so
/// we pipe the body rather than buffering.
async fn proxy_http(
    req: HttpRequest,
    mut payload: web::Payload,
    port: u16,
    tail: String,
) -> Result<HttpResponse, Error> {
    let query = req.query_string();
    let target = if query.is_empty() {
        format!("http://127.0.0.1:{}/{}", port, tail)
    } else {
        format!("http://127.0.0.1:{}/{}?{}", port, tail, query)
    };

    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("bad method: {}", e)))?;

    // Read the full client body. Selkies POSTs are tiny config/input
    // blobs; streaming the request body through reqwest would need a
    // channel bridge. For now buffer — responses stream fine.
    let mut body_bytes = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(actix_web::error::ErrorBadRequest)?;
        body_bytes.extend_from_slice(&chunk);
    }

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let mut builder = client.request(method, &target).body(body_bytes.freeze());
    for (name, val) in req.headers() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        if let Ok(v) = val.to_str() {
            builder = builder.header(name.as_str(), v);
        }
    }

    let upstream = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!("cluster_browser proxy upstream error: {}", e);
            return Ok(HttpResponse::BadGateway().body(format!("upstream error: {}", e)));
        }
    };

    let status = actix_web::http::StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = HttpResponse::build(status);
    for (name, val) in upstream.headers() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        resp.insert_header((name.as_str(), val.to_str().unwrap_or("")));
    }
    let stream = upstream
        .bytes_stream()
        .map(|r| r.map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string())));
    Ok(resp.streaming(stream))
}

/// WebSocket bridge — accept the browser upgrade, open a ws:// client
/// to the container's /websocket (or whatever path selkies put there),
/// pump frames in both directions until either side closes.
async fn proxy_websocket(
    req: HttpRequest,
    payload: web::Payload,
    port: u16,
    tail: String,
) -> Result<HttpResponse, Error> {
    let query = req.query_string();
    let upstream_url = if query.is_empty() {
        format!("ws://127.0.0.1:{}/{}", port, tail)
    } else {
        format!("ws://127.0.0.1:{}/{}?{}", port, tail, query)
    };

    let (upstream, _resp) = match tokio_tungstenite::connect_async(&upstream_url).await {
        Ok(pair) => pair,
        Err(e) => {
            error!("cluster_browser proxy ws connect failed {}: {}", upstream_url, e);
            return Ok(HttpResponse::BadGateway()
                .json(serde_json::json!({ "error": format!("ws connect failed: {}", e) })));
        }
    };

    // actix-ws defaults to a 64 KB max frame size — selkies streams
    // H264 video frames well over that (hundreds of KB, sometimes MB
    // for keyframes). Without bumping this, big frames get rejected
    // and the data WS closes without a clean close frame, which is
    // exactly the "client connected, then dropped" symptom in the
    // container's pcmflux/data_websocket logs.
    let (res, session, msg_stream) = actix_ws::handle(&req, payload)?;
    let msg_stream = msg_stream.max_frame_size(16 * 1024 * 1024);
    actix_rt::spawn(ws_bridge(session, msg_stream, upstream));
    Ok(res)
}

/// Ferry messages between the browser's actix_ws session and the
/// container's tungstenite client. Binary/Text/Ping/Close each map
/// 1:1 across the two stacks.
async fn ws_bridge(
    mut browser: actix_ws::Session,
    mut browser_rx: actix_ws::MessageStream,
    upstream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) {
    let (mut up_tx, mut up_rx) = upstream.split();

    loop {
        tokio::select! {
            // Container → browser
            up_msg = up_rx.next() => {
                match up_msg {
                    Some(Ok(tungstenite::Message::Binary(b))) => {
                        if browser.binary(b.to_vec()).await.is_err() { break; }
                    }
                    Some(Ok(tungstenite::Message::Text(t))) => {
                        if browser.text(t.to_string()).await.is_err() { break; }
                    }
                    Some(Ok(tungstenite::Message::Ping(b))) => {
                        let _ = browser.ping(&b).await;
                    }
                    Some(Ok(tungstenite::Message::Pong(_))) => {}
                    Some(Ok(tungstenite::Message::Close(_))) | None => break,
                    Some(Ok(tungstenite::Message::Frame(_))) => {}
                    Some(Err(e)) => {
                        warn!("cluster_browser ws upstream read: {}", e);
                        break;
                    }
                }
            }
            // Browser → container
            br_msg = browser_rx.next() => {
                match br_msg {
                    Some(Ok(Message::Binary(b))) => {
                        if up_tx.send(tungstenite::Message::Binary(b.to_vec().into())).await.is_err() { break; }
                    }
                    Some(Ok(Message::Text(t))) => {
                        if up_tx.send(tungstenite::Message::Text(t.to_string().into())).await.is_err() { break; }
                    }
                    Some(Ok(Message::Ping(b))) => {
                        let _ = browser.pong(&b).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    let _ = browser.close(None).await;
}
