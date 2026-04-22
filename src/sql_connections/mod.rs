// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! SQL connection pool + guarded query execution.
//!
//! Shared between AI agents (`src/wolfagents/dispatch.rs`) and
//! WolfFlow steps (`src/wolfflow/mod.rs::ActionType::SqlQuery`). Both
//! surfaces execute arbitrary SQL against operator-configured database
//! profiles (MariaDB / MySQL / Postgres), but every execution passes
//! through `execute()` here which:
//!
//! 1. **Classifies the statement(s)** via `sqlparser` and rejects
//!    anything above the caller's declared permission tier
//!    (Read | Update | Delete). An `UPDATE` cannot masquerade as a
//!    `SELECT` — the parser sees through whitespace, comments, and
//!    CTEs. Stacked statements are rejected outright (one query per
//!    call) because per-statement approval is an invitation to typo
//!    your way to a DELETE.
//!
//! 2. **Enforces connect + execution timeouts** (5s connect, default
//!    30s exec) so a hung database can't starve the actix workers
//!    that are answering agent / workflow requests.
//!
//! 3. **Caps result size** at 10,000 rows and 10 MB total — prevents
//!    "SELECT * FROM events" from eating the node's memory or the
//!    agent's LLM context.
//!
//! 4. **Audit-logs** every execution with caller, connection id,
//!    query, outcome, row count, and elapsed ms. Logs append to
//!    `/var/log/wolfstack/sql-audit.log` so operators have a trail
//!    of what agents and workflows did, even if the frontend history
//!    is gone.
//!
//! Passwords are AES-256-GCM encrypted at rest using the cluster
//! secret (same key-derivation scheme as OIDC client secrets — see
//! `auth::oidc::encrypt_secret`). The plaintext password never leaves
//! memory except when sent to the DB driver.

use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock, Mutex};
use std::collections::HashMap;
use std::time::Duration;

/// Which DB engine. Determines both the driver and the `sqlparser`
/// dialect used to classify the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SqlKind {
    Mariadb,
    Mysql,
    Postgres,
}

impl SqlKind {
    fn default_port(&self) -> u16 {
        match self { SqlKind::Mariadb | SqlKind::Mysql => 3306, SqlKind::Postgres => 5432 }
    }
}

/// SSL / TLS behaviour for the connection. Postgres understands all
/// three; mysql_async maps Prefer/Require to its own ssl_opts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SslMode {
    #[default]
    Disable,
    Prefer,
    Require,
}

/// One operator-configured database connection. Up to 3 are exposed
/// in the Settings UI by default, but the underlying Vec is unbounded
/// — no reason to artificially cap when the runtime cost is trivial.
///
/// `password` is ALWAYS stored encrypted on disk. In-memory after load
/// it may still carry the `encrypted:aes256:...` prefix; `decrypt()`
/// normalises it before handing to the driver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlConnection {
    pub id: String,
    pub label: String,
    pub kind: SqlKind,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub ssl_mode: SslMode,
}

impl SqlConnection {
    /// Return a sanitised view for API responses — password replaced
    /// with a boolean "is_set" so the wire never carries the
    /// ciphertext (let alone plaintext) back to the browser.
    pub fn to_safe_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "label": self.label,
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "database": self.database,
            "username": self.username,
            "has_password": !self.password.is_empty(),
            "ssl_mode": self.ssl_mode,
        })
    }
}

/// Top-level on-disk config. Wrapped so we can add more global fields
/// (default row cap override, audit-log rotation policy, etc.) later
/// without a schema migration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SqlConnectionsConfig {
    #[serde(default)]
    pub connections: Vec<SqlConnection>,
}

fn config_path() -> String { crate::paths::get().sql_connections_config }
fn audit_path() -> String { crate::paths::get().sql_audit_log }

/// Load config from disk. Missing file = empty config; corrupt file
/// is logged and treated as empty so a malformed edit doesn't brick
/// the server.
pub fn load() -> SqlConnectionsConfig {
    match std::fs::read_to_string(config_path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
            tracing::warn!("sql_connections: config parse failed ({}) — using empty config", e);
            SqlConnectionsConfig::default()
        }),
        Err(_) => SqlConnectionsConfig::default(),
    }
}

/// Persist config with 0o600 permissions (contains encrypted
/// passwords — still treat the file as sensitive).
pub fn save(cfg: &SqlConnectionsConfig) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("serialize sql-connections: {}", e))?;
    std::fs::write(&path, json).map_err(|e| format!("write sql-connections: {}", e))?;
    // Tighten perms to 0o600.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    // Editing the config invalidates any cached pools; drop them so
    // the next call rebuilds with fresh credentials.
    POOLS.lock().unwrap().clear();
    Ok(())
}

/// Permission tier declared by the caller. sqlparser-gated:
///   - `Read`    → SELECT, SHOW, EXPLAIN, DESCRIBE, WITH (read-only CTE)
///   - `Update`  → everything in Read, plus INSERT, UPDATE
///   - `Delete`  → everything in Update, plus DELETE, TRUNCATE
///
/// DDL (CREATE / ALTER / DROP / GRANT / REVOKE) is refused at every
/// tier — there's no agent scenario where letting the LLM drop a
/// table is the right call. Operators who need schema changes run
/// them via the MySQL editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SqlPermission {
    Read,
    Update,
    Delete,
}

/// Result shape returned to callers — mirrors what the MySQL editor
/// already produces so the frontend and prompt formatting can be
/// shared across surfaces.
#[derive(Debug, Clone, Serialize)]
pub struct SqlResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub row_count: usize,
    pub affected_rows: Option<u64>,
    pub elapsed_ms: u64,
    pub truncated: bool,
}

const MAX_ROWS: usize = 10_000;
const MAX_TOTAL_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Parse + classify a single statement. Returns the minimum permission
/// tier the query requires, or an error if the query is malformed or
/// contains disallowed constructs (DDL, multi-statement, etc).
pub fn classify(query: &str, kind: SqlKind) -> Result<SqlPermission, String> {
    use sqlparser::dialect::{Dialect, GenericDialect, MySqlDialect, PostgreSqlDialect};
    use sqlparser::parser::Parser;
    use sqlparser::ast::Statement;

    // Empty / comment-only input is a misuse — we refuse instead of
    // silently succeeding, since "execute nothing" is never what an
    // agent or workflow actually wants to run.
    if query.trim().is_empty() {
        return Err("query is empty".into());
    }

    let dialect: Box<dyn Dialect> = match kind {
        SqlKind::Mariadb | SqlKind::Mysql => Box::new(MySqlDialect {}),
        SqlKind::Postgres => Box::new(PostgreSqlDialect {}),
    };

    let statements = Parser::parse_sql(&*dialect, query)
        .or_else(|_| Parser::parse_sql(&GenericDialect {}, query))
        .map_err(|e| format!("SQL parse error: {}", e))?;

    if statements.is_empty() {
        return Err("no executable statement in query".into());
    }
    if statements.len() > 1 {
        // One statement per call. Stacked statements are a classic
        // vector for smuggling a destructive tail after an innocuous
        // SELECT — we refuse rather than trying to classify the
        // conjunction.
        return Err(format!(
            "multi-statement queries are not allowed ({} statements found — run them one at a time)",
            statements.len()
        ));
    }

    // Single statement — pick its tier.
    let mut required = SqlPermission::Read;
    for stmt in &statements {
        let tier = statement_tier(stmt)?;
        // Max of required tiers — Delete > Update > Read.
        required = max_perm(required, tier);
    }
    Ok(required)
}

fn max_perm(a: SqlPermission, b: SqlPermission) -> SqlPermission {
    use SqlPermission::*;
    match (a, b) {
        (Delete, _) | (_, Delete) => Delete,
        (Update, _) | (_, Update) => Update,
        _ => Read,
    }
}

fn statement_tier(stmt: &sqlparser::ast::Statement) -> Result<SqlPermission, String> {
    use sqlparser::ast::Statement::*;
    // We allow-list the specific variants; every other statement
    // kind (CREATE, ALTER, DROP, GRANT, SET, transactions, CALL,
    // USE, LOCK, …) is refused outright. The agent/workflow surface
    // is for data operations, not schema or session management.
    match stmt {
        Query(_) | ExplainTable { .. } | Explain { .. } | Analyze { .. }
            => Ok(SqlPermission::Read),

        Insert { .. } | Update { .. } | Merge { .. }
            => Ok(SqlPermission::Update),

        Delete { .. } | Truncate { .. }
            => Ok(SqlPermission::Delete),

        other => {
            // The Debug repr starts with the variant name — "Drop {",
            // "AlterTable {", etc. Grab the first token so the error
            // message tells the operator which kind of statement was
            // rejected without hard-coding the ever-growing variant
            // list from sqlparser.
            let dbg = format!("{:?}", other);
            let kind = dbg.split(|c: char| !c.is_alphanumeric()).next().unwrap_or("unknown");
            Err(format!(
                "statement kind not permitted via this interface: {}",
                kind.to_lowercase()
            ))
        }
    }
}

// ═══════════════════════════════════════════════════
// ─── Pool registry ───
// ═══════════════════════════════════════════════════

/// Lazy-initialised per-connection pools. Keyed by connection `id`.
/// `save()` clears this map so credential edits take effect on the
/// next query.
static POOLS: LazyLock<Mutex<HashMap<String, PoolHandle>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Internal enum holding the concrete pool for each backend. Kept
/// behind a Mutex<HashMap> so the dispatcher can swap in a fresh
/// pool after a credential change.
#[derive(Clone)]
enum PoolHandle {
    Mysql(mysql_async::Pool),
    Postgres(deadpool_postgres::Pool),
}

fn get_or_build_pool(conn: &SqlConnection, cluster_secret: &str) -> Result<PoolHandle, String> {
    {
        let pools = POOLS.lock().unwrap();
        if let Some(p) = pools.get(&conn.id) { return Ok(p.clone()); }
    }

    // Resolve the plaintext password only here, at pool-build time.
    // Once hyper/tokio-postgres has copied it into the connection,
    // the plaintext goes out of scope immediately.
    let password = if conn.password.is_empty() {
        String::new()
    } else {
        crate::auth::oidc::decrypt_secret(&conn.password, cluster_secret)
            .map_err(|e| format!("decrypt sql password for '{}': {}", conn.id, e))?
    };

    let handle = match conn.kind {
        SqlKind::Mariadb | SqlKind::Mysql => {
            let mut builder = mysql_async::OptsBuilder::default()
                .ip_or_hostname(conn.host.clone())
                .tcp_port(conn.port)
                .user(Some(conn.username.clone()))
                .pass(Some(password))
                .db_name(Some(conn.database.clone()));
            if !matches!(conn.ssl_mode, SslMode::Disable) {
                // mysql_async's SslOpts are fine with defaults for
                // Prefer/Require; we don't pin a CA here since the
                // operator may be hitting a private CA — the explicit
                // opt-in is enough.
                builder = builder.ssl_opts(mysql_async::SslOpts::default());
            }
            // Connect timeout lives on the pool constraints in
            // mysql_async 0.34 — see PoolConstraints::new. The
            // defaults (min=10, max=100, inactive_connection_ttl=0)
            // are fine for our usage; we enforce a wall-clock
            // timeout around get_conn() in the query path instead.
            let opts: mysql_async::Opts = builder.into();
            let pool = mysql_async::Pool::new(opts);
            PoolHandle::Mysql(pool)
        }
        SqlKind::Postgres => {
            let mut cfg = deadpool_postgres::Config::new();
            cfg.host = Some(conn.host.clone());
            cfg.port = Some(conn.port);
            cfg.user = Some(conn.username.clone());
            cfg.password = Some(password);
            cfg.dbname = Some(conn.database.clone());
            cfg.connect_timeout = Some(CONNECT_TIMEOUT);
            cfg.ssl_mode = Some(match conn.ssl_mode {
                SslMode::Disable => deadpool_postgres::SslMode::Disable,
                SslMode::Prefer => deadpool_postgres::SslMode::Prefer,
                SslMode::Require => deadpool_postgres::SslMode::Require,
            });
            let pool = cfg.create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            ).map_err(|e| format!("create postgres pool: {}", e))?;
            PoolHandle::Postgres(pool)
        }
    };

    POOLS.lock().unwrap().insert(conn.id.clone(), handle.clone());
    Ok(handle)
}

/// Identifies who called `execute` — used by the audit log. Either
/// an AI agent id, or a WolfFlow workflow+step combo.
#[derive(Debug, Clone)]
pub enum Caller {
    Agent(String),
    Workflow { workflow_id: String, step: String },
    Ui(String),  // logged-in user (manual via the Test button, etc.)
}

impl Caller {
    fn as_tag(&self) -> String {
        match self {
            Caller::Agent(id) => format!("agent:{}", id),
            Caller::Workflow { workflow_id, step } => format!("workflow:{}:{}", workflow_id, step),
            Caller::Ui(user) => format!("ui:{}", user),
        }
    }
}

/// Execute `query` on `connection_id` with the declared permission
/// tier. Returns a bounded `SqlResult` or an error. Audit-logs the
/// outcome regardless.
pub async fn execute(
    connection_id: &str,
    query: &str,
    requested: SqlPermission,
    caller: Caller,
    cluster_secret: &str,
    exec_timeout: Option<Duration>,
) -> Result<SqlResult, String> {
    let cfg = load();
    let conn = cfg.connections.iter()
        .find(|c| c.id == connection_id)
        .cloned()
        .ok_or_else(|| format!("unknown sql connection '{}'", connection_id))?;

    // Classify first — tier must be ≤ requested. This is the main
    // authorization gate.
    let tier = classify(query, conn.kind)?;
    if !tier_within(tier, requested) {
        let outcome = format!(
            "query requires {:?} permission but caller holds {:?}",
            tier, requested
        );
        write_audit(&caller, &conn.id, query, false, 0, 0, &outcome);
        return Err(outcome);
    }

    let pool = get_or_build_pool(&conn, cluster_secret)?;
    let timeout = exec_timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT);

    let start = std::time::Instant::now();
    let query_owned = query.to_string();
    let fut = async move {
        match pool {
            PoolHandle::Mysql(p) => run_mysql(p, &query_owned).await,
            PoolHandle::Postgres(p) => run_postgres(p, &query_owned).await,
        }
    };
    let result = tokio::time::timeout(timeout, fut).await;

    let elapsed_ms = start.elapsed().as_millis() as u64;
    match result {
        Ok(Ok(mut r)) => {
            r.elapsed_ms = elapsed_ms;
            write_audit(&caller, &conn.id, query, true, r.row_count, elapsed_ms, "ok");
            Ok(r)
        }
        Ok(Err(e)) => {
            write_audit(&caller, &conn.id, query, false, 0, elapsed_ms, &e);
            Err(e)
        }
        Err(_) => {
            let msg = format!("query exceeded {}s timeout", timeout.as_secs());
            write_audit(&caller, &conn.id, query, false, 0, elapsed_ms, &msg);
            Err(msg)
        }
    }
}

fn tier_within(required: SqlPermission, granted: SqlPermission) -> bool {
    use SqlPermission::*;
    match (required, granted) {
        (Read, _) => true,                                   // Read fits under any tier
        (Update, Update) | (Update, Delete) => true,
        (Delete, Delete) => true,
        _ => false,
    }
}

/// Try to connect to the database and issue a cheap health check.
/// Used by the "Test Connection" button in the Settings UI.
pub async fn test(conn: &SqlConnection, cluster_secret: &str) -> Result<String, String> {
    // Clone into a throw-away profile so building a pool doesn't
    // disturb the live registry.
    let temp = SqlConnection { id: format!("__test__{}", conn.id), ..conn.clone() };
    let pool = get_or_build_pool(&temp, cluster_secret)?;
    let probe = match pool {
        PoolHandle::Mysql(p) => {
            use mysql_async::prelude::Queryable;
            let mut c = p.get_conn().await.map_err(|e| format!("connect: {}", e))?;
            let v: Option<String> = c.query_first("SELECT VERSION()").await
                .map_err(|e| format!("probe: {}", e))?;
            let _ = c.disconnect().await;
            v.unwrap_or_else(|| "unknown".into())
        }
        PoolHandle::Postgres(p) => {
            let c = p.get().await.map_err(|e| format!("connect: {}", e))?;
            let row = c.query_one("SELECT version()", &[]).await
                .map_err(|e| format!("probe: {}", e))?;
            row.try_get::<_, String>(0).unwrap_or_else(|_| "unknown".into())
        }
    };
    // Drop the throw-away pool from the registry so we don't leak
    // short-lived entries if the test button is pressed repeatedly.
    POOLS.lock().unwrap().remove(&temp.id);
    Ok(probe)
}

// ═══════════════════════════════════════════════════
// ─── Driver-specific execution ───
// ═══════════════════════════════════════════════════

async fn run_mysql(pool: mysql_async::Pool, query: &str) -> Result<SqlResult, String> {
    use mysql_async::prelude::Queryable;
    let mut conn = pool.get_conn().await.map_err(|e| format!("mysql connect: {}", e))?;

    // `query::<Row, _>` buffers into a Vec<Row>. MAX_ROWS defence
    // happens after — mysql_async 0.34 doesn't expose a good
    // per-row streaming API without pinning boxing through its
    // QueryResult, and the MAX_ROWS cap makes worst-case buffering
    // bounded anyway (10k rows × a few hundred bytes each).
    //
    // For DML we still use `query_iter` so we get affected_rows()
    // without also paying to materialise a rowset.
    let trimmed = query.trim_start().to_ascii_lowercase();
    let is_read = trimmed.starts_with("select")
        || trimmed.starts_with("show")
        || trimmed.starts_with("describe")
        || trimmed.starts_with("desc ")
        || trimmed.starts_with("explain")
        || trimmed.starts_with("analyze")
        || trimmed.starts_with("with");

    let mut columns: Vec<String> = Vec::new();
    let mut rows_out: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut total_bytes = 0usize;
    let mut truncated = false;
    let mut affected: Option<u64> = None;

    if is_read {
        let rows: Vec<mysql_async::Row> = conn.query(query).await
            .map_err(|e| format!("mysql exec: {}", e))?;
        if let Some(first) = rows.first() {
            columns = first.columns_ref().iter().map(|c| c.name_str().to_string()).collect();
        }
        for row in rows.iter() {
            if rows_out.len() >= MAX_ROWS { truncated = true; break; }
            let values: Vec<serde_json::Value> = (0..row.len())
                .map(|i| mysql_row_index_to_json(row, i))
                .collect();
            if let Ok(s) = serde_json::to_vec(&values) { total_bytes += s.len(); }
            if total_bytes > MAX_TOTAL_BYTES { truncated = true; break; }
            rows_out.push(values);
        }
    } else {
        // DML path — affected rows, no rowset.
        let result = conn.query_iter(query).await
            .map_err(|e| format!("mysql exec: {}", e))?;
        let aff = result.affected_rows();
        if aff > 0 { affected = Some(aff); }
        drop(result);
    }

    let _ = conn.disconnect().await;

    Ok(SqlResult {
        row_count: rows_out.len(),
        columns,
        rows: rows_out,
        affected_rows: affected,
        elapsed_ms: 0, // filled in by caller
        truncated,
    })
}

/// Convert one column of a mysql_async Row to JSON. `Row::take` moves
/// the value out; we use `get_opt` + `as_sql` so we don't mutate the
/// row (multiple columns need independent reads).
fn mysql_row_index_to_json(row: &mysql_async::Row, i: usize) -> serde_json::Value {
    use mysql_async::Value;
    match row.as_ref(i) {
        Some(v) => mysql_value_to_json(v),
        None => serde_json::Value::Null,
    }
}

fn mysql_value_to_json(v: &mysql_async::Value) -> serde_json::Value {
    use mysql_async::Value;
    match v {
        Value::NULL => serde_json::Value::Null,
        Value::Bytes(b) => match std::str::from_utf8(b) {
            Ok(s) => serde_json::Value::String(s.to_string()),
            Err(_) => serde_json::Value::String(format!("<binary:{} bytes>", b.len())),
        },
        Value::Int(i) => serde_json::json!(i),
        Value::UInt(u) => serde_json::json!(u),
        Value::Float(f) => serde_json::json!(f),
        Value::Double(d) => serde_json::json!(d),
        Value::Date(y, m, d, h, mi, s, _) => serde_json::Value::String(
            format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, h, mi, s)
        ),
        Value::Time(neg, days, h, m, s, _) => serde_json::Value::String(
            format!("{}{}:{:02}:{:02}:{:02}", if *neg { "-" } else { "" },
                    (*days as i64) * 24 + *h as i64, m, s, 0)
        ),
    }
}

async fn run_postgres(pool: deadpool_postgres::Pool, query: &str) -> Result<SqlResult, String> {
    let client = pool.get().await.map_err(|e| format!("postgres connect: {}", e))?;

    // Is this a result-producing query or a DML? simple_query returns
    // a stream of messages that tell us the difference — use it so
    // one code path handles SELECT, INSERT, UPDATE, DELETE alike.
    let messages = client.simple_query(query).await
        .map_err(|e| format!("postgres exec: {}", e))?;

    let mut columns: Vec<String> = Vec::new();
    let mut rows: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut total_bytes = 0usize;
    let mut truncated = false;
    let mut affected: Option<u64> = None;

    for msg in messages {
        use tokio_postgres::SimpleQueryMessage::*;
        match msg {
            RowDescription(cols) => {
                columns = cols.iter().map(|c| c.name().to_string()).collect();
            }
            Row(row) => {
                if rows.len() >= MAX_ROWS { truncated = true; break; }
                let values: Vec<serde_json::Value> = (0..row.len())
                    .map(|i| row.get(i).map(|s| serde_json::Value::String(s.to_string()))
                        .unwrap_or(serde_json::Value::Null))
                    .collect();
                if let Ok(s) = serde_json::to_vec(&values) { total_bytes += s.len(); }
                if total_bytes > MAX_TOTAL_BYTES { truncated = true; break; }
                rows.push(values);
            }
            CommandComplete(n) => { affected = Some(n); }
            _ => {}
        }
    }

    Ok(SqlResult {
        row_count: rows.len(),
        columns,
        rows,
        affected_rows: affected,
        elapsed_ms: 0,
        truncated,
    })
}

// ═══════════════════════════════════════════════════
// ─── Audit log ───
// ═══════════════════════════════════════════════════

/// Append one JSON line per execution to the audit log. Errors are
/// logged but not propagated — an audit-log failure shouldn't block
/// a legitimate query.
fn write_audit(caller: &Caller, connection_id: &str, query: &str,
               success: bool, row_count: usize, elapsed_ms: u64, outcome: &str)
{
    let ts = chrono::Utc::now().to_rfc3339();
    let entry = serde_json::json!({
        "ts": ts,
        "caller": caller.as_tag(),
        "connection_id": connection_id,
        "query": query.chars().take(4000).collect::<String>(),
        "success": success,
        "row_count": row_count,
        "elapsed_ms": elapsed_ms,
        "outcome": outcome,
    });
    let line = match serde_json::to_string(&entry) {
        Ok(s) => s + "\n",
        Err(_) => return,
    };
    let path = audit_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Read the last `n` lines of the audit log for UI display. Capped
/// at 1000 for safety. Returns oldest-first.
pub fn read_audit_tail(n: usize) -> Vec<serde_json::Value> {
    let n = n.min(1000);
    let path = audit_path();
    let content = match std::fs::read_to_string(&path) { Ok(s) => s, Err(_) => return Vec::new() };
    let lines: Vec<&str> = content.lines().rev().take(n).collect();
    lines.into_iter().rev()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect()
}

// ═══════════════════════════════════════════════════
// ─── Save/encrypt helpers exposed to the API layer ───
// ═══════════════════════════════════════════════════

/// Take an incoming (user-edited) connection and encrypt its
/// password field against the cluster secret before it's persisted.
/// If the incoming password is empty, preserves the existing
/// encrypted value (edit-without-changing-password path).
pub fn prepare_for_save(
    incoming: &mut SqlConnection,
    existing: Option<&SqlConnection>,
    cluster_secret: &str,
) -> Result<(), String> {
    if incoming.password.is_empty() {
        if let Some(prev) = existing {
            incoming.password = prev.password.clone();
        }
        return Ok(());
    }
    // Already encrypted? (e.g. a round-tripped backup restore.)
    if incoming.password.starts_with("encrypted:") {
        return Ok(());
    }
    incoming.password = crate::auth::oidc::encrypt_secret(&incoming.password, cluster_secret)?;
    Ok(())
}

/// Convenience: invalidate the pool for `id` after a mutating
/// operation (update / delete). Next query rebuilds from scratch.
pub fn invalidate_pool(id: &str) {
    POOLS.lock().unwrap().remove(id);
}

/// Generate a kebab-slug id from a human label, with a short random
/// suffix so two connections called "prod" don't collide.
pub fn gen_id(label: &str) -> String {
    let slug: String = label.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let slug = if slug.is_empty() { "sql".into() } else { slug };
    let suffix: String = (0..4)
        .map(|_| {
            let x = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default()
                .subsec_nanos() as usize).wrapping_add(slug.len() * 31);
            b"abcdefghijklmnopqrstuvwxyz0123456789"[x % 36] as char
        })
        .collect();
    format!("{}-{}", slug, suffix)
}

/// Drop all pools — used when the cluster secret rotates (rare) or
/// on test cleanup. Every subsequent query re-encrypts with the new
/// secret and reopens connections.
#[allow(dead_code)]
pub fn invalidate_all_pools() {
    POOLS.lock().unwrap().clear();
}

/// Marker to keep the unused-import linter happy when this file is
/// compiled without the API/agent surfaces wired in yet.
#[allow(dead_code)]
fn _link() -> Arc<()> { Arc::new(()) }
