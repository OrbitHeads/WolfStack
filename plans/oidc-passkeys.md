# OIDC and WebAuthn/Passkey Authentication — Implementation Plan

## Executive Summary

Adds OpenID Connect (OIDC) authentication and WebAuthn/FIDO2 passkey support to WolfStack. OIDC enables login via external identity providers (Authentik, Pocket-ID, Keycloak for homelabbers; Azure AD, Okta, Google Workspace for enterprise). Both features are gated behind the Enterprise license. Existing Linux `/etc/shadow` and WolfStack-native auth remain as fallback.

---

## 1. Rust Crate Dependencies

```toml
openidconnect = "4"          # Full OIDC RP: discovery, token exchange, ID token validation
webauthn-rs = "0.5"          # Server-side WebAuthn ceremonies
webauthn-rs-proto = "0.5"    # Shared protocol types
```

**Why `openidconnect`**: Handles `.well-known/openid-configuration` discovery, JWKS fetching, JWT validation, nonce management, and claim extraction. Building from raw `oauth2` + `jsonwebtoken` would be 800+ lines of error-prone code.

**Why `webauthn-rs`**: Purpose-built for server-side WebAuthn — CBOR parsing, attestation verification, ceremony state management. The only production-quality Rust WebAuthn library.

---

## 2. Configuration

### 2.1 OIDC: `/etc/wolfstack/oidc.json`

```json
{
  "enabled": true,
  "providers": [
    {
      "id": "authentik-1",
      "name": "Authentik (Home Lab)",
      "issuer_url": "https://auth.example.com/application/o/wolfstack/",
      "client_id": "wolfstack-oidc",
      "client_secret": "encrypted:aes256:...",
      "scopes": ["openid", "profile", "email", "groups"],
      "role_mapping": {
        "claim": "groups",
        "admin_values": ["wolfstack-admins"],
        "viewer_values": ["wolfstack-viewers"],
        "default_role": "viewer"
      },
      "username_claim": "preferred_username",
      "auto_create_users": true,
      "button_label": "Sign in with Authentik",
      "button_icon": "authentik"
    }
  ],
  "redirect_uri_base": "https://wolfstack.example.com",
  "session_lifetime_hours": 8,
  "allow_local_fallback": true
}
```

### 2.2 WebAuthn: `/etc/wolfstack/webauthn.json`

```json
{
  "enabled": true,
  "rp_id": "wolfstack.example.com",
  "rp_name": "WolfStack",
  "rp_origin": "https://wolfstack.example.com:8553",
  "credentials": [
    {
      "username": "admin",
      "credential_id": "base64-credential-id",
      "public_key": "base64-cose-key",
      "counter": 42,
      "registered_at": "2026-04-09T10:00:00Z",
      "label": "YubiKey 5C"
    }
  ]
}
```

---

## 3. OIDC Authorization Code Flow

### Sequence

1. User clicks "Sign in with {Provider}" on login.html
2. `GET /api/auth/oidc/login/{provider_id}`
3. Server: checks Enterprise license → OIDC discovery (cached 1h) → generates state/nonce/PKCE → stores pending flow → 302 redirect to IdP
4. User authenticates at IdP, grants consent
5. IdP redirects → `GET /api/auth/oidc/callback?code=XXX&state=YYY`
6. Server: validates state → exchanges code for tokens (with PKCE) → validates ID token (signature, issuer, audience, nonce) → extracts claims → maps role → creates/updates WolfUser → creates session → sets `wolfstack_session` cookie → 302 to `/index.html`

### Key Design Decisions

- **No stored tokens**: WolfStack does NOT store OIDC access/refresh tokens. The ID token is validated once, claims extracted, token discarded. Session is purely WolfStack-managed.
- **PKCE mandatory**: Always used, even with client_secret, per security best practice.
- **No RP-Initiated Logout**: Destroying the local session is sufficient. Calling the IdP's `end_session_endpoint` would sign the user out of all apps.

---

## 4. Session Integration

All auth methods converge to the same session model — same `wolfstack_session` cookie, same lifetime. Extend `Session`:

```rust
pub enum AuthMethod {
    LinuxShadow,
    WolfStackNative,
    Oidc { provider_id: String },
    WebAuthn,
}

struct Session {
    username: String,
    created: Instant,
    auth_method: AuthMethod,
    role: Option<String>,     // from OIDC claims (None = use system role)
}
```

`require_auth()` continues to work unchanged — it returns the username. AuthMethod is for audit/display.

---

## 5. Role Mapping from OIDC Claims

```rust
fn map_claims_to_role(claims: &Value, mapping: &RoleMapping) -> String {
    let values = resolve_claim(claims, &mapping.claim); // supports dotted paths
    if values.iter().any(|v| mapping.admin_values.contains(v)) { "admin" }
    else if values.iter().any(|v| mapping.viewer_values.contains(v)) { "viewer" }
    else { &mapping.default_role }
}
```

### User Provisioning (auto_create_users = true)

1. Create `WolfUser` with username from `username_claim`
2. Set `oidc_subject` = `sub` claim (stable identifier)
3. Set `password_hash` = `"!oidc"` (locked — prevents password login)
4. Role from mapping
5. On subsequent logins, update role if claims changed (drift correction)

---

## 6. WebAuthn/Passkey Flow

### Registration (user already logged in)

1. `POST /api/auth/webauthn/register/start` → server generates challenge, returns `CreationChallengeResponse`
2. Browser calls `navigator.credentials.create()` with the challenge
3. `POST /api/auth/webauthn/register/finish` with the credential → server validates attestation, stores credential

### Authentication (login page)

1. `POST /api/auth/webauthn/login/start` → server generates challenge
2. Browser calls `navigator.credentials.get()`
3. `POST /api/auth/webauthn/login/finish` → server verifies assertion, creates session

Ceremony state stored in-memory on AppState with 5-minute TTL, cleaned up in existing background loop.

---

## 7. Enterprise License Gating

Every OIDC/WebAuthn handler checks `platform_ready()` first:

```rust
if !crate::compat::platform_ready() {
    return HttpResponse::Forbidden().json(json!({"error": "Enterprise license required"}));
}
```

Frontend: `GET /api/auth/oidc/providers` returns empty list without license → no OIDC buttons shown.

---

## 8. API Endpoints

### OIDC (no auth for login flow)

| Method | Path | Auth |
|--------|------|------|
| GET | `/api/auth/oidc/providers` | None (returns id, name, button_label only) |
| GET | `/api/auth/oidc/login/{provider_id}` | None (initiates flow) |
| GET | `/api/auth/oidc/callback` | None (handles IdP redirect) |

### OIDC Admin (Enterprise + Admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/auth/oidc/config` | Get config (secrets redacted) |
| POST | `/api/auth/oidc/config` | Save config |
| POST | `/api/auth/oidc/test/{provider_id}` | Test connectivity |
| DELETE | `/api/auth/oidc/providers/{id}` | Remove provider |

### WebAuthn

| Method | Path | Auth |
|--------|------|------|
| POST | `/api/auth/webauthn/register/start` | Session |
| POST | `/api/auth/webauthn/register/finish` | Session |
| POST | `/api/auth/webauthn/login/start` | None |
| POST | `/api/auth/webauthn/login/finish` | None |
| GET | `/api/auth/webauthn/credentials` | Session |
| DELETE | `/api/auth/webauthn/credentials/{id}` | Session |
| GET/POST | `/api/auth/webauthn/config` | Admin |

---

## 9. Frontend Changes

### 9.1 Login Page (`web/login.html`)

- Fetch `/api/auth/oidc/providers` → render one button per provider below the password form
- "or" divider between password and OIDC sections
- "Sign in with Passkey" button (only if WebAuthn enabled + credentials exist)
- All dynamically shown/hidden based on what's configured

### 9.2 Settings Page (`web/js/app.js`)

New **"SSO / OIDC"** tab in datacenter settings:
- OIDC enable/disable toggle
- Provider table (name, issuer, status) + "Add Provider" form
- Fields: name, issuer URL, client ID, client secret, scopes, username claim, role mapping
- "Test Connection" button per provider
- WebAuthn RP configuration
- Per-user passkey management in Users tab

---

## 10. Multi-Provider Support

- Config holds array of providers, each with unique `id` (slug: `[a-z0-9-]`)
- Login page shows one button per provider
- Callback URL shared — `state` parameter maps back to the originating provider
- User disambiguation via `(oidc_subject, oidc_provider_id)` tuple

---

## 11. Security

| Measure | Detail |
|---------|--------|
| **PKCE** | Mandatory for all flows |
| **State parameter** | Cryptographically random, server-side, single-use |
| **Nonce** | In authorization request, validated in ID token |
| **ID token validation** | Signature (JWKS), issuer, audience, expiry, nonce |
| **Client secret encryption** | AES-256-GCM at rest, key derived from cluster secret via HKDF |
| **TLS enforcement** | Issuer URLs must be `https://` (except localhost) |
| **WebAuthn challenges** | Fresh per ceremony, 5-minute expiry |
| **Counter validation** | Monotonic increase enforced (detects cloned keys) |
| **Rate limiting** | Existing `LoginRateLimiter` covers all auth endpoints |
| **Fallback safety** | `allow_local_fallback` defaults to `true` |

---

## 12. Implementation Sequence

### Phase 1: Foundation
1. Add crate deps to Cargo.toml
2. Add path constants to `src/paths.rs`
3. Create `src/auth/oidc.rs` — config, discovery cache, secret encryption
4. Create `src/auth/webauthn.rs` — config, ceremony functions
5. Extend `Session` with `AuthMethod`, extend `WolfUser` with OIDC fields

### Phase 2: API Endpoints
6. OIDC login flow endpoints (providers, login, callback)
7. OIDC admin endpoints (config CRUD, test)
8. WebAuthn endpoints (register, authenticate, credentials)
9. Add `oidc_pending_flows` + `webauthn_ceremonies` to AppState
10. Enterprise gating on all handlers

### Phase 3: Frontend
11. Login page OIDC buttons + passkey button
12. SSO/OIDC settings tab in datacenter settings
13. Per-user passkey management in Users tab

### Phase 4: Testing
14. Unit tests: claim mapping, role resolution, secret encryption, config serde
15. Manual testing: Authentik, Keycloak, Azure AD, Okta
16. Edge cases: expired tokens, unreachable IdP, concurrent flows

---

## Files to Modify/Create

| File | Action | Description |
|------|--------|-------------|
| `Cargo.toml` | Modify | Add openidconnect, webauthn-rs |
| `src/paths.rs` | Modify | Add oidc_config, webauthn_config |
| `src/auth/mod.rs` | Modify | Add module decls, extend Session |
| `src/auth/oidc.rs` | Create | OIDC config, discovery, flow logic |
| `src/auth/webauthn.rs` | Create | WebAuthn config, ceremony logic |
| `src/auth/users.rs` | Modify | Add OIDC fields to WolfUser |
| `src/api/mod.rs` | Modify | 15 new endpoints, AppState fields |
| `src/main.rs` | Modify | Init new AppState fields, cleanup task |
| `web/login.html` | Modify | OIDC buttons, passkey button |
| `web/js/app.js` | Modify | SSO settings tab, passkey management |
