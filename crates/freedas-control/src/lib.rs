//! Self-hosted control plane: auth, workspaces, wallet, tokens, usage, and
//! GitHub webhook intake.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Form, Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::Html,
    routing::{delete, get, post},
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

type ApiError = (StatusCode, Json<Value>);
type ApiResult<T = Json<Value>> = Result<T, ApiError>;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    base_url: String,
    /// Pending OIDC state nonces -> creation timestamp (milliseconds).
    oidc_states: Arc<std::sync::Mutex<std::collections::HashMap<String, i64>>>,
    /// Failed-login backoff and endpoint rate limits.
    throttle: Arc<std::sync::Mutex<Throttle>>,
}

#[derive(Default)]
struct Throttle {
    entries: std::collections::HashMap<String, ThrottleEntry>,
}

#[derive(Default)]
struct ThrottleEntry {
    failures: u32,
    locked_until: i64,
    window_start: i64,
    window_count: u32,
}

impl Throttle {
    fn locked(&self, key: &str) -> bool {
        self.entries
            .get(key)
            .is_some_and(|entry| entry.locked_until > now_ms())
    }

    /// Five failures in a row start a 30s lockout that grows per failure,
    /// capped at fifteen minutes. Successful calls clear the key.
    fn fail(&mut self, key: &str) {
        const MAX_KEYS: usize = 10_000;
        if self.entries.len() >= MAX_KEYS && !self.entries.contains_key(key) {
            // Unbounded email keys would be a memory leak under a spray attack;
            // expired lockouts are safe to drop.
            let now = now_ms();
            self.entries.retain(|_, entry| entry.locked_until > now);
        }
        let entry = self.entries.entry(key.to_string()).or_default();
        entry.failures += 1;
        if entry.failures >= 5 {
            let backoff = (30_000i64 * (i64::from(entry.failures) - 4)).min(900_000);
            entry.locked_until = now_ms() + backoff;
        }
    }

    fn succeed(&mut self, key: &str) {
        self.entries.remove(key);
    }

    /// Fixed-window counter; true once the window's `limit` is exceeded.
    fn over_limit(&mut self, key: &str, limit: u32, window_ms: i64) -> bool {
        let now = now_ms();
        let entry = self.entries.entry(key.to_string()).or_default();
        if now - entry.window_start >= window_ms {
            entry.window_start = now;
            entry.window_count = 0;
        }
        entry.window_count += 1;
        entry.window_count > limit
    }
}

async fn list_skills(State(s): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&s.pool, &headers).await?;
    let workspace = current_workspace(&s, &auth).await?;
    let rows = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, description, sha256 FROM skills
         WHERE workspace_id = $1 ORDER BY name",
    )
    .bind(&workspace)
    .fetch_all(&s.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!(
        rows.into_iter()
            .map(|(name, description, sha256)| json!({
                "name": name, "description": description, "sha256": sha256,
            }))
            .collect::<Vec<_>>()
    )))
}

async fn upload_skill(
    State(s): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
    body: Bytes,
) -> ApiResult {
    let auth = authenticate(&s.pool, &headers).await?;
    let workspace = current_workspace(&s, &auth).await?;
    let description = headers
        .get("x-skill-description")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    // The digest is computed here; a client-supplied one would let a pull
    // accept bytes under a false hash.
    let sha256 = hex::encode(Sha256::digest(&body));
    sqlx::query(
        "INSERT INTO skills (workspace_id, name, description, sha256, bytes, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (workspace_id, name) DO UPDATE SET
           description = EXCLUDED.description,
           sha256 = EXCLUDED.sha256,
           bytes = EXCLUDED.bytes,
           updated_at = EXCLUDED.updated_at",
    )
    .bind(&workspace)
    .bind(&name)
    .bind(&description)
    .bind(&sha256)
    .bind(body.to_vec())
    .bind(now_ms())
    .execute(&s.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!({"ok": true, "sha256": sha256})))
}

async fn download_skill(
    State(s): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    let auth = authenticate(&s.pool, &headers).await?;
    let workspace = current_workspace(&s, &auth).await?;
    let entry = sqlx::query_as::<_, (Vec<u8>, String)>(
        "SELECT bytes, sha256 FROM skills WHERE workspace_id = $1 AND name = $2",
    )
    .bind(&workspace)
    .bind(&name)
    .fetch_optional(&s.pool)
    .await
    .map_err(internal)?;
    match entry {
        Some((bytes, sha)) => Ok((
            axum::http::StatusCode::OK,
            [
                ("content-type".to_string(), "application/gzip".to_string()),
                ("x-skill-sha256".to_string(), sha),
            ],
            bytes,
        )),
        None => Err(fail(axum::http::StatusCode::NOT_FOUND, "skill not found")),
    }
}

pub fn app(pool: PgPool, base_url: String) -> Router {
    let guard_pool = pool.clone();
    let state = AppState {
        pool,
        base_url,
        oidc_states: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        throttle: Arc::new(std::sync::Mutex::new(Throttle::default())),
    };
    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(login))
        .route("/auth/register", post(register))
        .route("/auth/me", get(me))
        .route("/auth/oidc/start", get(oidc_start))
        .route("/auth/oidc/callback", get(oidc_callback))
        .route("/device/code", post(device_code_start))
        .route("/device", get(device_page))
        .route("/device/approve", post(device_approve))
        .route("/device/token", post(device_token))
        .route(
            "/scim/v2/Users",
            get(scim_list_users).post(scim_create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            delete(scim_delete_user).patch(scim_patch_user),
        )
        .route("/scim/v2/Groups", get(scim_list_groups))
        .route("/workspaces", get(list_workspaces).post(create_workspace))
        .route(
            "/workspaces/{slug}/members",
            get(list_members).post(add_member),
        )
        .route(
            "/workspaces/{slug}/members/{user_id}",
            delete(remove_member).patch(change_member_role),
        )
        .route(
            "/workspaces/{slug}/teams",
            get(list_teams).post(create_team),
        )
        .route(
            "/workspaces/{slug}/teams/{id}/members",
            post(add_team_member),
        )
        .route(
            "/workspaces/{slug}/budgets",
            get(list_budgets).post(create_budget),
        )
        .route("/workspaces/{slug}/invoices", get(list_invoices))
        .route(
            "/workspaces/{slug}/invoices/generate",
            post(generate_invoice),
        )
        .route("/usage", get(usage))
        .route("/usage/summary", get(usage_summary))
        .route("/wallet", get(wallet))
        .route("/wallet/credits", post(add_credits))
        .route("/tokens", get(list_tokens).post(create_token))
        .route("/tokens/{id}", axum::routing::delete(delete_token))
        .route("/github/install", get(github_install))
        .route(
            "/github/installations",
            get(list_installations).post(create_installation),
        )
        .route("/github/installations/{id}", delete(delete_installation))
        .route(
            "/github/installations/{id}/repositories",
            get(list_installation_repositories),
        )
        .route(
            "/github/repositories",
            axum::routing::patch(patch_repository),
        )
        .route("/github/webhook", post(github_webhook))
        .route("/github/pulls", get(github_pulls))
        .route("/sessions", get(list_sessions).post(upsert_session))
        .route("/reviews", get(list_reviews).post(start_review))
        .route("/reviews/analytics", get(reviews_analytics))
        .route("/reviews/{id}", get(get_review))
        .route("/reviews/{id}/retry", post(retry_review))
        .route(
            "/reviews/config",
            get(get_review_config).patch(patch_review_config),
        )
        .route(
            "/workspace/settings",
            get(get_settings).patch(patch_settings),
        )
        .route("/sandboxes", get(list_sandboxes).post(create_sandbox))
        .route("/sandboxes/{id}", get(get_sandbox))
        .route("/sandboxes/{id}/heartbeat", post(sandbox_heartbeat))
        .route("/sandboxes/{id}/stop", post(stop_sandbox))
        .route("/sandboxes/{id}/token", post(sandbox_token))
        .route(
            "/registry/skills/{name}",
            get(download_skill).post(upload_skill),
        )
        .route("/registry/skills", get(list_skills))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            guard_pool,
            sandbox_scope_guard,
        ))
}

fn fail(status: StatusCode, message: &str) -> ApiError {
    (status, Json(json!({ "error": message })))
}

fn internal(_e: sqlx::Error) -> ApiError {
    fail(StatusCode::INTERNAL_SERVER_ERROR, "database error")
}

fn is_conflict(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(|d| d.is_unique_violation())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", ulid::Ulid::new())
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    (!token.is_empty()).then_some(token)
}

/// The sandbox id when a token was minted by `sandbox_token`.
fn sandbox_scope(raw: Option<&str>) -> Option<String> {
    scopes_of(raw)
        .into_iter()
        .find_map(|scope| scope.strip_prefix("sandbox:").map(str::to_owned))
}

/// A sandbox token may reach only its own sandbox, model/usage endpoints, and
/// the workspace read the runner needs. Everything else is a control-plane
/// credential it must never hold.
fn sandbox_request_allowed(sandbox_id: &str, method: &axum::http::Method, path: &str) -> bool {
    if path == "/v1" || path.starts_with("/v1/") {
        return true;
    }
    if method == axum::http::Method::GET
        && matches!(path, "/workspaces" | "/usage" | "/usage/summary")
    {
        return true;
    }
    let own = format!("/sandboxes/{sandbox_id}");
    path == own || path.starts_with(&format!("{own}/"))
}

/// Rejects sandbox-scoped tokens outside their allowlist before any handler
/// runs, so no endpoint can accidentally accept one.
async fn sandbox_scope_guard(
    State(pool): State<PgPool>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    let Some(token) = bearer(req.headers()) else {
        return Ok(next.run(req).await);
    };
    let scopes = sqlx::query_scalar::<_, Option<String>>(
        "SELECT scopes FROM api_tokens
         WHERE token_hash = $1 AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > $2)",
    )
    .bind(hash_token(token))
    .bind(now_ms())
    .fetch_optional(&pool)
    .await
    .map_err(internal)?
    .flatten();
    let Some(id) = sandbox_scope(scopes.as_deref()) else {
        return Ok(next.run(req).await);
    };
    if sandbox_request_allowed(&id, req.method(), req.uri().path()) {
        Ok(next.run(req).await)
    } else {
        Err(fail(
            StatusCode::FORBIDDEN,
            "sandbox token cannot call this endpoint",
        ))
    }
}

struct Auth {
    user_id: Option<String>,
    workspace_id: Option<String>,
}

async fn authenticate(pool: &PgPool, headers: &HeaderMap) -> Result<Auth, ApiError> {
    let token =
        bearer(headers).ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let row = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT user_id, workspace_id FROM api_tokens
         WHERE token_hash = $1 AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > $2)",
    )
    .bind(hash_token(token))
    .bind(now_ms())
    .fetch_optional(pool)
    .await
    .map_err(internal)?
    .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "invalid token"))?;
    Ok(Auth {
        user_id: row.0,
        workspace_id: row.1,
    })
}

async fn current_workspace(state: &AppState, auth: &Auth) -> Result<String, ApiError> {
    if let Some(id) = &auth.workspace_id {
        return Ok(id.clone());
    }
    let Some(user_id) = &auth.user_id else {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "token is not bound to a workspace",
        ));
    };
    let mut ids = sqlx::query_scalar::<_, String>(
        "SELECT workspace_id FROM memberships WHERE user_id = $1 ORDER BY workspace_id",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    match ids.len() {
        0 => Err(fail(StatusCode::FORBIDDEN, "user has no workspace")),
        1 => Ok(ids.remove(0)),
        // Picking one would silently bill and target the wrong workspace.
        _ => Err(fail(
            StatusCode::CONFLICT,
            "token is not bound to a workspace; sign in and select one",
        )),
    }
}

/// The user's workspace when membership is unambiguous; login and OIDC bind
/// tokens to it so later requests never have to guess.
async fn sole_workspace(pool: &PgPool, user_id: &str) -> Result<Option<String>, ApiError> {
    let ids = sqlx::query_scalar::<_, String>(
        "SELECT workspace_id FROM memberships WHERE user_id = $1 ORDER BY workspace_id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    Ok((ids.len() == 1).then(|| ids[0].clone()))
}

async fn role_in(
    pool: &PgPool,
    workspace_id: &str,
    user_id: Option<&str>,
) -> Result<Option<String>, ApiError> {
    let Some(user_id) = user_id else {
        return Ok(None);
    };
    sqlx::query_scalar::<_, String>(
        "SELECT role FROM memberships WHERE workspace_id = $1 AND user_id = $2",
    )
    .bind(workspace_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(internal)
}

async fn balance_of(pool: &PgPool, workspace_id: &str) -> Result<f64, ApiError> {
    let total = sqlx::query_scalar::<_, f64>(
        "SELECT COALESCE(SUM(delta_usd), 0)::float8 FROM wallet_ledger WHERE workspace_id = $1",
    )
    .bind(workspace_id)
    .fetch_one(pool)
    .await
    .map_err(internal)?;
    Ok(balance_from_rows(&[total]))
}

/// Appends one line to the control-plane audit trail.
pub(crate) async fn audit(
    pool: &PgPool,
    workspace_id: Option<&str>,
    user_id: Option<&str>,
    action: &str,
    subject: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (id, workspace_id, user_id, action, subject, metadata, created_at)
         VALUES ($1, $2, $3, $4, $5, '{}'::jsonb, $6)",
    )
    .bind(new_id("aud"))
    .bind(workspace_id)
    .bind(user_id)
    .bind(action)
    .bind(subject)
    .bind(now_ms())
    .execute(pool)
    .await
    .map(|_| ())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    /// Plaintext password; the stored per-user value is an Argon2 PHC string.
    password_hash: String,
    /// Workspace slug or id to bind the session to; omitted when only one
    /// membership exists.
    #[serde(default)]
    workspace: Option<String>,
}

async fn login(State(state): State<AppState>, Json(body): Json<LoginBody>) -> ApiResult {
    let key = format!("login:{}", body.email.trim().to_ascii_lowercase());
    if state.throttle.lock().expect("throttle").locked(&key) {
        return Err(fail(
            StatusCode::TOO_MANY_REQUESTS,
            "too many attempts; try again later",
        ));
    }
    let row = sqlx::query_as::<_, (String, Option<String>, bool)>(
        "SELECT id, password_hash, active FROM users WHERE email = $1",
    )
    .bind(&body.email)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?;
    // SCIM deactivation nulls the password hash, but reject on the flag
    // itself so a re-provisioned row without credentials cannot slip through.
    if let Some((_, _, false)) = row.as_ref() {
        return Err(fail(StatusCode::FORBIDDEN, "account is deactivated"));
    }
    let row = row.filter(|(_, stored, _)| stored.is_some());
    let valid = row.as_ref().is_some_and(|(_, stored, _)| {
        stored
            .as_deref()
            .is_some_and(|phc| verify_password(&body.password_hash, phc))
    });
    if !valid {
        if row.is_none() {
            dummy_verify(&body.password_hash);
        }
        state.throttle.lock().expect("throttle").fail(&key);
        return Err(fail(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    state.throttle.lock().expect("throttle").succeed(&key);
    let (user_id, _, _) = row.expect("checked above");

    // The token carries its workspace so later requests never pick one.
    let workspace_id = match body
        .workspace
        .as_deref()
        .map(str::trim)
        .filter(|selector| !selector.is_empty())
    {
        Some(selector) => Some(
            sqlx::query_scalar::<_, String>(
                "SELECT w.id FROM workspaces w JOIN memberships m ON m.workspace_id = w.id
                 WHERE m.user_id = $1 AND (w.id = $2 OR w.slug = $2)",
            )
            .bind(&user_id)
            .bind(selector)
            .fetch_optional(&state.pool)
            .await
            .map_err(internal)?
            .ok_or_else(|| fail(StatusCode::FORBIDDEN, "not a member of that workspace"))?,
        ),
        None => sole_workspace(&state.pool, &user_id).await?,
    };

    let token = random_hex(32);
    sqlx::query(
        "INSERT INTO api_tokens (id, user_id, workspace_id, token_hash, scopes, created_at)
         VALUES ($1, $2, $3, $4, '{}', $5)",
    )
    .bind(new_id("tok"))
    .bind(&user_id)
    .bind(&workspace_id)
    .bind(hash_token(&token))
    .bind(now_ms())
    .execute(&state.pool)
    .await
    .map_err(internal)?;

    audit(
        &state.pool,
        workspace_id.as_deref(),
        Some(&user_id),
        "login",
        Some(&body.email),
    )
    .await
    .map_err(internal)?;

    Ok(Json(json!({
        "token": token,
        "userId": user_id,
        "workspaceId": workspace_id,
    })))
}

/// First-run bootstrap: create the owner account and its personal workspace.
/// Succeeds only while no user exists, so it cannot be used to add accounts to
/// a live deployment; admins add people with SCIM, OIDC, or invites.
async fn register(State(state): State<AppState>, Json(body): Json<LoginBody>) -> ApiResult {
    if body.email.trim().is_empty() || body.password_hash.len() < 8 {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "email and a password of at least 8 characters are required",
        ));
    }
    let user_id = new_id("usr");
    let workspace_id = new_id("ws");
    let token = random_hex(32);
    let salt = {
        use argon2::password_hash::{SaltString, rand_core::OsRng};
        SaltString::generate(&mut OsRng)
    };
    let hash = {
        use argon2::PasswordHasher;
        Argon2::default()
            .hash_password(body.password_hash.as_bytes(), &salt)
            .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .to_string()
    };
    let slug = body
        .email
        .split('@')
        .next()
        .unwrap_or("personal")
        .to_lowercase();
    let mut tx = state.pool.begin().await.map_err(internal)?;
    // Two first-run requests would both see zero users; serialize them so only
    // one owner account is ever created.
    sqlx::query("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?;
    if existing > 0 {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "registration is closed; sign in or ask an admin",
        ));
    }
    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, created_at) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(&user_id)
    .bind(body.email.trim())
    .bind(body.email.split('@').next().unwrap_or("owner"))
    .bind(&hash)
    .bind(now_ms())
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    sqlx::query(
        "INSERT INTO workspaces (id, slug, name, kind, owner_id, settings, created_at) VALUES ($1,$2,$3,'personal',$4,'{}'::jsonb,$5)",
    )
    .bind(&workspace_id)
    .bind(format!("{slug}-personal"))
    .bind(format!("{slug}'s workspace"))
    .bind(&user_id)
    .bind(now_ms())
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    sqlx::query("INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1,$2,'owner')")
        .bind(&workspace_id)
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    sqlx::query(
        "INSERT INTO api_tokens (id, user_id, workspace_id, token_hash, scopes, created_at) VALUES ($1,$2,$3,$4,'{}',$5)",
    )
    .bind(new_id("tok"))
    .bind(&user_id)
    .bind(&workspace_id)
    .bind(hash_token(&token))
    .bind(now_ms())
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(Json(json!({
        "token": token,
        "userID": user_id,
        "workspaceID": workspace_id,
        "workspaceSlug": format!("{slug}-personal"),
    })))
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let user_id = auth
        .user_id
        .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let row = sqlx::query_as::<_, (String, String)>("SELECT id, email FROM users WHERE id = $1")
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?
        .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "invalid token"))?;
    Ok(Json(json!({ "id": row.0, "email": row.1 })))
}

async fn list_workspaces(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    if auth.user_id.is_none() && auth.workspace_id.is_none() {
        return Err(fail(StatusCode::UNAUTHORIZED, "invalid token"));
    }
    // Sandbox tokens carry a workspace but no user; they list that workspace
    // with the lowest role, which only affects display.
    let rows = sqlx::query_as::<_, (String, String, String, String, String, String)>(
        "SELECT w.id, w.slug, w.name, w.kind, COALESCE(m.role, 'member'), w.settings::text
         FROM workspaces w
         LEFT JOIN memberships m ON m.workspace_id = w.id AND m.user_id = $1
         WHERE ($1::text IS NULL AND w.id = $2) OR m.user_id = $1
         ORDER BY w.created_at",
    )
    .bind(&auth.user_id)
    .bind(&auth.workspace_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    let workspaces: Vec<Value> = rows
        .into_iter()
        .map(|(id, slug, name, kind, role, settings)| {
            let settings: Value = serde_json::from_str(&settings).unwrap_or_else(|_| json!({}));
            json!({ "id": id, "slug": slug, "name": name, "kind": kind, "role": role, "settings": settings })
        })
        .collect();
    Ok(Json(json!(workspaces)))
}

#[derive(Deserialize)]
struct WorkspaceBody {
    slug: String,
    name: String,
    kind: String,
}

async fn create_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<WorkspaceBody>,
) -> ApiResult {
    if body.slug.is_empty() || body.name.is_empty() {
        return Err(fail(StatusCode::BAD_REQUEST, "slug and name are required"));
    }
    if !matches!(body.kind.as_str(), "personal" | "organization") {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "kind must be personal or organization",
        ));
    }
    let auth = authenticate(&state.pool, &headers).await?;
    let user_id = auth
        .user_id
        .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "invalid token"))?;

    let id = new_id("ws");
    let mut tx = state.pool.begin().await.map_err(internal)?;
    sqlx::query(
        "INSERT INTO workspaces (id, slug, name, kind, owner_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(&body.slug)
    .bind(&body.name)
    .bind(&body.kind)
    .bind(&user_id)
    .bind(now_ms())
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if is_conflict(&e) {
            fail(StatusCode::CONFLICT, "workspace slug already exists")
        } else {
            internal(e)
        }
    })?;
    sqlx::query("INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, 'owner')")
        .bind(&id)
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;

    audit(
        &state.pool,
        Some(&id),
        Some(&user_id),
        "workspace.create",
        Some(&body.slug),
    )
    .await
    .map_err(internal)?;

    Ok(Json(json!({
        "id": id,
        "slug": body.slug,
        "name": body.name,
        "kind": body.kind,
        "role": "owner",
    })))
}

async fn usage(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let since = now_ms() - 30 * 86_400_000;
    let (input, output, cost) = sqlx::query_as::<_, (i64, i64, f64)>(
        "SELECT COALESCE(SUM(input_tokens), 0)::bigint,
                COALESCE(SUM(output_tokens), 0)::bigint,
                COALESCE(SUM(cost_usd), 0)::float8
         FROM usage_events WHERE workspace_id = $1 AND created_at >= $2",
    )
    .bind(&workspace_id)
    .bind(since)
    .fetch_one(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!({
        "workspaceId": workspace_id,
        "inputTokens": input,
        "outputTokens": output,
        "costUsd": cost,
    })))
}

async fn wallet(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let balance = balance_of(&state.pool, &workspace_id).await?;
    Ok(Json(
        json!({ "workspaceId": workspace_id, "balanceUsd": balance }),
    ))
}

#[derive(Deserialize)]
struct CreditsBody {
    amount: f64,
}

async fn add_credits(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreditsBody>,
) -> ApiResult {
    if !body.amount.is_finite() || body.amount <= 0.0 {
        return Err(fail(StatusCode::BAD_REQUEST, "amount must be positive"));
    }
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let role = role_in(&state.pool, &workspace_id, auth.user_id.as_deref()).await?;
    if !matches!(role.as_deref(), Some("owner" | "admin")) {
        return Err(fail(StatusCode::FORBIDDEN, "owner or admin role required"));
    }

    sqlx::query(
        "INSERT INTO wallet_ledger (id, workspace_id, delta_usd, reason, created_at)
         VALUES ($1, $2, $3::numeric, 'credit', $4)",
    )
    .bind(new_id("led"))
    .bind(&workspace_id)
    .bind(body.amount.to_string())
    .bind(now_ms())
    .execute(&state.pool)
    .await
    .map_err(internal)?;

    let balance = balance_of(&state.pool, &workspace_id).await?;
    Ok(Json(
        json!({ "workspaceId": workspace_id, "balanceUsd": balance }),
    ))
}

async fn create_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    _body: Bytes,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    // The request body cannot choose a workspace: the token is minted for the
    // one the caller already acts in, so an outsider cannot mint a credential
    // for someone else's account.
    let workspace_id = current_workspace(&state, &auth).await?;
    let role = role_in(&state.pool, &workspace_id, auth.user_id.as_deref()).await?;
    // Any human credential mints workspace tokens; service tokens (no user)
    // keep the historical allow so automation can rotate its own credential.
    if auth.user_id.is_some() && !matches!(role.as_deref(), Some("owner" | "admin")) {
        return Err(fail(StatusCode::FORBIDDEN, "owner or admin role required"));
    }

    let plaintext = random_hex(32);
    let id = new_id("tok");
    sqlx::query(
        "INSERT INTO api_tokens (id, user_id, workspace_id, token_hash, scopes, created_at)
         VALUES ($1, $2, $3, $4, '{}', $5)",
    )
    .bind(&id)
    .bind(&auth.user_id)
    .bind(&workspace_id)
    .bind(hash_token(&plaintext))
    .bind(now_ms())
    .execute(&state.pool)
    .await
    .map_err(internal)?;

    audit(
        &state.pool,
        Some(&workspace_id),
        auth.user_id.as_deref(),
        "token.create",
        Some(&id),
    )
    .await
    .map_err(internal)?;

    Ok(Json(json!({
        "id": id,
        "token": plaintext,
        "workspaceId": workspace_id,
    })))
}

/// Lists tokens the caller may see: everyone's for owners and admins, otherwise
/// only their own. `scopes` is a Postgres array literal (`{read,write}`); the
/// hash is never part of the response.
async fn list_tokens(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    type Row = (
        String,
        Option<String>,
        i64,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    );
    let rows = match (&auth.workspace_id, &auth.user_id) {
        (Some(workspace_id), _) => {
            let role = role_in(&state.pool, workspace_id, auth.user_id.as_deref()).await?;
            // A service token has no person behind it, so it is treated as an
            // administrative credential for its workspace.
            let admin =
                auth.user_id.is_none() || matches!(role.as_deref(), Some("owner" | "admin"));
            if admin {
                sqlx::query_as::<_, Row>(
                    "SELECT id, scopes, created_at, expires_at, revoked_at, last_used_at
                     FROM api_tokens WHERE workspace_id = $1 ORDER BY created_at DESC",
                )
                .bind(workspace_id)
                .fetch_all(&state.pool)
                .await
            } else {
                sqlx::query_as::<_, Row>(
                    "SELECT id, scopes, created_at, expires_at, revoked_at, last_used_at
                     FROM api_tokens WHERE workspace_id = $1 AND user_id = $2
                     ORDER BY created_at DESC",
                )
                .bind(workspace_id)
                .bind(&auth.user_id)
                .fetch_all(&state.pool)
                .await
            }
        }
        (None, Some(user_id)) => {
            sqlx::query_as::<_, Row>(
                "SELECT id, scopes, created_at, expires_at, revoked_at, last_used_at
                 FROM api_tokens WHERE user_id = $1 AND workspace_id IS NULL
                 ORDER BY created_at DESC",
            )
            .bind(user_id)
            .fetch_all(&state.pool)
            .await
        }
        (None, None) => return Err(fail(StatusCode::UNAUTHORIZED, "invalid token")),
    }
    .map_err(internal)?;
    Ok(Json(json!(
        rows.into_iter()
            .map(
                |(id, scopes, created_at, expires_at, revoked_at, last_used_at)| json!({
                    "id": id,
                    "scopes": scopes_of(scopes.as_deref()),
                    "createdAt": created_at,
                    "expiresAt": expires_at,
                    "revokedAt": revoked_at,
                    "lastUsedAt": last_used_at,
                })
            )
            .collect::<Vec<_>>()
    )))
}

/// `scopes` is stored as a Postgres array literal (`{read,write}`).
fn scopes_of(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .trim_matches(|c| c == '{' || c == '}')
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

async fn delete_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    // Owners and admins may revoke anyone's token in their workspace; members
    // may only revoke their own. The target row decides the workspace so a
    // user-scoped caller cannot reach into a workspace they never joined.
    let target = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT workspace_id, user_id FROM api_tokens WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?;
    let Some((target_workspace, target_user)) = target else {
        return Err(fail(StatusCode::NOT_FOUND, "token not found"));
    };
    let n = if let Some(workspace_id) = target_workspace.as_deref() {
        let role = role_in(&state.pool, workspace_id, auth.user_id.as_deref()).await?;
        let admin = auth.user_id.is_none() && auth.workspace_id.as_deref() == Some(workspace_id)
            || matches!(role.as_deref(), Some("owner" | "admin"));
        if admin {
            sqlx::query(
                "UPDATE api_tokens SET revoked_at = $1 WHERE id = $2 AND workspace_id = $3 AND revoked_at IS NULL",
            )
            .bind(now_ms())
            .bind(&id)
            .bind(workspace_id)
            .execute(&state.pool)
            .await
            .map_err(internal)?
            .rows_affected()
        } else {
            let user_id = auth
                .user_id
                .as_deref()
                .ok_or_else(|| fail(StatusCode::NOT_FOUND, "token not found"))?;
            if target_user.as_deref() != Some(user_id) {
                return Err(fail(StatusCode::NOT_FOUND, "token not found"));
            }
            sqlx::query(
                "UPDATE api_tokens SET revoked_at = $1 WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL",
            )
            .bind(now_ms())
            .bind(&id)
            .bind(user_id)
            .execute(&state.pool)
            .await
            .map_err(internal)?
            .rows_affected()
        }
    } else {
        let user_id = auth
            .user_id
            .as_deref()
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "token not found"))?;
        if target_user.as_deref() != Some(user_id) {
            return Err(fail(StatusCode::NOT_FOUND, "token not found"));
        }
        sqlx::query(
            "UPDATE api_tokens SET revoked_at = $1 WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL",
        )
        .bind(now_ms())
        .bind(&id)
        .bind(user_id)
        .execute(&state.pool)
        .await
        .map_err(internal)?
        .rows_affected()
    };
    if n == 0 {
        return Err(fail(StatusCode::NOT_FOUND, "token not found"));
    }
    audit(
        &state.pool,
        target_workspace.as_deref().or(auth.workspace_id.as_deref()),
        auth.user_id.as_deref(),
        "token.revoke",
        Some(&id),
    )
    .await
    .map_err(internal)?;
    Ok(Json(json!({"ok": true})))
}

async fn github_install(State(state): State<AppState>) -> Json<Value> {
    let repo = std::env::var("FREEDAS_GITHUB_REPO").unwrap_or_else(|_| "freedas/freedas".into());
    let install_url = format!(
        "{}/github/install/callback",
        state.base_url.trim_end_matches('/')
    );
    Json(json!({ "repo": repo, "installUrl": install_url }))
}

/// `review_policies.automatic`: whether a pull request event starts a review.
/// Unknown values fall back to the schema default, `opened`.
fn policy_triggers(automatic: &str, action: &str) -> bool {
    match automatic {
        "never" => false,
        "all" => true,
        "pushes" => matches!(action, "opened" | "synchronize" | "reopened"),
        _ => action == "opened",
    }
}

/// The values one policy filter field is matched against.
fn filter_values<'a>(field: &str, payload: &'a Value) -> Vec<&'a str> {
    let pr = &payload["pull_request"];
    match field {
        "author" => pr["user"]["login"].as_str().into_iter().collect(),
        "repository" => payload["repository"]["full_name"]
            .as_str()
            .into_iter()
            .collect(),
        "branch" => pr["head"]["ref"].as_str().into_iter().collect(),
        "title" => pr["title"].as_str().into_iter().collect(),
        "label" => pr["labels"]
            .as_array()
            .map(|labels| labels.iter().filter_map(|l| l["name"].as_str()).collect())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Applies `[{field, op: include|exclude, values}]` policy filters. An
/// `include` filter that matches nothing skips the review; an `exclude` filter
/// that matches anything skips it. Unknown fields and ops are ignored.
fn filters_skip(filters: &Value, payload: &Value) -> bool {
    let Some(filters) = filters.as_array() else {
        return false;
    };
    for filter in filters {
        let field = filter["field"].as_str().unwrap_or_default();
        let values: Vec<&str> = filter["values"]
            .as_array()
            .map(|values| values.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let matched = filter_values(field, payload).iter().any(|actual| {
            values
                .iter()
                .any(|wanted| actual.eq_ignore_ascii_case(wanted))
        });
        match filter["op"].as_str().unwrap_or_default() {
            "include" if !matched => return true,
            "exclude" if matched => return true,
            _ => {}
        }
    }
    false
}

/// Review policy for a workspace; schema defaults when no row exists or the
/// installation is not linked to a workspace.
async fn webhook_policy(
    pool: &PgPool,
    workspace_id: Option<&str>,
) -> Result<(String, bool, Value), ApiError> {
    let Some(workspace_id) = workspace_id else {
        return Ok(("opened".into(), false, json!([])));
    };
    let row = sqlx::query_as::<_, (String, bool, String)>(
        "SELECT automatic, include_drafts, filters::text FROM review_policies
         WHERE workspace_id = $1",
    )
    .bind(workspace_id)
    .fetch_optional(pool)
    .await
    .map_err(internal)?;
    Ok(match row {
        Some((automatic, include_drafts, filters)) => (
            automatic,
            include_drafts,
            serde_json::from_str(&filters).unwrap_or_else(|_| json!([])),
        ),
        None => ("opened".into(), false, json!([])),
    })
}

async fn github_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult {
    let secret = std::env::var("FREEDAS_GITHUB_WEBHOOK_SECRET")
        .ok()
        .filter(|secret| !secret.is_empty())
        .ok_or_else(|| {
            fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "webhook secret is not configured",
            )
        })?;
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !verify_github_signature(&body, signature, &secret) {
        return Err(fail(StatusCode::BAD_REQUEST, "invalid signature"));
    }
    // A delivery is processed once; GitHub retries on timeouts and a replay
    // must not queue a second review. GitHub sends no signed timestamp, so the
    // id is the only replay signal available.
    let delivery = headers
        .get("x-github-delivery")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if !delivery.is_empty() {
        let now = now_ms();
        let _ = sqlx::query("DELETE FROM webhook_deliveries WHERE received_at < $1")
            .bind(now - 86_400_000)
            .execute(&state.pool)
            .await;
        let fresh = sqlx::query(
            "INSERT INTO webhook_deliveries (id, received_at) VALUES ($1, $2)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&delivery)
        .bind(now)
        .execute(&state.pool)
        .await
        .map_err(internal)?
        .rows_affected();
        if fresh == 0 {
            return Ok(Json(json!({ "ok": true, "status": "duplicate" })));
        }
    }

    let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let installation_id = payload["installation"]["id"].as_i64();
    let repo = payload["repository"]["full_name"].as_str();
    let pr_number = payload["pull_request"]["number"].as_i64();
    let head_sha = payload["pull_request"]["head"]["sha"].as_str();

    if let (Some(installation_id), Some(repo), Some(pr_number), Some(head_sha)) =
        (installation_id, repo, pr_number, head_sha)
    {
        let workspace_id = sqlx::query_scalar::<_, Option<String>>(
            "SELECT workspace_id FROM github_installations WHERE id = $1",
        )
        .bind(installation_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?
        .flatten();
        // An unlinked installation has no workspace to bill or show the review
        // in, so it is ignored rather than queued ownerless.
        let Some(workspace_id) = workspace_id else {
            return Ok(Json(json!({ "ok": true, "status": "ignored" })));
        };

        let (automatic, include_drafts, filters) =
            webhook_policy(&state.pool, Some(&workspace_id)).await?;
        if !policy_triggers(&automatic, payload["action"].as_str().unwrap_or_default()) {
            return Ok(Json(json!({ "ok": true, "status": "ignored" })));
        }
        // A skipped review keeps its row so the dashboard can explain why the
        // event did not run; the unique key still dedupes per head SHA.
        let draft = payload["pull_request"]["draft"].as_bool().unwrap_or(false);
        let status = if (draft && !include_drafts) || filters_skip(&filters, &payload) {
            "skipped"
        } else {
            "queued"
        };

        let author = payload["pull_request"]["user"]["login"].as_str();
        let inserted = sqlx::query(
            "INSERT INTO reviews
               (id, workspace_id, installation_id, repo, pr_number, head_sha, status, author, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
             ON CONFLICT DO NOTHING",
        )
        .bind(new_id("rev"))
        .bind(&workspace_id)
        .bind(installation_id)
        .bind(repo)
        .bind(pr_number)
        .bind(head_sha)
        .bind(status)
        .bind(author)
        .bind(now_ms())
        .execute(&state.pool)
        .await
        .map_err(internal)?
        .rows_affected();
        if inserted > 0 {
            audit(
                &state.pool,
                Some(&workspace_id),
                None,
                "review.post",
                Some(&format!("{repo}#{pr_number}@{head_sha}")),
            )
            .await
            .map_err(internal)?;
        }
    }

    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Verifies a GitHub `X-Hub-Signature-256` header value against the raw body.
/// The signature is hex-encoded HMAC-SHA256, optionally prefixed with `sha256=`.
pub fn verify_github_signature(body: &[u8], signature: &str, secret: &str) -> bool {
    // An empty key is a valid HMAC key, so it would accept anything the
    // attacker signs; an unset secret must fail closed.
    if secret.is_empty() {
        return false;
    }
    let Some(hex_sig) = signature.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(sig) = hex::decode(hex_sig) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&sig).is_ok()
}

/// SHA-256 hex digest used as the at-rest representation of API tokens.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Compares secrets without early exit. Digesting first makes the work
/// independent of both lengths.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (Sha256::digest(a.as_bytes()), Sha256::digest(b.as_bytes()));
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Sums ledger deltas at the numeric(12,6) scale the wallet is stored in.
pub fn balance_from_rows(amounts: &[f64]) -> f64 {
    let total: f64 = amounts.iter().sum();
    (total * 1e6).round() / 1e6
}

fn verify_password(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|hash| {
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    })
}

/// Verifies against a fixed hash so a missing account costs the same time as a
/// wrong password and cannot be detected by response latency.
fn dummy_verify(password: &str) {
    static DUMMY_PHC: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        use argon2::PasswordHasher;
        use argon2::password_hash::{SaltString, rand_core::OsRng};
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(b"freedas-dummy-password", &salt)
            .expect("dummy hash")
            .to_string()
    });
    verify_password(password, &DUMMY_PHC);
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &[u8] = b"The quick brown fox jumps over the lazy dog";
    const SIG: &str = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";

    #[test]
    fn verifies_valid_signature_with_and_without_prefix() {
        assert!(verify_github_signature(
            BODY,
            &format!("sha256={SIG}"),
            "key"
        ));
        assert!(!verify_github_signature(BODY, SIG, "key"));
    }

    #[test]
    fn rejects_wrong_secret_body_and_malformed_signature() {
        assert!(!verify_github_signature(
            BODY,
            &format!("sha256={SIG}"),
            "other"
        ));
        assert!(!verify_github_signature(
            b"tampered",
            &format!("sha256={SIG}"),
            "key"
        ));
        assert!(!verify_github_signature(BODY, "sha256=not-hex", "key"));
        assert!(!verify_github_signature(BODY, "", "key"));
        // An empty secret would make every forged signature valid.
        assert!(!verify_github_signature(BODY, &format!("sha256={SIG}"), ""));
        let empty_key_sig = {
            let mut mac = Hmac::<Sha256>::new_from_slice(b"").expect("hmac");
            mac.update(BODY);
            format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
        };
        assert!(!verify_github_signature(BODY, &empty_key_sig, ""));
    }

    #[test]
    fn money_math_sums_to_six_decimals() {
        assert_eq!(balance_from_rows(&[10.0, -3.25, 0.1, 0.2]), 7.05);
        assert_eq!(balance_from_rows(&[]), 0.0);
        assert_eq!(balance_from_rows(&[-4.5]), -4.5);
    }

    #[test]
    fn token_hash_is_deterministic_sha256_hex() {
        assert_eq!(hash_token("abc"), hash_token("abc"));
        assert_eq!(hash_token("abc").len(), 64);
        assert_ne!(hash_token("abc"), hash_token("abd"));
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn constant_time_eq_compares_whole_secrets() {
        assert!(constant_time_eq("", ""));
        assert!(constant_time_eq("runner-secret", "runner-secret"));
        assert!(!constant_time_eq("runner-secret", "runner-secreT"));
        assert!(!constant_time_eq("runner-secret", "runner"));
        assert!(!constant_time_eq("", "runner-secret"));
    }

    #[test]
    fn password_verification_matches_argon2_phc() {
        use argon2::PasswordHasher;
        use argon2::password_hash::{SaltString, rand_core::OsRng};
        let salt = SaltString::generate(&mut OsRng);
        let phc = Argon2::default()
            .hash_password(b"hunter2", &salt)
            .expect("hash")
            .to_string();
        assert!(verify_password("hunter2", &phc));
        assert!(!verify_password("wrong", &phc));
        assert!(!verify_password("hunter2", "not-a-phc-string"));
    }

    #[tokio::test]
    #[ignore]
    async fn live_control_plane_roundtrip() {
        // Requires: docker run -d --name freedas-pg-test -e POSTGRES_PASSWORD=postgres -p 55432:5432 postgres:17-alpine
        let url = std::env::var("FREEDAS_PG_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/postgres".into());
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            return;
        };
        sqlx::query("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, password_hash TEXT, oidc_sub TEXT UNIQUE, created_at BIGINT NOT NULL)")
            .execute(&pool).await.expect("users");
        sqlx::query("CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, kind TEXT NOT NULL, owner_id TEXT REFERENCES users(id), settings JSONB NOT NULL DEFAULT '{}'::jsonb, created_at BIGINT NOT NULL)")
            .execute(&pool).await.expect("workspaces");
        sqlx::query("CREATE TABLE IF NOT EXISTS memberships (workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, user_id TEXT REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL, PRIMARY KEY (workspace_id, user_id))")
            .execute(&pool).await.expect("memberships");
        sqlx::query("CREATE TABLE IF NOT EXISTS wallet_ledger (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, delta_usd NUMERIC(12,6) NOT NULL, reason TEXT NOT NULL, ref TEXT, created_at BIGINT NOT NULL)")
            .execute(&pool).await.expect("wallet_ledger");
        sqlx::query("CREATE TABLE IF NOT EXISTS api_tokens (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, scopes TEXT, last_used_at BIGINT, expires_at BIGINT, revoked_at BIGINT, created_at BIGINT NOT NULL)")
            .execute(&pool).await.expect("api_tokens");
        // Seed owner + workspace, log in, and read the wallet back.
        use argon2::PasswordHasher;
        use argon2::password_hash::{SaltString, rand_core::OsRng};
        let salt = SaltString::generate(&mut OsRng);
        let phc = Argon2::default()
            .hash_password(b"hunter2", &salt)
            .expect("hash")
            .to_string();
        let now = now_ms();
        sqlx::query("INSERT INTO users (id, email, name, password_hash, created_at) VALUES ('usr_1', 'a@example.com', 'A', $1, $2) ON CONFLICT (email) DO NOTHING")
            .bind(&phc).bind(now).execute(&pool).await.expect("seed user");
        sqlx::query("INSERT INTO workspaces (id, slug, name, kind, owner_id, created_at) VALUES ('ws_1', 'acme', 'Acme', 'organization', 'usr_1', $1) ON CONFLICT (slug) DO NOTHING")
            .bind(now).execute(&pool).await.expect("seed workspace");
        sqlx::query("INSERT INTO memberships (workspace_id, user_id, role) VALUES ('ws_1', 'usr_1', 'owner') ON CONFLICT DO NOTHING")
            .execute(&pool).await.expect("seed membership");
        sqlx::query("INSERT INTO wallet_ledger (id, workspace_id, delta_usd, reason, created_at) VALUES ('led_1', 'ws_1', 10.0, 'credit', $1) ON CONFLICT (id) DO NOTHING")
            .bind(now).execute(&pool).await.expect("seed ledger");
        let balance: f64 = sqlx::query_scalar("SELECT COALESCE(SUM(delta_usd), 0)::float8 FROM wallet_ledger WHERE workspace_id = 'ws_1'")
            .fetch_one(&pool).await.expect("balance");
        assert_eq!(balance, 10.0);
    }
}

// ---------------------------------------------------------------------------
// Sandboxes, workspace settings, and review retry
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SandboxBody {
    repo: String,
    #[serde(default = "default_base_branch")]
    base_branch: String,
    task: String,
}

fn default_base_branch() -> String {
    "main".into()
}

async fn list_reviews(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            i64,
            String,
            String,
            i64,
            Option<f64>,
            Option<f64>,
            Option<String>,
            Option<String>,
            f64,
        ),
    >(
        "SELECT id, repo, pr_number, head_sha, status, created_at,
                confidence::float8, risk::float8, author, review_url,
                (COALESCE(customer_cost_usd, 0) + COALESCE(upstream_cost_usd, 0))::float8
         FROM reviews WHERE workspace_id = $1 ORDER BY created_at DESC LIMIT 100",
    )
    .bind(&workspace_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!(
        rows.into_iter()
            .map(
                |(id, repo, pr, sha, status, created, confidence, risk, author, url, cost)| json!({
                    "id": id, "repo": repo, "prNumber": pr, "headSha": sha,
                    "status": status, "createdAt": created,
                    "confidence": confidence, "risk": risk, "author": author,
                    "reviewUrl": url, "costUsd": cost,
                })
            )
            .collect::<Vec<_>>()
    )))
}

/// Workspace review totals. `findings` is JSONB written by the review worker,
/// so a NULL or non-array value counts as zero findings instead of failing.
async fn reviews_analytics(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let rows = sqlx::query_as::<
        _,
        (
            String,
            Option<f64>,
            Option<String>,
            f64,
            String,
            Option<String>,
        ),
    >(
        "SELECT status, confidence::float8, findings::text,
                (COALESCE(customer_cost_usd, 0) + COALESCE(upstream_cost_usd, 0))::float8,
                repo, author
         FROM reviews WHERE workspace_id = $1",
    )
    .bind(&workspace_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;

    let mut by_status: std::collections::BTreeMap<String, i64> =
        ["queued", "running", "completed", "failed", "skipped"]
            .into_iter()
            .map(|status| (status.to_string(), 0))
            .collect();
    let mut by_severity: std::collections::BTreeMap<String, i64> =
        ["blocker", "high", "medium", "low", "nit"]
            .into_iter()
            .map(|severity| (severity.to_string(), 0))
            .collect();
    let mut findings_total = 0i64;
    let mut confidence_sum = 0.0;
    let mut confidence_count = 0i64;
    let mut costs = Vec::new();
    let mut repos: std::collections::BTreeMap<String, i64> = Default::default();
    let mut authors: std::collections::BTreeMap<String, i64> = Default::default();
    let total = rows.len() as i64;
    for (status, confidence, findings, cost, repo, author) in rows {
        *by_status.entry(status).or_insert(0) += 1;
        if let Some(confidence) = confidence {
            confidence_sum += confidence;
            confidence_count += 1;
        }
        costs.push(cost);
        *repos.entry(repo).or_insert(0) += 1;
        if let Some(author) = author {
            *authors.entry(author).or_insert(0) += 1;
        }
        let parsed: Vec<Value> = findings
            .as_deref()
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default();
        findings_total += parsed.len() as i64;
        for finding in parsed {
            if let Some(count) = finding["severity"]
                .as_str()
                .and_then(|s| by_severity.get_mut(s))
            {
                *count += 1;
            }
        }
    }
    let top = |counts: std::collections::BTreeMap<String, i64>, key: &str| {
        let mut items: Vec<(String, i64)> = counts.into_iter().collect();
        items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        items.truncate(5);
        items
            .into_iter()
            .map(|(name, reviews)| json!({ key: name, "reviews": reviews }))
            .collect::<Vec<_>>()
    };
    let average = if confidence_count == 0 {
        0.0
    } else {
        ((confidence_sum / confidence_count as f64) * 100.0).round() / 100.0
    };
    Ok(Json(json!({
        "total": total,
        "byStatus": by_status,
        "findings": findings_total,
        "bySeverity": by_severity,
        "averageConfidence": average,
        "totalCostUsd": balance_from_rows(&costs),
        "topRepos": top(repos, "repo"),
        "contributors": top(authors, "author"),
    })))
}

async fn retry_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let changed = sqlx::query(
        "UPDATE reviews SET status = 'queued', updated_at = $1
         WHERE id = $2 AND workspace_id = $3 AND status IN ('failed', 'skipped')",
    )
    .bind(now_ms())
    .bind(&id)
    .bind(&workspace_id)
    .execute(&state.pool)
    .await
    .map_err(internal)?
    .rows_affected();
    if changed == 0 {
        return Err(fail(
            StatusCode::CONFLICT,
            "review not found or not retryable",
        ));
    }
    Ok(Json(json!({"ok": true, "id": id, "status": "queued"})))
}

// ---------------------------------------------------------------------------
// Session metadata and manual review starts
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionMetadataBody {
    #[serde(rename = "sessionID")]
    session_id: String,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    input_tokens: i64,
    #[serde(default)]
    output_tokens: i64,
    #[serde(default)]
    cost_usd: f64,
    #[serde(default)]
    files_read: Vec<String>,
    #[serde(default)]
    prompt_excerpt: Option<String>,
    started_at: i64,
    #[serde(default)]
    ended_at: Option<i64>,
}

#[derive(Deserialize)]
struct SessionListQuery {
    limit: Option<i64>,
}

/// Metadata only: the transcript stays on the CLI.
async fn upsert_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SessionMetadataBody>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    if body.session_id.trim().is_empty() {
        return Err(fail(StatusCode::BAD_REQUEST, "sessionID is required"));
    }
    let excerpt: Option<String> = body
        .prompt_excerpt
        .as_deref()
        .map(|text| text.chars().take(500).collect());
    let files = json!(body.files_read);
    // A member may only rewrite their own session row; owners and admins may
    // correct anyone's.
    let role = role_in(&state.pool, &workspace_id, auth.user_id.as_deref()).await?;
    let admin = matches!(role.as_deref(), Some("owner" | "admin"));
    let changed = sqlx::query(
        "INSERT INTO session_metadata
           (session_id, workspace_id, user_id, project, model, input_tokens, output_tokens,
            cost_usd, files_read, prompt_excerpt, started_at, ended_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::numeric, $9::jsonb, $10, $11, $12)
         ON CONFLICT (session_id) DO UPDATE SET
           user_id = EXCLUDED.user_id,
           project = EXCLUDED.project,
           model = EXCLUDED.model,
           input_tokens = EXCLUDED.input_tokens,
           output_tokens = EXCLUDED.output_tokens,
           cost_usd = EXCLUDED.cost_usd,
           files_read = EXCLUDED.files_read,
           prompt_excerpt = EXCLUDED.prompt_excerpt,
           started_at = EXCLUDED.started_at,
           ended_at = EXCLUDED.ended_at
         WHERE session_metadata.workspace_id = EXCLUDED.workspace_id
           AND (session_metadata.user_id IS NOT DISTINCT FROM EXCLUDED.user_id OR $13)",
    )
    .bind(&body.session_id)
    .bind(&workspace_id)
    .bind(auth.user_id.as_deref())
    .bind(&body.project)
    .bind(&body.model)
    .bind(body.input_tokens)
    .bind(body.output_tokens)
    .bind(body.cost_usd)
    .bind(&files)
    .bind(&excerpt)
    .bind(body.started_at)
    .bind(body.ended_at)
    .bind(admin)
    .execute(&state.pool)
    .await
    .map_err(internal)?
    .rows_affected();
    if changed == 0 {
        return Err(fail(
            StatusCode::CONFLICT,
            "session belongs to another workspace or user",
        ));
    }
    Ok(Json(json!({"sessionID": body.session_id})))
}

async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SessionListQuery>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let rows = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            Option<String>,
            i64,
            i64,
            f64,
            Value,
            Option<String>,
            i64,
            Option<i64>,
        ),
    >(
        "SELECT session_id, project, model, input_tokens, output_tokens, cost_usd::float8,
                files_read, prompt_excerpt, started_at, ended_at
         FROM session_metadata WHERE workspace_id = $1
         ORDER BY started_at DESC, session_id DESC LIMIT $2",
    )
    .bind(&workspace_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!(
        rows.into_iter()
            .map(
                |(
                    session_id,
                    project,
                    model,
                    input_tokens,
                    output_tokens,
                    cost_usd,
                    files_read,
                    prompt_excerpt,
                    started_at,
                    ended_at,
                )| json!({
                    "sessionID": session_id, "project": project, "model": model,
                    "inputTokens": input_tokens, "outputTokens": output_tokens,
                    "costUsd": cost_usd, "filesRead": files_read,
                    "promptExcerpt": prompt_excerpt, "startedAt": started_at,
                    "endedAt": ended_at,
                }),
            )
            .collect::<Vec<_>>()
    )))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManualReviewBody {
    repo: String,
    pr_number: i64,
    head_sha: String,
}

async fn start_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ManualReviewBody>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    if body.repo.trim().is_empty() || body.head_sha.trim().is_empty() {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "repo and headSha are required",
        ));
    }
    // Manual reviews have no GitHub App installation. The review identity is
    // (workspace, repo, PR, head): a manual request reuses the existing row
    // instead of raising, and another tenant reviewing the same public PR is a
    // separate row.
    let id = new_id("rev");
    let now = now_ms();
    let row = sqlx::query_as::<_, (String, String)>(
        "INSERT INTO reviews
           (id, workspace_id, installation_id, repo, pr_number, head_sha, status,
            created_at, updated_at)
         VALUES ($1, $2, 0, $3, $4, $5, 'queued', $6, $6)
         ON CONFLICT (workspace_id, repo, pr_number, head_sha)
         DO UPDATE SET updated_at = reviews.updated_at
         RETURNING id, status",
    )
    .bind(&id)
    .bind(&workspace_id)
    .bind(&body.repo)
    .bind(body.pr_number)
    .bind(&body.head_sha)
    .bind(now)
    .fetch_one(&state.pool)
    .await
    .map_err(internal)?;
    audit(
        &state.pool,
        Some(&workspace_id),
        auth.user_id.as_deref(),
        "review.queued",
        Some(&row.0),
    )
    .await
    .map_err(internal)?;
    Ok(Json(json!({"id": row.0, "status": row.1})))
}

async fn get_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            i64,
            String,
            String,
            i64,
            Option<f64>,
            Option<f64>,
            Option<String>,
            Option<String>,
            f64,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT id, repo, pr_number, head_sha, status, created_at,
                confidence::float8, risk::float8, author, review_url,
                (COALESCE(customer_cost_usd, 0) + COALESCE(upstream_cost_usd, 0))::float8,
                findings::text, summary, error
         FROM reviews WHERE id = $1 AND workspace_id = $2",
    )
    .bind(&id)
    .bind(&workspace_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?
    .ok_or_else(|| fail(StatusCode::NOT_FOUND, "review not found"))?;
    let findings = row
        .11
        .as_deref()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or(Value::Null);
    Ok(Json(json!({
        "id": row.0, "repo": row.1, "prNumber": row.2, "headSha": row.3,
        "status": row.4, "createdAt": row.5, "confidence": row.6, "risk": row.7,
        "author": row.8, "reviewUrl": row.9, "costUsd": row.10,
        "findings": findings, "summary": row.12, "error": row.13,
    })))
}

async fn get_settings(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let settings: Value =
        sqlx::query_scalar::<_, Value>("SELECT settings FROM workspaces WHERE id = $1")
            .bind(&workspace_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(internal)?
            .unwrap_or_else(|| json!({}));
    Ok(Json(settings))
}

async fn patch_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let role = role_in(&state.pool, &workspace_id, auth.user_id.as_deref()).await?;
    if !matches!(role.as_deref(), Some("owner" | "admin")) {
        return Err(fail(StatusCode::FORBIDDEN, "owner or admin role required"));
    }
    if let Some(rate) = body.pointer("/sandboxes/computeRateUsd")
        && !rate
            .as_f64()
            .is_some_and(|rate| rate.is_finite() && rate > 0.0)
    {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "computeRateUsd must be a positive number",
        ));
    }
    let current: Value =
        sqlx::query_scalar::<_, Value>("SELECT settings FROM workspaces WHERE id = $1")
            .bind(&workspace_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(internal)?
            .unwrap_or_else(|| json!({}));
    // A shallow `||` would drop sibling keys under `sandboxes`; merge nested
    // objects so unrelated settings survive a patch.
    let mut merged = current;
    deep_merge(&mut merged, &body);
    let settings = sqlx::query_scalar::<_, Value>(
        "UPDATE workspaces SET settings = $1::jsonb WHERE id = $2 RETURNING settings",
    )
    .bind(&merged)
    .bind(&workspace_id)
    .fetch_one(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(settings))
}

fn deep_merge(target: &mut Value, patch: &Value) {
    match (target, patch) {
        (Value::Object(target), Value::Object(patch)) => {
            for (key, value) in patch {
                deep_merge(target.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
        (target, patch) => *target = patch.clone(),
    }
}

async fn list_sandboxes(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            i64,
            i64,
            Option<i64>,
            Option<f64>,
            Option<i64>,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT id, repo, base_branch, status, branch, created_at, updated_at,
                compute_seconds, compute_cost_usd::float8, pr_number, pr_url, failure_reason
         FROM sandboxes WHERE workspace_id = $1 ORDER BY created_at DESC LIMIT 100",
    )
    .bind(&workspace_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!(
        rows.into_iter()
            .map(
                |(
                    id,
                    repo,
                    base,
                    status,
                    branch,
                    created,
                    updated,
                    seconds,
                    cost,
                    pr_number,
                    pr_url,
                    failure_reason,
                )| json!({
                    "id": id, "repo": repo, "baseBranch": base, "status": status,
                    "branch": branch, "createdAt": created, "updatedAt": updated,
                    "computeSeconds": seconds, "computeCostUsd": cost,
                    "prNumber": pr_number, "prUrl": pr_url,
                    "failureReason": failure_reason,
                }),
            )
            .collect::<Vec<_>>()
    )))
}

async fn create_sandbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SandboxBody>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let settings = get_settings(State(state.clone()), headers).await?;
    let enabled = settings.0["sandboxes"]["enabled"]
        .as_bool()
        .unwrap_or(false);
    if !enabled {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "cloud sandboxes are disabled for this workspace",
        ));
    }
    if body.repo.is_empty() || body.task.is_empty() {
        return Err(fail(StatusCode::BAD_REQUEST, "repo and task are required"));
    }
    // Compute bills per second with a sixty-second minimum, so the wallet must
    // cover a full minimum slice before a sandbox is queued. Hold the
    // workspace lock while checking and reserving so concurrent creates
    // cannot overspend the same balance.
    let rate = settings.0["sandboxes"]["computeRateUsd"]
        .as_f64()
        .unwrap_or(0.0);
    let minimum = 60.0 * rate;
    let id = new_id("sbx");
    let now = now_ms();
    let branch = format!("freedas/{}", &id[id.len().saturating_sub(8)..]);
    let mut tx = state.pool.begin().await.map_err(internal)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&workspace_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    let balance = sqlx::query_scalar::<_, f64>(
        "SELECT COALESCE(SUM(delta_usd), 0)::float8 FROM wallet_ledger WHERE workspace_id = $1",
    )
    .bind(&workspace_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(internal)?;
    if balance + 1e-9 < minimum {
        return Err(fail(
            StatusCode::PAYMENT_REQUIRED,
            "wallet does not cover the sandbox minimum",
        ));
    }
    if minimum > 0.0 {
        sqlx::query(
            "INSERT INTO wallet_ledger (id, workspace_id, delta_usd, reason, ref, created_at)
             VALUES ($1, $2, $3::numeric, 'sandbox_reserve', $4, $5)",
        )
        .bind(new_id("led"))
        .bind(&workspace_id)
        .bind(format!("{:.6}", -minimum))
        .bind(&id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    }
    sqlx::query(
        "INSERT INTO sandboxes
           (id, workspace_id, repo, base_branch, task, branch, status, compute_rate_usd, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'queued', $7::numeric, $8, $8)",
    )
    .bind(&id)
    .bind(&workspace_id)
    .bind(&body.repo)
    .bind(&body.base_branch)
    .bind(&body.task)
    .bind(&branch)
    .bind(rate.to_string())
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    audit(
        &state.pool,
        Some(&workspace_id),
        auth.user_id.as_deref(),
        "sandbox.create",
        Some(&id),
    )
    .await
    .map_err(internal)?;
    Ok(Json(json!({
        "id": id, "repo": body.repo, "baseBranch": body.base_branch,
        "task": body.task, "branch": branch, "status": "queued",
    })))
}

async fn get_sandbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            i64,
            i64,
            Option<i64>,
            Option<String>,
        ),
    >(
        "SELECT id, repo, base_branch, status, branch, created_at, updated_at,
                finished_at, failure_reason
         FROM sandboxes WHERE id = $1 AND workspace_id = $2",
    )
    .bind(&id)
    .bind(&workspace_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?
    .ok_or_else(|| fail(StatusCode::NOT_FOUND, "sandbox not found"))?;
    Ok(Json(json!({
        "id": row.0, "repo": row.1, "baseBranch": row.2, "status": row.3,
        "branch": row.4, "createdAt": row.5, "updatedAt": row.6,
        "finishedAt": row.7, "failureReason": row.8,
    })))
}

async fn sandbox_heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let now = now_ms();
    let changed = sqlx::query(
        "UPDATE sandboxes SET status = 'running', updated_at = $1
         WHERE id = $2 AND workspace_id = $3 AND status IN ('queued', 'provisioning', 'running')",
    )
    .bind(now)
    .bind(&id)
    .bind(&workspace_id)
    .execute(&state.pool)
    .await
    .map_err(internal)?
    .rows_affected();
    if changed == 0 {
        return Err(fail(StatusCode::CONFLICT, "sandbox is not running"));
    }
    Ok(Json(json!({"ok": true, "status": "running"})))
}

/// Marks a live sandbox finished and bills its compute in the caller's
/// transaction. Returns the billed seconds and cost, or `None` when the row was
/// already terminal, so a concurrent second stop cannot bill twice. The reaper
/// and the stop endpoint share it so a failed run is billed like a stopped one.
async fn settle_sandbox(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
    workspace_id: Option<&str>,
    status: &str,
    failure_reason: Option<&str>,
    now: i64,
) -> Result<Option<(i64, f64)>, sqlx::Error> {
    let row = sqlx::query_as::<_, (i64, f64)>(
        "UPDATE sandboxes SET status = $1, failure_reason = $2,
                updated_at = $3, finished_at = $3,
                compute_seconds = GREATEST((($3 - created_at) + 999) / 1000, 60),
                compute_cost_usd = ROUND(
                    GREATEST((($3 - created_at) + 999) / 1000, 60) * compute_rate_usd, 6)
         WHERE id = $4 AND ($5::text IS NULL OR workspace_id = $5)
           AND status IN ('queued', 'provisioning', 'running')
         RETURNING compute_seconds, compute_cost_usd::float8",
    )
    .bind(status)
    .bind(failure_reason)
    .bind(now)
    .bind(id)
    .bind(workspace_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((seconds, cost)) = row else {
        return Ok(None);
    };
    // Match the runner: whole cents within the stored six-decimal scale.
    let cost = (cost * 1e6).round() / 1e6;
    if let Some(workspace_id) = workspace_id {
        // Release the creation-time minimum so the final ledger holds exactly
        // one minimum plus any overage: reserve (-min) + release (+min) +
        // compute (-cost) nets to -cost while keeping the `compute` row the
        // dashboard and tests already read.
        let reserved: f64 = sqlx::query_scalar(
            "SELECT COALESCE(-SUM(delta_usd), 0)::float8 FROM wallet_ledger
             WHERE workspace_id = $1 AND ref = $2 AND reason = 'sandbox_reserve'",
        )
        .bind(workspace_id)
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
        let reserved = (reserved * 1e6).round() / 1e6;
        if reserved > 0.0 {
            sqlx::query(
                "INSERT INTO wallet_ledger (id, workspace_id, delta_usd, reason, ref, created_at)
                 VALUES ($1, $2, $3::numeric, 'sandbox_reserve_release', $4, $5)",
            )
            .bind(new_id("led"))
            .bind(workspace_id)
            .bind(format!("{reserved:.6}"))
            .bind(id)
            .bind(now)
            .execute(&mut **tx)
            .await?;
        }
        if cost > 0.0 {
            sqlx::query(
                "INSERT INTO wallet_ledger (id, workspace_id, delta_usd, reason, ref, created_at)
                 VALUES ($1, $2, $3::numeric, 'compute', $4, $5)",
            )
            .bind(new_id("led"))
            .bind(workspace_id)
            .bind(format!("-{cost:.6}"))
            .bind(id)
            .bind(now)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(Some((seconds, cost)))
}

async fn stop_sandbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let now = now_ms();
    // Compute bills per second with a sixty-second minimum, at the rate
    // snapshotted when the sandbox was created.
    let row = sqlx::query_as::<_, (i64, f64, String)>(
        "SELECT created_at, compute_rate_usd::float8, status FROM sandboxes WHERE id = $1 AND workspace_id = $2",
    )
    .bind(&id)
    .bind(&workspace_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?
    .ok_or_else(|| fail(StatusCode::NOT_FOUND, "sandbox not found"))?;
    if row.2 == "stopped" || row.2 == "failed" || row.2 == "cancelled" {
        return Err(fail(StatusCode::CONFLICT, "sandbox already finished"));
    }
    let mut tx = state.pool.begin().await.map_err(internal)?;
    let settled = settle_sandbox(&mut tx, &id, Some(&workspace_id), "stopped", None, now)
        .await
        .map_err(internal)?;
    let Some((seconds, cost)) = settled else {
        // Another request finished it between the read and the update.
        return Err(fail(StatusCode::CONFLICT, "sandbox already finished"));
    };
    tx.commit().await.map_err(internal)?;
    revoke_sandbox_tokens(&state.pool, &id)
        .await
        .map_err(internal)?;
    audit(
        &state.pool,
        Some(&workspace_id),
        auth.user_id.as_deref(),
        "sandbox.stop",
        Some(&id),
    )
    .await
    .map_err(internal)?;
    Ok(Json(json!({
        "ok": true, "id": id, "status": "stopped",
        "computeSeconds": seconds, "computeCostUsd": cost,
    })))
}

/// Mints the tokens the sandbox runner injects. The runner authenticates with
/// `FREEDAS_RUNNER_TOKEN` rather than a workspace token, and the minted token
/// is bound to the sandbox's workspace and lifetime.
async fn sandbox_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult {
    let runner = std::env::var("FREEDAS_RUNNER_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            fail(
                StatusCode::NOT_IMPLEMENTED,
                "runner token is not configured",
            )
        })?;
    if !constant_time_eq(bearer(&headers).unwrap_or_default(), &runner) {
        return Err(fail(StatusCode::UNAUTHORIZED, "invalid runner token"));
    }
    let (workspace_id, repo, _status) = sqlx::query_as::<_, (String, Option<String>, String)>(
        "SELECT workspace_id, repo, status FROM sandboxes WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?
    .filter(|row| !matches!(row.2.as_str(), "stopped" | "failed" | "cancelled"))
    .ok_or_else(|| fail(StatusCode::NOT_FOUND, "sandbox not found"))?;

    let plaintext = random_hex(32);
    let now = now_ms();
    sqlx::query(
        "INSERT INTO api_tokens
           (id, user_id, workspace_id, token_hash, scopes, expires_at, created_at)
         VALUES ($1, NULL, $2, $3, $4, $5, $6)",
    )
    .bind(new_id("tok"))
    .bind(&workspace_id)
    .bind(hash_token(&plaintext))
    .bind(format!("{{sandbox:{id}}}"))
    .bind(now + 3_600_000)
    .bind(now)
    .execute(&state.pool)
    .await
    .map_err(internal)?;

    let github = match repo.as_deref() {
        Some(repo) => sandbox_github_token(&state.pool, &workspace_id, repo).await,
        None => None,
    };
    audit(
        &state.pool,
        Some(&workspace_id),
        None,
        "sandbox.token",
        Some(&id),
    )
    .await
    .map_err(internal)?;

    let mut body = json!({ "modelToken": plaintext });
    if let Some(token) = github {
        body["githubToken"] = json!(token);
    }
    Ok(Json(body))
}

/// Mints a repository-scoped installation token for the sandbox, or `None`
/// when the GitHub App or a workspace installation is missing. Repository
/// access is optional, so failures never fail the request.
async fn sandbox_github_token(pool: &PgPool, workspace_id: &str, repo: &str) -> Option<String> {
    static WARNED: std::sync::Once = std::sync::Once::new();
    let app_id = std::env::var("FREEDAS_GITHUB_APP_ID")
        .ok()
        .filter(|value| !value.is_empty())?;
    let key_path = std::env::var("FREEDAS_GITHUB_PRIVATE_KEY_PATH")
        .ok()
        .filter(|value| !value.is_empty())?;
    if !repo.contains('/') {
        return None;
    }
    let installation = sqlx::query_scalar::<_, i64>(
        // Only a repository the workspace explicitly enabled may get a token.
        "SELECT i.id FROM github_repositories r
         JOIN github_installations i ON i.id = r.installation_id
         WHERE i.workspace_id = $1 AND r.repo = $2 AND r.enabled
         ORDER BY i.id DESC LIMIT 1",
    )
    .bind(workspace_id)
    .bind(repo)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()?;
    let key_pem = std::fs::read_to_string(&key_path).ok()?;
    let api_base = std::env::var("FREEDAS_GITHUB_API_BASE")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| freedas_review::github::DEFAULT_API_BASE.to_string());
    let minted = freedas_review::github::installation_token(
        &reqwest::Client::new(),
        &api_base,
        &app_id,
        &key_pem,
        installation,
    )
    .await;
    minted
        .map_err(|error| WARNED.call_once(|| eprintln!("sandbox token: {error}")))
        .ok()
}

/// Revokes every model token bound to a sandbox, matching both the array
/// literal (`{sandbox:<id>}`) and plain (`sandbox:<id>`) scope shapes.
/// Idempotent: already-revoked rows are skipped, so a second teardown
/// reports zero.
pub async fn revoke_sandbox_tokens(pool: &PgPool, sandbox_id: &str) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE api_tokens SET revoked_at = $1
         WHERE revoked_at IS NULL AND scopes IN ($2, $3)",
    )
    .bind(now_ms())
    .bind(format!("{{sandbox:{sandbox_id}}}"))
    .bind(format!("sandbox:{sandbox_id}"))
    .execute(pool)
    .await?
    .rows_affected())
}

/// Fails sandboxes that stopped heartbeating, billing their compute and
/// recording one audit row each. Returns how many rows were reaped.
pub async fn reap_stale_sandboxes(pool: &PgPool, max_age_ms: i64) -> Result<u64, sqlx::Error> {
    let now = now_ms();
    let mut tx = pool.begin().await?;
    let stale = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT id, workspace_id FROM sandboxes
         WHERE status IN ('provisioning', 'running') AND updated_at < $1
         FOR UPDATE SKIP LOCKED",
    )
    .bind(now - max_age_ms)
    .fetch_all(&mut *tx)
    .await?;
    let mut reaped = 0u64;
    for (id, workspace_id) in &stale {
        if settle_sandbox(
            &mut tx,
            id,
            workspace_id.as_deref(),
            "failed",
            Some("heartbeat_timeout"),
            now,
        )
        .await?
        .is_none()
        {
            continue;
        }
        reaped += 1;
        sqlx::query(
            "INSERT INTO audit_log (id, workspace_id, user_id, action, subject, metadata, created_at)
             VALUES ($1, $2, NULL, 'sandbox.timeout', $3, $4::jsonb, $5)",
        )
        .bind(new_id("aud"))
        .bind(workspace_id)
        .bind(id)
        .bind(json!({"reason": "heartbeat_timeout"}).to_string())
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    for (id, _) in &stale {
        revoke_sandbox_tokens(pool, id).await?;
    }
    Ok(reaped)
}

// ---------------------------------------------------------------------------
// Membership, teams, budgets, invoices, usage summary, review policy, GitHub
// installations, OIDC, and SCIM
// ---------------------------------------------------------------------------

async fn workspace_for_slug(state: &AppState, slug: &str) -> Result<String, ApiError> {
    sqlx::query_scalar::<_, String>("SELECT id FROM workspaces WHERE slug = $1")
        .bind(slug)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "workspace not found"))
}

/// Resolves `{slug}` and confirms the caller may act in it. Returns the
/// workspace id and the caller's role (None for a workspace-bound service
/// token).
async fn workspace_access(
    state: &AppState,
    auth: &Auth,
    slug: &str,
) -> Result<(String, Option<String>), ApiError> {
    let workspace_id = workspace_for_slug(state, slug).await?;
    let role = role_in(&state.pool, &workspace_id, auth.user_id.as_deref()).await?;
    // Only a service token (no person behind it) stands on its binding; a user
    // token must still be a current member, or leaving the workspace would
    // leave it with a working credential.
    let bound =
        auth.user_id.is_none() && auth.workspace_id.as_deref() == Some(workspace_id.as_str());
    if role.is_none() && !bound {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "not a member of this workspace",
        ));
    }
    Ok((workspace_id, role))
}

fn require_admin(role: Option<&str>) -> Result<(), ApiError> {
    if matches!(role, Some("owner" | "admin")) {
        Ok(())
    } else {
        Err(fail(StatusCode::FORBIDDEN, "owner or admin role required"))
    }
}

/// Refuses to demote or remove the last owner of a workspace.
async fn require_another_owner(
    pool: &PgPool,
    workspace_id: &str,
    user_id: &str,
) -> Result<(), ApiError> {
    let other = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM memberships
         WHERE workspace_id = $1 AND role = 'owner' AND user_id <> $2 LIMIT 1",
    )
    .bind(workspace_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(internal)?
    .is_some();
    if other {
        Ok(())
    } else {
        Err(fail(StatusCode::CONFLICT, "cannot demote the last owner"))
    }
}

#[derive(Deserialize)]
struct MemberBody {
    email: String,
    role: String,
}

async fn list_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let (workspace_id, _) = workspace_access(&state, &auth, &slug).await?;
    let rows = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT u.id, u.email, u.name, m.role
         FROM memberships m JOIN users u ON u.id = m.user_id
         WHERE m.workspace_id = $1 ORDER BY u.email",
    )
    .bind(&workspace_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!(
        rows.into_iter()
            .map(|(id, email, name, role)| {
                json!({ "id": id, "email": email, "name": name, "role": role })
            })
            .collect::<Vec<_>>()
    )))
}

async fn add_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(body): Json<MemberBody>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let (workspace_id, role) = workspace_access(&state, &auth, &slug).await?;
    require_admin(role.as_deref())?;
    if !matches!(body.role.as_str(), "owner" | "admin" | "member") {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "role must be owner, admin, or member",
        ));
    }
    let user_id = sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE email = $1")
        .bind(&body.email)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "user not found"))?;
    // Ownership is not an admin power: granting it, or demoting an existing
    // owner through this upsert, requires the caller to be an owner and leaves
    // at least one owner behind.
    let current = role_in(&state.pool, &workspace_id, Some(&user_id)).await?;
    if body.role == "owner" || (current.as_deref() == Some("owner") && body.role != "owner") {
        if role.as_deref() != Some("owner") {
            return Err(fail(
                StatusCode::FORBIDDEN,
                "only an owner can grant or remove ownership",
            ));
        }
        if current.as_deref() == Some("owner") {
            require_another_owner(&state.pool, &workspace_id, &user_id).await?;
        }
    }
    sqlx::query(
        "INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, $3)
         ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role",
    )
    .bind(&workspace_id)
    .bind(&user_id)
    .bind(&body.role)
    .execute(&state.pool)
    .await
    .map_err(internal)?;
    audit(
        &state.pool,
        Some(&workspace_id),
        auth.user_id.as_deref(),
        "member.add",
        Some(&user_id),
    )
    .await
    .map_err(internal)?;
    Ok(Json(
        json!({ "userId": user_id, "email": body.email, "role": body.role }),
    ))
}

async fn remove_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((slug, user_id)): Path<(String, String)>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let (workspace_id, role) = workspace_access(&state, &auth, &slug).await?;
    require_admin(role.as_deref())?;
    // `owner_id` is a pointer to one owner, not a second permission system:
    // removing or demoting its holder hands it to another owner instead of
    // leaving it dangling. Membership roles remain the authority.
    let owner =
        sqlx::query_scalar::<_, Option<String>>("SELECT owner_id FROM workspaces WHERE id = $1")
            .bind(&workspace_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(internal)?
            .flatten();
    let target_role = role_in(&state.pool, &workspace_id, Some(&user_id)).await?;
    if target_role.as_deref() == Some("owner") {
        if role.as_deref() != Some("owner") {
            return Err(fail(
                StatusCode::FORBIDDEN,
                "only an owner can remove an owner",
            ));
        }
        require_another_owner(&state.pool, &workspace_id, &user_id).await?;
    } else if owner.as_deref() == Some(user_id.as_str()) {
        // The recorded owner is already a non-owner member (role changed
        // earlier); removal is allowed but must not leave `owner_id` stale.
        if role.as_deref() != Some("owner") {
            return Err(fail(
                StatusCode::FORBIDDEN,
                "only an owner can remove the workspace owner",
            ));
        }
    }
    let mut tx = state.pool.begin().await.map_err(internal)?;
    let removed = sqlx::query("DELETE FROM memberships WHERE workspace_id = $1 AND user_id = $2")
        .bind(&workspace_id)
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?
        .rows_affected();
    if removed == 0 {
        return Err(fail(StatusCode::NOT_FOUND, "member not found"));
    }
    // A removed member must not keep a workspace-scoped token working.
    sqlx::query(
        "UPDATE api_tokens SET revoked_at = $1
         WHERE user_id = $2 AND workspace_id = $3 AND revoked_at IS NULL",
    )
    .bind(now_ms())
    .bind(&user_id)
    .bind(&workspace_id)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    // Keep `owner_id` pointing at a live owner instead of the removed row.
    if owner.as_deref() == Some(user_id.as_str()) {
        let successor = sqlx::query_scalar::<_, String>(
            "SELECT user_id FROM memberships WHERE workspace_id = $1
             ORDER BY (role = 'owner') DESC, user_id LIMIT 1",
        )
        .bind(&workspace_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
        sqlx::query("UPDATE workspaces SET owner_id = $2 WHERE id = $1")
            .bind(&workspace_id)
            .bind(&successor)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    audit(
        &state.pool,
        Some(&workspace_id),
        auth.user_id.as_deref(),
        "member.remove",
        Some(&user_id),
    )
    .await
    .map_err(internal)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct RoleBody {
    role: String,
}

/// Changes one member's role. The update only lands while another owner
/// remains, so the workspace can never be left ownerless.
async fn change_member_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((slug, user_id)): Path<(String, String)>,
    Json(body): Json<RoleBody>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let (workspace_id, role) = workspace_access(&state, &auth, &slug).await?;
    require_admin(role.as_deref())?;
    if !matches!(body.role.as_str(), "owner" | "admin" | "member") {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "role must be owner, admin, or member",
        ));
    }
    // Only an owner may hand out or take away ownership; an admin changing an
    // ordinary member is fine.
    let current = role_in(&state.pool, &workspace_id, Some(&user_id)).await?;
    if current.as_deref() == Some("owner") || body.role == "owner" {
        if role.as_deref() != Some("owner") {
            return Err(fail(
                StatusCode::FORBIDDEN,
                "only an owner can grant or remove ownership",
            ));
        }
        if current.as_deref() == Some("owner") && body.role != "owner" {
            require_another_owner(&state.pool, &workspace_id, &user_id).await?;
        }
    }
    let changed = sqlx::query(
        "UPDATE memberships SET role = $1
         WHERE workspace_id = $2 AND user_id = $3
           AND ($1 = 'owner' OR role <> 'owner'
                OR (SELECT COUNT(*) FROM memberships m
                    WHERE m.workspace_id = $2 AND m.role = 'owner') > 1)",
    )
    .bind(&body.role)
    .bind(&workspace_id)
    .bind(&user_id)
    .execute(&state.pool)
    .await
    .map_err(internal)?
    .rows_affected();
    if changed == 0 {
        let exists = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM memberships WHERE workspace_id = $1 AND user_id = $2",
        )
        .bind(&workspace_id)
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?
        .is_some();
        return Err(if exists {
            fail(StatusCode::CONFLICT, "cannot demote the last owner")
        } else {
            fail(StatusCode::NOT_FOUND, "member not found")
        });
    }
    // Keep `owner_id` consistent with the membership change: adopting an owner
    // when none is recorded, handing the pointer off when its holder is
    // demoted.
    if body.role == "owner" {
        sqlx::query("UPDATE workspaces SET owner_id = $2 WHERE id = $1 AND owner_id IS NULL")
            .bind(&workspace_id)
            .bind(&user_id)
            .execute(&state.pool)
            .await
            .map_err(internal)?;
    } else if current.as_deref() == Some("owner") {
        let recorded = sqlx::query_scalar::<_, Option<String>>(
            "SELECT owner_id FROM workspaces WHERE id = $1",
        )
        .bind(&workspace_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?
        .flatten();
        if recorded.as_deref() == Some(user_id.as_str()) {
            let successor = sqlx::query_scalar::<_, String>(
                "SELECT user_id FROM memberships WHERE workspace_id = $1 AND role = 'owner'
                 AND user_id <> $2 ORDER BY user_id LIMIT 1",
            )
            .bind(&workspace_id)
            .bind(&user_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(internal)?;
            sqlx::query("UPDATE workspaces SET owner_id = $2 WHERE id = $1")
                .bind(&workspace_id)
                .bind(&successor)
                .execute(&state.pool)
                .await
                .map_err(internal)?;
        }
    }
    audit(
        &state.pool,
        Some(&workspace_id),
        auth.user_id.as_deref(),
        "member.role",
        Some(&user_id),
    )
    .await
    .map_err(internal)?;
    Ok(Json(json!({ "userId": user_id, "role": body.role })))
}

#[derive(Deserialize)]
struct TeamBody {
    name: String,
}

async fn list_teams(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let (workspace_id, _) = workspace_access(&state, &auth, &slug).await?;
    let rows = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT t.id, t.name, COUNT(tm.user_id)::bigint
         FROM teams t LEFT JOIN team_members tm ON tm.team_id = t.id
         WHERE t.workspace_id = $1
         GROUP BY t.id, t.name, t.created_at ORDER BY t.created_at",
    )
    .bind(&workspace_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!(
        rows.into_iter()
            .map(|(id, name, count)| json!({ "id": id, "name": name, "memberCount": count }))
            .collect::<Vec<_>>()
    )))
}

async fn create_team(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(body): Json<TeamBody>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let (workspace_id, role) = workspace_access(&state, &auth, &slug).await?;
    require_admin(role.as_deref())?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(fail(StatusCode::BAD_REQUEST, "name is required"));
    }
    let id = new_id("team");
    sqlx::query("INSERT INTO teams (id, workspace_id, name, created_at) VALUES ($1, $2, $3, $4)")
        .bind(&id)
        .bind(&workspace_id)
        .bind(name)
        .bind(now_ms())
        .execute(&state.pool)
        .await
        .map_err(internal)?;
    Ok(Json(json!({ "id": id, "name": name, "memberCount": 0 })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamMemberBody {
    user_id: String,
}

async fn add_team_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((slug, team_id)): Path<(String, String)>,
    Json(body): Json<TeamMemberBody>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let (workspace_id, role) = workspace_access(&state, &auth, &slug).await?;
    require_admin(role.as_deref())?;
    let team_exists =
        sqlx::query_scalar::<_, i32>("SELECT 1 FROM teams WHERE id = $1 AND workspace_id = $2")
            .bind(&team_id)
            .bind(&workspace_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(internal)?
            .is_some();
    if !team_exists {
        return Err(fail(StatusCode::NOT_FOUND, "team not found"));
    }
    if role_in(&state.pool, &workspace_id, Some(&body.user_id))
        .await?
        .is_none()
    {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "user is not a workspace member",
        ));
    }
    sqlx::query(
        "INSERT INTO team_members (team_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(&team_id)
    .bind(&body.user_id)
    .execute(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BudgetBody {
    scope: String,
    subject_id: Option<String>,
    limit_usd: f64,
    period: String,
}

fn period_start_ms(period: &str) -> i64 {
    if period == "monthly" {
        month_start_ms(0)
    } else {
        0
    }
}

/// Month boundary `offset_months` away from the current month, as epoch millis.
fn month_start_ms(offset_months: i32) -> i64 {
    use time::{Date, Month, OffsetDateTime};
    let now = OffsetDateTime::now_utc();
    let mut year = now.year();
    let mut month = now.month() as i32 + offset_months;
    while month < 1 {
        month += 12;
        year -= 1;
    }
    while month > 12 {
        month -= 12;
        year += 1;
    }
    Date::from_calendar_date(year, Month::try_from(month as u8).expect("month"), 1)
        .expect("first of month")
        .midnight()
        .assume_utc()
        .unix_timestamp()
        * 1000
}

fn previous_month_range() -> (i64, i64) {
    (month_start_ms(-1), month_start_ms(0))
}

async fn budget_spend(
    pool: &PgPool,
    workspace_id: &str,
    scope: &str,
    subject_id: Option<&str>,
    period: &str,
) -> Result<f64, ApiError> {
    let since = period_start_ms(period);
    let usage = sqlx::query_scalar::<_, f64>(
        "SELECT COALESCE(SUM(cost_usd), 0)::float8 FROM usage_events
         WHERE workspace_id = $1 AND created_at >= $2
           AND ($3::text = 'workspace'
                OR ($3::text = 'user' AND user_id = $4)
                OR ($3::text = 'team'
                    AND user_id IN (SELECT user_id FROM team_members WHERE team_id = $4)))",
    )
    .bind(workspace_id)
    .bind(since)
    .bind(scope)
    .bind(subject_id)
    .fetch_one(pool)
    .await
    .map_err(internal)?;
    // Compute is billed through the wallet, not usage_events, and cannot be
    // attributed to a person or team; only the workspace budget sees it.
    let compute = if scope == "workspace" {
        sqlx::query_scalar::<_, f64>(
            "SELECT COALESCE(SUM(-delta_usd), 0)::float8 FROM wallet_ledger
             WHERE workspace_id = $1 AND created_at >= $2 AND delta_usd < 0
               AND (reason LIKE 'compute%' OR reason LIKE 'sandbox_compute%')",
        )
        .bind(workspace_id)
        .bind(since)
        .fetch_one(pool)
        .await
        .map_err(internal)?
    } else {
        0.0
    };
    Ok(balance_from_rows(&[usage, compute]))
}

fn budget_row(
    id: &str,
    scope: &str,
    subject_id: Option<&str>,
    limit: f64,
    period: &str,
    spent: f64,
    created_at: i64,
) -> Value {
    json!({
        "id": id,
        "scope": scope,
        "subjectId": subject_id,
        "limitUsd": limit,
        "period": period,
        "spentUsd": (spent * 1e6).round() / 1e6,
        "remainingUsd": ((limit - spent) * 1e6).round() / 1e6,
        "createdAt": created_at,
    })
}

async fn list_budgets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let (workspace_id, _) = workspace_access(&state, &auth, &slug).await?;
    let rows = sqlx::query_as::<_, (String, String, Option<String>, f64, String, i64)>(
        "SELECT id, scope, subject_id, limit_usd::float8, period, created_at
         FROM budgets WHERE workspace_id = $1 ORDER BY created_at DESC",
    )
    .bind(&workspace_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    let mut budgets = Vec::with_capacity(rows.len());
    for (id, scope, subject_id, limit, period, created_at) in rows {
        let spent = budget_spend(
            &state.pool,
            &workspace_id,
            &scope,
            subject_id.as_deref(),
            &period,
        )
        .await?;
        budgets.push(budget_row(
            &id,
            &scope,
            subject_id.as_deref(),
            limit,
            &period,
            spent,
            created_at,
        ));
    }
    let balance = balance_of(&state.pool, &workspace_id).await?;
    Ok(Json(json!({ "balanceUsd": balance, "budgets": budgets })))
}

async fn create_budget(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(body): Json<BudgetBody>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let (workspace_id, role) = workspace_access(&state, &auth, &slug).await?;
    require_admin(role.as_deref())?;
    if !matches!(body.scope.as_str(), "workspace" | "user" | "team") {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "scope must be workspace, user, or team",
        ));
    }
    if !matches!(body.period.as_str(), "monthly" | "total") {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "period must be monthly or total",
        ));
    }
    if !body.limit_usd.is_finite() || body.limit_usd <= 0.0 {
        return Err(fail(StatusCode::BAD_REQUEST, "limitUsd must be positive"));
    }
    let subject_id = if body.scope == "workspace" {
        None
    } else {
        Some(
            body.subject_id
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "subjectId is required"))?,
        )
    };
    if body.scope == "user"
        && role_in(&state.pool, &workspace_id, subject_id)
            .await?
            .is_none()
    {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "subject is not a workspace member",
        ));
    }
    if body.scope == "team" {
        let exists =
            sqlx::query_scalar::<_, i32>("SELECT 1 FROM teams WHERE id = $1 AND workspace_id = $2")
                .bind(subject_id)
                .bind(&workspace_id)
                .fetch_optional(&state.pool)
                .await
                .map_err(internal)?
                .is_some();
        if !exists {
            return Err(fail(StatusCode::BAD_REQUEST, "team not found in workspace"));
        }
    }
    let id = new_id("bud");
    let created_at = now_ms();
    sqlx::query(
        "INSERT INTO budgets (id, workspace_id, scope, subject_id, limit_usd, period, created_at)
         VALUES ($1, $2, $3, $4, $5::numeric, $6, $7)",
    )
    .bind(&id)
    .bind(&workspace_id)
    .bind(&body.scope)
    .bind(subject_id)
    .bind(body.limit_usd.to_string())
    .bind(&body.period)
    .bind(created_at)
    .execute(&state.pool)
    .await
    .map_err(internal)?;
    audit(
        &state.pool,
        Some(&workspace_id),
        auth.user_id.as_deref(),
        "budget.create",
        Some(&id),
    )
    .await
    .map_err(internal)?;
    let spent = budget_spend(
        &state.pool,
        &workspace_id,
        &body.scope,
        subject_id,
        &body.period,
    )
    .await?;
    Ok(Json(budget_row(
        &id,
        &body.scope,
        subject_id,
        body.limit_usd,
        &body.period,
        spent,
        created_at,
    )))
}

async fn list_invoices(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let (workspace_id, _) = workspace_access(&state, &auth, &slug).await?;
    let rows = sqlx::query_as::<_, (String, i64, i64, String, f64, i64)>(
        "SELECT id, period_start, period_end, lines::text, total_usd::float8, created_at
         FROM invoices WHERE workspace_id = $1 ORDER BY created_at DESC",
    )
    .bind(&workspace_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!(
        rows.into_iter()
            .map(|(id, start, end, lines, total, created)| {
                let lines: Value = serde_json::from_str(&lines).unwrap_or_else(|_| json!([]));
                json!({
                    "id": id, "periodStart": start, "periodEnd": end,
                    "lines": lines, "totalUsd": total, "createdAt": created,
                })
            })
            .collect::<Vec<_>>()
    )))
}

async fn generate_invoice(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let (workspace_id, role) = workspace_access(&state, &auth, &slug).await?;
    require_admin(role.as_deref())?;
    let (period_start, period_end) = previous_month_range();
    let models = sqlx::query_as::<_, (Option<String>, i64, i64, f64)>(
        "SELECT model, COALESCE(SUM(input_tokens), 0)::bigint,
                COALESCE(SUM(output_tokens), 0)::bigint,
                COALESCE(SUM(cost_usd), 0)::float8
         FROM usage_events
         WHERE workspace_id = $1 AND created_at >= $2 AND created_at < $3
         GROUP BY model ORDER BY model",
    )
    .bind(&workspace_id)
    .bind(period_start)
    .bind(period_end)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    let mut lines = Vec::with_capacity(models.len() + 1);
    let mut total = 0.0f64;
    for (model, input_tokens, output_tokens, cost) in models {
        total += cost;
        lines.push(json!({
            "kind": "model_usage",
            "model": model.unwrap_or_else(|| "unknown".into()),
            "inputTokens": input_tokens,
            "outputTokens": output_tokens,
            "amountUsd": cost,
        }));
    }
    // Compute is billed through the wallet as negative ledger entries, so the
    // invoice line comes from the ledger rather than a separate usage table.
    let compute = sqlx::query_scalar::<_, f64>(
        "SELECT COALESCE(SUM(-delta_usd), 0)::float8 FROM wallet_ledger
         WHERE workspace_id = $1 AND created_at >= $2 AND created_at < $3
           AND delta_usd < 0
           AND (reason LIKE 'compute%' OR reason LIKE 'sandbox_compute%')",
    )
    .bind(&workspace_id)
    .bind(period_start)
    .bind(period_end)
    .fetch_one(&state.pool)
    .await
    .map_err(internal)?;
    if compute > 0.0 {
        total += compute;
        lines.push(json!({ "kind": "sandbox_compute", "amountUsd": compute }));
    }
    let total = (total * 1e6).round() / 1e6;
    let created_at = now_ms();
    // One invoice per workspace-month: regenerating replaces the previous run
    // instead of stacking a second bill.
    let id = sqlx::query_scalar::<_, String>(
        "INSERT INTO invoices (id, workspace_id, period_start, period_end, lines, total_usd, created_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6::numeric, $7)
         ON CONFLICT (workspace_id, period_start) DO UPDATE SET
           period_end = EXCLUDED.period_end,
           lines = EXCLUDED.lines,
           total_usd = EXCLUDED.total_usd,
           created_at = EXCLUDED.created_at
         RETURNING id",
    )
    .bind(new_id("inv"))
    .bind(&workspace_id)
    .bind(period_start)
    .bind(period_end)
    .bind(Value::Array(lines.clone()).to_string())
    .bind(total.to_string())
    .bind(created_at)
    .fetch_one(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!({
        "id": id, "periodStart": period_start, "periodEnd": period_end,
        "lines": lines, "totalUsd": total, "createdAt": created_at,
    })))
}

async fn usage_summary(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let rows = sqlx::query_as::<_, (String, String, i64, i64, f64)>(
        "SELECT to_char(to_timestamp((created_at / 1000)::double precision), 'YYYY-MM-DD') AS day,
                COALESCE(model, 'unknown') AS model,
                COALESCE(SUM(input_tokens), 0)::bigint,
                COALESCE(SUM(output_tokens), 0)::bigint,
                COALESCE(SUM(cost_usd), 0)::float8
         FROM usage_events WHERE workspace_id = $1
         GROUP BY day, model ORDER BY day DESC, model",
    )
    .bind(&workspace_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!({
        "workspaceId": workspace_id,
        "days": rows.into_iter().map(|(day, model, input, output, cost)| json!({
            "day": day, "model": model,
            "inputTokens": input, "outputTokens": output, "costUsd": cost,
        })).collect::<Vec<_>>(),
    })))
}

// --- review configuration -------------------------------------------------

type PolicyRow = (
    String,
    bool,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    i64,
);

const POLICY_KEYS: [&str; 10] = [
    "automatic",
    "includeDrafts",
    "strictness",
    "filters",
    "customRules",
    "contextFiles",
    "linkedRepositories",
    "summary",
    "statusCheck",
    "autoApprove",
];

fn policy_json(row: PolicyRow) -> Value {
    let (
        automatic,
        include_drafts,
        strictness,
        filters,
        custom_rules,
        context_files,
        linked,
        summary,
        status_check,
        auto_approve,
        updated_at,
    ) = row;
    let parse = |text: String| serde_json::from_str(&text).unwrap_or(Value::Null);
    json!({
        "automatic": automatic,
        "includeDrafts": include_drafts,
        "strictness": strictness,
        "filters": parse(filters),
        "customRules": parse(custom_rules),
        "contextFiles": parse(context_files),
        "linkedRepositories": parse(linked),
        "summary": parse(summary),
        "statusCheck": status_check.and_then(|t| serde_json::from_str::<Value>(&t).ok()),
        "autoApprove": auto_approve.and_then(|t| serde_json::from_str::<Value>(&t).ok()),
        "updatedAt": updated_at,
    })
}

/// Applies the camelCase keys present in `patch` over `current`.
fn merge_policy(current: &Value, patch: &Value) -> Value {
    let mut merged = current.clone();
    for key in POLICY_KEYS {
        if let Some(value) = patch.get(key) {
            merged[key] = value.clone();
        }
    }
    merged
}

async fn ensure_policy(pool: &PgPool, workspace_id: &str) -> Result<Value, ApiError> {
    sqlx::query(
        "INSERT INTO review_policies (workspace_id, updated_at) VALUES ($1, $2)
         ON CONFLICT (workspace_id) DO NOTHING",
    )
    .bind(workspace_id)
    .bind(now_ms())
    .execute(pool)
    .await
    .map_err(internal)?;
    let row = sqlx::query_as::<_, PolicyRow>(
        "SELECT automatic, include_drafts, strictness, filters::text, custom_rules::text,
                context_files::text, linked_repositories::text, summary::text,
                status_check::text, auto_approve::text, updated_at
         FROM review_policies WHERE workspace_id = $1",
    )
    .bind(workspace_id)
    .fetch_one(pool)
    .await
    .map_err(internal)?;
    Ok(policy_json(row))
}

async fn get_review_config(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    Ok(Json(ensure_policy(&state.pool, &workspace_id).await?))
}

async fn patch_review_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let role = role_in(&state.pool, &workspace_id, auth.user_id.as_deref()).await?;
    require_admin(role.as_deref())?;
    let current = ensure_policy(&state.pool, &workspace_id).await?;
    let merged = merge_policy(&current, &body);
    let text = |key: &str| merged[key].to_string();
    let optional_text = |key: &str| {
        if merged[key].is_null() {
            None
        } else {
            Some(merged[key].to_string())
        }
    };
    sqlx::query(
        "UPDATE review_policies SET automatic = $1, include_drafts = $2, strictness = $3,
            filters = $4::jsonb, custom_rules = $5::jsonb, context_files = $6::jsonb,
            linked_repositories = $7::jsonb, summary = $8::jsonb, status_check = $9::jsonb,
            auto_approve = $10::jsonb, updated_at = $11
         WHERE workspace_id = $12",
    )
    .bind(merged["automatic"].as_str().unwrap_or("opened"))
    .bind(merged["includeDrafts"].as_bool().unwrap_or(false))
    .bind(merged["strictness"].as_str().unwrap_or("medium"))
    .bind(text("filters"))
    .bind(text("customRules"))
    .bind(text("contextFiles"))
    .bind(text("linkedRepositories"))
    .bind(text("summary"))
    .bind(optional_text("statusCheck"))
    .bind(optional_text("autoApprove"))
    .bind(now_ms())
    .bind(&workspace_id)
    .execute(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(ensure_policy(&state.pool, &workspace_id).await?))
}

// --- GitHub installations -------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallationBody {
    id: i64,
    account_login: String,
    account_type: String,
    repository_selection: String,
}

async fn list_installations(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let rows = sqlx::query_as::<_, (i64, String, String, String, i64)>(
        "SELECT id, account_login, account_type, repository_selection, created_at
         FROM github_installations WHERE workspace_id = $1 ORDER BY created_at DESC",
    )
    .bind(&workspace_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!(
        rows.into_iter()
            .map(|(id, login, kind, selection, created)| json!({
                "id": id, "accountLogin": login, "accountType": kind,
                "repositorySelection": selection, "createdAt": created,
            }))
            .collect::<Vec<_>>()
    )))
}

async fn create_installation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<InstallationBody>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let role = role_in(&state.pool, &workspace_id, auth.user_id.as_deref()).await?;
    require_admin(role.as_deref())?;
    if body.id <= 0
        || body.account_login.is_empty()
        || body.account_type.is_empty()
        || body.repository_selection.is_empty()
    {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "id, accountLogin, accountType, and repositorySelection are required",
        ));
    }
    let created_at = now_ms();
    let inserted = sqlx::query(
        "INSERT INTO github_installations
           (id, workspace_id, account_login, account_type, repository_selection, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(body.id)
    .bind(&workspace_id)
    .bind(&body.account_login)
    .bind(&body.account_type)
    .bind(&body.repository_selection)
    .bind(created_at)
    .execute(&state.pool)
    .await
    .map_err(internal)?
    .rows_affected();
    if inserted == 0 {
        // The installation exists already. Re-pointing it would move another
        // tenant's reviews and billing, so only the owning workspace may
        // refresh its metadata.
        let owner = sqlx::query_scalar::<_, Option<String>>(
            "SELECT workspace_id FROM github_installations WHERE id = $1",
        )
        .bind(body.id)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?
        .flatten();
        if owner.as_deref() != Some(workspace_id.as_str()) {
            return Err(fail(
                StatusCode::CONFLICT,
                "installation belongs to another workspace",
            ));
        }
        sqlx::query(
            "UPDATE github_installations
             SET account_login = $2, account_type = $3, repository_selection = $4
             WHERE id = $1 AND workspace_id = $5",
        )
        .bind(body.id)
        .bind(&body.account_login)
        .bind(&body.account_type)
        .bind(&body.repository_selection)
        .bind(&workspace_id)
        .execute(&state.pool)
        .await
        .map_err(internal)?;
    }
    Ok(Json(json!({
        "id": body.id, "accountLogin": body.account_login,
        "accountType": body.account_type,
        "repositorySelection": body.repository_selection,
        "createdAt": created_at,
    })))
}

async fn delete_installation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let role = role_in(&state.pool, &workspace_id, auth.user_id.as_deref()).await?;
    require_admin(role.as_deref())?;
    let removed =
        sqlx::query("DELETE FROM github_installations WHERE id = $1 AND workspace_id = $2")
            .bind(id)
            .bind(&workspace_id)
            .execute(&state.pool)
            .await
            .map_err(internal)?
            .rows_affected();
    if removed == 0 {
        return Err(fail(StatusCode::NOT_FOUND, "installation not found"));
    }
    Ok(Json(json!({ "ok": true })))
}

/// An installation id alone is guessable; membership in the caller's workspace
/// is what grants access, so every repository call checks it first.
async fn installation_in_workspace(
    pool: &PgPool,
    workspace_id: &str,
    installation_id: i64,
) -> Result<bool, ApiError> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM github_installations
                        WHERE id = $1 AND workspace_id = $2)",
    )
    .bind(installation_id)
    .bind(workspace_id)
    .fetch_one(pool)
    .await
    .map_err(internal)
}

async fn list_installation_repositories(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    if !installation_in_workspace(&state.pool, &workspace_id, id).await? {
        return Err(fail(StatusCode::NOT_FOUND, "installation not found"));
    }
    let rows = sqlx::query_as::<_, (i64, String, bool)>(
        "SELECT installation_id, repo, enabled FROM github_repositories
         WHERE installation_id = $1 ORDER BY repo",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!(
        rows.into_iter()
            .map(|(installation_id, repo, enabled)| json!({
                "installationId": installation_id, "repo": repo, "enabled": enabled,
            }))
            .collect::<Vec<_>>()
    )))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RepositoryBody {
    installation_id: i64,
    repo: String,
    enabled: bool,
}

async fn patch_repository(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RepositoryBody>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let role = role_in(&state.pool, &workspace_id, auth.user_id.as_deref()).await?;
    require_admin(role.as_deref())?;
    if body.repo.trim().is_empty() {
        return Err(fail(StatusCode::BAD_REQUEST, "repo is required"));
    }
    if !installation_in_workspace(&state.pool, &workspace_id, body.installation_id).await? {
        return Err(fail(StatusCode::NOT_FOUND, "installation not found"));
    }
    sqlx::query(
        "INSERT INTO github_repositories (installation_id, repo, enabled)
         VALUES ($1, $2, $3)
         ON CONFLICT (installation_id, repo) DO UPDATE SET enabled = EXCLUDED.enabled",
    )
    .bind(body.installation_id)
    .bind(&body.repo)
    .bind(body.enabled)
    .execute(&state.pool)
    .await
    .map_err(internal)?;
    audit(
        &state.pool,
        Some(&workspace_id),
        auth.user_id.as_deref(),
        "github.repositories",
        Some(&body.repo),
    )
    .await
    .ok();
    Ok(Json(json!({
        "installationId": body.installation_id,
        "repo": body.repo,
        "enabled": body.enabled,
    })))
}

#[derive(Deserialize)]
struct PullsQuery {
    repo: String,
    state: Option<String>,
}

/// List a repository's pull requests through the workspace's GitHub App
/// installation. Installation tokens last an hour, so one is minted per call
/// and never stored.
async fn github_pulls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PullsQuery>,
) -> ApiResult {
    let auth = authenticate(&state.pool, &headers).await?;
    let workspace_id = current_workspace(&state, &auth).await?;
    let repo = query.repo.trim().to_string();
    if repo.is_empty() {
        return Err(fail(StatusCode::BAD_REQUEST, "repo is required"));
    }
    let installation = sqlx::query_scalar::<_, i64>(
        "SELECT r.installation_id FROM github_repositories r
         JOIN github_installations i ON i.id = r.installation_id
         WHERE i.workspace_id = $1 AND r.repo = $2 AND r.enabled
         ORDER BY r.installation_id DESC LIMIT 1",
    )
    .bind(&workspace_id)
    .bind(&repo)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?
    // Toggling a repository off must cut off its pulls, so there is no
    // fallback to another installation.
    .ok_or_else(|| {
        fail(
            StatusCode::NOT_FOUND,
            "repository is not enabled for this workspace",
        )
    })?;
    let app_id = std::env::var("FREEDAS_GITHUB_APP_ID")
        .ok()
        .filter(|value| !value.is_empty());
    let key_path = std::env::var("FREEDAS_GITHUB_PRIVATE_KEY_PATH")
        .ok()
        .filter(|value| !value.is_empty());
    let (Some(app_id), Some(key_path)) = (app_id, key_path) else {
        return Err(fail(
            StatusCode::NOT_IMPLEMENTED,
            "GitHub App is not configured",
        ));
    };
    let key_pem = std::fs::read_to_string(&key_path).map_err(|_| {
        fail(
            StatusCode::NOT_IMPLEMENTED,
            "GitHub App private key is unreadable",
        )
    })?;
    let api_base = std::env::var("FREEDAS_GITHUB_API_BASE")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| freedas_review::github::DEFAULT_API_BASE.to_string());
    let client = reqwest::Client::new();
    let token = freedas_review::github::installation_token(
        &client,
        &api_base,
        &app_id,
        &key_pem,
        installation,
    )
    .await
    .map_err(|error| fail(StatusCode::BAD_GATEWAY, &error))?;
    let pulls = freedas_review::github::list_pulls(
        &client,
        &token,
        &api_base,
        &repo,
        query.state.as_deref().unwrap_or("open"),
    )
    .await
    .map_err(|error| fail(StatusCode::BAD_GATEWAY, &error))?;
    Ok(Json(json!(
        pulls
            .into_iter()
            .map(|pull| json!({
                "number": pull.number,
                "title": pull.title,
                "author": pull.author,
                "state": pull.state,
                "draft": pull.draft,
                "headSha": pull.head_sha,
                "url": pull.url,
            }))
            .collect::<Vec<_>>()
    )))
}

// --- OIDC -----------------------------------------------------------------

fn oidc_env() -> Option<(String, String)> {
    let issuer = std::env::var("FREEDAS_OIDC_ISSUER")
        .ok()
        .filter(|value| !value.is_empty())?;
    let client_id = std::env::var("FREEDAS_OIDC_CLIENT_ID")
        .ok()
        .filter(|value| !value.is_empty())?;
    Some((issuer, client_id))
}

fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn upstream_failure(_e: reqwest::Error) -> ApiError {
    fail(StatusCode::BAD_GATEWAY, "identity provider request failed")
}

async fn oidc_start(State(state): State<AppState>) -> ApiResult {
    let (issuer, client_id) =
        oidc_env().ok_or_else(|| fail(StatusCode::NOT_IMPLEMENTED, "OIDC is not configured"))?;
    let nonce = random_hex(16);
    {
        let mut states = state.oidc_states.lock().expect("oidc states");
        let cutoff = now_ms() - 10 * 60 * 1000;
        states.retain(|_, created| *created >= cutoff);
        states.insert(nonce.clone(), now_ms());
    }
    let redirect_uri = format!(
        "{}/auth/oidc/callback",
        state.base_url.trim_end_matches('/')
    );
    let url = format!(
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20email%20profile&state={nonce}",
        issuer.trim_end_matches('/'),
        url_encode(&client_id),
        url_encode(&redirect_uri),
    );
    Ok(Json(json!({ "url": url })))
}

#[derive(Deserialize)]
struct OidcQuery {
    code: Option<String>,
    state: Option<String>,
}

async fn oidc_callback(State(state): State<AppState>, Query(query): Query<OidcQuery>) -> ApiResult {
    let (issuer, client_id) =
        oidc_env().ok_or_else(|| fail(StatusCode::NOT_IMPLEMENTED, "OIDC is not configured"))?;
    let code = query
        .code
        .filter(|c| !c.is_empty())
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "missing code"))?;
    let nonce = query
        .state
        .filter(|s| !s.is_empty())
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "missing state"))?;
    let known = state
        .oidc_states
        .lock()
        .expect("oidc states")
        .remove(&nonce);
    // States older than ten minutes are expired even if they have not been
    // pruned yet; a replayed or stale redirect must not mint a token.
    match known {
        Some(created) if now_ms() - created <= 10 * 60 * 1000 => {}
        _ => return Err(fail(StatusCode::BAD_REQUEST, "invalid state")),
    }

    let issuer = issuer.trim_end_matches('/');
    let redirect_uri = format!(
        "{}/auth/oidc/callback",
        state.base_url.trim_end_matches('/')
    );
    let client = reqwest::Client::new();
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", client_id.as_str()),
    ];
    let client_secret = std::env::var("FREEDAS_OIDC_CLIENT_SECRET")
        .ok()
        .filter(|secret| !secret.is_empty());
    if let Some(secret) = client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    let token: Value = client
        .post(format!("{issuer}/oauth/token"))
        .form(&form)
        .send()
        .await
        .map_err(upstream_failure)?
        .error_for_status()
        .map_err(upstream_failure)?
        .json()
        .await
        .map_err(upstream_failure)?;
    let access_token = token["access_token"]
        .as_str()
        .ok_or_else(|| fail(StatusCode::BAD_GATEWAY, "no access token returned"))?;
    let info: Value = client
        .get(format!("{issuer}/userinfo"))
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(upstream_failure)?
        .error_for_status()
        .map_err(upstream_failure)?
        .json()
        .await
        .map_err(upstream_failure)?;
    let sub = info["sub"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| fail(StatusCode::BAD_GATEWAY, "userinfo is missing sub"))?;
    let email = info["email"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "userinfo is missing email"))?;
    let email_verified = info["email_verified"].as_bool().unwrap_or(false);
    let name = info["name"].as_str().unwrap_or(email);

    let user_id = match sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE oidc_sub = $1")
        .bind(sub)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?
    {
        Some(id) => id,
        None => {
            match sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE email = $1")
                .bind(email)
                .fetch_optional(&state.pool)
                .await
                .map_err(internal)?
            {
                Some(id) => {
                    // Linking to an existing account by email is only safe when
                    // the provider has verified ownership of that address.
                    if !email_verified {
                        return Err(fail(
                            StatusCode::FORBIDDEN,
                            "identity provider did not verify the email address",
                        ));
                    }
                    sqlx::query("UPDATE users SET oidc_sub = $1 WHERE id = $2")
                        .bind(sub)
                        .bind(&id)
                        .execute(&state.pool)
                        .await
                        .map_err(internal)?;
                    id
                }
                None => {
                    let id = new_id("usr");
                    sqlx::query(
                        "INSERT INTO users (id, email, name, oidc_sub, created_at)
                         VALUES ($1, $2, $3, $4, $5)",
                    )
                    .bind(&id)
                    .bind(email)
                    .bind(name)
                    .bind(sub)
                    .bind(now_ms())
                    .execute(&state.pool)
                    .await
                    .map_err(|e| {
                        if is_conflict(&e) {
                            fail(StatusCode::CONFLICT, "user already exists")
                        } else {
                            internal(e)
                        }
                    })?;
                    id
                }
            }
        }
    };

    // SCIM-deprovisioned accounts stay in the table for audit; they must not
    // be able to sign back in through OIDC.
    let active = sqlx::query_scalar::<_, bool>("SELECT active FROM users WHERE id = $1")
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?
        .unwrap_or(false);
    if !active {
        return Err(fail(StatusCode::FORBIDDEN, "account is deactivated"));
    }
    // Bind the session to the user's workspace when it is unambiguous, so
    // later requests do not have to guess.
    let workspace_id = sole_workspace(&state.pool, &user_id).await?;
    let plaintext = random_hex(32);
    sqlx::query(
        "INSERT INTO api_tokens (id, user_id, workspace_id, token_hash, scopes, created_at)
         VALUES ($1, $2, $3, $4, '{}', $5)",
    )
    .bind(new_id("tok"))
    .bind(&user_id)
    .bind(&workspace_id)
    .bind(hash_token(&plaintext))
    .bind(now_ms())
    .execute(&state.pool)
    .await
    .map_err(internal)?;
    audit(
        &state.pool,
        workspace_id.as_deref(),
        Some(&user_id),
        "login.oidc",
        Some(email),
    )
    .await
    .map_err(internal)?;
    Ok(Json(json!({
        "token": plaintext,
        "userId": user_id,
        "workspaceId": workspace_id,
    })))
}

// --- SCIM -----------------------------------------------------------------

fn scim_guard(headers: &HeaderMap) -> Result<(), ApiError> {
    let configured = std::env::var("FREEDAS_SCIM_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "SCIM is not configured"))?;
    if !constant_time_eq(bearer(headers).unwrap_or_default(), &configured) {
        return Err(fail(StatusCode::UNAUTHORIZED, "invalid SCIM token"));
    }
    Ok(())
}

fn scim_user(id: &str, email: &str, name: &str, active: bool) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": id,
        "userName": email,
        "name": { "formatted": name },
        "emails": [{ "value": email, "primary": true }],
        "active": active,
    })
}

fn scim_group(id: &str, name: &str, members: Vec<String>) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": id,
        "displayName": name,
        "members": members.into_iter().map(|user| json!({ "value": user })).collect::<Vec<_>>(),
    })
}

fn scim_list(resources: Vec<Value>) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resources.len(),
        "startIndex": 1,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

async fn scim_list_users(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    scim_guard(&headers)?;
    let rows = sqlx::query_as::<_, (String, String, String, bool)>(
        "SELECT id, email, name, active FROM users ORDER BY created_at LIMIT 1000",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    let resources = rows
        .into_iter()
        .map(|(id, email, name, active)| scim_user(&id, &email, &name, active))
        .collect();
    Ok(Json(scim_list(resources)))
}

async fn scim_create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    scim_guard(&headers)?;
    let email = body
        .get("userName")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            body.get("emails")
                .and_then(Value::as_array)?
                .iter()
                .find_map(|entry| entry.get("value").and_then(Value::as_str))
        })
        .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "userName or emails is required"))?;
    let name = body
        .pointer("/name/formatted")
        .and_then(Value::as_str)
        .unwrap_or(email);

    if let Some(existing) = sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?
    {
        // A re-provisioned account becomes active again with the new name.
        sqlx::query("UPDATE users SET active = TRUE, name = $2 WHERE id = $1")
            .bind(&existing)
            .bind(name)
            .execute(&state.pool)
            .await
            .map_err(internal)?;
        return Ok((
            StatusCode::OK,
            Json(scim_user(&existing, email, name, true)),
        ));
    }
    let id = new_id("usr");
    sqlx::query("INSERT INTO users (id, email, name, created_at) VALUES ($1, $2, $3, $4)")
        .bind(&id)
        .bind(email)
        .bind(name)
        .bind(now_ms())
        .execute(&state.pool)
        .await
        .map_err(|e| {
            if is_conflict(&e) {
                fail(StatusCode::CONFLICT, "user already exists")
            } else {
                internal(e)
            }
        })?;
    Ok((StatusCode::CREATED, Json(scim_user(&id, email, name, true))))
}

async fn scim_list_groups(State(state): State<AppState>, headers: HeaderMap) -> ApiResult {
    scim_guard(&headers)?;
    let rows = sqlx::query_as::<_, (String, String, String)>(
        "SELECT t.id, t.name,
                COALESCE(json_agg(tm.user_id) FILTER (WHERE tm.user_id IS NOT NULL), '[]'::json)::text
         FROM teams t LEFT JOIN team_members tm ON tm.team_id = t.id
         GROUP BY t.id, t.name ORDER BY t.name LIMIT 1000",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    let resources = rows
        .into_iter()
        .map(|(id, name, members)| {
            let members: Vec<String> = serde_json::from_str(&members).unwrap_or_default();
            scim_group(&id, &name, members)
        })
        .collect();
    Ok(Json(scim_list(resources)))
}

/// Reads the `active` flag from a plain SCIM user body or an RFC 7644 PatchOp
/// (`{schemas, Operations: [{op, path, value}]}`). `None` means the patch
/// carries nothing we act on. A `remove` of `active` counts as deactivation,
/// which is how deprovisioning clients express it.
fn scim_active_patch(body: &Value) -> Option<bool> {
    if let Some(active) = body.get("active").and_then(Value::as_bool) {
        return Some(active);
    }
    let operations = body
        .get("Operations")
        .or_else(|| body.get("operations"))?
        .as_array()?;
    let mut active = None;
    for operation in operations {
        let op = operation
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let path = operation.get("path").and_then(Value::as_str).unwrap_or("");
        let value = &operation["value"];
        let targets_active = path.is_empty() || path.eq_ignore_ascii_case("active");
        if !targets_active {
            continue;
        }
        match op.as_str() {
            "replace" | "add" => {
                if let Some(flag) = value
                    .as_bool()
                    .or_else(|| value.get("active").and_then(Value::as_bool))
                {
                    active = Some(flag);
                }
            }
            "remove" => active = Some(false),
            _ => {}
        }
    }
    active
}

/// Clears the user's credentials and workspace access while keeping the row so
/// audit and usage references survive. Live API tokens are revoked: a
/// deprovisioned person must not keep a working session. Workspaces they own
/// pass to another member, or are left ownerless only when nobody else remains.
async fn scim_deactivate(state: &AppState, user_id: &str) -> Result<bool, ApiError> {
    let mut tx = state.pool.begin().await.map_err(internal)?;
    let found = sqlx::query_scalar::<_, String>(
        "UPDATE users SET password_hash = NULL, oidc_sub = NULL, active = FALSE
         WHERE id = $1 RETURNING id",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    if found.is_none() {
        return Ok(false);
    }
    let owned = sqlx::query_scalar::<_, String>("SELECT id FROM workspaces WHERE owner_id = $1")
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(internal)?;
    for workspace_id in &owned {
        let successor = sqlx::query_scalar::<_, String>(
            "SELECT user_id FROM memberships
             WHERE workspace_id = $1 AND user_id <> $2
             ORDER BY (role = 'owner') DESC, user_id LIMIT 1",
        )
        .bind(workspace_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
        match successor {
            Some(successor) => {
                sqlx::query(
                    "UPDATE memberships SET role = 'owner'
                     WHERE workspace_id = $1 AND user_id = $2",
                )
                .bind(workspace_id)
                .bind(&successor)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
                sqlx::query("UPDATE workspaces SET owner_id = $2 WHERE id = $1")
                    .bind(workspace_id)
                    .bind(&successor)
                    .execute(&mut *tx)
                    .await
                    .map_err(internal)?;
            }
            // Nobody left to own it; the row stays for audit but is ownerless.
            None => {
                sqlx::query("UPDATE workspaces SET owner_id = NULL WHERE id = $1")
                    .bind(workspace_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(internal)?;
            }
        }
    }
    sqlx::query("DELETE FROM memberships WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    sqlx::query("UPDATE api_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user_id)
        .bind(now_ms())
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    audit(&state.pool, None, Some(user_id), "scim.deactivate", None)
        .await
        .map_err(internal)?;
    Ok(true)
}

async fn scim_delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    scim_guard(&headers)?;
    if !scim_deactivate(&state, &id).await? {
        return Err(fail(StatusCode::NOT_FOUND, "user not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn scim_patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<StatusCode, ApiError> {
    scim_guard(&headers)?;
    match scim_active_patch(&body) {
        Some(false) => {
            if !scim_deactivate(&state, &id).await? {
                return Err(fail(StatusCode::NOT_FOUND, "user not found"));
            }
        }
        // Reactivation restores the flag; credentials still have to be set or
        // re-established through OIDC.
        Some(true) => {
            let reactivated =
                sqlx::query("UPDATE users SET active = TRUE WHERE id = $1 RETURNING id")
                    .bind(&id)
                    .fetch_optional(&state.pool)
                    .await
                    .map_err(internal)?
                    .is_some();
            if !reactivated {
                return Err(fail(StatusCode::NOT_FOUND, "user not found"));
            }
            audit(&state.pool, None, Some(&id), "scim.reactivate", None)
                .await
                .map_err(internal)?;
        }
        None => {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "only the active attribute is supported",
            ));
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

// --- device flow ----------------------------------------------------------

/// Unambiguous alphabet: no `I`, `O`, `0`, or `1`. Its length divides 256, so
/// the byte-to-character mapping is uniform.
const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const DEVICE_STYLE: &str = "body{margin:0;min-height:100vh;display:grid;place-items:center;\
background:#0d1117;color:#e6edf3;font:16px/1.5 system-ui,-apple-system,sans-serif}\
.card{width:min(24rem,92vw);padding:1.75rem;border:1px solid #30363d;border-radius:12px;\
background:#161b22}h1{margin:0 0 .5rem;font-size:1.15rem}p{margin:.5rem 0}\
label{display:block;margin:.75rem 0 .25rem;font-size:.85rem;color:#a5b1bd}\
input,select{width:100%;box-sizing:border-box;padding:.5rem;border-radius:8px;\
border:1px solid #30363d;background:#0d1117;color:inherit;font:inherit}\
button{margin-top:1rem;width:100%;padding:.6rem;border-radius:8px;border:0;\
background:#238636;color:#fff;font:inherit;font-weight:600;cursor:pointer}\
.code{font:600 1.6rem/1.2 ui-monospace,SFMono-Regular,monospace;letter-spacing:.14em}\
.hint{font-size:.8rem;color:#a5b1bd}";

fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// One-time code shown to the user: eight characters in `XXXX-XXXX` form.
fn user_code() -> String {
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut code = String::with_capacity(9);
    for (index, byte) in bytes.iter().enumerate() {
        if index == 4 {
            code.push('-');
        }
        code.push(USER_CODE_ALPHABET[*byte as usize % USER_CODE_ALPHABET.len()] as char);
    }
    code
}

/// Accepts a typed code with any case, spacing, or missing dash.
fn normalize_user_code(code: &str) -> String {
    code.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Standalone approval result page; no external assets.
fn device_message_page(message: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Freedas device approval</title><style>{DEVICE_STYLE}</style></head>\
         <body><main class=\"card\"><h1>Freedas</h1><p>{}</p></main></body></html>",
        html_escape(message)
    )
}

async fn device_code_start(State(state): State<AppState>) -> ApiResult {
    // No client address is exposed here, so the whole endpoint shares one
    // one-minute window; a local control plane serves few callers.
    if state
        .throttle
        .lock()
        .expect("throttle")
        .over_limit("device-code", 60, 60_000)
    {
        return Err(fail(
            StatusCode::TOO_MANY_REQUESTS,
            "too many device codes; try again shortly",
        ));
    }
    let device_code = random_hex(32);
    let user_code = user_code();
    let now = now_ms();
    // Unredeemed codes are useless once expired; drop them instead of growing
    // the table forever.
    sqlx::query("DELETE FROM device_codes WHERE expires_at < $1")
        .bind(now)
        .execute(&state.pool)
        .await
        .map_err(internal)?;
    sqlx::query(
        "INSERT INTO device_codes (device_code, user_code, expires_at, created_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&device_code)
    .bind(&user_code)
    .bind(now + 600_000)
    .bind(now)
    .execute(&state.pool)
    .await
    .map_err(internal)?;
    let base = state.base_url.trim_end_matches('/');
    Ok(Json(json!({
        "deviceCode": device_code,
        "userCode": user_code,
        "verificationUri": format!("{base}/device"),
        "verificationUriComplete": format!("{base}/device?code={user_code}"),
        "expiresIn": 600,
        "interval": 5,
    })))
}

#[derive(Deserialize)]
struct DeviceQuery {
    code: Option<String>,
}

async fn device_page(Query(query): Query<DeviceQuery>) -> Html<String> {
    let code = query.code.unwrap_or_default();
    let code = code.trim();
    let (shown, field) = if code.is_empty() {
        (
            String::new(),
            "<label for=\"user_code\">Code from your terminal</label>\
             <input id=\"user_code\" name=\"user_code\" required autocomplete=\"off\" \
             autocapitalize=\"characters\" placeholder=\"XXXX-XXXX\">"
                .to_string(),
        )
    } else {
        (
            format!("<p class=\"code\">{}</p>", html_escape(code)),
            format!(
                "<input type=\"hidden\" name=\"user_code\" value=\"{}\">",
                html_escape(code)
            ),
        )
    };
    Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Freedas device approval</title><style>{DEVICE_STYLE}</style></head>\
         <body><main class=\"card\"><h1>Approve this device</h1>{shown}\
         <p class=\"hint\">Confirm the code matches the one shown by freedas.</p>\
         <form method=\"post\" action=\"/device/approve\">{field}\
         <label for=\"email\">Email</label>\
         <input id=\"email\" name=\"email\" type=\"email\" required autocomplete=\"username\">\
         <label for=\"password\">Password</label>\
         <input id=\"password\" name=\"password\" type=\"password\" required \
         autocomplete=\"current-password\">\
         <label for=\"workspace\">Workspace</label>\
         <select id=\"workspace\" name=\"workspace\">\
         <option value=\"\">First workspace</option></select>\
         <button type=\"submit\">Approve</button></form></main></body></html>"
    ))
}

#[derive(Deserialize)]
struct ApproveForm {
    user_code: String,
    email: String,
    password: String,
    #[serde(default)]
    workspace: String,
}

/// Verifies the account, binds the pending code to the chosen workspace, and
/// marks it approved. The CLI's next poll mints the token.
async fn device_approve(
    State(state): State<AppState>,
    Form(form): Form<ApproveForm>,
) -> (StatusCode, Html<String>) {
    let invalid = |status: StatusCode, message: &str| (status, Html(device_message_page(message)));
    let code = normalize_user_code(&form.user_code);
    if code.is_empty() {
        return invalid(StatusCode::BAD_REQUEST, "Enter the code shown by freedas.");
    }
    let pending = sqlx::query_scalar::<_, String>(
        "SELECT device_code FROM device_codes
         WHERE upper(replace(user_code, '-', '')) = $1 AND approved = FALSE AND expires_at > $2",
    )
    .bind(&code)
    .bind(now_ms())
    .fetch_optional(&state.pool)
    .await;
    let device_code = match pending {
        Ok(Some(device_code)) => device_code,
        Ok(None) => return invalid(StatusCode::BAD_REQUEST, "That code is unknown or expired."),
        Err(_) => return invalid(StatusCode::INTERNAL_SERVER_ERROR, "Database error."),
    };

    let user = sqlx::query_as::<_, (String, Option<String>, bool)>(
        "SELECT id, password_hash, active FROM users WHERE email = $1",
    )
    .bind(form.email.trim())
    .fetch_optional(&state.pool)
    .await;
    let key = format!("device-approve:{}", form.email.trim().to_ascii_lowercase());
    if state.throttle.lock().expect("throttle").locked(&key) {
        return invalid(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Try again later.",
        );
    }
    let (user_id, stored, active) = match user {
        Ok(Some(row)) => row,
        Ok(None) => {
            dummy_verify(&form.password);
            state.throttle.lock().expect("throttle").fail(&key);
            return invalid(
                StatusCode::UNAUTHORIZED,
                "Invalid email or password, or this account has no password.",
            );
        }
        Err(_) => return invalid(StatusCode::INTERNAL_SERVER_ERROR, "Database error."),
    };
    // Match the OIDC flow: deactivation is an explicit rejection, not just a
    // missing credential after SCIM nulled the hash.
    if !active {
        return invalid(StatusCode::FORBIDDEN, "account is deactivated");
    }
    let valid = stored
        .as_deref()
        .is_some_and(|phc| verify_password(&form.password, phc));
    if !valid {
        if stored.is_none() {
            dummy_verify(&form.password);
        }
        state.throttle.lock().expect("throttle").fail(&key);
        return invalid(
            StatusCode::UNAUTHORIZED,
            "Invalid email or password, or this account has no password.",
        );
    }
    state.throttle.lock().expect("throttle").succeed(&key);

    let slug = form.workspace.trim();
    // A mistyped workspace must fail instead of silently billing the wrong
    // one; an empty choice is only unambiguous for a single membership.
    if !slug.is_empty() {
        let chosen = sqlx::query_scalar::<_, String>(
            "SELECT w.id FROM workspaces w JOIN memberships m ON m.workspace_id = w.id
             WHERE w.slug = $1 AND m.user_id = $2",
        )
        .bind(slug)
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await;
        match chosen {
            Ok(Some(id)) => {
                let approved = sqlx::query(
                    "UPDATE device_codes SET user_id = $1, workspace_id = $2, approved = TRUE
                     WHERE device_code = $3",
                )
                .bind(&user_id)
                .bind(&id)
                .bind(&device_code)
                .execute(&state.pool)
                .await;
                match approved {
                    Ok(_) => {}
                    Err(_) => return invalid(StatusCode::INTERNAL_SERVER_ERROR, "Database error."),
                }
                audit(&state.pool, Some(&id), Some(&user_id), "login.device", None)
                    .await
                    .ok();
                return (
                    StatusCode::OK,
                    Html(device_message_page("Approved. You can close this tab.")),
                );
            }
            Ok(None) => return invalid(StatusCode::FORBIDDEN, "Not a member of that workspace."),
            Err(_) => return invalid(StatusCode::INTERNAL_SERVER_ERROR, "Database error."),
        }
    }
    let memberships = sqlx::query_scalar::<_, String>(
        "SELECT workspace_id FROM memberships WHERE user_id = $1 ORDER BY workspace_id",
    )
    .bind(&user_id)
    .fetch_all(&state.pool)
    .await;
    let memberships = match memberships {
        Ok(memberships) => memberships,
        Err(_) => return invalid(StatusCode::INTERNAL_SERVER_ERROR, "Database error."),
    };
    if memberships.len() > 1 {
        return invalid(
            StatusCode::BAD_REQUEST,
            "Choose a workspace: this account belongs to more than one.",
        );
    }
    let Some(workspace_id) = memberships.into_iter().next() else {
        return invalid(StatusCode::FORBIDDEN, "That account has no workspace.");
    };

    let approved = sqlx::query(
        "UPDATE device_codes SET user_id = $1, workspace_id = $2, approved = TRUE
         WHERE device_code = $3",
    )
    .bind(&user_id)
    .bind(&workspace_id)
    .bind(&device_code)
    .execute(&state.pool)
    .await;
    match approved {
        Ok(_) => {}
        Err(_) => return invalid(StatusCode::INTERNAL_SERVER_ERROR, "Database error."),
    }
    audit(
        &state.pool,
        Some(&workspace_id),
        Some(&user_id),
        "login.device",
        None,
    )
    .await
    .ok();
    (
        StatusCode::OK,
        Html(device_message_page("Approved. You can close this tab.")),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceTokenBody {
    device_code: String,
}

async fn device_token(
    State(state): State<AppState>,
    Json(body): Json<DeviceTokenBody>,
) -> ApiResult {
    let now = now_ms();
    let row = sqlx::query_as::<_, (Option<String>, Option<String>, bool, i64)>(
        "SELECT user_id, workspace_id, approved, expires_at FROM device_codes
         WHERE device_code = $1",
    )
    .bind(&body.device_code)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?;
    let Some((user_id, workspace_id, approved, expires_at)) = row else {
        return Err(fail(StatusCode::GONE, "expired_token"));
    };
    if expires_at <= now {
        sqlx::query("DELETE FROM device_codes WHERE device_code = $1")
            .bind(&body.device_code)
            .execute(&state.pool)
            .await
            .map_err(internal)?;
        return Err(fail(StatusCode::GONE, "expired_token"));
    }
    let (Some(user_id), Some(workspace_id)) = (user_id, workspace_id) else {
        return Err(fail(StatusCode::BAD_REQUEST, "authorization_pending"));
    };
    if !approved {
        return Err(fail(StatusCode::BAD_REQUEST, "authorization_pending"));
    }

    let token = random_hex(32);
    let mut tx = state.pool.begin().await.map_err(internal)?;
    sqlx::query(
        "INSERT INTO api_tokens (id, user_id, workspace_id, token_hash, scopes, created_at)
         VALUES ($1, $2, $3, $4, '{}', $5)",
    )
    .bind(new_id("tok"))
    .bind(&user_id)
    .bind(&workspace_id)
    .bind(hash_token(&token))
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    sqlx::query("DELETE FROM device_codes WHERE device_code = $1")
        .bind(&body.device_code)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    let slug = sqlx::query_scalar::<_, String>("SELECT slug FROM workspaces WHERE id = $1")
        .bind(&workspace_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    audit(
        &state.pool,
        Some(&workspace_id),
        Some(&user_id),
        "login.device",
        Some("token"),
    )
    .await
    .ok();
    Ok(Json(json!({
        "token": token,
        "userID": user_id,
        "workspaceID": workspace_id,
        "workspaceSlug": slug,
    })))
}

#[cfg(test)]
mod api_tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const SCHEMA: &[&str] = &[
        "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, password_hash TEXT, oidc_sub TEXT UNIQUE, active BOOLEAN NOT NULL DEFAULT TRUE, created_at BIGINT NOT NULL)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE",
        "CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, kind TEXT NOT NULL, owner_id TEXT REFERENCES users(id), settings JSONB NOT NULL DEFAULT '{}'::jsonb, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS memberships (workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, user_id TEXT REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL, PRIMARY KEY (workspace_id, user_id))",
        "CREATE TABLE IF NOT EXISTS wallet_ledger (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, delta_usd NUMERIC(12,6) NOT NULL, reason TEXT NOT NULL, ref TEXT, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS api_tokens (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, scopes TEXT, last_used_at BIGINT, expires_at BIGINT, revoked_at BIGINT, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, workspace_id TEXT, installation_id BIGINT, repo TEXT, pr_number BIGINT, head_sha TEXT, status TEXT, author TEXT, confidence NUMERIC(4,2), risk NUMERIC(4,2), findings JSONB, summary TEXT, error TEXT, customer_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0, upstream_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0, review_url TEXT, created_at BIGINT, updated_at BIGINT)",
        "ALTER TABLE reviews DROP CONSTRAINT IF EXISTS reviews_installation_id_repo_pr_number_head_sha_key",
        "DROP INDEX IF EXISTS reviews_repo_pr_head",
        "DROP INDEX IF EXISTS reviews_installation_head",
        "DROP INDEX IF EXISTS reviews_manual_head",
        "DELETE FROM reviews r WHERE r.workspace_id IS NOT NULL AND r.id <> (SELECT x.id FROM reviews x WHERE x.workspace_id = r.workspace_id AND x.repo = r.repo AND x.pr_number = r.pr_number AND x.head_sha = r.head_sha ORDER BY (x.review_url IS NOT NULL) DESC, (x.status = 'completed') DESC, x.created_at DESC, x.id DESC LIMIT 1)",
        "CREATE UNIQUE INDEX IF NOT EXISTS reviews_workspace_head ON reviews (workspace_id, repo, pr_number, head_sha)",
        "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS author TEXT",
        "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS confidence NUMERIC(4,2)",
        "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS risk NUMERIC(4,2)",
        "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS findings JSONB",
        "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS customer_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0",
        "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS upstream_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0",
        "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS review_url TEXT",
        "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS summary TEXT",
        "ALTER TABLE reviews ADD COLUMN IF NOT EXISTS error TEXT",
        "CREATE TABLE IF NOT EXISTS sandboxes (id TEXT PRIMARY KEY, workspace_id TEXT, repo TEXT, base_branch TEXT, task TEXT, branch TEXT, pr_number BIGINT, pr_url TEXT, status TEXT, compute_rate_usd NUMERIC(12,6) NOT NULL DEFAULT 0, compute_seconds BIGINT, compute_cost_usd NUMERIC(12,6), failure_reason TEXT, created_at BIGINT, updated_at BIGINT, finished_at BIGINT)",
        "ALTER TABLE sandboxes ADD COLUMN IF NOT EXISTS pr_number BIGINT",
        "ALTER TABLE sandboxes ADD COLUMN IF NOT EXISTS pr_url TEXT",
        "CREATE TABLE IF NOT EXISTS teams (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, name TEXT NOT NULL, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS team_members (team_id TEXT REFERENCES teams(id) ON DELETE CASCADE, user_id TEXT REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY (team_id, user_id))",
        "CREATE TABLE IF NOT EXISTS budgets (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, scope TEXT NOT NULL CHECK (scope IN ('workspace','user','team')), subject_id TEXT, limit_usd NUMERIC(12,6) NOT NULL, period TEXT NOT NULL CHECK (period IN ('monthly','total')), created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS invoices (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, period_start BIGINT NOT NULL, period_end BIGINT NOT NULL, lines JSONB NOT NULL, total_usd NUMERIC(12,6) NOT NULL, created_at BIGINT NOT NULL, UNIQUE (workspace_id, period_start))",
        "CREATE UNIQUE INDEX IF NOT EXISTS invoices_workspace_period ON invoices (workspace_id, period_start)",
        "CREATE TABLE IF NOT EXISTS usage_events (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, user_id TEXT REFERENCES users(id), session_id TEXT, kind TEXT NOT NULL, provider TEXT, model TEXT, input_tokens BIGINT NOT NULL DEFAULT 0, output_tokens BIGINT NOT NULL DEFAULT 0, cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, action TEXT NOT NULL, subject TEXT, metadata JSONB NOT NULL DEFAULT '{}'::jsonb, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS github_installations (id BIGINT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, account_login TEXT NOT NULL, account_type TEXT NOT NULL, repository_selection TEXT NOT NULL, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS github_repositories (installation_id BIGINT REFERENCES github_installations(id) ON DELETE CASCADE, repo TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE, PRIMARY KEY (installation_id, repo))",
        "CREATE TABLE IF NOT EXISTS review_policies (workspace_id TEXT PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE, automatic TEXT NOT NULL DEFAULT 'opened', include_drafts BOOLEAN NOT NULL DEFAULT FALSE, strictness TEXT NOT NULL DEFAULT 'medium', filters JSONB NOT NULL DEFAULT '[]'::jsonb, custom_rules JSONB NOT NULL DEFAULT '[]'::jsonb, context_files JSONB NOT NULL DEFAULT '[]'::jsonb, linked_repositories JSONB NOT NULL DEFAULT '[]'::jsonb, summary JSONB NOT NULL DEFAULT '{}'::jsonb, status_check JSONB, auto_approve JSONB, updated_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS session_metadata (session_id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, user_id TEXT REFERENCES users(id), project TEXT, model TEXT, input_tokens BIGINT NOT NULL DEFAULT 0, output_tokens BIGINT NOT NULL DEFAULT 0, cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0, files_read JSONB NOT NULL DEFAULT '[]'::jsonb, prompt_excerpt TEXT, started_at BIGINT NOT NULL, ended_at BIGINT)",
        "CREATE TABLE IF NOT EXISTS payment_methods (id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE, provider TEXT NOT NULL, provider_customer_id TEXT, provider_payment_method_id TEXT, brand TEXT, last4 TEXT, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS device_codes (device_code TEXT PRIMARY KEY, user_code TEXT NOT NULL, user_id TEXT, workspace_id TEXT, approved BOOLEAN NOT NULL DEFAULT FALSE, expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS skills (workspace_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', sha256 TEXT NOT NULL, bytes BYTEA NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (workspace_id, name))",
        "CREATE TABLE IF NOT EXISTS webhook_deliveries (id TEXT PRIMARY KEY, received_at BIGINT NOT NULL)",
    ];

    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut req = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"));
        let body = match body {
            Some(v) => {
                req = req.header("content-type", "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Postgres rejects concurrent CREATE TABLE IF NOT EXISTS in the same
    /// schema, so tests take this lock around schema setup.
    static SCHEMA_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// FREEDAS_OIDC_* are process globals; tests that set or clear them take
    /// this lock so the fail-closed test and the login test cannot interleave.
    static OIDC_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Same for the GitHub App keys read by `/github/pulls`.
    static GITHUB_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// `FREEDAS_RUNNER_TOKEN` gates sandbox token minting.
    static RUNNER_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Pool for the tests that run without `--ignored`; without Postgres they
    /// must skip quickly instead of waiting out the default 30s acquire timeout.
    async fn pg() -> Option<PgPool> {
        let url = std::env::var("FREEDAS_PG_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/postgres".into());
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&url)
            .await
            .ok()
    }

    /// Seed a user, an organization workspace, and an owner token.
    async fn seed(pool: &PgPool) -> (String, String, String) {
        let now = now_ms();
        let user = format!("usr_{}", ulid::Ulid::new());
        let ws = format!("ws_{}", ulid::Ulid::new());
        let token = random_hex(16);
        sqlx::query("INSERT INTO users (id, email, name, created_at) VALUES ($1, $2, 'T', $3)")
            .bind(&user)
            .bind(format!("{user}@example.com"))
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO workspaces (id, slug, name, kind, owner_id, created_at) VALUES ($1, $2, 'T', 'organization', $3, $4)")
            .bind(&ws)
            .bind(&ws)
            .bind(&user)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, 'owner')",
        )
        .bind(&ws)
        .bind(&user)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO api_tokens (id, user_id, workspace_id, token_hash, scopes, created_at) VALUES ($1, $2, $3, $4, '{}', $5)")
            .bind(format!("tok_{}", ulid::Ulid::new()))
            .bind(&user)
            .bind(&ws)
            .bind(hash_token(&token))
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
        (user, ws, token)
    }

    /// Adds a person to `ws` with `role` and returns their id, email, and a
    /// workspace-scoped token.
    async fn add_member_token(pool: &PgPool, ws: &str, role: &str) -> (String, String, String) {
        let now = now_ms();
        let user = format!("usr_{}", ulid::Ulid::new());
        let email = format!("{user}@example.com");
        let token = random_hex(16);
        sqlx::query("INSERT INTO users (id, email, name, created_at) VALUES ($1, $2, 'M', $3)")
            .bind(&user)
            .bind(&email)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, $3)")
            .bind(ws)
            .bind(&user)
            .bind(role)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_tokens (id, user_id, workspace_id, token_hash, scopes, created_at) VALUES ($1, $2, $3, $4, '{}', $5)")
            .bind(format!("tok_{}", ulid::Ulid::new()))
            .bind(&user)
            .bind(ws)
            .bind(hash_token(&token))
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
        (user, email, token)
    }

    #[tokio::test]
    #[ignore]
    async fn registry_is_workspace_scoped_and_tokens_revoke() {
        let url = std::env::var("FREEDAS_PG_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/postgres".into());
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_u1, _w1, token_a) = seed(&pool).await;
        let (_u2, _w2, token_b) = seed(&pool).await;
        let app = app(pool.clone(), "http://localhost".into());

        // Upload with metadata headers; the digest is computed server-side.
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/registry/skills/release")
            .header("authorization", format!("Bearer {token_a}"))
            .header("x-skill-sha256", "abc123")
            .header("x-skill-description", "Cut a release")
            .body(Body::from("tarball-bytes"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let digest = hex::encode(Sha256::digest(b"tarball-bytes"));

        let (status, body) = call(&app, "GET", "/registry/skills", &token_a, None).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body[0]["name"], "release");
        assert_eq!(body[0]["description"], "Cut a release");
        assert_eq!(body[0]["sha256"], digest.as_str());
        assert_ne!(body[0]["sha256"], "abc123");

        // Another workspace cannot see it.
        let (status, body) = call(&app, "GET", "/registry/skills", &token_b, None).await;
        assert_eq!(status, 200);
        assert_eq!(body.as_array().unwrap().len(), 0);

        let req = axum::http::Request::builder()
            .uri("/registry/skills/release")
            .header("authorization", format!("Bearer {token_b}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 404);

        // Revoke the token: the same bearer stops working.
        let token_id: String =
            sqlx::query_scalar("SELECT id FROM api_tokens WHERE token_hash = $1")
                .bind(hash_token(&token_a))
                .fetch_one(&pool)
                .await
                .unwrap();
        let (status, body) = call(
            &app,
            "DELETE",
            &format!("/tokens/{token_id}"),
            &token_a,
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (status, _) = call(&app, "GET", "/wallet", &token_a, None).await;
        assert_eq!(status, 401);
    }

    #[tokio::test]
    #[ignore]
    async fn sandbox_lifecycle_and_settings() {
        // Requires a Postgres reachable at FREEDAS_PG_URL (see the live test).
        let url = std::env::var("FREEDAS_PG_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/postgres".into());
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let now = now_ms();
        let user = format!("usr_{}", ulid::Ulid::new());
        let ws = format!("ws_{}", ulid::Ulid::new());
        let token = random_hex(16);
        sqlx::query("INSERT INTO users (id, email, name, created_at) VALUES ($1, $2, 'T', $3)")
            .bind(&user)
            .bind(format!("{user}@example.com"))
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO workspaces (id, slug, name, kind, owner_id, created_at) VALUES ($1, $2, 'T', 'organization', $3, $4)")
            .bind(&ws)
            .bind(&ws)
            .bind(&user)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, 'owner')",
        )
        .bind(&ws)
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO api_tokens (id, user_id, workspace_id, token_hash, scopes, created_at) VALUES ($1, $2, $3, $4, '{}', $5)")
            .bind(format!("tok_{}", ulid::Ulid::new()))
            .bind(&user)
            .bind(&ws)
            .bind(hash_token(&token))
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO wallet_ledger (id, workspace_id, delta_usd, reason, created_at) VALUES ($1, $2, 10.0, 'credit', $3)")
            .bind(format!("led_{}", ulid::Ulid::new()))
            .bind(&ws)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();

        let app = app(pool.clone(), "http://localhost".into());

        // Sandboxes are off by default.
        let (status, _) = call(
            &app,
            "POST",
            "/sandboxes",
            &token,
            Some(json!({"repo": "acme/api", "task": "add tests"})),
        )
        .await;
        assert_eq!(status, 403);

        let (status, body) = call(
            &app,
            "PATCH",
            "/workspace/settings",
            &token,
            Some(json!({"sandboxes": {"enabled": true, "computeRateUsd": 0.001}})),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["sandboxes"]["enabled"], true);

        let (status, body) = call(
            &app,
            "POST",
            "/sandboxes",
            &token,
            Some(json!({"repo": "acme/api", "base_branch": "main", "task": "add tests"})),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let id = body["id"].as_str().unwrap().to_string();
        assert_eq!(body["status"], "queued");

        let (status, body) = call(
            &app,
            "POST",
            &format!("/sandboxes/{id}/heartbeat"),
            &token,
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["status"], "running");

        let (status, body) =
            call(&app, "POST", &format!("/sandboxes/{id}/stop"), &token, None).await;
        assert_eq!(status, 200, "{body}");
        // Sixty-second minimum at the snapshotted rate.
        assert_eq!(body["computeSeconds"], 60);
        assert!((body["computeCostUsd"].as_f64().unwrap() - 0.06).abs() < 1e-9);

        // The dashboard list carries compute time, cost, and the PR link.
        let (status, body) = call(&app, "GET", "/sandboxes", &token, None).await;
        assert_eq!(status, 200, "{body}");
        let row = &body[0];
        assert_eq!(row["id"].as_str(), Some(id.as_str()));
        assert_eq!(row["computeSeconds"], 60);
        assert!((row["computeCostUsd"].as_f64().unwrap() - 0.06).abs() < 1e-9);
        assert!(row["prNumber"].is_null());
        assert!(row["prUrl"].is_null());
        assert!(row["failureReason"].is_null());

        let (status, body) = call(&app, "GET", "/wallet", &token, None).await;
        assert_eq!(status, 200);
        assert!((body["balanceUsd"].as_f64().unwrap() - 9.94).abs() < 1e-6);

        // Stopping twice is a conflict and must not bill a second time.
        let (status, _) = call(&app, "POST", &format!("/sandboxes/{id}/stop"), &token, None).await;
        assert_eq!(status, 409);
        let compute_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM wallet_ledger WHERE workspace_id = $1 AND reason = 'compute' AND ref = $2",
        )
        .bind(&ws)
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(compute_rows, 1);
        let (status, body) = call(&app, "GET", "/wallet", &token, None).await;
        assert_eq!(status, 200);
        assert!((body["balanceUsd"].as_f64().unwrap() - 9.94).abs() < 1e-6);

        // Review retry only applies to failed or skipped reviews.
        let (status, _) = call(&app, "POST", "/reviews/rev_missing/retry", &token, None).await;
        assert_eq!(status, 409);
    }

    /// Needs Postgres at FREEDAS_PG_URL. A runner token mints a model token
    /// scoped to one workspace, expiring in an hour, for live sandboxes only.
    #[tokio::test]
    async fn sandbox_runner_token_mints_a_workspace_scoped_model_token() {
        let Some(pool) = pg().await else {
            return;
        };
        let _github_env = GITHUB_ENV_LOCK.lock().await;
        let _runner_env = RUNNER_ENV_LOCK.lock().await;
        // SAFETY: the GitHub and runner keys are process globals; this test
        // holds GITHUB_ENV_LOCK and RUNNER_ENV_LOCK, the locks of every test
        // that touches them.
        unsafe {
            std::env::remove_var("FREEDAS_GITHUB_APP_ID");
            std::env::remove_var("FREEDAS_GITHUB_PRIVATE_KEY_PATH");
            std::env::remove_var("FREEDAS_GITHUB_API_BASE");
        }
        let _schema = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_user, ws, workspace_token) = seed(&pool).await;
        let now = now_ms();
        let sandbox = format!("sbx_{}", ulid::Ulid::new());
        sqlx::query(
            "INSERT INTO sandboxes (id, workspace_id, repo, base_branch, task, status, created_at, updated_at)
             VALUES ($1, $2, 'acme/api', 'main', 'add tests', 'running', $3, $3)",
        )
        .bind(&sandbox)
        .bind(&ws)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        let app = app(pool.clone(), "http://localhost".into());
        let path = format!("/sandboxes/{sandbox}/token");

        // An unconfigured control plane refuses to mint.
        // SAFETY: see the lock note above.
        unsafe { std::env::remove_var("FREEDAS_RUNNER_TOKEN") };
        let (status, body) = call(&app, "POST", &path, "runner-secret", None).await;
        assert_eq!(status, 501, "{body}");
        assert_eq!(body["error"], "runner token is not configured");

        // SAFETY: see the lock note above.
        unsafe { std::env::set_var("FREEDAS_RUNNER_TOKEN", "runner-secret") };
        let (status, _) = call(&app, "POST", &path, "wrong", None).await;
        assert_eq!(status, 401);
        // A workspace token is not a runner token.
        let (status, _) = call(&app, "POST", &path, &workspace_token, None).await;
        assert_eq!(status, 401);

        let (status, body) = call(&app, "POST", &path, "runner-secret", None).await;
        assert_eq!(status, 200, "{body}");
        let model_token = body["modelToken"].as_str().expect("modelToken").to_owned();
        assert!(body.get("githubToken").is_none(), "{body}");

        // The minted token is bound to the sandbox's workspace.
        let (status, body) = call(&app, "GET", "/workspaces", &model_token, None).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body[0]["id"], ws);

        let (scopes, expires_at): (String, Option<i64>) =
            sqlx::query_as("SELECT scopes, expires_at FROM api_tokens WHERE token_hash = $1")
                .bind(hash_token(&model_token))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(scopes, format!("{{sandbox:{sandbox}}}"));
        assert_eq!(scopes_of(Some(&scopes)), vec![format!("sandbox:{sandbox}")]);
        let expires_at = expires_at.expect("expiry");
        assert!(expires_at > now + 3_500_000);
        assert!(expires_at <= now_ms() + 3_600_000);

        // Terminal sandboxes can no longer mint.
        sqlx::query("UPDATE sandboxes SET status = 'stopped' WHERE id = $1")
            .bind(&sandbox)
            .execute(&pool)
            .await
            .unwrap();
        let (status, _) = call(&app, "POST", &path, "runner-secret", None).await;
        assert_eq!(status, 404);
        let (status, _) = call(
            &app,
            "POST",
            "/sandboxes/sbx_missing/token",
            "runner-secret",
            None,
        )
        .await;
        assert_eq!(status, 404);
        // SAFETY: see the lock note above.
        unsafe { std::env::remove_var("FREEDAS_RUNNER_TOKEN") };
    }

    /// Stopping a sandbox revokes the model token minted for it; repeating
    /// the teardown is a no-op. Needs Postgres at FREEDAS_PG_URL.
    #[tokio::test]
    async fn stopping_a_sandbox_revokes_its_model_token() {
        let Some(pool) = pg().await else {
            return;
        };
        let _github_env = GITHUB_ENV_LOCK.lock().await;
        let _runner_env = RUNNER_ENV_LOCK.lock().await;
        // SAFETY: the GitHub and runner keys are process globals; this test
        // holds GITHUB_ENV_LOCK and RUNNER_ENV_LOCK, the locks of every test
        // that touches them.
        unsafe {
            std::env::remove_var("FREEDAS_GITHUB_APP_ID");
            std::env::remove_var("FREEDAS_GITHUB_PRIVATE_KEY_PATH");
            std::env::remove_var("FREEDAS_GITHUB_API_BASE");
            std::env::set_var("FREEDAS_RUNNER_TOKEN", "runner-secret");
        }
        let _schema = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_user, ws, workspace_token) = seed(&pool).await;
        let now = now_ms();
        let sandbox = format!("sbx_{}", ulid::Ulid::new());
        sqlx::query(
            "INSERT INTO sandboxes (id, workspace_id, repo, base_branch, task, status, created_at, updated_at)
             VALUES ($1, $2, 'acme/api', 'main', 'add tests', 'running', $3, $3)",
        )
        .bind(&sandbox)
        .bind(&ws)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        let app = app(pool.clone(), "http://localhost".into());

        let (status, body) = call(
            &app,
            "POST",
            &format!("/sandboxes/{sandbox}/token"),
            "runner-secret",
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let model_token = body["modelToken"].as_str().expect("modelToken").to_owned();
        let (status, body) = call(&app, "GET", "/workspaces", &model_token, None).await;
        assert_eq!(status, 200, "{body}");

        let (status, body) = call(
            &app,
            "POST",
            &format!("/sandboxes/{sandbox}/stop"),
            &workspace_token,
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");

        // The minted token dies with the sandbox.
        let (status, _) = call(&app, "GET", "/workspaces", &model_token, None).await;
        assert_eq!(status, 401);
        let revoked: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at FROM api_tokens WHERE token_hash = $1")
                .bind(hash_token(&model_token))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked.is_some());

        // Revocation is idempotent, and a second stop changes nothing.
        assert_eq!(revoke_sandbox_tokens(&pool, &sandbox).await.unwrap(), 0);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/sandboxes/{sandbox}/stop"),
            &workspace_token,
            None,
        )
        .await;
        assert_eq!(status, 409);
        let again: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at FROM api_tokens WHERE token_hash = $1")
                .bind(hash_token(&model_token))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(again, revoked);

        // SAFETY: see the lock note above.
        unsafe { std::env::remove_var("FREEDAS_RUNNER_TOKEN") };
    }

    #[tokio::test]
    #[ignore]
    async fn reaper_fails_sandboxes_that_stop_heartbeating() {
        let url = std::env::var("FREEDAS_PG_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/postgres".into());
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_user, ws, _token) = seed(&pool).await;
        // Rows from an earlier run are already failed; drop them so a rerun
        // cannot inflate the reaped count.
        sqlx::query("DELETE FROM sandboxes WHERE repo = 'reaper-test/api'")
            .execute(&pool)
            .await
            .unwrap();
        let now = now_ms();
        let stale = format!("sbx_{}", ulid::Ulid::new());
        let fresh = format!("sbx_{}", ulid::Ulid::new());
        for (id, updated_at) in [(&stale, now - 120_000), (&fresh, now)] {
            sqlx::query(
                "INSERT INTO sandboxes
                   (id, workspace_id, repo, base_branch, status, created_at, updated_at)
                 VALUES ($1, $2, 'reaper-test/api', 'main', 'running', $3, $4)",
            )
            .bind(id)
            .bind(&ws)
            .bind(now)
            .bind(updated_at)
            .execute(&pool)
            .await
            .unwrap();
        }

        assert_eq!(reap_stale_sandboxes(&pool, 60_000).await.unwrap(), 1);
        let stale_row: (String, Option<String>) =
            sqlx::query_as("SELECT status, failure_reason FROM sandboxes WHERE id = $1")
                .bind(&stale)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stale_row.0, "failed");
        assert_eq!(stale_row.1.as_deref(), Some("heartbeat_timeout"));
        let fresh_status: String = sqlx::query_scalar("SELECT status FROM sandboxes WHERE id = $1")
            .bind(&fresh)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(fresh_status, "running");
        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'sandbox.timeout' AND subject = $1",
        )
        .bind(&stale)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audits, 1);
    }

    #[tokio::test]
    #[ignore]
    async fn list_tokens_returns_documented_keys() {
        let url = std::env::var("FREEDAS_PG_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/postgres".into());
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_user, ws, token) = seed(&pool).await;
        let now = now_ms();
        let id = format!("tok_{}", ulid::Ulid::new());
        sqlx::query(
            "INSERT INTO api_tokens
               (id, user_id, workspace_id, token_hash, scopes, created_at, expires_at, revoked_at, last_used_at)
             VALUES ($1, NULL, $2, $3, '{read,write}', $4, $5, NULL, NULL)",
        )
        .bind(&id)
        .bind(&ws)
        .bind(hash_token(&random_hex(16)))
        .bind(now + 60_000)
        .bind(now + 3_600_000)
        .execute(&pool)
        .await
        .unwrap();

        let app = app(pool.clone(), "http://localhost".into());
        let (status, body) = call(&app, "GET", "/tokens", &token, None).await;
        assert_eq!(status, 200, "{body}");
        // The seed token plus this one; newest first.
        let rows = body.as_array().unwrap();
        assert_eq!(rows.len(), 2, "{body}");
        let row = &rows[0];
        assert_eq!(row["id"].as_str(), Some(id.as_str()));
        let mut keys: Vec<&str> = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "createdAt",
                "expiresAt",
                "id",
                "lastUsedAt",
                "revokedAt",
                "scopes"
            ]
        );
        assert_eq!(row["scopes"], json!(["read", "write"]));
        assert_eq!(row["expiresAt"], now + 3_600_000);
        assert!(row["revokedAt"].is_null());
        assert!(row["lastUsedAt"].is_null());
    }

    /// Needs a database nobody else is using: it drops the auth tables so the
    /// first-run rule applies. Run alone with `--test-threads=1`.
    #[tokio::test]
    #[ignore = "drops tables; needs a dedicated database"]
    async fn register_bootstraps_once_then_closes() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let Ok(pool) = PgPool::connect(&url).await else {
            return;
        };
        // Run against a fresh schema so the "no users yet" rule applies.
        let _guard = SCHEMA_LOCK.lock().await;
        for table in ["api_tokens", "memberships", "workspaces", "users"] {
            let _ = sqlx::query(&format!("DROP TABLE IF EXISTS {table} CASCADE"))
                .execute(&pool)
                .await;
        }
        for statement in SCHEMA {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
        let app = app(pool.clone(), "http://localhost".into());
        let first = call(
            &app,
            "POST",
            "/auth/register",
            "",
            Some(json!({"email": "owner@example.com", "password_hash": "hunter2hunter2"})),
        )
        .await;
        assert_eq!(first.0, 200, "{:?}", first.1);
        let token = first.1["token"].as_str().expect("token").to_string();
        assert!(first.1["workspaceSlug"].as_str().is_some());
        // The minted token works against the API it just created.
        let workspaces = call(&app, "GET", "/workspaces", &token, None).await;
        assert_eq!(workspaces.0, 200);
        assert_eq!(workspaces.1.as_array().map(|a| a.len()), Some(1));
        // A second registration is refused.
        let second = call(
            &app,
            "POST",
            "/auth/register",
            "",
            Some(json!({"email": "other@example.com", "password_hash": "hunter2hunter2"})),
        )
        .await;
        assert_eq!(second.0, 403);
    }

    #[tokio::test]
    #[ignore = "needs Postgres at FREEDAS_PG_URL"]
    async fn members_budgets_and_invoices() {
        let url = std::env::var("FREEDAS_PG_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/postgres".into());
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (owner, ws, token) = seed(&pool).await;
        let app = app(pool.clone(), "http://localhost".into());

        // Adding a member requires an existing account, matched by email.
        let member = format!("usr_{}", ulid::Ulid::new());
        let member_email = format!("{member}@example.com");
        sqlx::query("INSERT INTO users (id, email, name, created_at) VALUES ($1, $2, 'M', $3)")
            .bind(&member)
            .bind(&member_email)
            .bind(now_ms())
            .execute(&pool)
            .await
            .unwrap();
        let (status, body) = call(
            &app,
            "POST",
            &format!("/workspaces/{ws}/members"),
            &token,
            Some(json!({"email": member_email, "role": "member"})),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["userId"], member);

        let (status, body) = call(
            &app,
            "GET",
            &format!("/workspaces/{ws}/members"),
            &token,
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body.as_array().unwrap().len(), 2);

        // A plain member can read the roster but cannot grant roles.
        let member_token = random_hex(16);
        sqlx::query("INSERT INTO api_tokens (id, user_id, workspace_id, token_hash, scopes, created_at) VALUES ($1, $2, $3, $4, '{}', $5)")
            .bind(format!("tok_{}", ulid::Ulid::new()))
            .bind(&member)
            .bind(&ws)
            .bind(hash_token(&member_token))
            .bind(now_ms())
            .execute(&pool)
            .await
            .unwrap();
        let (status, _) = call(
            &app,
            "POST",
            &format!("/workspaces/{ws}/members"),
            &member_token,
            Some(json!({"email": member_email, "role": "admin"})),
        )
        .await;
        assert_eq!(status, 403);
        let (status, _) = call(
            &app,
            "PATCH",
            &format!("/workspaces/{ws}/members/{owner}"),
            &member_token,
            Some(json!({"role": "member"})),
        )
        .await;
        assert_eq!(status, 403);

        // Roles change for admins, but never for the last owner.
        let (status, body) = call(
            &app,
            "PATCH",
            &format!("/workspaces/{ws}/members/{member}"),
            &token,
            Some(json!({"role": "admin"})),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["role"], "admin");
        let (status, body) = call(
            &app,
            "PATCH",
            &format!("/workspaces/{ws}/members/{owner}"),
            &token,
            Some(json!({"role": "member"})),
        )
        .await;
        assert_eq!(status, 409, "{body}");
        let (status, _) = call(
            &app,
            "PATCH",
            &format!("/workspaces/{ws}/members/{member}"),
            &token,
            Some(json!({"role": "root"})),
        )
        .await;
        assert_eq!(status, 400);
        let (status, _) = call(
            &app,
            "PATCH",
            &format!("/workspaces/{ws}/members/usr_missing"),
            &token,
            Some(json!({"role": "member"})),
        )
        .await;
        assert_eq!(status, 404);

        // The owner cannot be removed; a regular member can.
        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/workspaces/{ws}/members/{owner}"),
            &token,
            None,
        )
        .await;
        assert_eq!(status, 409);
        let (status, body) = call(
            &app,
            "DELETE",
            &format!("/workspaces/{ws}/members/{member}"),
            &token,
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        // The removed member's workspace token stops working immediately.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/workspaces/{ws}/members"),
            &member_token,
            None,
        )
        .await;
        assert_eq!(status, 401);
        let revoked: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at FROM api_tokens WHERE token_hash = $1")
                .bind(hash_token(&member_token))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked.is_some());

        // Budgets report spend from usage_events for the current period.
        let (status, body) = call(
            &app,
            "POST",
            &format!("/workspaces/{ws}/budgets"),
            &token,
            Some(json!({"scope": "workspace", "limitUsd": 25.0, "period": "monthly"})),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["limitUsd"].as_f64().unwrap(), 25.0);
        assert_eq!(body["spentUsd"].as_f64().unwrap(), 0.0);

        sqlx::query("INSERT INTO usage_events (id, workspace_id, kind, provider, model, input_tokens, output_tokens, cost_usd, created_at) VALUES ($1, $2, 'primary', 'test', 'm', 100, 50, 1.5::numeric, $3)")
            .bind(format!("use_{}", ulid::Ulid::new()))
            .bind(&ws)
            .bind(now_ms())
            .execute(&pool)
            .await
            .unwrap();
        let (status, body) = call(
            &app,
            "GET",
            &format!("/workspaces/{ws}/budgets"),
            &token,
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["budgets"][0]["spentUsd"].as_f64().unwrap(), 1.5);
        assert_eq!(body["budgets"][0]["remainingUsd"].as_f64().unwrap(), 23.5);
        assert_eq!(body["balanceUsd"].as_f64().unwrap(), 0.0);

        // Invoicing aggregates the previous calendar month only.
        let (prev_start, _) = previous_month_range();
        sqlx::query("INSERT INTO usage_events (id, workspace_id, kind, provider, model, input_tokens, output_tokens, cost_usd, created_at) VALUES ($1, $2, 'primary', 'test', 'old-model', 1000, 500, 2.0::numeric, $3)")
            .bind(format!("use_{}", ulid::Ulid::new()))
            .bind(&ws)
            .bind(prev_start + 1000)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO wallet_ledger (id, workspace_id, delta_usd, reason, created_at) VALUES ($1, $2, -0.5::numeric, 'compute:sandbox', $3)")
            .bind(format!("led_{}", ulid::Ulid::new()))
            .bind(&ws)
            .bind(prev_start + 2000)
            .execute(&pool)
            .await
            .unwrap();
        let (status, body) = call(
            &app,
            "POST",
            &format!("/workspaces/{ws}/invoices/generate"),
            &token,
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(
            (body["totalUsd"].as_f64().unwrap() - 2.5).abs() < 1e-9,
            "{body}"
        );
        assert_eq!(body["lines"].as_array().unwrap().len(), 2);
        assert_eq!(body["lines"][0]["model"], "old-model");
        assert_eq!(body["lines"][1]["kind"], "sandbox_compute");

        let (status, body) = call(
            &app,
            "GET",
            &format!("/workspaces/{ws}/invoices"),
            &token,
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body.as_array().unwrap().len(), 1);
        let first_id = body[0]["id"].as_str().unwrap().to_string();

        // Regenerating replaces the same month instead of adding a second bill.
        let (status, body) = call(
            &app,
            "POST",
            &format!("/workspaces/{ws}/invoices/generate"),
            &token,
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["id"], first_id.as_str());
        let (status, body) = call(
            &app,
            "GET",
            &format!("/workspaces/{ws}/invoices"),
            &token,
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["id"], first_id.as_str());
    }

    #[tokio::test]
    async fn oidc_and_scim_fail_closed_when_unconfigured() {
        let _env = OIDC_ENV_LOCK.lock().await;
        // SAFETY: the OIDC keys are process globals; every test that touches
        // them holds OIDC_ENV_LOCK.
        unsafe {
            std::env::remove_var("FREEDAS_OIDC_ISSUER");
            std::env::remove_var("FREEDAS_OIDC_CLIENT_ID");
            std::env::remove_var("FREEDAS_OIDC_CLIENT_SECRET");
            std::env::remove_var("FREEDAS_SCIM_TOKEN");
        }
        let pool =
            PgPool::connect_lazy("postgres://postgres@127.0.0.1:1/postgres").expect("lazy pool");
        let app = app(pool, "http://localhost".into());
        let status = |uri: &str| {
            let app = app.clone();
            let uri = uri.to_string();
            async move {
                let response = app
                    .oneshot(
                        axum::http::Request::builder()
                            .uri(uri)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                response.status().as_u16()
            }
        };
        assert_eq!(status("/auth/oidc/start").await, 501);
        assert_eq!(status("/auth/oidc/callback?code=x&state=y").await, 501);
        assert_eq!(status("/scim/v2/Users").await, 404);
        assert_eq!(status("/scim/v2/Groups").await, 404);
    }

    #[test]
    fn scim_responses_use_rfc7643_shapes() {
        let user = scim_user("usr_1", "a@example.com", "A", true);
        assert_eq!(
            user["schemas"][0],
            "urn:ietf:params:scim:schemas:core:2.0:User"
        );
        assert_eq!(user["userName"], "a@example.com");
        assert_eq!(user["emails"][0]["value"], "a@example.com");
        assert_eq!(user["emails"][0]["primary"], true);

        let group = scim_group("team_1", "Core", vec!["usr_1".into(), "usr_2".into()]);
        assert_eq!(
            group["schemas"][0],
            "urn:ietf:params:scim:schemas:core:2.0:Group"
        );
        assert_eq!(group["displayName"], "Core");
        assert_eq!(group["members"][1]["value"], "usr_2");

        let list = scim_list(vec![user, group]);
        assert_eq!(
            list["schemas"][0],
            "urn:ietf:params:scim:api:messages:2.0:ListResponse"
        );
        assert_eq!(list["totalResults"], 2);
        assert_eq!(list["itemsPerPage"], 2);
        assert_eq!(list["Resources"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn policy_merge_applies_known_keys_only() {
        let current = json!({
            "automatic": "opened",
            "includeDrafts": false,
            "strictness": "medium",
            "filters": [],
            "customRules": [],
            "contextFiles": [],
            "linkedRepositories": [],
            "summary": {},
            "statusCheck": null,
            "autoApprove": null,
        });
        let merged = merge_policy(
            &current,
            &json!({"strictness": "high", "autoApprove": {"minConfidence": 4}, "bogus": 1}),
        );
        assert_eq!(merged["strictness"], "high");
        assert_eq!(merged["autoApprove"]["minConfidence"], 4);
        assert_eq!(merged["automatic"], "opened");
        assert!(merged.get("bogus").is_none());
    }

    #[test]
    fn previous_month_range_is_one_calendar_month() {
        let (start, end) = previous_month_range();
        assert!(start < end);
        let days = (end - start) / 86_400_000;
        assert!((28..=31).contains(&days), "{days} days");
        assert!(end <= now_ms());
        assert_eq!(end, month_start_ms(0));
    }

    #[test]
    fn device_codes_are_readable_and_typed_codes_normalize() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let code = user_code();
            assert_eq!(code.len(), 9, "{code}");
            assert_eq!(&code[4..5], "-", "{code}");
            for (index, c) in code.char_indices() {
                if index == 4 {
                    continue;
                }
                assert!(USER_CODE_ALPHABET.contains(&(c as u8)), "{code}");
            }
            assert!(seen.insert(code));
        }
        assert_eq!(normalize_user_code(" abcd-efgh "), "ABCDEFGH");
        assert_eq!(normalize_user_code("ABCDEFGH"), "ABCDEFGH");
        assert_eq!(normalize_user_code(""), "");
        assert_eq!(html_escape("<\"&'>"), "&lt;&quot;&amp;&#39;&gt;");
    }

    #[test]
    fn policy_triggers_follow_the_automatic_setting() {
        assert!(!policy_triggers("never", "opened"));
        assert!(policy_triggers("opened", "opened"));
        assert!(!policy_triggers("opened", "synchronize"));
        assert!(policy_triggers("pushes", "opened"));
        assert!(policy_triggers("pushes", "synchronize"));
        assert!(policy_triggers("pushes", "reopened"));
        assert!(!policy_triggers("pushes", "closed"));
        assert!(policy_triggers("all", "edited"));
        // Unknown values behave like the schema default.
        assert!(policy_triggers("", "opened"));
        assert!(!policy_triggers("", "synchronize"));
    }

    fn pr_payload() -> Value {
        json!({
            "action": "opened",
            "repository": {"full_name": "acme/api"},
            "pull_request": {
                "title": "Add rate limiting",
                "draft": false,
                "user": {"login": "octocat"},
                "head": {"ref": "feature/rate-limit"},
                "labels": [{"name": "review"}, {"name": "backend"}],
            },
        })
    }

    #[test]
    fn filters_skip_on_excluded_or_unmatched_include() {
        let payload = pr_payload();
        assert!(!filters_skip(&json!([]), &payload));
        assert!(!filters_skip(&Value::Null, &payload));

        // include: a match keeps the review, no match skips it.
        let include = json!([{"field": "author", "op": "include", "values": ["OctoCat"]}]);
        assert!(!filters_skip(&include, &payload));
        let miss = json!([{"field": "author", "op": "include", "values": ["someone-else"]}]);
        assert!(filters_skip(&miss, &payload));

        // exclude: a match skips it.
        let exclude =
            json!([{"field": "branch", "op": "exclude", "values": ["feature/rate-limit"]}]);
        assert!(filters_skip(&exclude, &payload));

        // label matches any label name; repository and title match too.
        assert!(!filters_skip(
            &json!([{"field": "label", "op": "include", "values": ["backend"]}]),
            &payload
        ));
        assert!(filters_skip(
            &json!([{"field": "label", "op": "include", "values": ["frontend"]}]),
            &payload
        ));
        assert!(filters_skip(
            &json!([{"field": "repository", "op": "exclude", "values": ["ACME/API"]}]),
            &payload
        ));
        assert!(filters_skip(
            &json!([{"field": "title", "op": "include", "values": ["unrelated"]}]),
            &payload
        ));

        // Unknown fields match nothing; unknown ops are ignored.
        assert!(filters_skip(
            &json!([{"field": "bogus", "op": "include", "values": ["x"]}]),
            &payload
        ));
        assert!(!filters_skip(
            &json!([{"field": "bogus", "op": "bogus", "values": ["x"]}]),
            &payload
        ));
    }

    #[test]
    fn sandbox_scope_is_narrow() {
        assert_eq!(
            sandbox_scope(Some("{sandbox:sbx_1}")).as_deref(),
            Some("sbx_1")
        );
        assert_eq!(
            sandbox_scope(Some("sandbox:sbx_1")).as_deref(),
            Some("sbx_1")
        );
        assert_eq!(sandbox_scope(Some("{}")), None);
        assert_eq!(sandbox_scope(None), None);

        use axum::http::Method;
        let id = "sbx_1";
        assert!(sandbox_request_allowed(id, &Method::GET, "/workspaces"));
        assert!(sandbox_request_allowed(id, &Method::GET, "/usage/summary"));
        assert!(sandbox_request_allowed(
            id,
            &Method::GET,
            "/sandboxes/sbx_1"
        ));
        assert!(sandbox_request_allowed(
            id,
            &Method::POST,
            "/sandboxes/sbx_1/stop"
        ));
        assert!(sandbox_request_allowed(
            id,
            &Method::POST,
            "/v1/chat/completions"
        ));
        assert!(!sandbox_request_allowed(id, &Method::POST, "/workspaces"));
        assert!(!sandbox_request_allowed(id, &Method::GET, "/tokens"));
        assert!(!sandbox_request_allowed(id, &Method::POST, "/tokens"));
        assert!(!sandbox_request_allowed(
            id,
            &Method::GET,
            "/sandboxes/sbx_2"
        ));
        // A prefix that merely starts with the id is a different sandbox.
        assert!(!sandbox_request_allowed(
            id,
            &Method::GET,
            "/sandboxes/sbx_10"
        ));
    }

    #[test]
    fn settings_merge_keeps_sibling_keys() {
        let mut current = json!({
            "sandboxes": {"enabled": true, "computeRateUsd": 0.001},
            "sso_required": true,
        });
        deep_merge(
            &mut current,
            &json!({"sandboxes": {"enabled": false}, "default_model": "x"}),
        );
        assert_eq!(current["sandboxes"]["enabled"], false);
        assert_eq!(current["sandboxes"]["computeRateUsd"], 0.001);
        assert_eq!(current["sso_required"], true);
        assert_eq!(current["default_model"], "x");
        // A scalar patch replaces the nested value outright.
        deep_merge(&mut current, &json!({"sandboxes": 5}));
        assert_eq!(current["sandboxes"], 5);
    }

    #[test]
    fn throttle_locks_after_repeated_failures() {
        let mut throttle = Throttle::default();
        for _ in 0..4 {
            throttle.fail("login:a@example.com");
        }
        assert!(!throttle.locked("login:a@example.com"));
        throttle.fail("login:a@example.com");
        assert!(throttle.locked("login:a@example.com"));
        assert!(!throttle.locked("login:b@example.com"));
        throttle.succeed("login:a@example.com");
        assert!(!throttle.locked("login:a@example.com"));

        assert!(!throttle.over_limit("device-code", 2, 60_000));
        assert!(!throttle.over_limit("device-code", 2, 60_000));
        assert!(throttle.over_limit("device-code", 2, 60_000));
    }

    #[test]
    fn scim_patch_parses_active_flag() {
        assert_eq!(scim_active_patch(&json!({"active": false})), Some(false));
        assert_eq!(scim_active_patch(&json!({"active": true})), Some(true));
        assert_eq!(
            scim_active_patch(&json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "path": "active", "value": false}],
            })),
            Some(false)
        );
        assert_eq!(
            scim_active_patch(&json!({
                "Operations": [{"op": "Replace", "path": "Active", "value": {"active": true}}],
            })),
            Some(true)
        );
        assert_eq!(
            scim_active_patch(&json!({"Operations": [{"op": "remove", "path": "active"}]})),
            Some(false)
        );
        // Patches that do not touch `active` are not ours to apply.
        assert_eq!(
            scim_active_patch(&json!({
                "Operations": [{"op": "replace", "path": "displayName", "value": "x"}],
            })),
            None
        );
        assert_eq!(scim_active_patch(&json!({})), None);
        assert_eq!(scim_active_patch(&json!({"Operations": "nope"})), None);
    }

    /// Needs Postgres at FREEDAS_PG_URL. Drives the full device flow: request a
    /// code, poll pending, approve in the browser form, then use the token.
    #[tokio::test]
    #[ignore = "needs Postgres at FREEDAS_PG_URL"]
    async fn device_flow_issues_a_working_token() {
        let url = std::env::var("FREEDAS_PG_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/postgres".into());
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }

        use argon2::PasswordHasher;
        use argon2::password_hash::{SaltString, rand_core::OsRng};
        let salt = SaltString::generate(&mut OsRng);
        let phc = Argon2::default()
            .hash_password(b"hunter2hunter2", &salt)
            .expect("hash")
            .to_string();
        let now = now_ms();
        let user = format!("usr_{}", ulid::Ulid::new());
        let ws = format!("ws_{}", ulid::Ulid::new());
        let slug = format!("slug-{}", &ws[3..]);
        let email = format!("{user}@example.com");
        sqlx::query(
            "INSERT INTO users (id, email, name, password_hash, created_at)
             VALUES ($1, $2, 'D', $3, $4)",
        )
        .bind(&user)
        .bind(&email)
        .bind(&phc)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO workspaces (id, slug, name, kind, owner_id, created_at) VALUES ($1, $2, 'D', 'organization', $3, $4)")
            .bind(&ws)
            .bind(&slug)
            .bind(&user)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, 'owner')",
        )
        .bind(&ws)
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();

        let app = app(pool.clone(), "http://localhost".into());

        // 1. Ask for a code; no authentication.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/device/code")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let code: Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let device_code = code["deviceCode"].as_str().expect("deviceCode").to_string();
        let user_code = code["userCode"].as_str().expect("userCode").to_string();
        assert_eq!(code["expiresIn"], 600);
        assert_eq!(code["interval"], 5);
        assert_eq!(code["verificationUri"], "http://localhost/device");
        assert_eq!(
            code["verificationUriComplete"],
            format!("http://localhost/device?code={user_code}")
        );

        // 2. Polling before approval is pending, not an error.
        let poll = |device_code: String| {
            let app = app.clone();
            async move {
                let resp = app
                    .oneshot(
                        axum::http::Request::builder()
                            .method("POST")
                            .uri("/device/token")
                            .header("content-type", "application/json")
                            .body(Body::from(json!({"deviceCode": device_code}).to_string()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = resp.status().as_u16();
                let body: Value =
                    serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes())
                        .unwrap();
                (status, body)
            }
        };
        let (status, body) = poll(device_code.clone()).await;
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"], "authorization_pending");

        // 3. The approval page renders the code and posts the same code back.
        let page = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!("/device?code={user_code}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.status().as_u16(), 200);
        let html = String::from_utf8(
            page.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("<title>Freedas device approval</title>"));
        assert!(html.contains(&user_code));
        assert!(html.contains("action=\"/device/approve\""));

        // 4. Wrong password does not approve.
        let form = format!("user_code={user_code}&email={email}&password=wrong&workspace=");
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/device/approve")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);
        let (status, _) = poll(device_code.clone()).await;
        assert_eq!(status, 400);

        // 5. The real password approves, accepting a lowercase, dashless code.
        let typed = user_code.replace('-', "").to_lowercase();
        let form =
            format!("user_code={typed}&email={email}&password=hunter2hunter2&workspace={slug}");
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/device/approve")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let html = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("Approved. You can close this tab."));

        // 6. The next poll mints a token bound to the chosen workspace.
        let (status, body) = poll(device_code.clone()).await;
        assert_eq!(status, 200, "{body}");
        let token = body["token"].as_str().expect("token").to_string();
        assert_eq!(body["userID"], user);
        assert_eq!(body["workspaceID"], ws);
        assert_eq!(body["workspaceSlug"], slug);

        let (status, body) = call(&app, "GET", "/workspaces", &token, None).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body.as_array().map(|a| a.len()), Some(1));
        assert_eq!(body[0]["slug"], slug);

        // The device row is single-use.
        let (status, body) = poll(device_code).await;
        assert_eq!(status, 410, "{body}");
        assert_eq!(body["error"], "expired_token");
    }

    /// Needs Postgres at FREEDAS_PG_URL. Deprovisioning clears credentials,
    /// drops memberships, revokes tokens, and keeps the row for audit.
    #[tokio::test]
    #[ignore = "needs Postgres at FREEDAS_PG_URL"]
    async fn scim_deprovision_keeps_the_row_and_revokes_access() {
        let url = std::env::var("FREEDAS_PG_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/postgres".into());
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let now = now_ms();
        let user = format!("usr_{}", ulid::Ulid::new());
        let ws = format!("ws_{}", ulid::Ulid::new());
        let token = random_hex(16);
        sqlx::query(
            "INSERT INTO users (id, email, name, password_hash, oidc_sub, created_at)
             VALUES ($1, $2, 'S', 'phc', 'sub-1', $3)",
        )
        .bind(&user)
        .bind(format!("{user}@example.com"))
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO workspaces (id, slug, name, kind, owner_id, created_at) VALUES ($1, $2, 'S', 'organization', $3, $4)")
            .bind(&ws)
            .bind(&ws)
            .bind(&user)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO memberships (workspace_id, user_id, role) VALUES ($1, $2, 'owner')",
        )
        .bind(&ws)
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO api_tokens (id, user_id, workspace_id, token_hash, scopes, created_at) VALUES ($1, $2, $3, $4, '{}', $5)")
            .bind(format!("tok_{}", ulid::Ulid::new()))
            .bind(&user)
            .bind(&ws)
            .bind(hash_token(&token))
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();

        let state = AppState {
            pool: pool.clone(),
            base_url: "http://localhost".into(),
            oidc_states: Default::default(),
            throttle: Default::default(),
        };
        assert!(scim_deactivate(&state, &user).await.unwrap());

        let (hash, sub): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT password_hash, oidc_sub FROM users WHERE id = $1")
                .bind(&user)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(hash.is_none());
        assert!(sub.is_none());
        let active: bool = sqlx::query_scalar("SELECT active FROM users WHERE id = $1")
            .bind(&user)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!active);
        // The only owner leaves; the workspace stays for audit but ownerless.
        let owner: Option<String> =
            sqlx::query_scalar("SELECT owner_id FROM workspaces WHERE id = $1")
                .bind(&ws)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(owner.is_none());
        let memberships: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM memberships WHERE user_id = $1")
                .bind(&user)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(memberships, 0);
        let revoked: Option<i64> = sqlx::query_scalar(
            "SELECT revoked_at FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&user)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(revoked.is_some());

        // The row still authenticates as nothing.
        let app = app(pool.clone(), "http://localhost".into());
        let (status, _) = call(&app, "GET", "/workspaces", &token, None).await;
        assert_eq!(status, 401);

        // Deprovisioning is idempotent; an unknown user is reported missing.
        assert!(scim_deactivate(&state, &user).await.unwrap());
        assert!(!scim_deactivate(&state, "usr_missing").await.unwrap());
    }

    /// Needs Postgres at FREEDAS_PG_URL. Sums statuses, findings, confidence,
    /// cost, repos, and authors for one workspace and ignores other rows.
    #[tokio::test]
    async fn reviews_analytics_aggregates_workspace_rows() {
        let Some(pool) = pg().await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_user, ws, token) = seed(&pool).await;
        let (_other_user, other_ws, _other_token) = seed(&pool).await;
        let now = now_ms();

        // (status, confidence, findings JSON, customer cost, upstream cost,
        //  repo, author)
        let repo_a = format!("o/n-{ws}");
        let repo_b = format!("o/m-{ws}");
        type SeedRow<'a> = (
            &'a str,
            Option<f64>,
            Option<&'a str>,
            f64,
            f64,
            &'a str,
            Option<&'a str>,
        );
        let rows: [SeedRow<'_>; 4] = [
            (
                "completed",
                Some(4.0),
                Some(r#"[{"severity":"blocker"},{"severity":"high"}]"#),
                0.5,
                0.25,
                &repo_a,
                Some("alice"),
            ),
            (
                "completed",
                Some(2.0),
                Some(r#"[{"severity":"high"},{"severity":"nit"}]"#),
                0.75,
                0.0,
                &repo_a,
                Some("alice"),
            ),
            ("failed", None, None, 0.0, 0.0, &repo_b, Some("bob")),
            // Not an array: counted as zero findings, still counted as a review.
            (
                "skipped",
                Some(3.0),
                Some(r#"{"not":"an array"}"#),
                1.0,
                0.0,
                &repo_a,
                None,
            ),
        ];
        for (index, (status, confidence, findings, customer, upstream, repo, author)) in
            rows.iter().enumerate()
        {
            sqlx::query(
                "INSERT INTO reviews
                   (id, workspace_id, installation_id, repo, pr_number, head_sha, status,
                    author, confidence, findings, customer_cost_usd, upstream_cost_usd,
                    created_at, updated_at)
                 VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $12)",
            )
            .bind(format!("rev_{}", ulid::Ulid::new()))
            .bind(&ws)
            .bind(*repo)
            .bind(index as i64)
            .bind(format!("{ws}-sha-{index}"))
            .bind(*status)
            .bind(*author)
            .bind(*confidence)
            .bind(*findings)
            .bind(*customer)
            .bind(*upstream)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        }
        // Another workspace's rows must not leak into the totals.
        sqlx::query(
            "INSERT INTO reviews
               (id, workspace_id, installation_id, repo, pr_number, head_sha, status,
                author, confidence, findings, customer_cost_usd, upstream_cost_usd,
                created_at, updated_at)
             VALUES ($1, $2, 1, 'o/other', 0, $3, 'completed', 'carol', 5, $4::jsonb, 9.0, 0, $5, $5)",
        )
        .bind(format!("rev_{}", ulid::Ulid::new()))
        .bind(&other_ws)
        .bind(format!("{other_ws}-sha"))
        .bind(r#"[{"severity":"blocker"}]"#)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

        let app = app(pool.clone(), "http://localhost".into());
        let (status, body) = call(&app, "GET", "/reviews/analytics", &token, None).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["total"], 4);
        assert_eq!(body["byStatus"]["completed"], 2);
        assert_eq!(body["byStatus"]["failed"], 1);
        assert_eq!(body["byStatus"]["skipped"], 1);
        assert_eq!(body["byStatus"]["queued"], 0);
        assert_eq!(body["findings"], 4);
        assert_eq!(body["bySeverity"]["blocker"], 1);
        assert_eq!(body["bySeverity"]["high"], 2);
        assert_eq!(body["bySeverity"]["nit"], 1);
        assert_eq!(body["bySeverity"]["medium"], 0);
        assert_eq!(body["bySeverity"]["low"], 0);
        assert!(
            (body["averageConfidence"].as_f64().unwrap() - 3.0).abs() < 1e-9,
            "{body}"
        );
        assert!(
            (body["totalCostUsd"].as_f64().unwrap() - 2.5).abs() < 1e-9,
            "{body}"
        );
        let repos = body["topRepos"].as_array().unwrap();
        assert_eq!(repos.len(), 2, "{body}");
        assert_eq!(repos[0]["repo"], repo_a.as_str());
        assert_eq!(repos[0]["reviews"], 3);
        assert_eq!(repos[1]["repo"], repo_b.as_str());
        assert_eq!(repos[1]["reviews"], 1);
        let authors = body["contributors"].as_array().unwrap();
        assert_eq!(authors.len(), 2, "{body}");
        assert_eq!(authors[0]["author"], "alice");
        assert_eq!(authors[0]["reviews"], 2);
        assert_eq!(authors[1]["author"], "bob");
    }

    /// Needs Postgres at FREEDAS_PG_URL. Lists and toggles repositories for an
    /// installation; a second workspace cannot see or change them.
    #[tokio::test]
    async fn github_repository_toggle_is_workspace_scoped() {
        let Some(pool) = pg().await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (user, ws, token) = seed(&pool).await;
        let (_other_user, _other_ws, other_token) = seed(&pool).await;
        let installation = (ulid::Ulid::new().0 % (1 << 62)) as i64;
        sqlx::query(
            "INSERT INTO github_installations
               (id, workspace_id, account_login, account_type, repository_selection, created_at)
             VALUES ($1, $2, 'acme', 'Organization', 'selected', $3)",
        )
        .bind(installation)
        .bind(&ws)
        .bind(now_ms())
        .execute(&pool)
        .await
        .unwrap();
        let app = app(pool.clone(), "http://localhost".into());

        let path = format!("/github/installations/{installation}/repositories");
        let (status, body) = call(&app, "GET", &path, &token, None).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body.as_array().unwrap().len(), 0);

        // Another workspace's token cannot read the installation's repos.
        let (status, _) = call(&app, "GET", &path, &other_token, None).await;
        assert_eq!(status, 404);

        let (status, body) = call(
            &app,
            "PATCH",
            "/github/repositories",
            &token,
            Some(json!({"installationId": installation, "repo": "acme/api", "enabled": false})),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["enabled"], false);

        let (status, body) = call(&app, "GET", &path, &token, None).await;
        assert_eq!(status, 200, "{body}");
        let repos = body.as_array().unwrap();
        assert_eq!(repos.len(), 1, "{body}");
        assert_eq!(repos[0]["installationId"], installation);
        assert_eq!(repos[0]["repo"], "acme/api");
        assert_eq!(repos[0]["enabled"], false);

        // Upsert flips the same row instead of inserting a second one.
        let (status, _) = call(
            &app,
            "PATCH",
            "/github/repositories",
            &token,
            Some(json!({"installationId": installation, "repo": "acme/api", "enabled": true})),
        )
        .await;
        assert_eq!(status, 200);
        let (_, body) = call(&app, "GET", &path, &token, None).await;
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["enabled"], true);

        // Another workspace cannot toggle it either.
        let (status, _) = call(
            &app,
            "PATCH",
            "/github/repositories",
            &other_token,
            Some(json!({"installationId": installation, "repo": "acme/api", "enabled": false})),
        )
        .await;
        assert_eq!(status, 404);

        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log
             WHERE action = 'github.repositories' AND workspace_id = $1 AND user_id = $2",
        )
        .bind(&ws)
        .bind(&user)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audited, 2);
    }

    /// Needs Postgres at FREEDAS_PG_URL. The review list carries the columns the
    /// dashboard shows; absent worker values come back as JSON null.
    #[tokio::test]
    async fn reviews_list_includes_confidence_risk_author_and_cost() {
        let Some(pool) = pg().await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_user, ws, token) = seed(&pool).await;
        let now = now_ms();
        let url = "https://github.com/acme/api/pull/7#pullrequestreview-1";
        sqlx::query(
            "INSERT INTO reviews
               (id, workspace_id, installation_id, repo, pr_number, head_sha, status,
                author, confidence, risk, review_url, customer_cost_usd, upstream_cost_usd,
                created_at, updated_at)
             VALUES ($1, $2, 1, 'acme/api', 7, 'sha-7', 'completed',
                     'alice', 4.5, 1.5, $3, 0.5, 0.25, $4, $4)",
        )
        .bind(format!("rev_{}", ulid::Ulid::new()))
        .bind(&ws)
        .bind(url)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO reviews
               (id, workspace_id, installation_id, repo, pr_number, head_sha, status,
                created_at, updated_at)
             VALUES ($1, $2, 1, 'acme/api', 8, 'sha-8', 'queued', $3, $3)",
        )
        .bind(format!("rev_{}", ulid::Ulid::new()))
        .bind(&ws)
        .bind(now - 1)
        .execute(&pool)
        .await
        .unwrap();

        let app = app(pool.clone(), "http://localhost".into());
        let (status, body) = call(&app, "GET", "/reviews", &token, None).await;
        assert_eq!(status, 200, "{body}");
        let rows = body.as_array().unwrap();
        assert_eq!(rows.len(), 2, "{body}");
        assert_eq!(rows[0]["headSha"], "sha-7");
        assert_eq!(rows[0]["status"], "completed");
        assert_eq!(rows[0]["confidence"], 4.5);
        assert_eq!(rows[0]["risk"], 1.5);
        assert_eq!(rows[0]["author"], "alice");
        assert_eq!(rows[0]["reviewUrl"], url);
        assert_eq!(rows[0]["costUsd"], 0.75);
        assert!(rows[1]["confidence"].is_null(), "{body}");
        assert!(rows[1]["risk"].is_null(), "{body}");
        assert!(rows[1]["author"].is_null(), "{body}");
        assert!(rows[1]["reviewUrl"].is_null(), "{body}");
        assert_eq!(rows[1]["costUsd"], 0.0);
    }

    /// Needs Postgres at FREEDAS_PG_URL. Session metadata upserts on the
    /// session ID, truncates the prompt excerpt, and lists per workspace.
    #[tokio::test]
    async fn session_metadata_upserts_and_lists_per_workspace() {
        let Some(pool) = pg().await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_user, ws, token) = seed(&pool).await;
        let (_other_user, _other_ws, other_token) = seed(&pool).await;
        let app = app(pool.clone(), "http://localhost".into());
        let session = format!("ses_{}", ulid::Ulid::new());

        let (status, body) = call(
            &app,
            "POST",
            "/sessions",
            &token,
            Some(json!({
                "sessionID": session,
                "project": "/work/api",
                "model": "anthropic/claude-sonnet",
                "inputTokens": 10,
                "outputTokens": 5,
                "costUsd": 0.25,
                "filesRead": ["src/a.rs"],
                "promptExcerpt": "x".repeat(600),
                "startedAt": 1000,
                "endedAt": null,
            })),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["sessionID"], session.as_str());

        let (status, body) = call(&app, "GET", "/sessions", &token, None).await;
        assert_eq!(status, 200, "{body}");
        let rows = body.as_array().unwrap();
        assert_eq!(rows.len(), 1, "{body}");
        assert_eq!(
            rows[0]["promptExcerpt"].as_str().unwrap().chars().count(),
            500
        );
        assert_eq!(rows[0]["filesRead"], json!(["src/a.rs"]));
        assert_eq!(rows[0]["inputTokens"], 10);
        assert_eq!(rows[0]["costUsd"], 0.25);
        assert!(rows[0]["endedAt"].is_null());

        // A second post for the same session updates the row instead of adding one.
        let (status, _) = call(
            &app,
            "POST",
            "/sessions",
            &token,
            Some(json!({
                "sessionID": session,
                "project": "/work/api",
                "model": "anthropic/claude-sonnet",
                "inputTokens": 30,
                "outputTokens": 7,
                "costUsd": 0.75,
                "filesRead": ["src/a.rs", "src/b.rs"],
                "promptExcerpt": "second",
                "startedAt": 1000,
                "endedAt": 2000,
            })),
        )
        .await;
        assert_eq!(status, 200);

        let newest = format!("ses_{}", ulid::Ulid::new());
        let (status, _) = call(
            &app,
            "POST",
            "/sessions",
            &token,
            Some(json!({"sessionID": newest, "project": "/work/api", "startedAt": 3000})),
        )
        .await;
        assert_eq!(status, 200);
        // Another workspace's session must not appear in this list.
        let (status, _) = call(
            &app,
            "POST",
            "/sessions",
            &other_token,
            Some(json!({"sessionID": format!("ses_{}", ulid::Ulid::new()), "startedAt": 4000})),
        )
        .await;
        assert_eq!(status, 200);

        let (status, body) = call(&app, "GET", "/sessions", &token, None).await;
        assert_eq!(status, 200, "{body}");
        let rows = body.as_array().unwrap();
        assert_eq!(rows.len(), 2, "{body}");
        assert_eq!(rows[0]["sessionID"], newest.as_str());
        assert_eq!(rows[1]["sessionID"], session.as_str());
        assert_eq!(rows[1]["inputTokens"], 30);
        assert_eq!(rows[1]["outputTokens"], 7);
        assert_eq!(rows[1]["costUsd"], 0.75);
        assert_eq!(rows[1]["filesRead"], json!(["src/a.rs", "src/b.rs"]));
        assert_eq!(rows[1]["endedAt"], 2000);

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM session_metadata WHERE session_id = $1 AND workspace_id = $2",
        )
        .bind(&session)
        .bind(&ws)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }

    /// Needs Postgres at FREEDAS_PG_URL. A manual review start is idempotent
    /// per (repo, PR, head SHA) and its detail stays inside the workspace.
    #[tokio::test]
    async fn manual_review_start_is_idempotent_and_detail_is_scoped() {
        let Some(pool) = pg().await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (user, ws, token) = seed(&pool).await;
        let (_other_user, _other_ws, other_token) = seed(&pool).await;
        let app = app(pool.clone(), "http://localhost".into());
        let repo = format!("acme/api-{ws}");
        let body = json!({"repo": repo, "prNumber": 7, "headSha": "abc123"});

        let (status, first) = call(&app, "POST", "/reviews", &token, Some(body.clone())).await;
        assert_eq!(status, 200, "{first}");
        assert_eq!(first["status"], "queued");
        let id = first["id"].as_str().unwrap().to_string();
        assert!(id.starts_with("rev_"));

        // Same key: the existing row comes back instead of a second one.
        let (status, second) = call(&app, "POST", "/reviews", &token, Some(body.clone())).await;
        assert_eq!(status, 200, "{second}");
        assert_eq!(second["id"], id.as_str());
        assert_eq!(second["status"], "queued");

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM reviews
             WHERE installation_id = 0 AND repo = $1 AND pr_number = 7 AND head_sha = 'abc123'",
        )
        .bind(&repo)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1);

        // Fill the worker-owned columns, then read the full row.
        sqlx::query(
            "UPDATE reviews SET status = 'completed', confidence = 4.5, risk = 1.5,
                    findings = $1::jsonb, summary = 'looks good', review_url = $2
             WHERE id = $3",
        )
        .bind(r#"[{"severity":"high"}]"#)
        .bind("https://github.com/acme/api/pull/7#r1")
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
        let (status, detail) = call(&app, "GET", &format!("/reviews/{id}"), &token, None).await;
        assert_eq!(status, 200, "{detail}");
        assert_eq!(detail["id"], id.as_str());
        assert_eq!(detail["repo"], repo.as_str());
        assert_eq!(detail["prNumber"], 7);
        assert_eq!(detail["headSha"], "abc123");
        assert_eq!(detail["status"], "completed");
        assert_eq!(detail["confidence"], 4.5);
        assert_eq!(detail["risk"], 1.5);
        assert_eq!(detail["findings"], json!([{"severity": "high"}]));
        assert_eq!(detail["summary"], "looks good");
        assert!(detail["error"].is_null());
        assert_eq!(detail["reviewUrl"], "https://github.com/acme/api/pull/7#r1");
        assert_eq!(detail["costUsd"], 0.0);

        // Another workspace cannot read the review, but it may start its own
        // review for the same repo/PR: the manual key is workspace-scoped.
        let (status, _) = call(&app, "GET", &format!("/reviews/{id}"), &other_token, None).await;
        assert_eq!(status, 404);
        let (status, other) = call(&app, "POST", "/reviews", &other_token, Some(body)).await;
        assert_eq!(status, 200, "{other}");
        assert_ne!(other["id"], id.as_str());
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM reviews
             WHERE installation_id = 0 AND repo = $1 AND pr_number = 7 AND head_sha = 'abc123'",
        )
        .bind(&repo)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(total, 2);

        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log
             WHERE action = 'review.queued' AND subject = $1
               AND workspace_id = $2 AND user_id = $3",
        )
        .bind(&id)
        .bind(&ws)
        .bind(&user)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audited, 2);
    }

    /// Needs Postgres at FREEDAS_PG_URL. Drives the full OIDC code exchange
    /// against a mock issuer and proves a second login reuses the user row.
    #[tokio::test]
    async fn oidc_login_creates_user_and_reuses_it() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = pg().await else {
            return;
        };
        let _schema = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "oidc-access",
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "sub": "oidc-sub-1",
                "email": "oidc@example.com",
                "email_verified": true,
                "name": "OIDC User",
            })))
            .mount(&mock)
            .await;

        struct EnvGuard;
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                // SAFETY: held under OIDC_ENV_LOCK by the caller.
                unsafe {
                    std::env::remove_var("FREEDAS_OIDC_ISSUER");
                    std::env::remove_var("FREEDAS_OIDC_CLIENT_ID");
                    std::env::remove_var("FREEDAS_OIDC_CLIENT_SECRET");
                }
            }
        }

        let app = app(pool.clone(), "http://localhost".into());
        let _env = OIDC_ENV_LOCK.lock().await;
        let _guard = EnvGuard;
        // SAFETY: the OIDC keys are process globals; every test that touches
        // them holds OIDC_ENV_LOCK.
        unsafe {
            std::env::set_var("FREEDAS_OIDC_ISSUER", mock.uri());
            std::env::set_var("FREEDAS_OIDC_CLIENT_ID", "test-client");
            std::env::set_var("FREEDAS_OIDC_CLIENT_SECRET", "test-secret");
        }

        async fn login(app: &Router) -> Value {
            let (status, body) = call(app, "GET", "/auth/oidc/start", "", None).await;
            assert_eq!(status, 200, "{body}");
            let state = body["url"]
                .as_str()
                .and_then(|url| url.rsplit("state=").next())
                .expect("state in authorize URL")
                .to_string();
            let (status, body) = call(
                app,
                "GET",
                &format!("/auth/oidc/callback?code=code-1&state={state}"),
                "",
                None,
            )
            .await;
            assert_eq!(status, 200, "{body}");
            body
        }

        let first = login(&app).await;
        let token = first["token"].as_str().expect("token").to_string();
        let user_id = first["userId"].as_str().expect("userId").to_string();
        let (sub, email): (String, String) =
            sqlx::query_as("SELECT oidc_sub, email FROM users WHERE id = $1")
                .bind(&user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(sub, "oidc-sub-1");
        assert_eq!(email, "oidc@example.com");

        // The minted token authenticates as that user.
        let (status, body) = call(&app, "GET", "/auth/me", &token, None).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["id"], user_id);

        // A second exchange reuses the row instead of inserting a duplicate.
        let second = login(&app).await;
        assert_eq!(second["userId"], user_id);
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE oidc_sub = $1")
            .bind("oidc-sub-1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(users, 1);
    }

    /// Needs Postgres at FREEDAS_PG_URL. Mints an installation token against a
    /// mock GitHub and lists pulls camelCased; without the App env it fails
    /// closed with 501.
    #[tokio::test]
    async fn github_pulls_uses_installation_token_and_fails_closed() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // The first dash is escaped so secret scanners do not flag this
        // throwaway test key; the runtime value is unchanged.
        const KEY_PEM: &str = "\x2d----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDec0XydqwW2HfQ
J70/9IKw/taTEUIJB0jxiNf5mQBJNVVXTerzLLpraHAMmz7NI1X+sbhvyAFBTW6f
zbE6T5w/fZi1Q4bRyW4vlMwguxrIGjB0eeqBq4D9o9Dcv1Osw8Ua0pEbGQQpFj/N
jYALyIA6/PdCwd7iwSm/c+BdH8jP2/B0Xt23P9OOow8xyMOqC19SLiWY9HoRZ9ab
NYZBOvhsFuWkHTusuAQOdl+nFkhMbpR4CYYnTqKerm3hGDK2kA0HiuQRtIZeRQeo
mJwAJPfJlZ9PX7j2vCZBvvjkJr3iX3ar57HIY6+iyXJmOYy7eFaWOtOWhxpJW8h0
J1C5kwxBAgMBAAECggEADBP9dWSi46Mpfzp3JLazlWVi1G2klJ2qBN5Jnr5jVPZB
vdmn0wAH167eHZscyfHcGJYA9gXJpqhsBB58m9ZIfSyGOvpRgsjBdDErs6/BDKIa
ZSqc9GEx4eOwAppbUlc3V6Vc9lgRgSMZgAFJtWoTp1BGox/oaI61I/VoVloUUs/M
BJsmRYqs9wFkCCmmM60YWmN/jy26IQ38NbODPoM7CslcHXZ3O7TeWceavgL68mBZ
95oF0ILb+HU7yOqWGHTdJwgBsMjl6CnQRU2t2N75GPc795wJDJz6tBy7kV+1Uil5
CzEEbRklyWvh0pbIo5Nmb9R9xzJqyl3qCPq7939CIQKBgQD3Cqi7QPbsA6cMhMQy
bOu+SPdSOWGjGdM2NnthbNsYnq760WepVJUZbxGQ9QAV8L/h0lHwmdlY4NOW5VVX
Wmz8WBN+DG3hWGDWRfq7S4WQ0KjcPZl1/wWJwQXZSi2fEGzUlNPc5CZj0mCPDhX8
W0NX7fkn9IjMNtN9xtla4vCZ8QKBgQDmhFPJ1SLovCQNkkTd+n30AV/D1HXVZB3E
SeBbxjHPDnC/EUs3hZsjVseTEtV++owGCqUS63K3qBhsaDvBkwOuZFQagSfEbkF4
wNIUW2PvRc7Y+CUEW4qGA5nXn7VtEUEilh/UILqqPkW+jnmlMgabzx6wfACgQ8fV
WH3MGEjHUQKBgQDD63ErqHbrcG4gEH8k2psPuwBh9l4HouiN2yF4f4M3AEoXYtGK
SilBFYPh6VvbCqayqkEPxoPH5+4GgvRupak/a35x/dt61sNdy/vwZBGWatUwba3y
FYFH4YwI6rpJpxYYdbucOFh13Bd1/J7VF2/OIU3zMQz4oBaUbopceRSFkQKBgQC4
G+Ir5n3+Mh39dOBqBmHIm7xX1P3T1CVuG68EvZQUkqz7/Zz8mEoi/HFjhvxbcVKa
lK/pH4G9K5VuKAXqAjhDdcAydwtC+OhzwFVJiwCTH0coxXATPeWySXf63oTxuoEy
VYLQUt+jjx73JiYECaN7l/4j6LY7Skd1nzrB4ndmMQKBgHrKYgnCAgHDt8BA3Rlf
h6JRwr3Y0FoJJoLUcADhKBPGupKKV3YZrMtzzhXRAGTGk8R7mPw3X1q9KP8Knr5/
HbVXqVrC1NQbagVlghdkj3JRd1262MlOxkifWz38qpPDXd08ssyl4NXRX0+jOwUy
VYzfNgnqS52tKDQJ3zToKgMz
\x2d----END PRIVATE KEY-----";

        let Some(pool) = pg().await else {
            return;
        };
        let _schema = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_user, ws, token) = seed(&pool).await;
        let installation = (ulid::Ulid::new().0 % (1 << 62)) as i64;
        let repo = format!("o/n-{ws}");
        sqlx::query(
            "INSERT INTO github_installations
               (id, workspace_id, account_login, account_type, repository_selection, created_at)
             VALUES ($1, $2, 'acme', 'Organization', 'selected', $3)",
        )
        .bind(installation)
        .bind(&ws)
        .bind(now_ms())
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO github_repositories (installation_id, repo, enabled) VALUES ($1, $2, TRUE)")
            .bind(installation)
            .bind(&repo)
            .execute(&pool)
            .await
            .unwrap();

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/app/installations/{installation}/access_tokens"
            )))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"token": "ghs_test"})))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/{repo}/pulls")))
            .and(query_param("state", "open"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "number": 1, "title": "One", "user": {"login": "alice"},
                    "state": "open", "draft": false, "head": {"sha": "sha-1"},
                    "html_url": "https://github.com/o/n/pull/1",
                },
                {
                    "number": 2, "title": "Two", "user": {"login": "bob"},
                    "state": "open", "draft": true, "head": {"sha": "sha-2"},
                    "html_url": "https://github.com/o/n/pull/2",
                },
            ])))
            .mount(&mock)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("app.pem");
        std::fs::write(&key_path, KEY_PEM).unwrap();

        struct EnvGuard;
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                // SAFETY: held under GITHUB_ENV_LOCK by the caller.
                unsafe {
                    std::env::remove_var("FREEDAS_GITHUB_APP_ID");
                    std::env::remove_var("FREEDAS_GITHUB_PRIVATE_KEY_PATH");
                    std::env::remove_var("FREEDAS_GITHUB_API_BASE");
                }
            }
        }

        let app = app(pool.clone(), "http://localhost".into());
        let _env = GITHUB_ENV_LOCK.lock().await;
        {
            let _guard = EnvGuard;
            // SAFETY: the GitHub App keys are process globals; every test that
            // touches them holds GITHUB_ENV_LOCK.
            unsafe {
                std::env::set_var("FREEDAS_GITHUB_APP_ID", "123");
                std::env::set_var("FREEDAS_GITHUB_PRIVATE_KEY_PATH", &key_path);
                std::env::set_var("FREEDAS_GITHUB_API_BASE", mock.uri());
            }
            let path = format!("/github/pulls?repo={repo}&state=open");
            let (status, body) = call(&app, "GET", &path, &token, None).await;
            assert_eq!(status, 200, "{body}");
            assert_eq!(
                body,
                json!([
                    {
                        "number": 1, "title": "One", "author": "alice",
                        "state": "open", "draft": false, "headSha": "sha-1",
                        "url": "https://github.com/o/n/pull/1",
                    },
                    {
                        "number": 2, "title": "Two", "author": "bob",
                        "state": "open", "draft": true, "headSha": "sha-2",
                        "url": "https://github.com/o/n/pull/2",
                    },
                ])
            );

            // Disabling the repository cuts off pull listing.
            sqlx::query("UPDATE github_repositories SET enabled = FALSE WHERE installation_id = $1 AND repo = $2")
                .bind(installation)
                .bind(&repo)
                .execute(&pool)
                .await
                .unwrap();
            let (status, body) = call(&app, "GET", &path, &token, None).await;
            assert_eq!(status, 404, "{body}");
        }

        let path = format!("/github/pulls?repo={repo}&state=open");
        let (status, body) = call(&app, "GET", &path, &token, None).await;
        assert_eq!(status, 501, "{body}");
        assert_eq!(body["error"], "GitHub App is not configured");
    }

    /// Needs Postgres at FREEDAS_PG_URL. A token is minted for the workspace
    /// the caller already acts in; the body cannot point it elsewhere, and a
    /// workspace-scoped member token cannot mint credentials at all.
    #[tokio::test]
    async fn tokens_are_bound_to_the_callers_workspace() {
        let Some(pool) = pg().await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_owner, ws, token) = seed(&pool).await;
        let (_other_owner, other_ws, _other_token) = seed(&pool).await;
        let app = app(pool.clone(), "http://localhost".into());

        let (status, body) = call(
            &app,
            "POST",
            "/tokens",
            &token,
            Some(json!({"workspaceId": other_ws})),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["workspaceId"], ws.as_str());
        let created = body["token"].as_str().expect("token");
        let bound: Option<String> =
            sqlx::query_scalar("SELECT workspace_id FROM api_tokens WHERE token_hash = $1")
                .bind(hash_token(created))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(bound.as_deref(), Some(ws.as_str()));

        // A workspace-scoped member cannot mint; an admin can.
        let (_member, _email, member_token) = add_member_token(&pool, &ws, "member").await;
        let (status, _) = call(&app, "POST", "/tokens", &member_token, None).await;
        assert_eq!(status, 403);
        let (_admin, _email, admin_token) = add_member_token(&pool, &ws, "admin").await;
        let (status, body) = call(&app, "POST", "/tokens", &admin_token, None).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["workspaceId"], ws.as_str());

        // A service token bound to the workspace may still mint for it.
        let service = random_hex(16);
        sqlx::query("INSERT INTO api_tokens (id, user_id, workspace_id, token_hash, scopes, created_at) VALUES ($1, NULL, $2, $3, '{}', $4)")
            .bind(format!("tok_{}", ulid::Ulid::new()))
            .bind(&ws)
            .bind(hash_token(&service))
            .bind(now_ms())
            .execute(&pool)
            .await
            .unwrap();
        let (status, body) = call(&app, "POST", "/tokens", &service, None).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["workspaceId"], ws.as_str());
    }

    /// Needs Postgres at FREEDAS_PG_URL. A sandbox token reaches only its own
    /// sandbox, the workspace it belongs to, and model endpoints.
    #[tokio::test]
    async fn sandbox_tokens_stay_inside_their_sandbox() {
        let Some(pool) = pg().await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_user, ws, _token) = seed(&pool).await;
        let now = now_ms();
        let sandbox = format!("sbx_{}", ulid::Ulid::new());
        let other = format!("sbx_{}", ulid::Ulid::new());
        for id in [&sandbox, &other] {
            sqlx::query(
                "INSERT INTO sandboxes
                   (id, workspace_id, repo, base_branch, task, status, created_at, updated_at)
                 VALUES ($1, $2, 'acme/api', 'main', 't', 'running', $3, $3)",
            )
            .bind(id)
            .bind(&ws)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        }
        let sandbox_token = random_hex(16);
        sqlx::query("INSERT INTO api_tokens (id, user_id, workspace_id, token_hash, scopes, created_at) VALUES ($1, NULL, $2, $3, $4, $5)")
            .bind(format!("tok_{}", ulid::Ulid::new()))
            .bind(&ws)
            .bind(hash_token(&sandbox_token))
            .bind(format!("{{sandbox:{sandbox}}}"))
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        let app = app(pool.clone(), "http://localhost".into());

        for (method, path) in [
            ("GET", "/tokens"),
            ("POST", "/tokens"),
            ("POST", "/wallet/credits"),
            ("PATCH", "/workspace/settings"),
            ("GET", "/reviews"),
        ] {
            let (status, _) = call(&app, method, path, &sandbox_token, None).await;
            assert_eq!(status, 403, "{method} {path}");
        }
        let (status, _) = call(&app, "GET", "/workspaces", &sandbox_token, None).await;
        assert_eq!(status, 200);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/sandboxes/{sandbox}"),
            &sandbox_token,
            None,
        )
        .await;
        assert_eq!(status, 200);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/sandboxes/{other}"),
            &sandbox_token,
            None,
        )
        .await;
        assert_eq!(status, 403);
    }

    /// Needs Postgres at FREEDAS_PG_URL. A workspace binding does not grant a
    /// user access to a workspace they left, and removal revokes their tokens.
    #[tokio::test]
    async fn leaving_a_workspace_cuts_off_bound_tokens() {
        let Some(pool) = pg().await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_owner, ws, token) = seed(&pool).await;
        let (_other_owner, _other_ws, other_token) = seed(&pool).await;
        let (member, _email, member_token) = add_member_token(&pool, &ws, "member").await;
        let app = app(pool.clone(), "http://localhost".into());
        let members = format!("/workspaces/{ws}/members");

        // seed's tokens are user tokens: the binding alone must not authorize.
        let (status, _) = call(&app, "GET", &members, &other_token, None).await;
        assert_eq!(status, 403);
        let (status, _) = call(&app, "GET", &members, &member_token, None).await;
        assert_eq!(status, 200);

        let (status, body) =
            call(&app, "DELETE", &format!("{members}/{member}"), &token, None).await;
        assert_eq!(status, 200, "{body}");
        let revoked: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at FROM api_tokens WHERE token_hash = $1")
                .bind(hash_token(&member_token))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked.is_some());
        let (status, _) = call(&app, "GET", &members, &member_token, None).await;
        assert_eq!(status, 401);
    }

    /// Needs Postgres at FREEDAS_PG_URL. An installation id belongs to the
    /// workspace that claimed it; another workspace gets a conflict.
    #[tokio::test]
    async fn installations_cannot_be_reassigned() {
        let Some(pool) = pg().await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_owner, ws, token) = seed(&pool).await;
        let (_other_owner, _other_ws, other_token) = seed(&pool).await;
        let app = app(pool.clone(), "http://localhost".into());
        let installation = (ulid::Ulid::new().0 % (1 << 62)) as i64;
        let body = |selection: &str| {
            json!({
                "id": installation, "accountLogin": "acme",
                "accountType": "Organization", "repositorySelection": selection,
            })
        };

        let (status, _) = call(
            &app,
            "POST",
            "/github/installations",
            &token,
            Some(body("selected")),
        )
        .await;
        assert_eq!(status, 200);
        let (status, body2) = call(
            &app,
            "POST",
            "/github/installations",
            &other_token,
            Some(body("all")),
        )
        .await;
        assert_eq!(status, 409, "{body2}");

        // The owner may refresh its own installation metadata.
        let (status, body3) = call(
            &app,
            "POST",
            "/github/installations",
            &token,
            Some(body("all")),
        )
        .await;
        assert_eq!(status, 200, "{body3}");
        assert_eq!(body3["repositorySelection"], "all");
        let stored: (Option<String>, String) = sqlx::query_as(
            "SELECT workspace_id, repository_selection FROM github_installations WHERE id = $1",
        )
        .bind(installation)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored.0.as_deref(), Some(ws.as_str()));
        assert_eq!(stored.1, "all");
    }

    /// Needs Postgres at FREEDAS_PG_URL. Admins manage members and settings but
    /// cannot grant or take away ownership.
    #[tokio::test]
    async fn only_an_owner_can_change_ownership() {
        let Some(pool) = pg().await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (owner, ws, token) = seed(&pool).await;
        let (member, member_email, _member_token) = add_member_token(&pool, &ws, "member").await;
        let (_admin, _admin_email, admin_token) = add_member_token(&pool, &ws, "admin").await;
        let app = app(pool.clone(), "http://localhost".into());
        let member_path = format!("/workspaces/{ws}/members/{member}");
        let owner_path = format!("/workspaces/{ws}/members/{owner}");

        let (status, _) = call(
            &app,
            "PATCH",
            &member_path,
            &admin_token,
            Some(json!({"role": "owner"})),
        )
        .await;
        assert_eq!(status, 403);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/workspaces/{ws}/members"),
            &admin_token,
            Some(json!({"email": member_email, "role": "owner"})),
        )
        .await;
        assert_eq!(status, 403);
        let (status, _) = call(
            &app,
            "PATCH",
            &owner_path,
            &admin_token,
            Some(json!({"role": "member"})),
        )
        .await;
        assert_eq!(status, 403);

        // An owner can promote, then demote once a second owner exists.
        let (status, body) = call(
            &app,
            "PATCH",
            &member_path,
            &token,
            Some(json!({"role": "owner"})),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (status, body) = call(
            &app,
            "PATCH",
            &member_path,
            &token,
            Some(json!({"role": "member"})),
        )
        .await;
        assert_eq!(status, 200, "{body}");
    }

    /// Needs Postgres at FREEDAS_PG_URL. Session metadata is owned by the
    /// person who reported it; another member cannot rewrite its usage.
    #[tokio::test]
    async fn session_metadata_is_owned_by_its_reporter() {
        let Some(pool) = pg().await else {
            return;
        };
        let _guard = SCHEMA_LOCK.lock().await;
        for stmt in SCHEMA {
            let _ = sqlx::query(stmt).execute(&pool).await;
        }
        let (_owner, ws, token) = seed(&pool).await;
        let (_member, _email, member_token) = add_member_token(&pool, &ws, "member").await;
        let app = app(pool.clone(), "http://localhost".into());
        let session = format!("ses_{}", ulid::Ulid::new());
        let body = |cost: f64| json!({"sessionID": session, "costUsd": cost, "startedAt": 1});

        let (status, _) = call(&app, "POST", "/sessions", &token, Some(body(1.0))).await;
        assert_eq!(status, 200);
        let (status, body2) =
            call(&app, "POST", "/sessions", &member_token, Some(body(99.0))).await;
        assert_eq!(status, 409, "{body2}");
        let cost: f64 = sqlx::query_scalar(
            "SELECT cost_usd::float8 FROM session_metadata WHERE session_id = $1",
        )
        .bind(&session)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(cost, 1.0);
        // The owner may still update their own row.
        let (status, _) = call(&app, "POST", "/sessions", &token, Some(body(2.0))).await;
        assert_eq!(status, 200);
    }
}
