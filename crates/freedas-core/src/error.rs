use thiserror::Error;

#[derive(Debug, Error)]
pub enum FreedasError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("SQLite: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("provider: {0}")]
    Provider(String),
    #[error("permission denied: {action} {resource}")]
    PermissionDenied { action: String, resource: String },
    #[error("permission asked: {action} {resource}")]
    PermissionAsked { action: String, resource: String },
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("stale read: {0} changed on disk")]
    StaleRead(String),
    #[error("budget exceeded")]
    BudgetExceeded,
    #[error("sandbox unavailable: {0}")]
    SandboxUnavailable(String),
    #[error("cancelled")]
    Cancelled,
    #[error("tool error: {0}")]
    Tool(String),
    #[error("{0}")]
    Other(String),
}
