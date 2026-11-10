//! Shared types: configuration, paths, IDs, errors, events, redaction.

pub mod config;
pub mod error;
pub mod event;
pub mod id;
pub mod paths;
pub mod redact;

pub use config::{
    Config, MemoryConfig, PermissionConfig, RouterConfig, SandboxConfig, StandardsConfig,
};
pub use error::FreedasError;
pub use id::{MessageId, PartId, SessionId};
pub use paths::Paths;

pub type Result<T, E = FreedasError> = std::result::Result<T, E>;
