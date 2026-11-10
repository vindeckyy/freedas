use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub id: u64,
    pub timestamp: i64,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}

impl Event {
    pub fn new(id: u64, event_type: impl Into<String>) -> Self {
        Self {
            id,
            timestamp: crate::paths::now_ms(),
            event_type: event_type.into(),
            session_id: None,
            properties: None,
        }
    }

    pub fn session(id: u64, event_type: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            id,
            timestamp: crate::paths::now_ms(),
            event_type: event_type.into(),
            session_id: Some(session_id.into()),
            properties: None,
        }
    }
}
