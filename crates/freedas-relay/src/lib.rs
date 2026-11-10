//! Relay client: outbound WebSocket connection to a self-hosted relay.
//!
//! Non-loopback URLs must use `wss://`; plain `ws://` is only allowed for
//! loopback hosts (`localhost`, `127.0.0.1`, `::1`) so tokens and transcripts
//! never travel in cleartext. TLS terminates at the reverse proxy.

pub mod daemon;

pub use daemon::{DaemonOptions, start, stop};

use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// Frames larger than this are replaced by a marker event on the wire.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Wire protocol frame, tagged with `type` on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayFrame {
    Hello {
        machine_id: String,
        version: String,
        scope: String,
        token: String,
    },
    Heartbeat {
        ts: i64,
    },
    Event {
        session_id: String,
        seq: u64,
        event: serde_json::Value,
    },
    Prompt {
        session_id: String,
        text: String,
    },
    Abort {
        session_id: String,
    },
    /// Client → server: expose (or stop exposing) a session to the dashboard.
    Share {
        session_id: String,
    },
    Unshare {
        session_id: String,
    },
    /// Client → server: a permission prompt surfaced by the local server.
    /// `session_id` binds the prompt to the session that raised it.
    Permission {
        #[serde(default)]
        session_id: String,
        permission_id: String,
        action: String,
        resource: String,
    },
    /// Server → client: the dashboard's answer to a permission prompt.
    /// `session_id` must match the session that raised the prompt.
    PermissionReply {
        #[serde(default)]
        session_id: String,
        permission_id: String,
        response: String,
    },
    Error {
        message: String,
    },
}

impl RelayFrame {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("relay frame is always serializable")
    }

    pub fn from_json(text: &str) -> Option<Self> {
        serde_json::from_str(text).ok()
    }
}

/// Persistent machine identity, generated once and reused across restarts.
pub fn machine_id() -> String {
    let paths = freedas_core::Paths::resolve(std::env::current_dir().unwrap_or_default());
    machine_id_in(&paths.config_dir)
}

/// Read or create `machine-id` in `dir`; the file is written mode 0600.
pub fn machine_id_in(dir: &Path) -> String {
    let path = dir.join("machine-id");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let id = text.trim();
        if !id.is_empty() {
            return id.to_owned();
        }
    }
    let id = ulid::Ulid::new().to_string();
    let _ = std::fs::create_dir_all(dir);
    let _ = write_private(&path, &id);
    id
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Live relay connection. The socket is driven by two background tasks:
/// one writes queued frames and heartbeats, one pumps decoded frames into
/// the receiving channel.
pub struct RelayConnection {
    outgoing: mpsc::Sender<RelayFrame>,
    incoming: mpsc::Receiver<RelayFrame>,
}

impl RelayConnection {
    pub async fn send(&self, frame: RelayFrame) -> Result<(), String> {
        self.outgoing
            .send(frame)
            .await
            .map_err(|_| "connection closed".to_string())
    }

    /// Cloneable handle for tasks that emit frames while the caller reads.
    pub fn sender(&self) -> mpsc::Sender<RelayFrame> {
        self.outgoing.clone()
    }

    pub async fn next(&mut self) -> Option<RelayFrame> {
        self.incoming.recv().await
    }
}

/// Replace an over-cap event with a marker so the frame stays under the limit.
fn fit_frame(frame: RelayFrame) -> RelayFrame {
    let text = frame.to_json();
    if text.len() <= MAX_FRAME {
        return frame;
    }
    match frame {
        RelayFrame::Event {
            session_id, seq, ..
        } => RelayFrame::Event {
            session_id,
            seq,
            event: serde_json::json!({ "type": "event.truncated", "bytes": text.len() }),
        },
        other => other,
    }
}

pub async fn connect(url: &str, token: &str, machine_id: &str) -> Result<RelayConnection, String> {
    connect_scoped(url, token, machine_id, "machine").await
}

/// Reject cleartext `ws://` to non-loopback hosts. `wss://` is always allowed;
/// `ws://` is only allowed for loopback hosts used by local tests and dev.
fn check_url(url: &str) -> Result<(), String> {
    if url.starts_with("wss://") {
        return Ok(());
    }
    if !url.starts_with("ws://") {
        return Err("relay url must start with wss:// or ws://".to_string());
    }
    let after = &url["ws://".len()..];
    let host = after
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.split(']').next())
        .unwrap_or_else(|| host.split(':').next().unwrap_or_default());
    if host == "localhost"
        || host == "::1"
        || host == "0:0:0:0:0:0:0:1"
        || host == "127.0.0.1"
        || host.starts_with("127.")
    {
        Ok(())
    } else {
        Err("relay requires wss:// for non-loopback hosts".to_string())
    }
}

/// Connect and announce the exposure `scope` (`machine` or `session`).
pub async fn connect_scoped(
    url: &str,
    token: &str,
    machine_id: &str,
    scope: &str,
) -> Result<RelayConnection, String> {
    if scope != "machine" && scope != "session" {
        return Err("unknown relay scope".to_string());
    }
    check_url(url)?;
    let (ws, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|err| match err {
            tokio_tungstenite::tungstenite::Error::Http(response)
                if matches!(response.status().as_u16(), 401 | 403) =>
            {
                "forbidden".to_string()
            }
            other => other.to_string(),
        })?;
    let (mut sink, mut stream) = ws.split();

    let hello = RelayFrame::Hello {
        machine_id: machine_id.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        scope: scope.to_owned(),
        token: token.to_owned(),
    };
    sink.send(Message::Text(hello.to_json().into()))
        .await
        .map_err(|err| err.to_string())?;

    let (outgoing, mut outgoing_rx) = mpsc::channel::<RelayFrame>(256);
    let (incoming_tx, incoming) = mpsc::channel::<RelayFrame>(256);

    tokio::spawn(async move {
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        heartbeat.tick().await; // the first tick is immediate
        loop {
            let frame = tokio::select! {
                _ = heartbeat.tick() => RelayFrame::Heartbeat {
                    ts: freedas_core::paths::now_ms(),
                },
                frame = outgoing_rx.recv() => match frame {
                    Some(frame) => frame,
                    None => break,
                },
            };
            let frame = fit_frame(frame);
            let text = frame.to_json();
            if text.len() > MAX_FRAME {
                continue;
            }
            if sink.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        while let Some(message) = stream.next().await {
            let text = match message {
                Ok(Message::Text(text)) => text.as_str().to_owned(),
                Ok(Message::Binary(bytes)) => match String::from_utf8(bytes.to_vec()) {
                    Ok(text) => text,
                    Err(_) => continue,
                },
                Ok(Message::Close(_)) | Err(_) => break,
                _ => continue,
            };
            if let Some(frame) = RelayFrame::from_json(&text)
                && incoming_tx.send(frame).await.is_err()
            {
                break;
            }
        }
    });

    Ok(RelayConnection { outgoing, incoming })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_json() {
        let frames = [
            RelayFrame::Hello {
                machine_id: "01AN4Z07BY79KA1307SR9X4MV3".into(),
                version: "0.1.0".into(),
                scope: "machine".into(),
                token: "secret".into(),
            },
            RelayFrame::Heartbeat {
                ts: 1_760_000_000_000,
            },
            RelayFrame::Event {
                session_id: "ses_1".into(),
                seq: 7,
                event: serde_json::json!({ "type": "message.part.updated" }),
            },
            RelayFrame::Prompt {
                session_id: "ses_1".into(),
                text: "run the tests".into(),
            },
            RelayFrame::Abort {
                session_id: "ses_1".into(),
            },
            RelayFrame::Share {
                session_id: "ses_1".into(),
            },
            RelayFrame::Unshare {
                session_id: "ses_1".into(),
            },
            RelayFrame::Permission {
                session_id: "ses_1".into(),
                permission_id: "perm_1".into(),
                action: "bash".into(),
                resource: "git push".into(),
            },
            RelayFrame::PermissionReply {
                session_id: "ses_1".into(),
                permission_id: "perm_1".into(),
                response: "once".into(),
            },
            RelayFrame::Error {
                message: "boom".into(),
            },
        ];
        for frame in frames {
            assert_eq!(RelayFrame::from_json(&frame.to_json()), Some(frame));
        }
    }

    #[test]
    fn frames_are_tagged_by_type() {
        let json = RelayFrame::Heartbeat { ts: 1 }.to_json();
        assert!(json.contains(r#""type":"heartbeat""#), "got {json}");
        assert!(RelayFrame::from_json("{").is_none());
        assert!(RelayFrame::from_json(r#"{"type":"nope"}"#).is_none());
    }

    #[test]
    fn machine_id_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let first = machine_id_in(dir.path());
        let second = machine_id_in(dir.path());
        assert_eq!(first, second);
        assert_eq!(first.len(), 26, "expected a ULID, got {first}");
    }

    #[cfg(unix)]
    #[test]
    fn machine_id_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        machine_id_in(dir.path());
        let mode = std::fs::metadata(dir.path().join("machine-id"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
