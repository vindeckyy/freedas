//! Live relay loop: a real relay server, a real daemon, and dashboard calls.

use std::time::Duration;

use freedas_core::Paths;
use freedas_relay::{DaemonOptions, RelayFrame, machine_id_in};
use freedas_relay_server::app;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

struct Fixture {
    dir: tempfile::TempDir,
    paths: Paths,
    session_id: String,
    addr: std::net::SocketAddr,
    token: String,
}

impl Fixture {
    fn url(&self) -> String {
        format!("ws://{}/ws", self.addr)
    }

    fn http(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

async fn fixture() -> Fixture {
    // The daemon runs the session runner; keep it offline and deterministic.
    unsafe {
        std::env::set_var("FREEDAS_TEST_PROVIDER", "fake");
    }
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let paths = Paths {
        home: dir.path().join("home"),
        config_dir: dir.path().join("config"),
        data_dir: dir.path().join("data"),
        state_dir: dir.path().join("state"),
        cache_dir: dir.path().join("cache"),
        bin_dir: dir.path().join("bin"),
        project_root: project.clone(),
    };
    std::fs::create_dir_all(&paths.data_dir).unwrap();
    std::fs::create_dir_all(&paths.state_dir).unwrap();

    let db = freedas_db::Db::open(&paths.db_path()).unwrap();
    let project_id = db.ensure_project(&project).unwrap();
    let session_id = db
        .create_session(&project_id, "build", "relay fixture", None)
        .unwrap();
    let message_id = db.add_message(&session_id, "user", &json!({})).unwrap();
    db.add_part(
        &session_id,
        &message_id,
        0,
        "text",
        &json!({ "text": "fixture message" }),
    )
    .unwrap();
    drop(db);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = "relay-secret".to_owned();
    let server_token = token.clone();
    tokio::spawn(async move {
        axum::serve(listener, app(server_token)).await.unwrap();
    });

    Fixture {
        dir,
        paths,
        session_id,
        addr,
        token,
    }
}

fn dashboard_client(token: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}

async fn dashboard_socket(
    fixture: &Fixture,
    machine_id: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let (mut socket, _) = tokio_tungstenite::connect_async(fixture.url())
        .await
        .unwrap();
    let hello = RelayFrame::Hello {
        machine_id: machine_id.to_owned(),
        version: "0.1.0".into(),
        scope: "machine".into(),
        token: fixture.token.clone(),
    };
    socket
        .send(Message::Text(hello.to_json().into()))
        .await
        .unwrap();
    socket
}

async fn poll_json(client: &reqwest::Client, url: &str, needle: &str) -> Value {
    for _ in 0..40 {
        let body = client.get(url).send().await.unwrap().text().await.unwrap();
        if body.contains(needle) {
            return serde_json::from_str(&body).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("{url} never contained {needle}");
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_registers_and_accepts_dashboard_prompts() {
    let fixture = fixture().await;
    let client = dashboard_client(&fixture.token);
    let machine_id = machine_id_in(&fixture.paths.state_dir);

    let daemon_paths = fixture.paths.clone();
    let daemon_url = fixture.url();
    let daemon_token = fixture.token.clone();
    tokio::spawn(async move {
        freedas_relay::start(DaemonOptions {
            url: daemon_url,
            token: daemon_token,
            paths: daemon_paths,
        })
        .await
        .unwrap();
    });

    let pid_path = fixture.paths.state_dir.join("relay.pid");
    for _ in 0..40 {
        if pid_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let pid = std::fs::read_to_string(&pid_path).expect("daemon writes a pid file");
    assert_eq!(pid.trim(), std::process::id().to_string());

    let machines = poll_json(&client, &fixture.http("/machines"), &machine_id).await;
    let entry = machines
        .as_array()
        .unwrap()
        .iter()
        .find(|machine| machine["machineID"] == machine_id.as_str())
        .unwrap();
    assert_eq!(entry["scope"], "machine");

    let sessions = poll_json(&client, &fixture.http("/sessions"), &fixture.session_id).await;
    let session = sessions
        .as_array()
        .unwrap()
        .iter()
        .find(|session| session["sessionID"] == fixture.session_id.as_str())
        .unwrap();
    assert_eq!(session["machineID"], machine_id.as_str());

    let response = client
        .post(fixture.http(&format!("/sessions/{}/prompt", fixture.session_id)))
        .json(&json!({ "text": "hello from the dashboard" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let abort = client
        .post(fixture.http(&format!("/sessions/{}/abort", fixture.session_id)))
        .send()
        .await
        .unwrap();
    assert_eq!(abort.status(), reqwest::StatusCode::OK);

    let missing = client
        .post(fixture.http("/sessions/ses_missing/prompt"))
        .json(&json!({ "text": "nobody home" }))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);

    // The prompt must have reached the daemon: it echoes it as a relay
    // event on the dashboard SSE stream (machines no longer receive the
    // broadcast — the dashboard channel is the only subscriber).
    let mut seen_prompt = false;
    let mut sse = client
        .get(fixture.http(&format!(
            "/events?session_id={}",
            fixture.session_id
        )))
        .send()
        .await
        .unwrap();
    'outer: for _ in 0..80 {
        let chunk = match tokio::time::timeout(Duration::from_millis(500), sse.chunk()).await {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => break,
            _ => continue,
        };
        for line in String::from_utf8_lossy(&chunk).lines() {
            let Some(data) = line.strip_prefix("data: ") else {
                continue;
            };
            let Ok(frame) = serde_json::from_str::<Value>(data) else {
                continue;
            };
            if frame["event"]["type"] == "relay.prompt"
                && frame["event"]["text"] == "hello from the dashboard"
            {
                seen_prompt = true;
                break 'outer;
            }
        }
    }
    assert!(seen_prompt, "daemon never received the dashboard prompt");

    drop(fixture.dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_frames_are_rejected() {
    let fixture = fixture().await;
    let dash = dashboard_socket(&fixture, "big-machine").await;
    let mut dash = dash;
    let huge = "x".repeat(freedas_relay::MAX_FRAME + 64);
    let big_event = RelayFrame::Event {
        session_id: "ses_big".into(),
        seq: 1,
        event: json!({ "type": "message.part.updated", "blob": huge }),
    };
    dash.send(Message::Text(big_event.to_json().into()))
        .await
        .unwrap();
    let mut rejected = false;
    for _ in 0..20 {
        let Ok(Some(Ok(Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(500), dash.next()).await
        else {
            continue;
        };
        if let Some(RelayFrame::Error { message }) = RelayFrame::from_json(text.as_str())
            && message == "frame too large"
        {
            rejected = true;
            break;
        }
    }
    assert!(rejected, "server must reject frames over the cap");
    drop(fixture.dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_signals_the_daemon_and_clears_state() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let paths = Paths {
        home: dir.path().join("home"),
        config_dir: dir.path().join("config"),
        data_dir: dir.path().join("data"),
        state_dir: state_dir.clone(),
        cache_dir: dir.path().join("cache"),
        bin_dir: dir.path().join("bin"),
        project_root: dir.path().to_path_buf(),
    };
    let mut child = tokio::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    std::fs::write(state_dir.join("relay.pid"), child.id().unwrap().to_string()).unwrap();
    std::fs::write(
        state_dir.join("relay.json"),
        json!({ "running": true, "scope": "machine" }).to_string(),
    )
    .unwrap();

    freedas_relay::stop(&paths).unwrap();

    let exited = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("daemon should be signalled")
        .unwrap();
    assert!(!exited.success(), "SIGTERM should end the process");
    assert!(!state_dir.join("relay.pid").exists());
    assert!(!state_dir.join("relay.json").exists());
    child.kill().await.expect("child already waited");
}
