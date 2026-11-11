//! Server client for `freedas attach`: list sessions and prompt over HTTP.

use reqwest::{Client, RequestBuilder};
use serde_json::Value;

/// Attach the configured server credential to a request. The server enforces
/// auth only when `FREEDAS_SERVER_TOKEN`/`FREEDAS_SERVER_PASSWORD` is set.
fn authorized(builder: RequestBuilder) -> RequestBuilder {
    if let Some(token) = std::env::var("FREEDAS_SERVER_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
    {
        return builder.bearer_auth(token);
    }
    if let Some(password) = std::env::var("FREEDAS_SERVER_PASSWORD")
        .ok()
        .filter(|password| !password.is_empty())
    {
        let user = std::env::var("FREEDAS_SERVER_USERNAME").unwrap_or_else(|_| "freedas".into());
        return builder.basic_auth(user, Some(password));
    }
    builder
}

pub async fn request(
    client: &Client,
    url: &str,
    method: &str,
    json: Option<&Value>,
) -> Result<Value, String> {
    let mut req = authorized(client.request(method.parse().map_err(|e| format!("{e}"))?, url));
    if let Some(body) = json {
        req = req.json(body);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        let status = resp.status();
        // The server answers {"error": "..."}; keep it — a bare code tells
        // the user nothing.
        let text = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str().map(String::from)))
            .unwrap_or(text);
        let detail: String = detail.chars().take(300).collect();
        return Err(format!("http {status}: {detail}"));
    }
    resp.json().await.map_err(|e| e.to_string())
}

pub async fn list_sessions(base: &str) -> Result<Vec<Value>, String> {
    let client = Client::new();
    let url = format!("{base}/session?limit=50");
    let value = request(&client, &url, "GET", None).await?;
    Ok(value.as_array().cloned().unwrap_or_default())
}

pub async fn prompt_session(base: &str, session_id: &str, text: &str) -> Result<Value, String> {
    let client = Client::new();
    let url = format!("{base}/session/{session_id}/message");
    request(
        &client,
        &url,
        "POST",
        Some(&serde_json::json!({"text": text})),
    )
    .await
}

pub async fn stream_events(base: &str, on_event: impl AsyncFn(Value)) -> Result<(), String> {
    use futures::StreamExt;
    let client = Client::new();
    let url = format!("{base}/event");
    let resp = authorized(client.get(&url))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let mut stream = resp.bytes_stream();
    let mut buffer = String::new();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| e.to_string())?;
        buffer.push_str(&String::from_utf8_lossy(&bytes));
        while let Some(idx) = buffer.find("\n\n") {
            let frame = buffer[..idx].to_string();
            buffer.drain(..=idx + 1);
            for line in frame.lines() {
                if let Some(data) = line.strip_prefix("data:")
                    && let Ok(value) = serde_json::from_str::<Value>(data.trim())
                {
                    on_event(value).await;
                }
            }
        }
    }
    Ok(())
}
