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

/// How many times an idempotent request is tried before giving up.
const MAX_ATTEMPTS: u32 = 3;

/// Statuses that mean "try again": a rate limit or a proxy/backend hiccup.
fn transient_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429 | 502 | 503 | 504)
}

fn backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_millis(100 * u64::from(attempt))
}

/// Send one request. A GET is idempotent, so a transient failure is worth
/// another try; a POST is not - a retried prompt could start a second run.
pub async fn request(
    client: &Client,
    url: &str,
    method: &str,
    json: Option<&Value>,
) -> Result<Value, String> {
    let idempotent = method.eq_ignore_ascii_case("GET");
    let mut attempt = 0;
    loop {
        attempt += 1;
        let mut req = authorized(client.request(method.parse().map_err(|e| format!("{e}"))?, url));
        if let Some(body) = json {
            req = req.json(body);
        }
        let resp = match req.send().await {
            Ok(resp) => resp,
            Err(error) => {
                if idempotent && attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(backoff(attempt)).await;
                    continue;
                }
                return Err(error.to_string());
            }
        };
        if resp.status().is_success() {
            return resp.json().await.map_err(|e| e.to_string());
        }
        let status = resp.status();
        let retryable = idempotent && attempt < MAX_ATTEMPTS && transient_status(status.as_u16());
        // The server answers {"error": "..."}; keep it — a bare code tells
        // the user nothing.
        let text = resp.text().await.unwrap_or_default();
        if retryable {
            tokio::time::sleep(backoff(attempt)).await;
            continue;
        }
        let detail = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str().map(String::from)))
            .unwrap_or(text);
        let detail: String = detail.chars().take(300).collect();
        return Err(format!("http {status}: {detail}"));
    }
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
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str().map(String::from)))
            .unwrap_or(text);
        let detail: String = detail.chars().take(300).collect();
        return Err(format!("http {status}: {detail}"));
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A local server that fails the first `failures` requests with 503.
    async fn flaky(failures: usize) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let app = axum::Router::new().route(
            "/x",
            axum::routing::any(move || {
                let counter = counter.clone();
                async move {
                    if counter.fetch_add(1, Ordering::SeqCst) < failures {
                        (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response()
                    } else {
                        (StatusCode::OK, "{\"ok\":true}").into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}/x"), hits)
    }

    #[tokio::test]
    async fn a_get_is_retried_after_a_transient_status() {
        let (url, hits) = flaky(1).await;
        let value = request(&Client::new(), &url, "GET", None)
            .await
            .expect("retried");
        assert_eq!(value["ok"], serde_json::json!(true));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_get_gives_up_after_the_attempt_budget() {
        let (url, hits) = flaky(99).await;
        let error = request(&Client::new(), &url, "GET", None)
            .await
            .expect_err("must fail");
        assert!(error.contains("503"), "got {error}");
        assert_eq!(hits.load(Ordering::SeqCst), MAX_ATTEMPTS as usize);
    }

    #[tokio::test]
    async fn a_post_is_never_retried() {
        let (url, hits) = flaky(1).await;
        let error = request(
            &Client::new(),
            &url,
            "POST",
            Some(&serde_json::json!({"text": "hi"})),
        )
        .await
        .expect_err("must fail");
        assert!(error.contains("503"), "got {error}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_client_error_is_not_retried() {
        let (url, hits) = flaky(0).await;
        let missing = url.replace("/x", "/missing");
        let error = request(&Client::new(), &missing, "GET", None)
            .await
            .expect_err("must fail");
        assert!(error.contains("404"), "got {error}");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "the handler never ran");
    }
}
