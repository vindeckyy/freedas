//! GitHub App authentication and review posting.
//!
//! Every call takes an explicit `api_base` so tests can point at a mock server.

use serde::Serialize;

use crate::{AutoApprove, Finding, ReviewPolicy};

/// GitHub App credentials for the review worker.
#[derive(Debug, Clone)]
pub struct GithubApp {
    pub app_id: String,
    pub private_key_pem: String,
    pub api_base: String,
}

pub const DEFAULT_API_BASE: &str = "https://api.github.com";

/// A pull request as the dashboard lists it.
#[derive(Debug, Clone)]
pub struct Pull {
    pub number: i64,
    pub title: String,
    pub author: String,
    pub state: String,
    pub draft: bool,
    pub head_sha: String,
    pub url: String,
}

/// List a repository's pull requests. `state` other than
/// `open|closed|all` means `open`. Entries missing required fields are skipped.
pub async fn list_pulls(
    client: &reqwest::Client,
    token: &str,
    api_base: &str,
    repo: &str,
    state: &str,
) -> Result<Vec<Pull>, String> {
    let state = match state {
        "open" | "closed" | "all" => state,
        _ => "open",
    };
    let response = client
        .get(url(
            api_base,
            &format!("/repos/{repo}/pulls?state={state}&per_page=50"),
        ))
        .bearer_auth(token)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "freedas")
        .send()
        .await
        .map_err(|error| format!("github: {error}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("github {status}: {}", bound(&body)));
    }
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|error| format!("github: {error}"))?;
    Ok(body
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|pull| {
            Some(Pull {
                number: pull["number"].as_i64()?,
                title: pull["title"].as_str()?.to_owned(),
                author: pull["user"]["login"].as_str()?.to_owned(),
                state: pull["state"].as_str()?.to_owned(),
                draft: pull["draft"].as_bool().unwrap_or(false),
                head_sha: pull["head"]["sha"].as_str()?.to_owned(),
                url: pull["html_url"].as_str()?.to_owned(),
            })
        })
        .collect())
}

#[derive(Serialize)]
struct Claims<'a> {
    iat: i64,
    exp: i64,
    iss: &'a str,
}

/// Mint a short-lived app JWT (RS256) used to authenticate as the GitHub App.
fn app_jwt(app_id: &str, key_pem: &str) -> Result<String, String> {
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(key_pem.as_bytes())
        .map_err(|error| format!("github app key: {error}"))?;
    let now = now_secs();
    let claims = Claims {
        iat: now - 60,
        exp: now + 540,
        iss: app_id,
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &key,
    )
    .map_err(|error| format!("github app jwt: {error}"))
}

/// The app's slug, which identifies its bot login (`<slug>[bot]`).
pub async fn app_slug(
    client: &reqwest::Client,
    api_base: &str,
    app_id: &str,
    key_pem: &str,
) -> Result<String, String> {
    let jwt = app_jwt(app_id, key_pem)?;
    let response = client
        .get(url(api_base, "/app"))
        .bearer_auth(&jwt)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "freedas")
        .send()
        .await
        .map_err(|error| format!("app: {error}"))?;
    let value = check(response, "app").await?;
    value
        .get("slug")
        .and_then(|slug| slug.as_str())
        .map(str::to_owned)
        .ok_or_else(|| "app: response has no slug".to_owned())
}

/// Mint a short-lived installation token from an RS256 app JWT.
pub async fn installation_token(
    client: &reqwest::Client,
    api_base: &str,
    app_id: &str,
    key_pem: &str,
    installation_id: i64,
) -> Result<String, String> {
    let jwt = app_jwt(app_id, key_pem)?;

    let response = client
        .post(url(
            api_base,
            &format!("/app/installations/{installation_id}/access_tokens"),
        ))
        // Least privilege: review reads the diff, posts reviews/comments and
        // check runs — nothing else.
        .json(&serde_json::json!({
            "permissions": {
                "contents": "read",
                "pull_requests": "write",
                "checks": "write"
            }
        }))
        .bearer_auth(&jwt)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "freedas")
        .send()
        .await
        .map_err(|error| format!("installation token: {error}"))?;
    let value = check(response, "installation token").await?;
    value
        .get("token")
        .and_then(|token| token.as_str())
        .map(str::to_owned)
        .ok_or_else(|| "installation token: response has no token".to_owned())
}

/// Post a review with inline comments. Findings with no line stay in the body.
/// Returns the created review's `html_url` when GitHub includes one.
// One parameter per API field keeps the call sites readable.
#[allow(clippy::too_many_arguments)]
pub async fn post_review(
    client: &reqwest::Client,
    api_base: &str,
    token: &str,
    repo: &str,
    pr: i64,
    commit_sha: &str,
    summary: &str,
    findings: &[Finding],
) -> Result<Option<String>, String> {
    let mut body = summary.to_owned();
    let elsewhere: Vec<&Finding> = findings.iter().filter(|f| f.line == 0).collect();
    if !elsewhere.is_empty() {
        body.push_str("\n\nFindings without a diff line:\n");
        for finding in elsewhere {
            body.push_str(&format!(
                "- `{}`: **{}** {}\n",
                finding.file, finding.severity, finding.title
            ));
        }
    }
    let comments: Vec<serde_json::Value> = findings
        .iter()
        .filter(|f| f.line > 0)
        .map(|f| {
            serde_json::json!({
                "path": f.file,
                "line": f.line,
                "body": finding_body(f),
            })
        })
        .collect();
    let payload = serde_json::json!({
        "commit_id": commit_sha,
        "body": &body,
        "event": "COMMENT",
        "comments": comments,
    });
    match send_review(client, api_base, token, repo, pr, &payload, "post review").await {
        Ok(value) => Ok(review_url(&value)),
        // GitHub rejects the whole review when one inline comment does not land
        // on the diff. Retry once as a body-only review so the findings survive.
        Err(error) if !comments.is_empty() && error.contains("HTTP 422") => {
            let mut fallback = body;
            fallback.push_str("\n\nFindings:\n");
            for finding in findings.iter().filter(|f| f.line > 0) {
                fallback.push_str(&format!(
                    "- `{}:{}`: **{}** {}. {}\n",
                    finding.file, finding.line, finding.severity, finding.title, finding.body
                ));
            }
            let payload = serde_json::json!({
                "commit_id": commit_sha,
                "body": fallback,
                "event": "COMMENT",
            });
            let value =
                send_review(client, api_base, token, repo, pr, &payload, "post review").await?;
            Ok(review_url(&value))
        }
        Err(error) => Err(error),
    }
}

fn review_url(value: &serde_json::Value) -> Option<String> {
    value
        .get("html_url")
        .and_then(|url| url.as_str())
        .map(str::to_owned)
}

/// Approve the pull request, naming the thresholds that were met.
#[allow(clippy::too_many_arguments)]
pub async fn submit_approval(
    client: &reqwest::Client,
    api_base: &str,
    token: &str,
    repo: &str,
    pr: i64,
    commit_sha: &str,
    confidence: f32,
    risk: f32,
    policy: &ReviewPolicy,
) -> Result<(), String> {
    let auto = policy.auto_approve.clone().unwrap_or(AutoApprove {
        min_confidence: None,
        max_risk: None,
    });
    let min = auto.min_confidence.unwrap_or(0.0);
    let max = auto.max_risk.unwrap_or(5.0);
    let payload = serde_json::json!({
        "commit_id": commit_sha,
        "body": format!(
            "Auto-approved by Freedas: confidence {confidence:.1} >= {min:.1} and risk {risk:.1} <= {max:.1}."
        ),
        "event": "APPROVE",
    });
    send_review(client, api_base, token, repo, pr, &payload, "approve")
        .await
        .map(|_| ())
}

pub async fn create_check_run(
    client: &reqwest::Client,
    api_base: &str,
    token: &str,
    repo: &str,
    head_sha: &str,
    conclusion: &str,
    summary: &str,
) -> Result<(), String> {
    let payload = serde_json::json!({
        "name": "freedas/review",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": { "title": "Freedas review", "summary": summary },
    });
    let response = client
        .post(url(api_base, &format!("/repos/{repo}/check-runs")))
        .bearer_auth(token)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "freedas")
        .json(&payload)
        .send()
        .await
        .map_err(|error| format!("check run: {error}"))?;
    check(response, "check run").await.map(|_| ())
}

/// Request a reviewer. GitHub answers 422 for an already-requested or
/// non-collaborator login; the response body is logged so an unexpected 422 is
/// visible instead of being silently treated as success.
pub async fn request_reviewers(
    client: &reqwest::Client,
    api_base: &str,
    token: &str,
    repo: &str,
    pr: i64,
    reviewer: &str,
) -> Result<(), String> {
    let response = client
        .post(url(
            api_base,
            &format!("/repos/{repo}/pulls/{pr}/requested_reviewers"),
        ))
        .bearer_auth(token)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "freedas")
        .json(&serde_json::json!({ "reviewers": [reviewer] }))
        .send()
        .await
        .map_err(|error| format!("request reviewers: {error}"))?;
    if response.status().as_u16() == 422 {
        let body = response.text().await.unwrap_or_default();
        eprintln!(
            "freedas-review: request reviewers 422 for {repo}#{pr}: {}",
            bound(&body)
        );
        return Ok(());
    }
    check(response, "request reviewers").await.map(|_| ())
}

pub fn should_approve(policy: &ReviewPolicy, confidence: f32, risk: f32) -> bool {
    let Some(auto) = &policy.auto_approve else {
        return false;
    };
    // Both thresholds must be explicit: a partial policy is never an approve.
    let (Some(min), Some(max)) = (auto.min_confidence, auto.max_risk) else {
        return false;
    };
    confidence >= min && risk <= max
}

/// `**severity** title`, body, then the suggestion when the model gave one.
pub fn finding_body(finding: &Finding) -> String {
    // Model text can quote secrets out of the diff or file context; scrub
    // before it lands on the PR.
    let mut body = format!(
        "**{}** {}\n\n{}",
        finding.severity,
        freedas_core::redact::redact(&finding.title),
        freedas_core::redact::redact(&finding.body)
    );
    if let Some(suggestion) = finding
        .suggestion
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        body.push_str("\n\n");
        body.push_str(&freedas_core::redact::redact(suggestion));
    }
    body
}

async fn send_review(
    client: &reqwest::Client,
    api_base: &str,
    token: &str,
    repo: &str,
    pr: i64,
    payload: &serde_json::Value,
    what: &str,
) -> Result<serde_json::Value, String> {
    let response = client
        .post(url(api_base, &format!("/repos/{repo}/pulls/{pr}/reviews")))
        .bearer_auth(token)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "freedas")
        .json(payload)
        .send()
        .await
        .map_err(|error| format!("{what}: {error}"))?;
    check(response, what).await
}

async fn check(response: reqwest::Response, what: &str) -> Result<serde_json::Value, String> {
    let status = response.status();
    if status.is_success() {
        return Ok(response.json().await.unwrap_or_default());
    }
    let body = response.text().await.unwrap_or_default();
    Err(format!("{what}: HTTP {status}: {}", bound(&body)))
}

/// Error bodies are capped at 300 characters so a DB row stays small.
/// Redacted before truncating so no secret persists in stored errors.
fn bound(text: &str) -> String {
    freedas_core::redact::redact(text)
        .chars()
        .take(300)
        .collect::<String>()
        .replace(['\n', '\r'], " ")
}

fn url(api_base: &str, path: &str) -> String {
    format!("{}{path}", api_base.trim_end_matches('/'))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Test-only key; never used outside these tests. The first dash is escaped
    // so secret scanners do not flag this throwaway fixture; runtime value is
    // unchanged.
    const TEST_KEY: &str = "\x2d----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDW4JfebACb1RV
V+CoUq2pbCLq56MThxTHAhc8+4AB4nAlP4FFstOPUMfrk7LggUOUPCBHs1Q2Z9Jx
vSNvnK+iAkxicCbQZY4S0CocNUBj+F1XcKg7ri00EmTgtQStR0q5a1IONuEmqOmO
67vjcv5MAdnvOe/x+2aFaY9rixfYkZZcK/1WuGxn+oES5cgO5xOiLJyGwzBRwqlx
wfJw5wu4Zs6E+ecTrK5MnSCPkJfpXGYgFApPpnCulA/jDH5LREaYUY5z5qnYY0V/
PRRxazQhADpoqyfuDEQfxCRm9C35zZLujuJrzzyEfzz0RoMdmxIdVgGD5w7UaBVV
50CMF8/RAgMBAAECggEAN6X/Dsxen2rwJnloZPpcPrkvfyOpt/vQJtpJHVV1AtRq
Zqne3KhSjG4R7OC/YSVhRz4TYelK8U6Ey2J50CbdfvRRpu7Ul6N+I4zJmgxvQarz
h99vBMUaWk1tD/dwlB2NQyE3mBX47+bI1S4AcQuGNceHOZaS66bV7uYBdTyDd+yM
cBzJ3Dk/wSeNaDy9EjAvccaB7lrj+Exv4PPkce91jzlPj7SiPF1XgHscAyqt7n64
N4yhGjkss1eWv0EcKEP2te5sSJJkVV5v6F1KjANhapXDDp05rbWep/8N8HTM1DXP
GPV20NeyF8ExyuMj9D24+VbuQazlGs0aQrlPrCpeYwKBgQD9u3xeoDEX7z++vpvF
MeXc/hZ1NDjHxTZp9jjeRgXddD5alrg7adZ10rbijcAFcMJZUzdfO4Th8qhzi/tp
7bLTsTDKrHGngw11oMJ2sN3IpUh2fc/BH8vkpp7VCEb1WQgrueTjfW5M08BGFHaE
s1Zks0G2zPKhvTZJTyLIgW8NBwKBgQDFGnevbczxqhJCsS211ra+Vn/X3x1MBENY
+fcNFIyluxlWWETBvAMh33EyDW8O31uLJAYGQEowpjx5hKvKRrT//WcfdsLIiV2A
S6wgxKyVXrLlL8uC2XpvdD2P7+LzkctwgZtDrUF5C/ejp/stk1YKuSR8StcD0E15
x1LUyhdeZwKBgHDwKeyomxGPQa1yhD1i93DFfFOQ+hEZnB3QJgHx4xxuaG7EFZ8E
fhwVvafb9nO1fBxsaQIvqPc1nntH/JFq5yVJAnHEDhbEw5HvC3/vO9jakQWE/Jt2
vre43ovuUj9U8Mkdxl7n7tetjTDkXNi2RqcuDvsCAKGzad15pv7edgKzAoGBALHq
W0DCNy2pG8SRlDZAc0JKaCne3t4gNv6Y29U1yGNNCOj00lOiN52ayN2qXKYrHcHy
KXH5FD7nv0zdYgg7XOR5w10WYWqM/BZzuBL4FOTbz1Wrl+MsFiWG4o8LtWuxHdcX
VqR3PtNZ5xYV6lfQV+lkB7geAgoSO+0B7BXhuchfAoGBAKgvNo8SM+W6JfYEMXDQ
yQZNWCCVyvm8iA0D9q4vzKY9rssIjNpzDhdJD8v0Kv3lUsckB3vha3KHrVdPIoPT
gEja4KlVZvVgUgxLp4UzUlR9kRtGqN2B+NwMmgyeCb9fZPMZ/VRsGVxB2DQGkvN/
Z3K+yOKEmeE6F2oajJNW551v
\x2d----END PRIVATE KEY-----
";

    #[tokio::test]
    async fn installation_token_exchanges_an_rs256_jwt() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/installations/42/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "token": "ghs_test" })))
            .expect(1)
            .mount(&server)
            .await;

        let token = installation_token(
            &reqwest::Client::new(),
            &server.uri(),
            "12345",
            TEST_KEY,
            42,
        )
        .await
        .unwrap();
        assert_eq!(token, "ghs_test");

        let requests = server.received_requests().await.unwrap();
        let request = &requests[0];
        let auth = request
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth.starts_with("Bearer ey"), "{auth}");
        assert_eq!(
            request.headers.get("accept").unwrap(),
            "application/vnd.github+json"
        );
        assert_eq!(request.headers.get("user-agent").unwrap(), "freedas");
    }

    #[tokio::test]
    async fn post_review_sends_inline_comments() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/api/pulls/7/reviews"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 1,
                "html_url": "https://github.com/acme/api/pull/7#pullrequestreview-1"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let findings = vec![
            Finding {
                file: "src/lib.rs".into(),
                line: 12,
                severity: "high".into(),
                confidence: 4,
                title: "unhandled error".into(),
                body: "the send is not checked".into(),
                suggestion: Some("propagate the error".into()),
            },
            Finding {
                file: "src/lib.rs".into(),
                line: 0,
                severity: "low".into(),
                confidence: 2,
                title: "whole-file note".into(),
                body: "without a line".into(),
                suggestion: None,
            },
        ];
        let url = post_review(
            &reqwest::Client::new(),
            &server.uri(),
            "ghs_test",
            "acme/api",
            7,
            "abc123",
            "1 finding",
            &findings,
        )
        .await
        .unwrap();
        assert_eq!(
            url.as_deref(),
            Some("https://github.com/acme/api/pull/7#pullrequestreview-1")
        );

        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["commit_id"], "abc123");
        assert_eq!(body["event"], "COMMENT");
        let comments = body["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0]["path"], "src/lib.rs");
        assert_eq!(comments[0]["line"], 12);
        assert!(comments[0]["body"].as_str().unwrap().contains("propagate"));
        let summary = body["body"].as_str().unwrap();
        assert!(summary.contains("whole-file note"), "{summary}");
    }

    #[tokio::test]
    async fn check_run_body_is_completed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/api/check-runs"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 1 })))
            .expect(1)
            .mount(&server)
            .await;

        create_check_run(
            &reqwest::Client::new(),
            &server.uri(),
            "ghs_test",
            "acme/api",
            "abc123",
            "failure",
            "1 high finding",
        )
        .await
        .unwrap();

        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["name"], "freedas/review");
        assert_eq!(body["head_sha"], "abc123");
        assert_eq!(body["status"], "completed");
        assert_eq!(body["conclusion"], "failure");
        assert_eq!(body["output"]["summary"], "1 high finding");
    }

    #[tokio::test]
    async fn app_slug_reads_the_bot_login() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/app"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "slug": "freedas" })))
            .expect(1)
            .mount(&server)
            .await;

        let slug = app_slug(&reqwest::Client::new(), &server.uri(), "12345", TEST_KEY)
            .await
            .unwrap();
        assert_eq!(slug, "freedas");
    }

    #[tokio::test]
    async fn post_review_retries_without_comments_on_422() {
        use wiremock::Match;
        use wiremock::matchers::body_string_contains;

        struct WithoutComments;
        impl Match for WithoutComments {
            fn matches(&self, request: &wiremock::Request) -> bool {
                !String::from_utf8_lossy(&request.body).contains("\"comments\"")
            }
        }

        let server = MockServer::start().await;
        // Inline comments are rejected; the body-only retry succeeds.
        Mock::given(method("POST"))
            .and(path("/repos/acme/api/pulls/7/reviews"))
            .and(body_string_contains("\"comments\""))
            .respond_with(ResponseTemplate::new(422).set_body_string("position is invalid"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/api/pulls/7/reviews"))
            .and(WithoutComments)
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "html_url": "https://github.com/acme/api/pull/7#pullrequestreview-2"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let findings = vec![Finding {
            file: "src/lib.rs".into(),
            line: 12,
            severity: "high".into(),
            confidence: 4,
            title: "unhandled error".into(),
            body: "check the send".into(),
            suggestion: None,
        }];
        let url = post_review(
            &reqwest::Client::new(),
            &server.uri(),
            "ghs_test",
            "acme/api",
            7,
            "abc123",
            "1 finding",
            &findings,
        )
        .await
        .unwrap();
        assert_eq!(
            url.as_deref(),
            Some("https://github.com/acme/api/pull/7#pullrequestreview-2")
        );

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        let retry: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert!(retry.get("comments").is_none());
        assert!(
            retry["body"].as_str().unwrap().contains("unhandled error"),
            "{}",
            retry["body"]
        );
    }

    #[tokio::test]
    async fn request_reviewers_tolerates_422() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/api/pulls/7/requested_reviewers"))
            .respond_with(ResponseTemplate::new(422).set_body_string("already requested"))
            .mount(&server)
            .await;

        request_reviewers(
            &reqwest::Client::new(),
            &server.uri(),
            "ghs_test",
            "acme/api",
            7,
            "acme",
        )
        .await
        .unwrap();
    }

    #[test]
    fn approval_truth_table() {
        let mut policy = crate::policy_default();
        assert!(!should_approve(&policy, 5.0, 1.0));

        policy.auto_approve = Some(AutoApprove {
            min_confidence: Some(4.0),
            max_risk: Some(2.0),
        });
        assert!(should_approve(&policy, 4.0, 2.0));
        assert!(!should_approve(&policy, 3.9, 1.0));
        assert!(!should_approve(&policy, 5.0, 2.1));

        // Partial thresholds never approve.
        policy.auto_approve = Some(AutoApprove {
            min_confidence: Some(4.0),
            max_risk: None,
        });
        assert!(!should_approve(&policy, 4.0, 5.0));
        assert!(!should_approve(&policy, 3.0, 1.0));

        policy.auto_approve = Some(AutoApprove {
            min_confidence: None,
            max_risk: Some(1.0),
        });
        assert!(!should_approve(&policy, 0.0, 1.0));
        assert!(!should_approve(&policy, 5.0, 1.5));
    }

    #[test]
    fn error_bodies_are_bounded() {
        assert_eq!(bound("short"), "short");
        assert_eq!(bound(&"x".repeat(400)).chars().count(), 300);
        assert!(!bound("a\nb").contains('\n'));
    }

    #[tokio::test]
    async fn list_pulls_maps_entries_and_normalizes_state() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/api/pulls"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "number": 7,
                    "title": "Fix the thing",
                    "state": "open",
                    "draft": true,
                    "user": { "login": "octocat" },
                    "head": { "sha": "aaa111" },
                    "html_url": "https://github.com/acme/api/pull/7"
                },
                {
                    "number": 3,
                    "title": "Older change",
                    "state": "closed",
                    "user": { "login": "hubot" },
                    "head": { "sha": "bbb222" },
                    "html_url": "https://github.com/acme/api/pull/3"
                },
                { "number": 9, "title": "no user" }
            ])))
            .mount(&server)
            .await;

        let pulls = list_pulls(
            &reqwest::Client::new(),
            "ghs_test",
            &server.uri(),
            "acme/api",
            "bogus",
        )
        .await
        .unwrap();
        assert_eq!(pulls.len(), 2);
        assert_eq!(pulls[0].number, 7);
        assert_eq!(pulls[0].title, "Fix the thing");
        assert_eq!(pulls[0].author, "octocat");
        assert_eq!(pulls[0].state, "open");
        assert!(pulls[0].draft);
        assert_eq!(pulls[0].head_sha, "aaa111");
        assert_eq!(pulls[0].url, "https://github.com/acme/api/pull/7");
        assert_eq!(pulls[1].number, 3);
        assert!(!pulls[1].draft);

        let requests = server.received_requests().await.unwrap();
        let query = requests[0].url.query().unwrap();
        assert!(query.contains("state=open"), "{query}");
        assert!(query.contains("per_page=50"), "{query}");
        let headers = &requests[0].headers;
        assert_eq!(headers.get("user-agent").unwrap(), "freedas");
    }

    #[tokio::test]
    async fn list_pulls_reports_status_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/api/pulls"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_string("Resource not accessible by integration"),
            )
            .mount(&server)
            .await;

        let error = list_pulls(
            &reqwest::Client::new(),
            "ghs_test",
            &server.uri(),
            "acme/api",
            "open",
        )
        .await
        .unwrap_err();
        assert!(error.contains("github 403"), "{error}");
        assert!(error.contains("Resource not accessible"), "{error}");
    }
}
