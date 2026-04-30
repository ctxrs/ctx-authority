use assert_cmd::Command;
use ctxa::backends::SecretBackendConfig;
use ctxa::config::AppConfig;
use predicates::prelude::*;
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn ctxa() -> Command {
    let path = assert_cmd::cargo::cargo_bin("ctxa");
    codesign_ctxa_for_external_target(&path);
    Command::new(path)
}

#[cfg(target_os = "macos")]
fn codesign_ctxa_for_external_target(path: &Path) {
    static SIGN_ONCE: std::sync::Once = std::sync::Once::new();
    SIGN_ONCE.call_once(|| {
        let output = std::process::Command::new("codesign")
            .args(["--force", "--sign", "-"])
            .arg(path)
            .output()
            .expect("codesign ctxa test binary");
        assert!(
            output.status.success(),
            "codesign ctxa test binary failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    });
}

#[cfg(not(target_os = "macos"))]
fn codesign_ctxa_for_external_target(_path: &Path) {}

#[derive(Debug, Clone)]
struct ExpectedRequest {
    method: &'static str,
    path_and_query: &'static str,
    authorization: &'static str,
    status: &'static str,
    body: &'static str,
    request_id: &'static str,
}

#[derive(Debug, Clone)]
struct RecordedRequest {
    first_line: String,
    authorization: Option<String>,
}

struct FakeServer {
    base_url: String,
    records: Arc<Mutex<Vec<RecordedRequest>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl FakeServer {
    fn start(expected: Vec<ExpectedRequest>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let records = Arc::new(Mutex::new(Vec::new()));
        let thread_records = Arc::clone(&records);
        let handle = thread::spawn(move || {
            let mut expected = VecDeque::from(expected);
            while let Some(expected) = expected.pop_front() {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                let first_line = request.lines().next().unwrap_or("").to_string();
                let authorization = request
                    .lines()
                    .find_map(|line| line.strip_prefix("authorization: "))
                    .map(ToOwned::to_owned)
                    .or_else(|| {
                        request
                            .lines()
                            .find_map(|line| line.strip_prefix("Authorization: "))
                            .map(ToOwned::to_owned)
                    });
                thread_records.lock().unwrap().push(RecordedRequest {
                    first_line: first_line.clone(),
                    authorization: authorization.clone(),
                });
                assert_eq!(
                    first_line,
                    format!("{} {} HTTP/1.1", expected.method, expected.path_and_query)
                );
                assert_eq!(authorization.as_deref(), Some(expected.authorization));
                let response = format!(
                    "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nx-github-request-id: {}\r\nrequest-id: {}\r\nconnection: close\r\n\r\n{}",
                    expected.status,
                    expected.body.len(),
                    expected.request_id,
                    expected.request_id,
                    expected.body
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        Self {
            base_url,
            records,
            handle: Some(handle),
        }
    }

    fn join(mut self) -> Vec<RecordedRequest> {
        self.handle.take().unwrap().join().unwrap();
        let records = Arc::try_unwrap(self.records).unwrap().into_inner().unwrap();
        for record in &records {
            let _ = (&record.first_line, &record.authorization);
        }
        records
    }
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let start = Instant::now();
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap_or(0);
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            let header_text = String::from_utf8_lossy(&bytes);
            let content_length = header_text
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .or_else(|| {
                    header_text
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                })
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let header_end = bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            if bytes.len() >= header_end + content_length {
                break;
            }
        }
        assert!(start.elapsed() < Duration::from_secs(5));
    }
    String::from_utf8_lossy(&bytes).to_string()
}

fn set_fake_backend(home: &Path, values: BTreeMap<String, String>) {
    let config_path = home.join("config.yaml");
    let mut config = AppConfig::load(&config_path).unwrap();
    config.secret_backend = Some(SecretBackendConfig::Fake { values });
    config.save(&config_path).unwrap();
}

#[test]
fn github_capability_execution_returns_response_and_redacted_receipt() {
    let server = FakeServer::start(vec![ExpectedRequest {
        method: "GET",
        path_and_query: "/repos/acme/app/issues?state=open",
        authorization: "Bearer gh-secret-token",
        status: "200 OK",
        body: r#"[{"number":1,"title":"bug"},{"number":2,"pull_request":{}}]"#,
        request_id: "gh-req-1",
    }]);
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["profile", "create", "openclaw", "--agent", "openclaw"])
        .assert()
        .success();
    set_fake_backend(
        home.path(),
        BTreeMap::from([("github-token".into(), "gh-secret-token".into())]),
    );
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "provider",
            "add-github",
            "--id",
            "github",
            "--api-base",
            &server.base_url,
            "--token-ref",
            "github-token",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "grant",
            "create",
            "--id",
            "github-read",
            "--profile",
            "openclaw",
            "--provider",
            "github",
            "--capability",
            "github.issues.read",
            "--resource",
            "github:acme/app",
        ])
        .assert()
        .success();

    let output = ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "execute",
            "--profile",
            "openclaw",
            "--provider",
            "github",
            "--capability",
            "github.issues.read",
            "--resource",
            "github:acme/app",
            "--operation",
            r#"{"state":"open"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("github.issues.read"))
        .stdout(predicate::str::contains("provider_response"))
        .stdout(predicate::str::contains("gh-secret-token").not())
        .stdout(predicate::str::contains("github-token").not())
        .get_output()
        .stdout
        .clone();
    let parsed: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed["provider_response"][0]["number"], 1);
    assert_eq!(parsed["provider_response"].as_array().unwrap().len(), 1);
    assert_eq!(
        parsed["capability"]["receipt"]["execution"]["provider_request_id"],
        "gh-req-1"
    );
    server.join();
}

#[test]
fn github_app_installation_auth_mints_short_lived_token_before_execution() {
    let server = FakeServer::start(vec![
        ExpectedRequest {
            method: "POST",
            path_and_query: "/app/installations/123/access_tokens",
            authorization: "Bearer app-jwt-secret",
            status: "200 OK",
            body: r#"{"token":"minted-installation-token","expires_at":"2026-04-30T12:00:00Z"}"#,
            request_id: "gh-mint-1",
        },
        ExpectedRequest {
            method: "GET",
            path_and_query: "/repos/acme/app/pulls?state=open",
            authorization: "Bearer minted-installation-token",
            status: "200 OK",
            body: r#"[{"number":5}]"#,
            request_id: "gh-prs-1",
        },
    ]);
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["profile", "create", "codex", "--agent", "codex"])
        .assert()
        .success();
    set_fake_backend(
        home.path(),
        BTreeMap::from([("github-app-jwt".into(), "app-jwt-secret".into())]),
    );
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "provider",
            "add-github",
            "--id",
            "github",
            "--api-base",
            &server.base_url,
            "--app-jwt-ref",
            "github-app-jwt",
            "--installation-id",
            "123",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "grant",
            "create",
            "--id",
            "github-prs",
            "--profile",
            "codex",
            "--provider",
            "github",
            "--capability",
            "github.prs.read",
            "--resource",
            "github:acme/app",
        ])
        .assert()
        .success();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "execute",
            "--profile",
            "codex",
            "--provider",
            "github",
            "--capability",
            "github.prs.read",
            "--resource",
            "github:acme/app",
            "--operation",
            r#"{"state":"open"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("minted-installation-token").not())
        .stdout(predicate::str::contains("app-jwt-secret").not())
        .stdout(predicate::str::contains("github-app-jwt").not());
    server.join();
}

#[test]
fn provider_api_base_path_prefix_is_preserved() {
    let server = FakeServer::start(vec![ExpectedRequest {
        method: "GET",
        path_and_query: "/api/v3/repos/acme/app/issues?state=open",
        authorization: "Bearer gh-secret-token",
        status: "200 OK",
        body: r#"[{"number":1,"title":"bug"}]"#,
        request_id: "gh-prefixed-1",
    }]);
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["profile", "create", "agent", "--agent", "agent"])
        .assert()
        .success();
    set_fake_backend(
        home.path(),
        BTreeMap::from([("github-token".into(), "gh-secret-token".into())]),
    );
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "provider",
            "add-github",
            "--id",
            "github",
            "--api-base",
            &format!("{}/api/v3", server.base_url),
            "--token-ref",
            "github-token",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "grant",
            "create",
            "--id",
            "github-read",
            "--profile",
            "agent",
            "--provider",
            "github",
            "--capability",
            "github.issues.read",
            "--resource",
            "github:acme/app",
        ])
        .assert()
        .success();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "execute",
            "--profile",
            "agent",
            "--provider",
            "github",
            "--capability",
            "github.issues.read",
            "--resource",
            "github:acme/app",
            "--operation",
            r#"{"state":"open"}"#,
        ])
        .assert()
        .success();
    server.join();
}

#[test]
fn unknown_operation_keys_fail_closed() {
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["profile", "create", "agent", "--agent", "agent"])
        .assert()
        .success();
    set_fake_backend(
        home.path(),
        BTreeMap::from([("github-token".into(), "gh-secret-token".into())]),
    );
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "provider",
            "add-github",
            "--id",
            "github",
            "--api-base",
            "http://127.0.0.1:9",
            "--token-ref",
            "github-token",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "grant",
            "create",
            "--id",
            "github-read",
            "--profile",
            "agent",
            "--provider",
            "github",
            "--capability",
            "github.issues.read",
            "--resource",
            "github:acme/app",
        ])
        .assert()
        .success();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "execute",
            "--profile",
            "agent",
            "--provider",
            "github",
            "--capability",
            "github.issues.read",
            "--resource",
            "github:acme/app",
            "--operation",
            r#"{"statee":"open"}"#,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "operation key statee is not supported",
        ))
        .stderr(predicate::str::contains("gh-secret-token").not())
        .stderr(predicate::str::contains("github-token").not());
}

#[test]
fn oversized_provider_responses_fail_closed() {
    let oversized_body: &'static str = Box::leak("x".repeat(1024 * 1024 + 1).into_boxed_str());
    let server = FakeServer::start(vec![ExpectedRequest {
        method: "GET",
        path_and_query: "/repos/acme/app/issues",
        authorization: "Bearer gh-secret-token",
        status: "200 OK",
        body: oversized_body,
        request_id: "gh-large-1",
    }]);
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["profile", "create", "agent", "--agent", "agent"])
        .assert()
        .success();
    set_fake_backend(
        home.path(),
        BTreeMap::from([("github-token".into(), "gh-secret-token".into())]),
    );
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "provider",
            "add-github",
            "--id",
            "github",
            "--api-base",
            &server.base_url,
            "--token-ref",
            "github-token",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "grant",
            "create",
            "--id",
            "github-read",
            "--profile",
            "agent",
            "--provider",
            "github",
            "--capability",
            "github.issues.read",
            "--resource",
            "github:acme/app",
        ])
        .assert()
        .success();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "execute",
            "--profile",
            "agent",
            "--provider",
            "github",
            "--capability",
            "github.issues.read",
            "--resource",
            "github:acme/app",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "provider response exceeded size limit",
        ))
        .stderr(predicate::str::contains("gh-secret-token").not())
        .stderr(predicate::str::contains("github-token").not());
    server.join();
}

#[test]
fn google_and_microsoft_capabilities_route_to_provider_apis() {
    let google = FakeServer::start(vec![ExpectedRequest {
        method: "POST",
        path_and_query: "/gmail/v1/users/me/drafts",
        authorization: "Bearer google-token",
        status: "200 OK",
        body: r#"{"id":"draft-1"}"#,
        request_id: "google-1",
    }]);
    let microsoft = FakeServer::start(vec![ExpectedRequest {
        method: "GET",
        path_and_query: "/v1.0/me/messages?%24top=5",
        authorization: "Bearer ms-token",
        status: "200 OK",
        body: r#"{"value":[{"id":"message-1"}]}"#,
        request_id: "ms-1",
    }]);
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["profile", "create", "assistant", "--agent", "assistant"])
        .assert()
        .success();
    set_fake_backend(
        home.path(),
        BTreeMap::from([
            ("google-token-ref".into(), "google-token".into()),
            ("ms-token-ref".into(), "ms-token".into()),
        ]),
    );
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "provider",
            "add-google",
            "--id",
            "google",
            "--api-base",
            &google.base_url,
            "--token-ref",
            "google-token-ref",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "provider",
            "add-microsoft",
            "--id",
            "microsoft",
            "--api-base",
            &microsoft.base_url,
            "--token-ref",
            "ms-token-ref",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "grant",
            "create",
            "--id",
            "google-draft",
            "--profile",
            "assistant",
            "--provider",
            "google",
            "--capability",
            "google.gmail.drafts.create",
            "--resource",
            "google:gmail",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "grant",
            "create",
            "--id",
            "ms-read",
            "--profile",
            "assistant",
            "--provider",
            "microsoft",
            "--capability",
            "microsoft.outlook.messages.read",
            "--resource",
            "microsoft:outlook",
        ])
        .assert()
        .success();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "execute",
            "--profile",
            "assistant",
            "--provider",
            "google",
            "--capability",
            "google.gmail.drafts.create",
            "--resource",
            "google:gmail",
            "--payload",
            r#"{"message":{"raw":"abc"}}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("google-token").not())
        .stdout(predicate::str::contains("google-token-ref").not());
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "execute",
            "--profile",
            "assistant",
            "--provider",
            "microsoft",
            "--capability",
            "microsoft.outlook.messages.read",
            "--resource",
            "microsoft:outlook",
            "--operation",
            r#"{"$top":5}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ms-token").not())
        .stdout(predicate::str::contains("ms-token-ref").not());
    google.join();
    microsoft.join();
}

#[test]
fn capability_grant_delegation_rejects_broader_children() {
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["profile", "create", "admin", "--agent", "admin"])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["profile", "create", "worker", "--agent", "worker"])
        .assert()
        .success();
    set_fake_backend(
        home.path(),
        BTreeMap::from([("github-token".into(), "gh-secret-token".into())]),
    );
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "provider",
            "add-github",
            "--id",
            "github",
            "--token-ref",
            "github-token",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "grant",
            "create",
            "--id",
            "github-root",
            "--profile",
            "admin",
            "--provider",
            "github",
            "--capability",
            "github.issues.read",
            "--capability",
            "github.issues.create",
            "--resource",
            "github:acme/app",
            "--delegable",
            "--max-depth",
            "2",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "grant",
            "delegate",
            "--from",
            "github-root",
            "--id",
            "github-worker",
            "--profile",
            "worker",
            "--capability",
            "github.issues.read",
            "--resource",
            "github:acme/app",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "grant",
            "delegate",
            "--from",
            "github-worker",
            "--id",
            "github-worker-prs",
            "--profile",
            "worker",
            "--capability",
            "github.prs.read",
            "--resource",
            "github:acme/app",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not allow delegation"));
}

#[test]
fn denied_capability_attempt_is_audited_without_calling_provider() {
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["profile", "create", "agent", "--agent", "agent"])
        .assert()
        .success();
    set_fake_backend(
        home.path(),
        BTreeMap::from([("github-token".into(), "gh-secret-token".into())]),
    );
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "provider",
            "add-github",
            "--id",
            "github",
            "--token-ref",
            "github-token",
        ])
        .assert()
        .success();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "execute",
            "--profile",
            "agent",
            "--provider",
            "github",
            "--capability",
            "github.issues.read",
            "--resource",
            "github:acme/app",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not granted"))
        .stderr(predicate::str::contains("gh-secret-token").not())
        .stderr(predicate::str::contains("github-token").not());

    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["log", "--limit", "10"])
        .assert()
        .success()
        .stdout(predicate::str::contains("capability_denied"))
        .stdout(predicate::str::contains("no_matching_grant"))
        .stdout(predicate::str::contains("gh-secret-token").not())
        .stdout(predicate::str::contains("github-token").not());
}

#[test]
fn provider_failure_is_audited_without_leaking_token() {
    let server = FakeServer::start(vec![ExpectedRequest {
        method: "POST",
        path_and_query: "/repos/acme/app/issues",
        authorization: "Bearer gh-secret-token",
        status: "500 Internal Server Error",
        body: r#"{"message":"server error"}"#,
        request_id: "gh-fail-1",
    }]);
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["profile", "create", "agent", "--agent", "agent"])
        .assert()
        .success();
    set_fake_backend(
        home.path(),
        BTreeMap::from([("github-token".into(), "gh-secret-token".into())]),
    );
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "provider",
            "add-github",
            "--id",
            "github",
            "--api-base",
            &server.base_url,
            "--token-ref",
            "github-token",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "grant",
            "create",
            "--id",
            "github-write",
            "--profile",
            "agent",
            "--provider",
            "github",
            "--capability",
            "github.issues.create",
            "--resource",
            "github:acme/app",
        ])
        .assert()
        .success();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "capability",
            "execute",
            "--profile",
            "agent",
            "--provider",
            "github",
            "--capability",
            "github.issues.create",
            "--resource",
            "github:acme/app",
            "--payload",
            r#"{"title":"bug"}"#,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("provider returned HTTP 500"))
        .stderr(predicate::str::contains("gh-secret-token").not())
        .stderr(predicate::str::contains("github-token").not());
    server.join();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["log", "--limit", "10"])
        .assert()
        .success()
        .stdout(predicate::str::contains("capability_execution_failed"))
        .stdout(predicate::str::contains("provider_execution_failed"))
        .stdout(predicate::str::contains("gh-secret-token").not())
        .stdout(predicate::str::contains("github-token").not());
}
