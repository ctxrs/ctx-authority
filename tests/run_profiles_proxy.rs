use assert_cmd::Command;
use ctxa::audit::AuditLog;
use ctxa::backends::{FakeBackend, SecretBackend, SecretBackendConfig, SecretLease};
use ctxa::config::{
    AppConfig, AppPaths, HttpAllowConfig, HttpAuthConfig, HttpResourceConfig, ProfileConfig,
};
use ctxa::models::Receipt;
use ctxa::proxy::{ProxyConfig, ProxyServer};
use ctxa::receipts::ReceiptSigner;
use predicates::prelude::*;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn ctxa() -> Command {
    Command::cargo_bin("ctxa").expect("ctxa binary")
}

#[test]
fn profile_cli_creates_and_updates_http_resources() {
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["profile", "create", "github-reader", "--agent", "my-agent"])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "profile",
            "add-http",
            "github-reader",
            "--id",
            "github-issues",
            "--host",
            "api.github.com",
            "--secret-ref",
            "op://example-vault/github-token/token",
            "--allow-method",
            "GET",
            "--path-prefix",
            "/repos/example/repo/issues",
        ])
        .assert()
        .success();

    let config = AppConfig::load(&home.path().join("config.yaml")).unwrap();
    let profile = config.profile("github-reader").expect("profile");
    assert_eq!(profile.agent.as_deref(), Some("my-agent"));
    let resource = profile.http_resources.first().expect("resource");
    assert_eq!(resource.id, "github-issues");
    assert_eq!(resource.allow.methods, vec!["GET"]);
}

#[test]
fn run_injects_proxy_environment_without_backend_secret() {
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    let config = AppConfig {
        profiles: vec![ProfileConfig {
            id: "demo".into(),
            agent: Some("my-agent".into()),
            env_vars: BTreeMap::from([("GITHUB_API_BASE".into(), "http://api.github.com".into())]),
            http_resources: Vec::new(),
        }],
        secret_backend: Some(SecretBackendConfig::Fake {
            values: BTreeMap::from([("github".into(), "run-hidden-value".into())]),
        }),
        ..AppConfig::default()
    };
    config.save(&home.path().join("config.yaml")).unwrap();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["run", "--profile", "demo", "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("CTXA_PROFILE=demo"))
        .stdout(predicate::str::contains("HTTP_PROXY=http://ctxa:"))
        .stdout(predicate::str::contains("CTXA_PROXY_URL=http://ctxa:"))
        .stdout(predicate::str::contains(
            "GITHUB_API_BASE=http://api.github.com",
        ))
        .stdout(predicate::str::contains("run-hidden-value").not());
}

#[test]
fn proxy_allows_configured_http_request_and_records_verifiable_receipt() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let upstream = spawn_upstream();
    let upstream_address = upstream.address;
    let upstream_received = Arc::clone(&upstream.received);
    let mut profile = profile_for(upstream.address, "/safe");
    profile.http_resources.insert(
        0,
        HttpResourceConfig {
            id: "same-host-other-path".into(),
            host: upstream.address.to_string(),
            secret_ref: "other-secret".into(),
            auth: HttpAuthConfig::default(),
            allow: HttpAllowConfig {
                methods: vec!["GET".into()],
                path_prefixes: vec!["/other".into()],
            },
        },
    );
    let backend = Arc::new(FakeBackend::new(BTreeMap::from([
        ("github".into(), "proxy-backend-value".into()),
        ("other-secret".into(), "wrong-secret-value".into()),
    ])));
    let proxy = ProxyServer::start(ProxyConfig {
        profile,
        secret_backend: backend,
        audit: audit.clone(),
        signer: signer.clone(),
    })
    .unwrap();

    let response = send_proxy_request(
        proxy.address(),
        &format!(
            "GET http://{}/safe/item?api_key=raw-query-value HTTP/1.1\r\nHost: attacker.invalid\r\nProxy-Authorization: Bearer {}\r\nAuthorization: Bearer caller-token\r\nProxy-Connection: keep-alive\r\n\r\n",
            upstream_address,
            proxy.token()
        ),
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    upstream.join();
    let received = upstream_received.lock().unwrap().clone().expect("request");
    assert_eq!(
        received.request_line,
        "GET /safe/item?api_key=raw-query-value HTTP/1.1"
    );
    assert_eq!(
        header(&received.headers, "authorization"),
        Some("Bearer proxy-backend-value")
    );
    assert_eq!(header(&received.headers, "proxy-authorization"), None);
    assert_eq!(header(&received.headers, "proxy-connection"), None);
    let expected_host = upstream_address.to_string();
    assert_eq!(
        header(&received.headers, "host"),
        Some(expected_host.as_str())
    );

    let events = audit.list(20).unwrap();
    let events_text = serde_json::to_string(&events).unwrap();
    assert!(!events_text.contains("proxy-backend-value"));
    assert!(!events_text.contains("raw-query-value"));
    let receipt_value = events
        .iter()
        .find(|(_, kind, _)| kind == "proxy_request_receipt")
        .map(|(_, _, value)| value.clone())
        .expect("receipt event");
    let receipt: Receipt = serde_json::from_value(receipt_value).unwrap();
    signer.verify_local_receipt(&receipt).unwrap();
    assert_eq!(receipt.action, "http.request");
    assert_eq!(receipt.resource, "github-issues");
    proxy.stop();
}

#[test]
fn proxy_rejects_header_unsafe_bearer_secrets() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let profile = profile_for("127.0.0.1:9".parse().unwrap(), "/safe");
    let backend = Arc::new(FakeBackend::new(BTreeMap::from([(
        "github".into(),
        "bad\r\nX-Leak: yes".into(),
    )])));
    let proxy = ProxyServer::start(ProxyConfig {
        profile,
        secret_backend: backend,
        audit: audit.clone(),
        signer,
    })
    .unwrap();

    let response = send_proxy_request(
        proxy.address(),
        &format!(
            "GET http://127.0.0.1:9/safe/item HTTP/1.1\r\nProxy-Authorization: Bearer {}\r\n\r\n",
            proxy.token()
        ),
    );
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    let events_text = serde_json::to_string(&audit.list(20).unwrap()).unwrap();
    assert!(!events_text.contains("X-Leak"));
    assert!(!events_text.contains("bad"));
    proxy.stop();
}

#[test]
fn proxy_denies_before_secret_resolution() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let resolve_count = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(CountingBackend {
        resolve_count: Arc::clone(&resolve_count),
    });
    let profile = profile_for("127.0.0.1:9".parse().unwrap(), "/safe");
    let proxy = ProxyServer::start(ProxyConfig {
        profile,
        secret_backend: backend,
        audit,
        signer,
    })
    .unwrap();

    let no_auth = send_proxy_request(
        proxy.address(),
        "GET http://127.0.0.1:9/safe/item HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n",
    );
    assert!(no_auth.starts_with("HTTP/1.1 407"), "{no_auth}");

    let bad_path = send_proxy_request(
        proxy.address(),
        &format!(
            "GET http://127.0.0.1:9/unsafe HTTP/1.1\r\nProxy-Authorization: Bearer {}\r\n\r\n",
            proxy.token()
        ),
    );
    assert!(bad_path.starts_with("HTTP/1.1 403"), "{bad_path}");

    let encoded_slash = send_proxy_request(
        proxy.address(),
        &format!(
            "GET http://127.0.0.1:9/safe/%2fadmin HTTP/1.1\r\nProxy-Authorization: Bearer {}\r\n\r\n",
            proxy.token()
        ),
    );
    assert!(encoded_slash.starts_with("HTTP/1.1 403"), "{encoded_slash}");

    let unsupported_scheme = send_proxy_request(
        proxy.address(),
        &format!(
            "GET https://127.0.0.1:9/safe/item HTTP/1.1\r\nProxy-Authorization: Bearer {}\r\n\r\n",
            proxy.token()
        ),
    );
    assert!(
        unsupported_scheme.starts_with("HTTP/1.1 400"),
        "{unsupported_scheme}"
    );
    assert_eq!(resolve_count.load(Ordering::SeqCst), 0);

    let smuggled_header = send_proxy_request(
        proxy.address(),
        &format!(
            "GET http://127.0.0.1:9/safe/item HTTP/1.1\r\nProxy-Authorization: Bearer {}\r\nX-Smuggle: ok\nAuthorization: Bearer attacker\r\n\r\n",
            proxy.token()
        ),
    );
    assert!(
        smuggled_header.starts_with("HTTP/1.1 400"),
        "{smuggled_header}"
    );
    assert_eq!(resolve_count.load(Ordering::SeqCst), 0);

    proxy.stop();
}

fn profile_for(address: SocketAddr, path_prefix: &str) -> ProfileConfig {
    ProfileConfig {
        id: "github-reader".into(),
        agent: Some("my-agent".into()),
        env_vars: BTreeMap::new(),
        http_resources: vec![HttpResourceConfig {
            id: "github-issues".into(),
            host: address.to_string(),
            secret_ref: "github".into(),
            auth: HttpAuthConfig::default(),
            allow: HttpAllowConfig {
                methods: vec!["GET".into()],
                path_prefixes: vec![path_prefix.into()],
            },
        }],
    }
}

fn send_proxy_request(address: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[derive(Clone)]
struct ReceivedRequest {
    request_line: String,
    headers: Vec<(String, String)>,
}

struct Upstream {
    address: SocketAddr,
    received: Arc<Mutex<Option<ReceivedRequest>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Upstream {
    fn join(mut self) {
        self.thread.take().unwrap().join().unwrap();
    }
}

fn spawn_upstream() -> Upstream {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(None));
    let received_for_thread = Arc::clone(&received);
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buffer = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            let read = stream.read(&mut byte).unwrap();
            if read == 0 {
                break;
            }
            buffer.push(byte[0]);
            if buffer.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8(buffer).unwrap();
        let mut lines = text.split("\r\n");
        let request_line = lines.next().unwrap().to_string();
        let headers = lines
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.to_string(), value.trim_start().to_string())
            })
            .collect();
        *received_for_thread.lock().unwrap() = Some(ReceivedRequest {
            request_line,
            headers,
        });
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    Upstream {
        address,
        received,
        thread: Some(thread),
    }
}

struct CountingBackend {
    resolve_count: Arc<AtomicUsize>,
}

impl SecretBackend for CountingBackend {
    fn resolve(&self, _reference: &str) -> ctxa::Result<SecretLease> {
        self.resolve_count.fetch_add(1, Ordering::SeqCst);
        Ok(SecretLease::new("counting-backend-value"))
    }
}
