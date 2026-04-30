use assert_cmd::Command;
use base64::Engine;
use ctxa::audit::AuditLog;
use ctxa::backends::{FakeBackend, SecretBackend, SecretBackendConfig, SecretLease};
use ctxa::config::{
    AppConfig, AppPaths, GrantDelegationConfig, HttpAllowConfig, HttpAuthConfig, HttpGrantConfig,
    HttpResourceConfig, HttpResourceScheme, ProfileConfig,
};
use ctxa::models::Receipt;
use ctxa::proxy::{ProxyConfig, ProxyServer};
use ctxa::receipts::ReceiptSigner;
use predicates::prelude::*;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, SanType,
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
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

fn curl_available() -> bool {
    std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_ok()
}

#[test]
fn profile_cli_creates_and_updates_http_resources() {
    let home = tempfile::tempdir().unwrap();
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
fn profile_cli_creates_https_resources_and_tests_urls() {
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
            "add-https",
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
    let resource = config
        .profile("github-reader")
        .expect("profile")
        .http_resources
        .first()
        .expect("resource");
    assert_eq!(resource.scheme, HttpResourceScheme::Https);
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "profile",
            "test",
            "github-reader",
            "--url",
            "https://api.github.com/repos/example/repo/issues/1",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("allowed authority=github-issues"));
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "profile",
            "test",
            "github-reader",
            "--url",
            "https://api.github.com:80/repos/example/repo/issues/1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("denied by profile"));
}

#[test]
fn setup_runtime_installs_skill_and_preserves_existing_profile() {
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["setup", "runtime", "codex", "--profile", "codex"])
        .assert()
        .success()
        .stdout(predicate::str::contains("profile codex"))
        .stdout(predicate::str::contains(
            "next run: ctxa run --profile codex -- codex",
        ));
    let skill = std::fs::read_to_string(
        home.path()
            .join("skills")
            .join("ctx-authority")
            .join("SKILL.md"),
    )
    .unwrap();
    assert!(skill.contains("ctx authority"));

    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "profile",
            "add-https",
            "codex",
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
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "setup",
            "runtime",
            "codex",
            "--profile",
            "codex",
            "--agent",
            "other-agent",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("agent codex"))
        .stdout(predicate::str::contains("agent other-agent").not());

    let config = AppConfig::load(&home.path().join("config.yaml")).unwrap();
    assert_eq!(config.profiles.len(), 1);
    let profile = config.profile("codex").unwrap();
    assert_eq!(profile.agent.as_deref(), Some("codex"));
    assert_eq!(profile.http_resources.len(), 1);
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
        .env("CTXA_AMBIENT_ALLOWED", "ambient-value")
        .args(["run", "--profile", "demo", "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("CTXA_PROFILE=demo"))
        .stdout(predicate::str::contains("HTTP_PROXY=http://ctxa:"))
        .stdout(predicate::str::contains("HTTPS_PROXY=http://ctxa:"))
        .stdout(predicate::str::contains("CTXA_PROXY_URL=http://ctxa:"))
        .stdout(predicate::str::contains("SSL_CERT_FILE="))
        .stdout(predicate::str::contains("REQUESTS_CA_BUNDLE="))
        .stdout(predicate::str::contains("CURL_CA_BUNDLE="))
        .stdout(predicate::str::contains(
            "GITHUB_API_BASE=http://api.github.com",
        ))
        .stdout(predicate::str::contains(
            "CTXA_AMBIENT_ALLOWED=ambient-value",
        ))
        .stdout(predicate::str::contains("run-hidden-value").not());
}

#[test]
fn run_clean_env_drops_ambient_env_and_allows_explicit_inherit() {
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
            env_vars: BTreeMap::from([("PROFILE_HINT".into(), "profile-value".into())]),
            http_resources: Vec::new(),
        }],
        secret_backend: Some(SecretBackendConfig::Fake {
            values: BTreeMap::new(),
        }),
        ..AppConfig::default()
    };
    config.save(&home.path().join("config.yaml")).unwrap();

    ctxa()
        .env("CTXA_HOME", home.path())
        .env("CTXA_AMBIENT_SECRET", "ambient-value")
        .env("CTXA_ALLOWED_MODEL_KEY", "model-value")
        .args([
            "run",
            "--profile",
            "demo",
            "--clean-env",
            "--inherit-env",
            "CTXA_ALLOWED_MODEL_KEY",
            "--",
            "env",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("CTXA_PROFILE=demo"))
        .stdout(predicate::str::contains("PROFILE_HINT=profile-value"))
        .stdout(predicate::str::contains(
            "CTXA_ALLOWED_MODEL_KEY=model-value",
        ))
        .stdout(predicate::str::contains("CTXA_AMBIENT_SECRET").not())
        .stdout(predicate::str::contains("ambient-value").not());
}

#[test]
fn run_https_proxy_env_supports_child_connect_denials() {
    if !curl_available() {
        eprintln!("skipping curl-dependent HTTPS run profile test");
        return;
    }
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
            env_vars: BTreeMap::new(),
            http_resources: vec![HttpResourceConfig {
                id: "loopback".into(),
                scheme: HttpResourceScheme::Https,
                host: "127.0.0.1:9".into(),
                secret_ref: "github".into(),
                auth: HttpAuthConfig::default(),
                allow: HttpAllowConfig {
                    methods: vec!["GET".into()],
                    path_prefixes: vec!["/safe".into()],
                },
            }],
        }],
        secret_backend: Some(SecretBackendConfig::Fake {
            values: BTreeMap::from([("github".into(), "run-hidden-value".into())]),
        }),
        ..AppConfig::default()
    };
    config.save(&home.path().join("config.yaml")).unwrap();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "run",
            "--profile",
            "demo",
            "--",
            "curl",
            "-sS",
            "--noproxy",
            "",
            "--max-time",
            "5",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "https://127.0.0.1:9/unsafe",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("403"))
        .stdout(predicate::str::contains("run-hidden-value").not());
}

#[test]
fn doctor_reports_local_state_without_secret_values() {
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("config ok"))
        .stdout(predicate::str::contains("process CA ok"))
        .stdout(predicate::str::contains("proxy bind ok"));
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
            scheme: HttpResourceScheme::Http,
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
        profiles: vec![profile.clone()],
        profile,
        grants: Vec::new(),
        secret_backend: backend,
        audit: audit.clone(),
        signer: signer.clone(),
        upstream_root_certs_pem: Vec::new(),
    })
    .unwrap();

    let response = send_proxy_request(
        proxy.address(),
        &format!(
            "GET http://{}/safe/item?api_key=raw-query-value HTTP/1.1\r\nHost: attacker.invalid\r\nProxy-Authorization: Bearer {}\r\nAuthorization: Bearer caller-token\r\nProxy-Connection: keep-alive\r\nX-HTTP-Method-Override: DELETE\r\nX-GitHub-Api-Version: attacker\r\n\r\n",
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
    assert_eq!(header(&received.headers, "x-http-method-override"), None);
    assert_eq!(header(&received.headers, "x-github-api-version"), None);
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
fn proxy_allows_configured_https_request_and_records_verifiable_receipt() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let upstream = spawn_https_upstream();
    let upstream_address = upstream.address;
    let upstream_received = Arc::clone(&upstream.received);
    let profile = https_profile_for(upstream.address, "/safe");
    let backend = Arc::new(FakeBackend::new(BTreeMap::from([(
        "github".into(),
        "https-backend-value".into(),
    )])));
    let proxy = ProxyServer::start(ProxyConfig {
        profiles: vec![profile.clone()],
        profile,
        grants: Vec::new(),
        secret_backend: backend,
        audit: audit.clone(),
        signer: signer.clone(),
        upstream_root_certs_pem: vec![upstream.root_cert_pem.as_bytes().to_vec()],
    })
    .unwrap();
    let reqwest_proxy = reqwest::Proxy::all(format!("http://{}", proxy.address()))
        .unwrap()
        .basic_auth("ctxa", proxy.token());
    let client = reqwest::blocking::Client::builder()
        .proxy(reqwest_proxy)
        .add_root_certificate(
            reqwest::Certificate::from_pem(proxy.ca_cert_pem().as_bytes()).unwrap(),
        )
        .build()
        .unwrap();

    let response = client
        .get(format!(
            "https://{upstream_address}/safe/item?api_key=raw-query-value"
        ))
        .header("Authorization", "Bearer caller-token")
        .header("X-HTTP-Method-Override", "DELETE")
        .header("X-GitHub-Api-Version", "attacker")
        .send()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().unwrap(), "ok");
    upstream.join();
    let received = upstream_received.lock().unwrap().clone().expect("request");
    assert_eq!(
        received.request_line,
        "GET /safe/item?api_key=raw-query-value HTTP/1.1"
    );
    assert_eq!(
        header(&received.headers, "authorization"),
        Some("Bearer https-backend-value")
    );
    assert_eq!(header(&received.headers, "proxy-authorization"), None);
    assert_eq!(header(&received.headers, "x-http-method-override"), None);
    assert_eq!(header(&received.headers, "x-github-api-version"), None);

    let events = audit.list(20).unwrap();
    let events_text = serde_json::to_string(&events).unwrap();
    assert!(!events_text.contains("https-backend-value"));
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
fn https_upstream_redirect_to_disallowed_same_host_is_not_followed() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let upstream = spawn_https_sequence_upstream(|address| {
        vec![
            format!(
                "HTTP/1.1 302 Found\r\nLocation: https://{address}/admin\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .into_bytes(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nredirect-followed"
                .to_vec(),
        ]
    });
    let profile = https_profile_for(upstream.address, "/safe");
    let proxy = ProxyServer::start(ProxyConfig {
        profiles: vec![profile.clone()],
        profile,
        grants: Vec::new(),
        secret_backend: Arc::new(FakeBackend::new(BTreeMap::from([(
            "github".into(),
            "https-backend-value".into(),
        )]))),
        audit: audit.clone(),
        signer,
        upstream_root_certs_pem: vec![upstream.root_cert_pem.as_bytes().to_vec()],
    })
    .unwrap();
    let client = proxied_https_client(&proxy, true);

    let response = client
        .get(format!("https://{}/safe/redirect", upstream.address))
        .send()
        .unwrap();
    assert_eq!(response.status(), 302);
    assert_eq!(response.text().unwrap(), "");
    proxy.stop();

    let received = upstream.join();
    assert_eq!(received.len(), 1, "{received:?}");
    assert_eq!(received[0].request_line, "GET /safe/redirect HTTP/1.1");
    let events_text = serde_json::to_string(&audit.list(20).unwrap()).unwrap();
    assert!(!events_text.contains("https-backend-value"));
}

#[test]
fn https_upstream_redirect_to_different_host_is_not_followed() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let redirected = spawn_https_sequence_upstream(|_| {
        vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nredirect-followed"
                .to_vec(),
        ]
    });
    let upstream = spawn_https_sequence_upstream(|_| {
        vec![format!(
            "HTTP/1.1 302 Found\r\nLocation: https://{}/admin\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            redirected.address
        )
        .into_bytes()]
    });
    let profile = https_profile_for(upstream.address, "/safe");
    let proxy = ProxyServer::start(ProxyConfig {
        profiles: vec![profile.clone()],
        profile,
        grants: Vec::new(),
        secret_backend: Arc::new(FakeBackend::new(BTreeMap::from([(
            "github".into(),
            "https-backend-value".into(),
        )]))),
        audit: audit.clone(),
        signer,
        upstream_root_certs_pem: vec![
            upstream.root_cert_pem.as_bytes().to_vec(),
            redirected.root_cert_pem.as_bytes().to_vec(),
        ],
    })
    .unwrap();
    let client = proxied_https_client(&proxy, true);

    let response = client
        .get(format!("https://{}/safe/redirect", upstream.address))
        .send()
        .unwrap();
    assert_eq!(response.status(), 302);
    proxy.stop();
    let upstream_requests = upstream.join();
    let redirected_requests = redirected.join();

    assert_eq!(upstream_requests.len(), 1);
    assert_eq!(redirected_requests.len(), 0);
    let events_text = serde_json::to_string(&audit.list(20).unwrap()).unwrap();
    assert!(!events_text.contains("https-backend-value"));
}

#[test]
fn https_upstream_tls_failure_returns_bad_gateway_without_secret_leak() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let upstream = spawn_https_upstream();
    let profile = https_profile_for(upstream.address, "/safe");
    let proxy = ProxyServer::start(ProxyConfig {
        profiles: vec![profile.clone()],
        profile,
        grants: Vec::new(),
        secret_backend: Arc::new(FakeBackend::new(BTreeMap::from([(
            "github".into(),
            "https-backend-value".into(),
        )]))),
        audit: audit.clone(),
        signer,
        upstream_root_certs_pem: Vec::new(),
    })
    .unwrap();
    let client = proxied_https_client(&proxy, true);

    let response = client
        .get(format!("https://{}/safe/item", upstream.address))
        .send()
        .unwrap();
    assert_eq!(response.status(), 502);
    proxy.stop();
    upstream.join();

    let events_text = serde_json::to_string(&audit.list(20).unwrap()).unwrap();
    assert!(events_text.contains("proxy_upstream_failed"));
    assert!(!events_text.contains("https-backend-value"));
}

#[test]
fn https_connect_rejects_authority_mismatch_inside_tunnel() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let resolve_count = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(CountingBackend {
        resolve_count: Arc::clone(&resolve_count),
    });
    let profile = ProfileConfig {
        id: "github-reader".into(),
        agent: Some("my-agent".into()),
        env_vars: BTreeMap::new(),
        http_resources: vec![HttpResourceConfig {
            id: "github-issues".into(),
            scheme: HttpResourceScheme::Https,
            host: "localhost:9".into(),
            secret_ref: "github".into(),
            auth: HttpAuthConfig::default(),
            allow: HttpAllowConfig {
                methods: vec!["GET".into()],
                path_prefixes: vec!["/safe".into()],
            },
        }],
    };
    let proxy = ProxyServer::start(ProxyConfig {
        profiles: vec![profile.clone()],
        profile,
        grants: Vec::new(),
        secret_backend: backend,
        audit: audit.clone(),
        signer,
        upstream_root_certs_pem: Vec::new(),
    })
    .unwrap();

    let response = send_tunnel_request(
        &proxy,
        "localhost:9",
        "GET https://example.com/safe/item HTTP/1.1\r\nHost: localhost:9\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert_eq!(resolve_count.load(Ordering::SeqCst), 0);
    let events_text = serde_json::to_string(&audit.list(20).unwrap()).unwrap();
    assert!(events_text.contains("invalid_tunnel_target"));
    proxy.stop();
}

#[test]
fn https_denial_records_redacted_proposal_without_secret_resolution() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let resolve_count = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(CountingBackend {
        resolve_count: Arc::clone(&resolve_count),
    });
    let profile = https_profile_for("127.0.0.1:9".parse().unwrap(), "/safe");
    let proxy = ProxyServer::start(ProxyConfig {
        profiles: vec![profile.clone()],
        profile,
        grants: Vec::new(),
        secret_backend: backend,
        audit: audit.clone(),
        signer,
        upstream_root_certs_pem: Vec::new(),
    })
    .unwrap();
    let reqwest_proxy = reqwest::Proxy::all(format!("http://{}", proxy.address()))
        .unwrap()
        .basic_auth("ctxa", proxy.token());
    let client = reqwest::blocking::Client::builder()
        .proxy(reqwest_proxy)
        .add_root_certificate(
            reqwest::Certificate::from_pem(proxy.ca_cert_pem().as_bytes()).unwrap(),
        )
        .build()
        .unwrap();

    let response = client
        .get("https://127.0.0.1:9/unsafe?api_key=raw-query-value")
        .send()
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(resolve_count.load(Ordering::SeqCst), 0);
    let events = audit.list(20).unwrap();
    let proposal = events
        .iter()
        .find(|(_, kind, _)| kind == "proxy_request_proposal")
        .map(|(_, _, value)| value.clone())
        .expect("proposal event");
    let proposal_text = serde_json::to_string(&proposal).unwrap();
    assert!(proposal_text.contains("\"path\":\"/unsafe\""));
    assert!(!proposal_text.contains("raw-query-value"));
    assert!(!proposal_text.contains("counting-backend-value"));

    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["proposals", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("proxy_request_proposal").not())
        .stdout(predicate::str::contains("/unsafe"))
        .stdout(predicate::str::contains("raw-query-value").not());
    proxy.stop();
}

#[test]
fn proposal_apply_enables_denied_https_request_and_receipt_inspection() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let upstream = spawn_https_upstream();
    let upstream_address = upstream.address;
    let upstream_received = Arc::clone(&upstream.received);
    let initial_profile = https_profile_for(upstream.address, "/safe");
    AppConfig {
        profiles: vec![initial_profile.clone()],
        ..AppConfig::default()
    }
    .save(&paths.config_file)
    .unwrap();

    let resolve_count = Arc::new(AtomicUsize::new(0));
    let first_proxy = ProxyServer::start(ProxyConfig {
        profiles: vec![initial_profile.clone()],
        profile: initial_profile,
        grants: Vec::new(),
        secret_backend: Arc::new(CountingBackend {
            resolve_count: Arc::clone(&resolve_count),
        }),
        audit: audit.clone(),
        signer: signer.clone(),
        upstream_root_certs_pem: vec![upstream.root_cert_pem.as_bytes().to_vec()],
    })
    .unwrap();
    let client = proxied_https_client(&first_proxy, true);
    let denied = client
        .get(format!(
            "https://{upstream_address}/unsafe/item?api_key=raw-query-value"
        ))
        .header("Authorization", "Bearer caller-token")
        .body("body must not enter proposal")
        .send()
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(resolve_count.load(Ordering::SeqCst), 0);
    first_proxy.stop();

    let proposals = audit.list_all_kind("proxy_request_proposal").unwrap();
    assert_eq!(proposals.len(), 1);
    let proposal = proposals.first().unwrap().1.clone();
    let proposal_id = proposal["id"].as_str().unwrap().to_string();
    let proposal_text = serde_json::to_string(&proposal).unwrap();
    assert!(proposal_text.contains("\"scheme\":\"https\""));
    assert!(proposal_text.contains("\"path\":\"/unsafe/item\""));
    assert!(!proposal_text.contains("raw-query-value"));
    assert!(!proposal_text.contains("caller-token"));
    assert!(!proposal_text.contains("body must not enter proposal"));

    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["proposals", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&proposal_id))
        .stdout(predicate::str::contains("open"))
        .stdout(predicate::str::contains("raw-query-value").not());
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "proposals",
            "apply",
            &proposal_id,
            "--secret-ref",
            "github",
            "--resource-id",
            "github-unsafe",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("github-unsafe"));
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "proposals",
            "apply",
            &proposal_id,
            "--secret-ref",
            "github",
            "--resource-id",
            "github-unsafe",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("already applied"));
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["proposals", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&proposal_id).not());
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["proposals", "list", "--all"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&proposal_id))
        .stdout(predicate::str::contains("applied"));

    let updated_config = AppConfig::load(&paths.config_file).unwrap();
    let updated_profile = updated_config.profile("github-reader").unwrap().clone();
    assert_eq!(updated_profile.http_resources.len(), 2);
    let applied_resource = updated_profile
        .http_resources
        .iter()
        .find(|resource| resource.id == "github-unsafe")
        .unwrap();
    assert_eq!(applied_resource.scheme, HttpResourceScheme::Https);
    assert_eq!(applied_resource.host, upstream_address.to_string());
    assert_eq!(applied_resource.secret_ref, "github");
    assert_eq!(applied_resource.allow.path_prefixes, vec!["/unsafe/item"]);

    let second_proxy = ProxyServer::start(ProxyConfig {
        profiles: vec![updated_profile.clone()],
        profile: updated_profile,
        grants: Vec::new(),
        secret_backend: Arc::new(FakeBackend::new(BTreeMap::from([(
            "github".into(),
            "https-backend-value".into(),
        )]))),
        audit: audit.clone(),
        signer: signer.clone(),
        upstream_root_certs_pem: vec![upstream.root_cert_pem.as_bytes().to_vec()],
    })
    .unwrap();
    let client = proxied_https_client(&second_proxy, true);
    let allowed = client
        .get(format!(
            "https://{upstream_address}/unsafe/item?api_key=raw-query-value"
        ))
        .send()
        .unwrap();
    assert_eq!(allowed.status(), 200);
    assert_eq!(allowed.text().unwrap(), "ok");
    second_proxy.stop();
    upstream.join();
    let received = upstream_received.lock().unwrap().clone().expect("request");
    assert_eq!(
        received.request_line,
        "GET /unsafe/item?api_key=raw-query-value HTTP/1.1"
    );
    assert_eq!(
        header(&received.headers, "authorization"),
        Some("Bearer https-backend-value")
    );

    let receipt_value = audit
        .list_all_kind("proxy_request_receipt")
        .unwrap()
        .first()
        .unwrap()
        .1
        .clone();
    let receipt: Receipt = serde_json::from_value(receipt_value.clone()).unwrap();
    signer.verify_local_receipt(&receipt).unwrap();
    assert_eq!(receipt.resource, "github-unsafe");
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["receipts", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&receipt.receipt_id))
        .stdout(predicate::str::contains("github-unsafe"));
    let show_output = ctxa()
        .env("CTXA_HOME", home.path())
        .args(["receipts", "show", &receipt.receipt_id])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let shown: Receipt = serde_json::from_slice(&show_output).unwrap();
    signer.verify_local_receipt(&shown).unwrap();
}

#[test]
fn proposal_dismiss_hides_open_proposal() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    audit
        .record(
            "proxy_request_proposal",
            &serde_json::json!({
                "id": "prop_dismiss_me",
                "profile": "demo",
                "agent": "demo",
                "capability": "http.request",
                "scheme": "https",
                "method": "GET",
                "host": "api.example.com:443",
                "path": "/safe",
                "query_present": false,
                "reason": "no_matching_authority",
            }),
        )
        .unwrap();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "proposals",
            "dismiss",
            "prop_dismiss_me",
            "--reason",
            "not needed\nwith newline",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["proposals", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("prop_dismiss_me").not());
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["proposals", "show", "prop_dismiss_me"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"dismissed\""));
    let dismiss_event = audit
        .list_all_kind("proxy_request_proposal_dismissed")
        .unwrap()
        .first()
        .unwrap()
        .1
        .clone();
    assert_eq!(dismiss_event["reason"], "not needed with newline");
}

#[test]
fn grant_cli_delegates_without_secret_copy_and_audits() {
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["profile", "create", "main-agent", "--agent", "main-agent"])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "profile",
            "create",
            "worker-agent",
            "--agent",
            "worker-agent",
        ])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "grants",
            "create-https",
            "--id",
            "github-root",
            "--profile",
            "main-agent",
            "--host",
            "api.github.com",
            "--secret-ref",
            "op://example-vault/github-token/token",
            "--allow-method",
            "GET",
            "--path-prefix",
            "/repos/acme/app",
            "--delegable",
            "--max-depth",
            "2",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("op://").not());
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "grants",
            "delegate",
            "--from",
            "github-root",
            "--id",
            "github-issues",
            "--profile",
            "worker-agent",
            "--allow-method",
            "GET",
            "--path-prefix",
            "/repos/acme/app/issues",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("github-issues"));
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "grants",
            "delegate",
            "--from",
            "github-root",
            "--id",
            "github-admin",
            "--profile",
            "worker-agent",
            "--allow-method",
            "GET",
            "--path-prefix",
            "/repos/acme",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("path_prefix"));
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["grants", "show", "github-root"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"has_secret_ref\": true"))
        .stdout(predicate::str::contains("op://").not());
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "profile",
            "test",
            "worker-agent",
            "--url",
            "https://api.github.com/repos/acme/app/issues/1",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("allowed authority=github-issues"));

    let config = AppConfig::load(&home.path().join("config.yaml")).unwrap();
    let child = config.grant("github-issues").unwrap();
    assert_eq!(child.secret_ref, None);
    assert_eq!(child.parent.as_deref(), Some("github-root"));

    let audit = AuditLog::open(home.path().join("audit.sqlite3")).unwrap();
    let text = serde_json::to_string(&audit.list_all().unwrap()).unwrap();
    assert!(text.contains("grant_created"));
    assert!(text.contains("grant_delegated"));
    assert!(!text.contains("op://example-vault/github-token/token"));
}

#[test]
fn grant_backed_proxy_request_uses_root_secret_and_receipts_chain() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().into());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let upstream = spawn_https_upstream();
    let worker_profile = ProfileConfig {
        id: "worker-agent".into(),
        agent: Some("worker-agent".into()),
        env_vars: BTreeMap::new(),
        http_resources: Vec::new(),
    };
    let grants = vec![
        HttpGrantConfig {
            id: "github-root".into(),
            parent: None,
            profile: "main-agent".into(),
            subject: "main-agent".into(),
            scheme: HttpResourceScheme::Https,
            host: upstream.address.to_string(),
            secret_ref: Some("github".into()),
            allow: HttpAllowConfig {
                methods: vec!["GET".into(), "POST".into()],
                path_prefixes: vec!["/repos/acme/app".into()],
            },
            delegation: GrantDelegationConfig {
                allowed: true,
                remaining_depth: 2,
            },
        },
        HttpGrantConfig {
            id: "github-issues".into(),
            parent: Some("github-root".into()),
            profile: "worker-agent".into(),
            subject: "worker-agent".into(),
            scheme: HttpResourceScheme::Https,
            host: upstream.address.to_string(),
            secret_ref: None,
            allow: HttpAllowConfig {
                methods: vec!["GET".into()],
                path_prefixes: vec!["/repos/acme/app/issues".into()],
            },
            delegation: GrantDelegationConfig::default(),
        },
    ];
    AppConfig {
        profiles: vec![
            ProfileConfig {
                id: "main-agent".into(),
                agent: Some("main-agent".into()),
                env_vars: BTreeMap::new(),
                http_resources: Vec::new(),
            },
            worker_profile.clone(),
        ],
        grants: grants.clone(),
        ..Default::default()
    }
    .save(&paths.config_file)
    .unwrap();

    let proxy = ProxyServer::start(ProxyConfig {
        profiles: vec![
            ProfileConfig {
                id: "main-agent".into(),
                agent: Some("main-agent".into()),
                env_vars: BTreeMap::new(),
                http_resources: Vec::new(),
            },
            worker_profile.clone(),
        ],
        profile: worker_profile,
        grants,
        secret_backend: Arc::new(FakeBackend::new(BTreeMap::from([(
            "github".into(),
            "grant-backed-secret".into(),
        )]))),
        audit: audit.clone(),
        signer,
        upstream_root_certs_pem: vec![upstream.root_cert_pem.as_bytes().to_vec()],
    })
    .unwrap();
    let client = proxied_https_client(&proxy, true);
    let response = client
        .get(format!(
            "https://{}/repos/acme/app/issues/1",
            upstream.address
        ))
        .send()
        .unwrap();
    assert_eq!(response.status(), 200);

    let received = upstream.received.lock().unwrap().clone().unwrap();
    assert_eq!(
        header(&received.headers, "Authorization"),
        Some("Bearer grant-backed-secret")
    );
    let receipts = audit.list_all_kind("proxy_request_receipt").unwrap();
    assert_eq!(receipts.len(), 1);
    let receipt = receipts.first().unwrap().1.clone();
    assert_eq!(receipt["resource"], "github-issues");
    assert_eq!(
        receipt["execution"]["result"]["grant_chain_ids"],
        serde_json::json!(["github-root", "github-issues"])
    );
    let receipt_text = serde_json::to_string(&receipt).unwrap();
    assert!(!receipt_text.contains("grant-backed-secret"));
    assert!(!receipt_text.contains("op://"));

    proxy.stop();
    upstream.join();
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
        profiles: vec![profile.clone()],
        profile,
        grants: Vec::new(),
        secret_backend: backend,
        audit: audit.clone(),
        signer,
        upstream_root_certs_pem: Vec::new(),
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
    assert!(!events_text.contains("bad\\r\\nX-Leak"));
    assert!(!events_text.contains("bad\r\nX-Leak"));
    proxy.stop();
}

#[test]
fn proxy_start_rejects_duplicate_grant_ids() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let profile = ProfileConfig {
        id: "worker".into(),
        agent: Some("worker".into()),
        env_vars: BTreeMap::new(),
        http_resources: Vec::new(),
    };
    let grant = HttpGrantConfig {
        id: "dup".into(),
        parent: None,
        profile: "worker".into(),
        subject: "worker".into(),
        scheme: HttpResourceScheme::Http,
        host: "api.example.com".into(),
        secret_ref: Some("github".into()),
        allow: HttpAllowConfig {
            methods: vec!["GET".into()],
            path_prefixes: vec!["/safe".into()],
        },
        delegation: GrantDelegationConfig::default(),
    };

    let err = match ProxyServer::start(ProxyConfig {
        profiles: vec![profile.clone()],
        profile,
        grants: vec![grant.clone(), grant],
        secret_backend: Arc::new(FakeBackend::new(BTreeMap::new())),
        audit,
        signer,
        upstream_root_certs_pem: Vec::new(),
    }) {
        Ok(_) => panic!("proxy started with duplicate grant ids"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("duplicate grant id dup"), "{err}");
}

#[test]
fn proxy_start_rejects_active_profile_drift() {
    let home = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_home(home.path().to_path_buf());
    paths.ensure().unwrap();
    let audit = AuditLog::open(&paths.audit_db).unwrap();
    let signer = ReceiptSigner::load_or_create(&paths).unwrap();
    let listed_profile = ProfileConfig {
        id: "worker".into(),
        agent: Some("worker".into()),
        env_vars: BTreeMap::new(),
        http_resources: Vec::new(),
    };
    let active_profile = ProfileConfig {
        agent: Some("different-worker".into()),
        ..listed_profile.clone()
    };
    let grant = HttpGrantConfig {
        id: "worker-root".into(),
        parent: None,
        profile: "worker".into(),
        subject: "worker".into(),
        scheme: HttpResourceScheme::Http,
        host: "api.example.com".into(),
        secret_ref: Some("github".into()),
        allow: HttpAllowConfig {
            methods: vec!["GET".into()],
            path_prefixes: vec!["/safe".into()],
        },
        delegation: GrantDelegationConfig::default(),
    };

    let err = match ProxyServer::start(ProxyConfig {
        profiles: vec![listed_profile],
        profile: active_profile,
        grants: vec![grant],
        secret_backend: Arc::new(FakeBackend::new(BTreeMap::new())),
        audit,
        signer,
        upstream_root_certs_pem: Vec::new(),
    }) {
        Ok(_) => panic!("proxy started with active profile drift"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("active proxy profile worker must match"),
        "{err}"
    );
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
        profiles: vec![profile.clone()],
        profile,
        grants: Vec::new(),
        secret_backend: backend,
        audit: audit.clone(),
        signer,
        upstream_root_certs_pem: Vec::new(),
    })
    .unwrap();

    let no_auth = send_proxy_request(
        proxy.address(),
        "GET http://127.0.0.1:9/safe/item HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n",
    );
    assert!(no_auth.starts_with("HTTP/1.1 407"), "{no_auth}");

    let no_auth_connect = send_proxy_request(
        proxy.address(),
        "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n",
    );
    assert!(
        no_auth_connect.starts_with("HTTP/1.1 407"),
        "{no_auth_connect}"
    );

    let bad_path = send_proxy_request(
        proxy.address(),
        &format!(
            "GET http://127.0.0.1:9/unsafe HTTP/1.1\r\nProxy-Authorization: Bearer {}\r\n\r\n",
            proxy.token()
        ),
    );
    assert!(bad_path.starts_with("HTTP/1.1 403"), "{bad_path}");
    let proposals = audit.list_all_kind("proxy_request_proposal").unwrap();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].1["path"], "/unsafe");

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
    assert_eq!(
        audit.list_all_kind("proxy_request_proposal").unwrap().len(),
        2
    );

    proxy.stop();
}

fn profile_for(address: SocketAddr, path_prefix: &str) -> ProfileConfig {
    ProfileConfig {
        id: "github-reader".into(),
        agent: Some("my-agent".into()),
        env_vars: BTreeMap::new(),
        http_resources: vec![HttpResourceConfig {
            id: "github-issues".into(),
            scheme: HttpResourceScheme::Http,
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

fn https_profile_for(address: SocketAddr, path_prefix: &str) -> ProfileConfig {
    ProfileConfig {
        id: "github-reader".into(),
        agent: Some("my-agent".into()),
        env_vars: BTreeMap::new(),
        http_resources: vec![HttpResourceConfig {
            id: "github-issues".into(),
            scheme: HttpResourceScheme::Https,
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

fn proxied_https_client(proxy: &ProxyServer, disable_redirects: bool) -> reqwest::blocking::Client {
    let reqwest_proxy = reqwest::Proxy::all(format!("http://{}", proxy.address()))
        .unwrap()
        .basic_auth("ctxa", proxy.token());
    let mut builder = reqwest::blocking::Client::builder()
        .proxy(reqwest_proxy)
        .add_root_certificate(
            reqwest::Certificate::from_pem(proxy.ca_cert_pem().as_bytes()).unwrap(),
        );
    if disable_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }
    builder.build().unwrap()
}

fn send_tunnel_request(proxy: &ProxyServer, connect_target: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(proxy.address()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let credential =
        base64::engine::general_purpose::STANDARD.encode(format!("ctxa:{}", proxy.token()));
    write!(
        stream,
        "CONNECT {connect_target} HTTP/1.1\r\nHost: {connect_target}\r\nProxy-Authorization: Basic {credential}\r\n\r\n"
    )
    .unwrap();
    let connect_response = read_headers(&mut stream);
    assert!(
        connect_response.starts_with(b"HTTP/1.1 200 Connection Established"),
        "{}",
        String::from_utf8_lossy(&connect_response)
    );

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(&rustls::Certificate(pem_to_der(proxy.ca_cert_pem())))
        .unwrap();
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let host = connect_target.split(':').next().unwrap();
    let server_name = rustls::ServerName::try_from(host).unwrap();
    let mut client = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls = rustls::Stream::new(&mut client, &mut stream);
    tls.write_all(request.as_bytes()).unwrap();
    tls.flush().unwrap();
    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => panic!("failed to read tunnel response: {err}"),
        }
    }
    String::from_utf8(response).unwrap()
}

fn read_headers(stream: &mut impl Read) -> Vec<u8> {
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
    buffer
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let encoded: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap()
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[derive(Clone, Debug)]
struct ReceivedRequest {
    request_line: String,
    headers: Vec<(String, String)>,
}

struct Upstream {
    address: SocketAddr,
    root_cert_pem: String,
    received: Arc<Mutex<Option<ReceivedRequest>>>,
    thread: Option<thread::JoinHandle<()>>,
}

struct SequenceUpstream {
    address: SocketAddr,
    root_cert_pem: String,
    received: Arc<Mutex<Vec<ReceivedRequest>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SequenceUpstream {
    fn join(mut self) -> Vec<ReceivedRequest> {
        self.thread.take().unwrap().join().unwrap();
        self.received.lock().unwrap().clone()
    }
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
        root_cert_pem: String::new(),
        received,
        thread: Some(thread),
    }
}

fn spawn_https_upstream() -> Upstream {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let (root_cert_pem, server_config) = test_https_server_config();
    let received = Arc::new(Mutex::new(None));
    let received_for_thread = Arc::clone(&received);
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut tls = rustls::Stream::new(&mut server, &mut stream);
        let Some(request) = read_https_request(&mut tls) else {
            return;
        };
        *received_for_thread.lock().unwrap() = Some(request);
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
        tls.flush().unwrap();
    });
    Upstream {
        address,
        root_cert_pem,
        received,
        thread: Some(thread),
    }
}

fn spawn_https_sequence_upstream(
    response_builder: impl FnOnce(SocketAddr) -> Vec<Vec<u8>>,
) -> SequenceUpstream {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let responses = response_builder(address);
    let (root_cert_pem, server_config) = test_https_server_config();
    let server_config = Arc::new(server_config);
    let received = Arc::new(Mutex::new(Vec::new()));
    let received_for_thread = Arc::clone(&received);
    let thread = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut next_response = 0;
        while next_response < responses.len() && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut server =
                        rustls::ServerConnection::new(Arc::clone(&server_config)).unwrap();
                    let mut tls = rustls::Stream::new(&mut server, &mut stream);
                    if let Some(request) = read_https_request(&mut tls) {
                        received_for_thread.lock().unwrap().push(request);
                    }
                    tls.write_all(&responses[next_response]).unwrap();
                    tls.flush().unwrap();
                    next_response += 1;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("accept failed: {err}"),
            }
        }
    });
    SequenceUpstream {
        address,
        root_cert_pem,
        received,
        thread: Some(thread),
    }
}

fn read_https_request(stream: &mut impl Read) -> Option<ReceivedRequest> {
    let mut buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = match stream.read(&mut byte) {
            Ok(read) => read,
            Err(_) => return None,
        };
        if read == 0 {
            break;
        }
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if buffer.is_empty() {
        return None;
    }
    let text = String::from_utf8(buffer).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?.to_string();
    let headers = lines
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.to_string(), value.trim_start().to_string()))
        })
        .collect();
    Some(ReceivedRequest {
        request_line,
        headers,
    })
}

fn test_https_server_config() -> (String, rustls::ServerConfig) {
    let mut root_params = CertificateParams::default();
    root_params.distinguished_name = DistinguishedName::new();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "ctxa test upstream CA");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let root = Certificate::from_params(root_params).unwrap();
    let root_pem = root.serialize_pem().unwrap();
    let root_der = root.serialize_der().unwrap();

    let mut leaf_params = CertificateParams::default();
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.subject_alt_names =
        vec![SanType::IpAddress("127.0.0.1".parse::<IpAddr>().unwrap())];
    let leaf = Certificate::from_params(leaf_params).unwrap();
    let leaf_der = leaf.serialize_der_with_signer(&root).unwrap();
    let key = leaf.serialize_private_key_der();
    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::Certificate(leaf_der), rustls::Certificate(root_der)],
            rustls::PrivateKey(key),
        )
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (root_pem, config)
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
