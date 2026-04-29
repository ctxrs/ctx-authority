use assert_cmd::Command;
use base64::Engine;
use ctxa::audit::AuditLog;
use ctxa::backends::{FakeBackend, SecretBackend, SecretBackendConfig, SecretLease};
use ctxa::config::{
    AppConfig, AppPaths, HttpAllowConfig, HttpAuthConfig, HttpResourceConfig, HttpResourceScheme,
    ProfileConfig,
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn ctxa() -> Command {
    Command::cargo_bin("ctxa").expect("ctxa binary")
}

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
        .stdout(predicate::str::contains("allowed resource=github-issues"));
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
        .stdout(predicate::str::contains("HTTPS_PROXY=http://ctxa:"))
        .stdout(predicate::str::contains("CTXA_PROXY_URL=http://ctxa:"))
        .stdout(predicate::str::contains("SSL_CERT_FILE="))
        .stdout(predicate::str::contains("REQUESTS_CA_BUNDLE="))
        .stdout(predicate::str::contains("CURL_CA_BUNDLE="))
        .stdout(predicate::str::contains(
            "GITHUB_API_BASE=http://api.github.com",
        ))
        .stdout(predicate::str::contains("run-hidden-value").not());
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
        profile,
        secret_backend: backend,
        audit: audit.clone(),
        signer: signer.clone(),
        upstream_root_certs_pem: Vec::new(),
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
        profile,
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
        profile,
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
        profile,
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
        profile,
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
        profile,
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
        profile,
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
