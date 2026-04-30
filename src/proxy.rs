use crate::audit::AuditLog;
use crate::backends::SecretBackend;
use crate::config::{
    canonical_host_port_for_scheme, HttpAuthType, HttpGrantConfig, HttpResourceConfig,
    HttpResourceScheme, ProfileConfig,
};
use crate::grants::{matching_grant, validate_http_grants, GrantMatch};
use crate::models::{ActionRequest, ProviderExecution, Receipt};
use crate::policy::http_path_matches_prefix;
use crate::receipts::{payload_hash, ReceiptSigner};
use crate::{AuthorityError, Result};
use base64::Engine;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, SanType,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tempfile::NamedTempFile;
use uuid::Uuid;

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONCURRENT_REQUESTS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_SLEEP: Duration = Duration::from_millis(25);

pub struct ProxyConfig {
    pub profiles: Vec<ProfileConfig>,
    pub profile: ProfileConfig,
    pub grants: Vec<HttpGrantConfig>,
    pub secret_backend: Arc<dyn SecretBackend>,
    pub audit: AuditLog,
    pub signer: ReceiptSigner,
    pub upstream_root_certs_pem: Vec<Vec<u8>>,
}

pub struct ProxyServer {
    address: SocketAddr,
    token: String,
    ca_cert_file: NamedTempFile,
    ca: Arc<LocalCa>,
    shutdown: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl ProxyServer {
    pub fn start(config: ProxyConfig) -> Result<Self> {
        config.profile.validate()?;
        let profiles = if config.profiles.is_empty() {
            vec![config.profile.clone()]
        } else {
            config.profiles.clone()
        };
        for profile in &profiles {
            profile.validate()?;
        }
        ensure_unique_proxy_profiles(&profiles)?;
        ensure_active_profile_matches(&config.profile, &profiles)?;
        ensure_unique_proxy_grants(&config.grants)?;
        for grant in &config.grants {
            grant.validate()?;
        }
        validate_http_grants(&profiles, &config.grants)?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let token = Uuid::new_v4().to_string();
        let (ca, ca_cert_file) = LocalCa::generate()?;
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let workers = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(ProxyState {
            config,
            token: token.clone(),
            ca: Arc::clone(&ca),
            in_flight: AtomicUsize::new(0),
            workers: Arc::clone(&workers),
        });
        let thread = thread::spawn(move || accept_loop(listener, state, shutdown_rx));
        Ok(Self {
            address,
            token,
            ca_cert_file,
            ca,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
            workers,
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn proxy_url(&self) -> String {
        format!("http://ctxa:{}@{}", self.token, self.address)
    }

    pub fn ca_cert_path(&self) -> &std::path::Path {
        self.ca_cert_file.path()
    }

    pub fn ca_cert_pem(&self) -> &str {
        self.ca.ca_cert_pem()
    }

    pub fn stop(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Ok(mut workers) = self.workers.lock() {
            while let Some(worker) = workers.pop() {
                let _ = worker.join();
            }
        }
    }
}

fn ensure_unique_proxy_profiles(profiles: &[ProfileConfig]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for profile in profiles {
        if !seen.insert(profile.id.as_str()) {
            return Err(AuthorityError::Config(format!(
                "duplicate profile id {}",
                profile.id
            )));
        }
    }
    Ok(())
}

fn ensure_active_profile_matches(active: &ProfileConfig, profiles: &[ProfileConfig]) -> Result<()> {
    if profiles.iter().any(|profile| profile == active) {
        return Ok(());
    }
    Err(AuthorityError::Config(format!(
        "active proxy profile {} must match a supplied profile entry",
        active.id
    )))
}

fn ensure_unique_proxy_grants(grants: &[HttpGrantConfig]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for grant in grants {
        if !seen.insert(grant.id.as_str()) {
            return Err(AuthorityError::Config(format!(
                "duplicate grant id {}",
                grant.id
            )));
        }
    }
    Ok(())
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

struct ProxyState {
    config: ProxyConfig,
    token: String,
    ca: Arc<LocalCa>,
    in_flight: AtomicUsize,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

pub fn can_create_process_ca_file() -> Result<()> {
    let (_ca, _file) = LocalCa::generate()?;
    Ok(())
}

struct LocalCa {
    certificate: Mutex<Certificate>,
    ca_der: Vec<u8>,
    ca_cert_pem: String,
    server_configs: Mutex<BTreeMap<String, Arc<rustls::ServerConfig>>>,
}

impl LocalCa {
    fn generate() -> Result<(Arc<Self>, NamedTempFile)> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "ctxa local proxy");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let certificate = Certificate::from_params(params)
            .map_err(|_| AuthorityError::Config("failed to create local CA".into()))?;
        let ca_cert_pem = certificate
            .serialize_pem()
            .map_err(|_| AuthorityError::Config("failed to serialize local CA".into()))?;
        let ca_der = certificate
            .serialize_der()
            .map_err(|_| AuthorityError::Config("failed to serialize local CA".into()))?;
        let mut ca_cert_file = NamedTempFile::new()?;
        ca_cert_file.write_all(ca_cert_pem.as_bytes())?;
        ca_cert_file.flush()?;
        Ok((
            Arc::new(Self {
                certificate: Mutex::new(certificate),
                ca_der,
                ca_cert_pem,
                server_configs: Mutex::new(BTreeMap::new()),
            }),
            ca_cert_file,
        ))
    }

    fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    fn server_config_for_host(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        if let Ok(cache) = self.server_configs.lock() {
            if let Some(config) = cache.get(host) {
                return Ok(Arc::clone(config));
            }
        }
        let config = Arc::new(self.build_server_config(host)?);
        let mut cache = self
            .server_configs
            .lock()
            .map_err(|_| AuthorityError::Config("local CA cache unavailable".into()))?;
        Ok(Arc::clone(cache.entry(host.to_string()).or_insert(config)))
    }

    fn build_server_config(&self, host: &str) -> Result<rustls::ServerConfig> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.subject_alt_names = match host.parse::<IpAddr>() {
            Ok(ip) => vec![SanType::IpAddress(ip)],
            Err(_) => vec![SanType::DnsName(host.to_string())],
        };
        let leaf = Certificate::from_params(params)
            .map_err(|_| AuthorityError::Config("failed to create leaf certificate".into()))?;
        let ca = self
            .certificate
            .lock()
            .map_err(|_| AuthorityError::Config("local CA unavailable".into()))?;
        let leaf_der = leaf
            .serialize_der_with_signer(&ca)
            .map_err(|_| AuthorityError::Config("failed to sign leaf certificate".into()))?;
        let leaf_key = leaf.serialize_private_key_der();
        let mut config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(
                vec![
                    rustls::Certificate(leaf_der),
                    rustls::Certificate(self.ca_der.clone()),
                ],
                rustls::PrivateKey(leaf_key),
            )
            .map_err(|_| AuthorityError::Config("failed to build TLS server config".into()))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

fn accept_loop(listener: TcpListener, state: Arc<ProxyState>, shutdown_rx: mpsc::Receiver<()>) {
    loop {
        if shutdown_rx.try_recv().is_ok() {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if state.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_CONCURRENT_REQUESTS {
                    state.in_flight.fetch_sub(1, Ordering::SeqCst);
                    let mut stream = stream;
                    let _ = write_simple_response(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "too many proxy requests",
                    );
                    continue;
                }
                let worker_state = Arc::clone(&state);
                let worker = thread::spawn(move || {
                    handle_connection(stream, &worker_state);
                    worker_state.in_flight.fetch_sub(1, Ordering::SeqCst);
                });
                if let Ok(mut workers) = state.workers.lock() {
                    workers.push(worker);
                } else {
                    let _ = worker.join();
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_SLEEP);
            }
            Err(_) => break,
        }
    }
}

fn handle_connection(mut stream: TcpStream, state: &ProxyState) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    match handle_request(&mut stream, state) {
        Ok(()) => {}
        Err(ProxyFailure {
            status,
            reason,
            body,
            audit_kind,
            audit_data,
        }) => {
            record_failure(state, status, &body, audit_kind, audit_data);
            let _ = write_simple_response(&mut stream, status, &reason, &body);
        }
    }
}

fn record_failure(
    state: &ProxyState,
    status: u16,
    body: &str,
    audit_kind: Option<String>,
    audit_data: serde_json::Value,
) {
    let (kind, data) = audit_kind
        .map(|kind| (kind, audit_data))
        .unwrap_or_else(|| {
            (
                "proxy_request_rejected".into(),
                json!({
                    "status": status,
                    "reason": body,
                }),
            )
        });
    let _ = state.config.audit.record(&kind, &data);
}

fn handle_request(
    stream: &mut TcpStream,
    state: &ProxyState,
) -> std::result::Result<(), ProxyFailure> {
    let request = read_proxy_request(stream)?;
    if !proxy_authorized(&request.headers, &state.token) {
        return Err(ProxyFailure::new(
            407,
            "Proxy Authentication Required",
            "proxy authorization required",
            Some("proxy_auth_failed"),
            json!({"reason": "missing_or_invalid_proxy_authorization"}),
        ));
    }
    if request.method.eq_ignore_ascii_case("CONNECT") {
        return handle_connect_request(stream, state, request);
    }
    let method = canonical_method(&request.method).map_err(|failure| {
        failure.with_audit(
            "proxy_request_rejected",
            json!({"reason": "invalid_method"}),
        )
    })?;
    let target =
        parse_absolute_target(&request.target, HttpResourceScheme::Http).map_err(|failure| {
            failure.with_audit(
                "proxy_request_rejected",
                json!({"reason": "invalid_target"}),
            )
        })?;
    execute_proxy_request(
        stream,
        state,
        &request,
        &target,
        &method,
        HttpResourceScheme::Http,
    )
}

fn handle_connect_request(
    stream: &mut TcpStream,
    state: &ProxyState,
    request: ProxyRequest,
) -> std::result::Result<(), ProxyFailure> {
    if !request.body.is_empty() {
        return Err(ProxyFailure::new(
            400,
            "Bad Request",
            "CONNECT request body is not supported",
            Some("proxy_request_rejected"),
            json!({"reason": "connect_body_not_supported"}),
        ));
    }
    let connect_target = parse_connect_target(&request.target).map_err(|failure| {
        failure.with_audit(
            "proxy_request_rejected",
            json!({"reason": "invalid_connect_target"}),
        )
    })?;
    write_connect_established(stream)
        .map_err(|_| ProxyFailure::without_audit(504, "Gateway Timeout", "client write failed"))?;
    let server_config = state
        .ca
        .server_config_for_host(&connect_target.host)
        .map_err(|_| {
            ProxyFailure::new(
                502,
                "Bad Gateway",
                "local TLS setup failed",
                Some("proxy_tls_failed"),
                json!({
                    "profile": state.config.profile.id,
                    "host": connect_target.canonical_host_port,
                    "reason": "local_tls_setup_failed",
                }),
            )
        })?;
    let mut server = rustls::ServerConnection::new(server_config).map_err(|_| {
        ProxyFailure::new(
            502,
            "Bad Gateway",
            "local TLS setup failed",
            Some("proxy_tls_failed"),
            json!({
                "profile": state.config.profile.id,
                "host": connect_target.canonical_host_port,
                "reason": "local_tls_connection_failed",
            }),
        )
    })?;
    let mut tls = rustls::Stream::new(&mut server, stream);
    let inner = match read_proxy_request(&mut tls) {
        Ok(inner) => inner,
        Err(failure) => {
            let failure = failure.with_audit(
                "proxy_request_rejected",
                json!({
                    "profile": state.config.profile.id,
                    "host": connect_target.canonical_host_port,
                    "reason": "invalid_tunnel_request",
                }),
            );
            write_failure_inside_tunnel(&mut tls, state, failure);
            return Ok(());
        }
    };
    if inner.method.eq_ignore_ascii_case("CONNECT") {
        write_failure_inside_tunnel(
            &mut tls,
            state,
            ProxyFailure::new(
                400,
                "Bad Request",
                "nested CONNECT is not supported",
                Some("proxy_request_rejected"),
                json!({
                    "profile": state.config.profile.id,
                    "host": connect_target.canonical_host_port,
                    "reason": "nested_connect_not_supported",
                }),
            ),
        );
        return Ok(());
    }
    let method = match canonical_method(&inner.method) {
        Ok(method) => method,
        Err(failure) => {
            let failure = failure.with_audit(
                "proxy_request_rejected",
                json!({
                    "profile": state.config.profile.id,
                    "host": connect_target.canonical_host_port,
                    "reason": "invalid_method",
                }),
            );
            write_failure_inside_tunnel(&mut tls, state, failure);
            return Ok(());
        }
    };
    let target = match parse_tunnel_target(&inner, &connect_target) {
        Ok(target) => target,
        Err(failure) => {
            let failure = failure.with_audit(
                "proxy_request_rejected",
                json!({
                    "profile": state.config.profile.id,
                    "host": connect_target.canonical_host_port,
                    "reason": "invalid_tunnel_target",
                }),
            );
            write_failure_inside_tunnel(&mut tls, state, failure);
            return Ok(());
        }
    };
    if let Err(failure) = execute_proxy_request(
        &mut tls,
        state,
        &inner,
        &target,
        &method,
        HttpResourceScheme::Https,
    ) {
        write_failure_inside_tunnel(&mut tls, state, failure);
    }
    Ok(())
}

fn write_failure_inside_tunnel(stream: &mut impl Write, state: &ProxyState, failure: ProxyFailure) {
    record_failure(
        state,
        failure.status,
        &failure.body,
        failure.audit_kind.clone(),
        failure.audit_data.clone(),
    );
    let _ = write_simple_response(stream, failure.status, &failure.reason, &failure.body);
}

fn execute_proxy_request(
    stream: &mut impl Write,
    state: &ProxyState,
    request: &ProxyRequest,
    target: &ProxyTarget,
    method: &str,
    scheme: HttpResourceScheme,
) -> std::result::Result<(), ProxyFailure> {
    let Some(authority) = find_authority(
        &state.config.profile,
        &state.config.grants,
        scheme,
        &target.canonical_host_port,
        method,
        &target.path,
    )
    .map_err(|_| {
        ProxyFailure::new(
            403,
            "Forbidden",
            "request is not allowed by this profile",
            Some("proxy_request_denied"),
            json!({
                "profile": state.config.profile.id,
                "reason": "invalid_grant_chain",
                "method": method,
                "host": target.canonical_host_port,
                "path": target.path,
                "query_present": target.query.is_some(),
                "scheme": scheme_name(scheme),
            }),
        )
    })?
    else {
        record_proxy_proposal(state, method, scheme, target, "no_matching_authority");
        return Err(ProxyFailure::new(
            403,
            "Forbidden",
            "request is not allowed by this profile",
            Some("proxy_request_denied"),
            json!({
                "profile": state.config.profile.id,
                "reason": "no_matching_authority",
                "method": method,
                "host": target.canonical_host_port,
                "path": target.path,
                "query_present": target.query.is_some(),
                "scheme": scheme_name(scheme),
            }),
        ));
    };
    let resource_id = authority.id().to_string();
    let secret = state
        .config
        .secret_backend
        .resolve(authority.secret_ref())
        .map_err(|_| {
            ProxyFailure::new(
                502,
                "Bad Gateway",
                "secret backend resolution failed",
                Some("proxy_secret_failed"),
                json!({
                    "profile": state.config.profile.id,
                    "resource": resource_id,
                    "method": method,
                    "host": target.canonical_host_port,
                    "path": target.path,
                    "query_present": target.query.is_some(),
                    "scheme": scheme_name(scheme),
                }),
            )
        })?;

    let response = forward_request(
        request,
        target,
        method,
        scheme,
        secret.expose_to_provider(),
        &state.config.upstream_root_certs_pem,
    )
    .map_err(|failure| {
        ProxyFailure::new(
            failure.status,
            &failure.reason,
            &failure.body,
            Some("proxy_upstream_failed"),
            json!({
                "profile": state.config.profile.id,
                "resource": resource_id,
                "method": method,
                "host": target.canonical_host_port,
                "path": target.path,
                "query_present": target.query.is_some(),
                "scheme": scheme_name(scheme),
                "reason": failure.audit_reason,
            }),
        )
    })?;

    let receipt = issue_proxy_receipt(
        state,
        &authority,
        target,
        method,
        scheme,
        &request.body,
        response.status_code,
    )
    .map_err(|_| {
        ProxyFailure::new(
            502,
            "Bad Gateway",
            "receipt issuance failed",
            Some("proxy_receipt_failed"),
            json!({
                "profile": state.config.profile.id,
                "resource": resource_id,
                "method": method,
                "host": target.canonical_host_port,
                "path": target.path,
                "query_present": target.query.is_some(),
                "scheme": scheme_name(scheme),
            }),
        )
    })?;
    let value = serde_json::to_value(&receipt).map_err(|_| {
        ProxyFailure::new(
            502,
            "Bad Gateway",
            "receipt serialization failed",
            Some("proxy_receipt_failed"),
            json!({
                "profile": state.config.profile.id,
                "resource": resource_id,
                "method": method,
                "host": target.canonical_host_port,
                "path": target.path,
                "query_present": target.query.is_some(),
                "scheme": scheme_name(scheme),
            }),
        )
    })?;
    state
        .config
        .audit
        .record("proxy_request_receipt", &value)
        .map_err(|_| {
            ProxyFailure::new(
                502,
                "Bad Gateway",
                "receipt audit write failed",
                Some("proxy_receipt_failed"),
                json!({
                    "profile": state.config.profile.id,
                    "resource": resource_id,
                    "method": method,
                    "host": target.canonical_host_port,
                    "path": target.path,
                    "query_present": target.query.is_some(),
                    "scheme": scheme_name(scheme),
                }),
            )
        })?;
    stream
        .write_all(&response.bytes)
        .map_err(|_| ProxyFailure::without_audit(504, "Gateway Timeout", "client write failed"))?;
    Ok(())
}

fn read_proxy_request(stream: &mut impl Read) -> std::result::Result<ProxyRequest, ProxyFailure> {
    let mut buffer = Vec::new();
    let header_end = loop {
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(ProxyFailure::without_audit(
                    400,
                    "Bad Request",
                    "request ended before headers",
                ))
            }
            Ok(_) => {
                buffer.push(byte[0]);
                if buffer.len() > MAX_HEADER_BYTES {
                    return Err(ProxyFailure::without_audit(
                        431,
                        "Request Header Fields Too Large",
                        "request headers are too large",
                    ));
                }
                if buffer.ends_with(b"\r\n\r\n") {
                    break buffer.len();
                }
            }
            Err(_) => {
                return Err(ProxyFailure::without_audit(
                    400,
                    "Bad Request",
                    "failed to read request",
                ))
            }
        }
    };
    let header_text = std::str::from_utf8(&buffer[..header_end])
        .map_err(|_| ProxyFailure::without_audit(400, "Bad Request", "headers must be UTF-8"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| ProxyFailure::without_audit(400, "Bad Request", "missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| ProxyFailure::without_audit(400, "Bad Request", "missing method"))?;
    let target = request_parts
        .next()
        .ok_or_else(|| ProxyFailure::without_audit(400, "Bad Request", "missing target"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| ProxyFailure::without_audit(400, "Bad Request", "missing version"))?;
    if request_parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "invalid request line",
        ));
    }

    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(ProxyFailure::without_audit(
                400,
                "Bad Request",
                "malformed header",
            ));
        };
        if name.is_empty()
            || name
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b' ' | b'\t' | b':'))
        {
            return Err(ProxyFailure::without_audit(
                400,
                "Bad Request",
                "malformed header name",
            ));
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(ProxyFailure::without_audit(
                400,
                "Bad Request",
                "malformed header value",
            ));
        }
        headers.push((name.to_string(), value.trim_start().to_string()));
    }

    if headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
    }) {
        return Err(ProxyFailure::without_audit(
            501,
            "Not Implemented",
            "chunked request bodies are not supported",
        ));
    }
    let content_lengths: Vec<usize> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.parse::<usize>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| ProxyFailure::without_audit(400, "Bad Request", "invalid content-length"))?;
    if content_lengths.len() > 1 {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "multiple content-length headers",
        ));
    }
    let body_len = content_lengths.first().copied().unwrap_or(0);
    if body_len > MAX_BODY_BYTES {
        return Err(ProxyFailure::without_audit(
            413,
            "Payload Too Large",
            "request body is too large",
        ));
    }
    let mut body = vec![0; body_len];
    if body_len > 0 {
        stream
            .read_exact(&mut body)
            .map_err(|_| ProxyFailure::without_audit(400, "Bad Request", "failed to read body"))?;
    }

    Ok(ProxyRequest {
        method: method.to_string(),
        target: target.to_string(),
        headers,
        body,
    })
}

fn proxy_authorized(headers: &[(String, String)], token: &str) -> bool {
    headers.iter().any(|(name, value)| {
        if !name.eq_ignore_ascii_case("proxy-authorization") {
            return false;
        }
        let Some((scheme, credential)) = value.split_once(' ') else {
            return false;
        };
        if scheme.eq_ignore_ascii_case("bearer") {
            return constant_time_eq(credential.as_bytes(), token.as_bytes());
        }
        if scheme.eq_ignore_ascii_case("basic") {
            return base64::engine::general_purpose::STANDARD
                .decode(credential.as_bytes())
                .ok()
                .and_then(|decoded| String::from_utf8(decoded).ok())
                .and_then(|decoded| decoded.strip_prefix("ctxa:").map(str::to_string))
                .is_some_and(|candidate| constant_time_eq(candidate.as_bytes(), token.as_bytes()));
        }
        false
    })
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

fn canonical_method(method: &str) -> std::result::Result<String, ProxyFailure> {
    let method = method.to_ascii_uppercase();
    crate::config::validate_http_method(&method)
        .map_err(|_| ProxyFailure::without_audit(400, "Bad Request", "invalid method"))?;
    Ok(method)
}

fn parse_connect_target(target: &str) -> std::result::Result<ProxyTarget, ProxyFailure> {
    if target.contains('/')
        || target.contains('?')
        || target.contains('#')
        || target
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "invalid CONNECT target",
        ));
    }
    let canonical_host_port = canonical_host_port_for_scheme(target, HttpResourceScheme::Https)
        .ok_or_else(|| ProxyFailure::without_audit(400, "Bad Request", "invalid CONNECT host"))?;
    let (host, port) = split_canonical_host_port(&canonical_host_port)?;
    Ok(ProxyTarget {
        canonical_host_port,
        host,
        port,
        path: "/".into(),
        query: None,
        request_target: "/".into(),
    })
}

fn parse_tunnel_target(
    request: &ProxyRequest,
    connect_target: &ProxyTarget,
) -> std::result::Result<ProxyTarget, ProxyFailure> {
    let target = if request.target.starts_with("https://") {
        let target = parse_absolute_target(&request.target, HttpResourceScheme::Https)?;
        if target.canonical_host_port != connect_target.canonical_host_port {
            return Err(ProxyFailure::without_audit(
                400,
                "Bad Request",
                "absolute target does not match CONNECT host",
            ));
        }
        target
    } else if request.target.starts_with("http://") {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "tunnel request must use HTTPS authority",
        ));
    } else {
        let (path, query, request_target) = parse_path_query_target(&request.target)?;
        ProxyTarget {
            canonical_host_port: connect_target.canonical_host_port.clone(),
            host: connect_target.host.clone(),
            port: connect_target.port,
            path,
            query,
            request_target,
        }
    };
    let host = header_value(&request.headers, "host").ok_or_else(|| {
        ProxyFailure::without_audit(400, "Bad Request", "tunnel request missing Host header")
    })?;
    let canonical_host = canonical_host_port_for_scheme(host, HttpResourceScheme::Https)
        .ok_or_else(|| ProxyFailure::without_audit(400, "Bad Request", "invalid Host header"))?;
    if canonical_host != connect_target.canonical_host_port {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "Host header does not match CONNECT host",
        ));
    }
    Ok(target)
}

fn parse_absolute_target(
    target: &str,
    scheme: HttpResourceScheme,
) -> std::result::Result<ProxyTarget, ProxyFailure> {
    let prefix = match scheme {
        HttpResourceScheme::Http => "http://",
        HttpResourceScheme::Https => "https://",
    };
    if !target.starts_with(prefix) {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "absolute URL required",
        ));
    }
    if target.contains('#')
        || target
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "ambiguous target URL",
        ));
    }
    let rest = &target[prefix.len()..];
    let split_at = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..split_at];
    if authority.is_empty() || authority.contains('@') {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "invalid target authority",
        ));
    }
    let canonical_host_port = canonical_host_port_for_scheme(authority, scheme)
        .ok_or_else(|| ProxyFailure::without_audit(400, "Bad Request", "invalid target host"))?;
    let (host, port) = split_canonical_host_port(&canonical_host_port)?;
    let remainder = &rest[split_at..];
    let (path, query, request_target) = parse_path_query_target(remainder)?;
    Ok(ProxyTarget {
        canonical_host_port,
        host,
        port,
        path,
        query,
        request_target,
    })
}

fn parse_path_query_target(
    raw_target: &str,
) -> std::result::Result<(String, Option<String>, String), ProxyFailure> {
    if raw_target.contains('#')
        || raw_target
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "ambiguous target URL",
        ));
    }
    let (path, query) = if raw_target.is_empty() {
        ("/".to_string(), None)
    } else if let Some(query) = raw_target.strip_prefix('?') {
        ("/".to_string(), Some(query.to_string()))
    } else if raw_target.starts_with('/') {
        raw_target
            .split_once('?')
            .map(|(path, query)| (path.to_string(), Some(query.to_string())))
            .unwrap_or_else(|| (raw_target.to_string(), None))
    } else {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "origin-form target required",
        ));
    };
    if !query.as_deref().map(is_safe_query).unwrap_or(true) {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "invalid target query",
        ));
    }
    let request_target = match &query {
        Some(query) => format!("{path}?{query}"),
        None => path.clone(),
    };
    Ok((path, query, request_target))
}

fn split_canonical_host_port(host_port: &str) -> std::result::Result<(String, u16), ProxyFailure> {
    let (host, port) = host_port
        .rsplit_once(':')
        .ok_or_else(|| ProxyFailure::without_audit(400, "Bad Request", "invalid host"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| ProxyFailure::without_audit(400, "Bad Request", "invalid host port"))?;
    Ok((host.to_string(), port))
}

fn is_safe_query(query: &str) -> bool {
    !query
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn scheme_name(scheme: HttpResourceScheme) -> &'static str {
    match scheme {
        HttpResourceScheme::Http => "http",
        HttpResourceScheme::Https => "https",
    }
}

fn find_resource<'a>(
    profile: &'a ProfileConfig,
    scheme: HttpResourceScheme,
    canonical_target_host: &str,
    method: &str,
    path: &str,
) -> Option<&'a HttpResourceConfig> {
    profile.http_resources.iter().find(|resource| {
        resource.scheme == scheme
            && canonical_host_port_for_scheme(&resource.host, resource.scheme).as_deref()
                == Some(canonical_target_host)
            && resource
                .allow
                .methods
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(method))
            && resource
                .allow
                .path_prefixes
                .iter()
                .any(|prefix| http_path_matches_prefix(path, prefix))
    })
}

enum MatchedProxyAuthority<'a> {
    Resource(&'a HttpResourceConfig),
    Grant(Box<GrantMatch>),
}

impl MatchedProxyAuthority<'_> {
    fn id(&self) -> &str {
        match self {
            Self::Resource(resource) => &resource.id,
            Self::Grant(grant) => &grant.grant.id,
        }
    }

    fn secret_ref(&self) -> &str {
        match self {
            Self::Resource(resource) => &resource.secret_ref,
            Self::Grant(grant) => &grant.root_secret_ref,
        }
    }
}

fn find_authority<'a>(
    profile: &'a ProfileConfig,
    grants: &[HttpGrantConfig],
    scheme: HttpResourceScheme,
    canonical_target_host: &str,
    method: &str,
    path: &str,
) -> Result<Option<MatchedProxyAuthority<'a>>> {
    if let Some(resource) = find_resource(profile, scheme, canonical_target_host, method, path) {
        return Ok(Some(MatchedProxyAuthority::Resource(resource)));
    }
    Ok(
        matching_grant(profile, grants, scheme, canonical_target_host, method, path)?
            .map(|grant| MatchedProxyAuthority::Grant(Box::new(grant))),
    )
}

fn forward_request(
    request: &ProxyRequest,
    target: &ProxyTarget,
    method: &str,
    scheme: HttpResourceScheme,
    bearer: &str,
    upstream_root_certs_pem: &[Vec<u8>],
) -> std::result::Result<UpstreamResponse, UpstreamFailure> {
    match scheme {
        HttpResourceScheme::Http => forward_plain_http_request(request, target, method, bearer),
        HttpResourceScheme::Https => {
            forward_https_request(request, target, method, bearer, upstream_root_certs_pem)
        }
    }
}

fn forward_plain_http_request(
    request: &ProxyRequest,
    target: &ProxyTarget,
    method: &str,
    bearer: &str,
) -> std::result::Result<UpstreamResponse, UpstreamFailure> {
    validate_bearer_secret(bearer)?;
    let addresses = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|_| {
            UpstreamFailure::new(502, "Bad Gateway", "upstream address resolution failed")
        })?;
    let mut upstream = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, IO_TIMEOUT) {
            Ok(stream) => {
                upstream = Some(stream);
                break;
            }
            Err(_) => continue,
        }
    }
    let mut upstream = upstream
        .ok_or_else(|| UpstreamFailure::new(502, "Bad Gateway", "upstream connect failed"))?;
    upstream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|_| {
        UpstreamFailure::new(504, "Gateway Timeout", "upstream timeout setup failed")
    })?;
    upstream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| {
        UpstreamFailure::new(504, "Gateway Timeout", "upstream timeout setup failed")
    })?;

    let mut upstream_request = Vec::new();
    write!(
        upstream_request,
        "{method} {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n",
        target.request_target, target.canonical_host_port, bearer
    )
    .map_err(|_| UpstreamFailure::new(502, "Bad Gateway", "failed to build upstream request"))?;
    for (name, value) in &request.headers {
        if should_strip_header(name) {
            continue;
        }
        write!(upstream_request, "{name}: {value}\r\n").map_err(|_| {
            UpstreamFailure::new(502, "Bad Gateway", "failed to build upstream request")
        })?;
    }
    if !request.body.is_empty() {
        write!(
            upstream_request,
            "Content-Length: {}\r\n",
            request.body.len()
        )
        .map_err(|_| {
            UpstreamFailure::new(502, "Bad Gateway", "failed to build upstream request")
        })?;
    }
    upstream_request.extend_from_slice(b"\r\n");
    upstream_request.extend_from_slice(&request.body);
    upstream
        .write_all(&upstream_request)
        .map_err(|_| UpstreamFailure::new(504, "Gateway Timeout", "upstream write failed"))?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = upstream
            .read(&mut chunk)
            .map_err(|_| UpstreamFailure::new(504, "Gateway Timeout", "upstream read failed"))?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.len() > MAX_RESPONSE_BYTES {
            return Err(UpstreamFailure::new(
                502,
                "Bad Gateway",
                "upstream response too large",
            ));
        }
    }
    let status_code = parse_response_status(&response);
    Ok(UpstreamResponse {
        bytes: response,
        status_code,
    })
}

fn forward_https_request(
    request: &ProxyRequest,
    target: &ProxyTarget,
    method: &str,
    bearer: &str,
    upstream_root_certs_pem: &[Vec<u8>],
) -> std::result::Result<UpstreamResponse, UpstreamFailure> {
    validate_bearer_secret(bearer)?;
    let mut builder = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(IO_TIMEOUT);
    for cert in upstream_root_certs_pem {
        let cert = reqwest::Certificate::from_pem(cert).map_err(|_| {
            UpstreamFailure::new(502, "Bad Gateway", "invalid upstream root certificate")
        })?;
        builder = builder.add_root_certificate(cert);
    }
    let client = builder
        .build()
        .map_err(|_| UpstreamFailure::new(502, "Bad Gateway", "HTTPS client setup failed"))?;
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| UpstreamFailure::new(400, "Bad Request", "invalid method"))?;
    let url = format!(
        "https://{}{}",
        target.canonical_host_port, target.request_target
    );
    let mut request_builder = client
        .request(method, &url)
        .bearer_auth(bearer)
        .body(request.body.clone());
    for (name, value) in &request.headers {
        if should_strip_header(name) {
            continue;
        }
        request_builder = request_builder.header(name.as_str(), value.as_str());
    }
    let response = request_builder
        .send()
        .map_err(|_| UpstreamFailure::new(502, "Bad Gateway", "upstream HTTPS request failed"))?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .map_err(|_| UpstreamFailure::new(504, "Gateway Timeout", "upstream read failed"))?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(UpstreamFailure::new(
            502,
            "Bad Gateway",
            "upstream response too large",
        ));
    }
    let mut bytes = Vec::new();
    write!(
        bytes,
        "HTTP/1.1 {} {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or(""),
        body.len()
    )
    .map_err(|_| UpstreamFailure::new(502, "Bad Gateway", "failed to build response"))?;
    for (name, value) in &headers {
        if should_strip_response_header(name.as_str()) {
            continue;
        }
        let Ok(value) = value.to_str() else {
            continue;
        };
        if value
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            continue;
        }
        write!(bytes, "{}: {}\r\n", name.as_str(), value)
            .map_err(|_| UpstreamFailure::new(502, "Bad Gateway", "failed to build response"))?;
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(&body);
    Ok(UpstreamResponse {
        bytes,
        status_code: Some(status.as_u16()),
    })
}

fn validate_bearer_secret(bearer: &str) -> std::result::Result<(), UpstreamFailure> {
    if bearer
        .bytes()
        .any(|byte| byte.is_ascii_control() || matches!(byte, b'\r' | b'\n'))
    {
        return Err(UpstreamFailure::new(
            502,
            "Bad Gateway",
            "bearer secret is not safe for HTTP headers",
        ));
    }
    Ok(())
}

fn should_strip_header(name: &str) -> bool {
    [
        "authorization",
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|strip| name.eq_ignore_ascii_case(strip))
}

fn should_strip_response_header(name: &str) -> bool {
    [
        "connection",
        "content-length",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|strip| name.eq_ignore_ascii_case(strip))
}

fn parse_response_status(response: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(response).ok()?;
    let line = text.split("\r\n").next()?;
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

fn issue_proxy_receipt(
    state: &ProxyState,
    authority: &MatchedProxyAuthority<'_>,
    target: &ProxyTarget,
    method: &str,
    scheme: HttpResourceScheme,
    body: &[u8],
    status_code: Option<u16>,
) -> Result<Receipt> {
    let profile = &state.config.profile;
    let query_hash = target
        .query
        .as_deref()
        .map(|query| payload_hash(&QueryEnvelope { query }))
        .transpose()?;
    let payload = if body.is_empty() {
        json!({})
    } else {
        json!({"body_sha256": bytes_hash(body)})
    };
    let mut operation = serde_json::Map::new();
    operation.insert("method".into(), json!(method));
    operation.insert("scheme".into(), json!(scheme_name(scheme)));
    operation.insert("host".into(), json!(target.canonical_host_port));
    operation.insert("path".into(), json!(target.path));
    if let Some(query_hash) = &query_hash {
        operation.insert("query_hash".into(), json!(query_hash));
    }
    let request = ActionRequest {
        id: format!("proxy_{}", Uuid::new_v4()),
        agent_id: profile.agent.clone().unwrap_or_else(|| profile.id.clone()),
        task_id: None,
        capability: "http.request".into(),
        resource: authority.id().to_string(),
        operation: serde_json::Value::Object(operation),
        payload,
        payload_hash: None,
        idempotency_key: None,
        requested_at: None,
    };
    let policy_hash = authority_policy_hash(profile, authority)?;
    let mut result = BTreeMap::new();
    result.insert("redacted".into(), json!(true));
    result.insert("query_present".into(), json!(target.query.is_some()));
    if let MatchedProxyAuthority::Grant(grant) = authority {
        let chain_ids: Vec<&str> = grant.chain.iter().map(|item| item.id.as_str()).collect();
        result.insert("grant_chain_hash".into(), json!(grant.chain_hash));
        result.insert("grant_chain_ids".into(), json!(chain_ids));
    }
    if let Some(status_code) = status_code {
        result.insert("status_code".into(), json!(status_code));
    }
    let execution = ProviderExecution {
        status: "succeeded".into(),
        provider: "ctxa-http-proxy".into(),
        provider_request_id: Some(format!("proxy_{}", Uuid::new_v4())),
        result,
    };
    state.config.signer.issue(
        profile.id.clone(),
        &request,
        crate::receipts::action_hash(&request)?,
        policy_hash,
        None,
        execution,
    )
}

fn authority_policy_hash(
    profile: &ProfileConfig,
    authority: &MatchedProxyAuthority<'_>,
) -> Result<String> {
    match authority {
        MatchedProxyAuthority::Resource(resource) => profile_policy_hash(profile, resource),
        MatchedProxyAuthority::Grant(grant) => grant_policy_hash(profile, grant),
    }
}

fn profile_policy_hash(profile: &ProfileConfig, resource: &HttpResourceConfig) -> Result<String> {
    let secret_ref_hash = payload_hash(&SecretReferenceEnvelope {
        secret_ref: &resource.secret_ref,
    })?;
    payload_hash(&ProfilePolicyEnvelope {
        profile_id: &profile.id,
        agent: profile.agent.as_deref(),
        resource_id: &resource.id,
        scheme: scheme_name(resource.scheme),
        host: &canonical_host_port_for_scheme(&resource.host, resource.scheme)
            .ok_or_else(|| AuthorityError::Config("invalid resource host".into()))?,
        methods: &resource.allow.methods,
        path_prefixes: &resource.allow.path_prefixes,
        auth_type: match resource.auth.kind {
            HttpAuthType::Bearer => "bearer",
        },
        secret_ref_hash: &secret_ref_hash,
    })
}

fn grant_policy_hash(profile: &ProfileConfig, grant: &GrantMatch) -> Result<String> {
    let root_secret_ref_hash = payload_hash(&SecretReferenceEnvelope {
        secret_ref: &grant.root_secret_ref,
    })?;
    let chain: Vec<serde_json::Value> = grant
        .chain
        .iter()
        .map(|item| {
            Ok(json!({
                "id": item.id,
                "parent": item.parent,
                "profile": item.profile,
                "subject": item.subject,
                "scheme": scheme_name(item.scheme),
                "host": canonical_host_port_for_scheme(&item.host, item.scheme)
                    .ok_or_else(|| AuthorityError::Config("invalid grant host".into()))?,
                "methods": item.allow.methods,
                "path_prefixes": item.allow.path_prefixes,
                "delegation": {
                    "allowed": item.delegation.allowed,
                    "remaining_depth": item.delegation.remaining_depth,
                },
            }))
        })
        .collect::<Result<_>>()?;
    payload_hash(&json!({
        "type": "ctxa.grant-policy.v1",
        "holder_profile": profile.id,
        "holder_subject": profile.agent.as_deref().unwrap_or(&profile.id),
        "matched_grant_id": grant.grant.id,
        "chain_ids": grant.chain.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(),
        "chain": chain,
        "root_secret_ref_hash": root_secret_ref_hash,
    }))
}

fn record_proxy_proposal(
    state: &ProxyState,
    method: &str,
    scheme: HttpResourceScheme,
    target: &ProxyTarget,
    reason: &str,
) {
    let _ = state.config.audit.record(
        "proxy_request_proposal",
        &json!({
            "id": format!("prop_{}", Uuid::new_v4()),
            "profile": state.config.profile.id,
            "agent": state.config.profile.agent.as_deref().unwrap_or(&state.config.profile.id),
            "capability": "http.request",
            "scheme": scheme_name(scheme),
            "method": method,
            "host": target.canonical_host_port,
            "path": target.path,
            "query_present": target.query.is_some(),
            "reason": reason,
        }),
    );
}

pub fn profile_allows_url(
    profile: &ProfileConfig,
    grants: &[HttpGrantConfig],
    method: &str,
    url: &str,
) -> Result<Option<String>> {
    let method = method.to_ascii_uppercase();
    crate::config::validate_http_method(&method)?;
    let (scheme, target) =
        parse_url_for_profile_test(url).map_err(|failure| AuthorityError::Config(failure.body))?;
    if let Some(resource) = find_resource(
        profile,
        scheme,
        &target.canonical_host_port,
        &method,
        &target.path,
    ) {
        return Ok(Some(resource.id.clone()));
    }
    Ok(matching_grant(
        profile,
        grants,
        scheme,
        &target.canonical_host_port,
        &method,
        &target.path,
    )?
    .map(|grant| grant.grant.id))
}

fn parse_url_for_profile_test(
    url: &str,
) -> std::result::Result<(HttpResourceScheme, ProxyTarget), ProxyFailure> {
    if url.starts_with("https://") {
        Ok((
            HttpResourceScheme::Https,
            parse_absolute_target(url, HttpResourceScheme::Https)?,
        ))
    } else if url.starts_with("http://") {
        Ok((
            HttpResourceScheme::Http,
            parse_absolute_target(url, HttpResourceScheme::Http)?,
        ))
    } else {
        Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "profile test URL must start with http:// or https://",
        ))
    }
}

fn bytes_hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn write_simple_response(
    stream: &mut impl Write,
    status: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn write_connect_established(stream: &mut impl Write) -> std::io::Result<()> {
    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
}

#[derive(Debug)]
struct ProxyRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct ProxyTarget {
    canonical_host_port: String,
    host: String,
    port: u16,
    path: String,
    query: Option<String>,
    request_target: String,
}

struct UpstreamResponse {
    bytes: Vec<u8>,
    status_code: Option<u16>,
}

struct UpstreamFailure {
    status: u16,
    reason: String,
    body: String,
    audit_reason: String,
}

impl UpstreamFailure {
    fn new(status: u16, reason: &str, body: &str) -> Self {
        Self {
            status,
            reason: reason.into(),
            body: body.into(),
            audit_reason: body.into(),
        }
    }
}

struct ProxyFailure {
    status: u16,
    reason: String,
    body: String,
    audit_kind: Option<String>,
    audit_data: serde_json::Value,
}

impl ProxyFailure {
    fn new(
        status: u16,
        reason: &str,
        body: &str,
        audit_kind: Option<&str>,
        audit_data: serde_json::Value,
    ) -> Self {
        Self {
            status,
            reason: reason.into(),
            body: body.into(),
            audit_kind: audit_kind.map(str::to_string),
            audit_data,
        }
    }

    fn without_audit(status: u16, reason: &str, body: &str) -> Self {
        Self::new(status, reason, body, None, serde_json::Value::Null)
    }

    fn with_audit(mut self, kind: &str, data: serde_json::Value) -> Self {
        self.audit_kind = Some(kind.into());
        self.audit_data = data;
        self
    }
}

#[derive(Serialize)]
struct QueryEnvelope<'a> {
    query: &'a str,
}

#[derive(Serialize)]
struct SecretReferenceEnvelope<'a> {
    secret_ref: &'a str,
}

#[derive(Serialize)]
struct ProfilePolicyEnvelope<'a> {
    profile_id: &'a str,
    agent: Option<&'a str>,
    resource_id: &'a str,
    scheme: &'a str,
    host: &'a str,
    methods: &'a [String],
    path_prefixes: &'a [String],
    auth_type: &'a str,
    secret_ref_hash: &'a str,
}
