use crate::audit::AuditLog;
use crate::backends::SecretBackend;
use crate::config::{canonical_host_port, HttpAuthType, HttpResourceConfig, ProfileConfig};
use crate::models::{ActionRequest, ProviderExecution, Receipt};
use crate::policy::http_path_matches_prefix;
use crate::receipts::{payload_hash, ReceiptSigner};
use crate::{AuthorityError, Result};
use base64::Engine;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use uuid::Uuid;

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONCURRENT_REQUESTS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_SLEEP: Duration = Duration::from_millis(25);

pub struct ProxyConfig {
    pub profile: ProfileConfig,
    pub secret_backend: Arc<dyn SecretBackend>,
    pub audit: AuditLog,
    pub signer: ReceiptSigner,
}

pub struct ProxyServer {
    address: SocketAddr,
    token: String,
    shutdown: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl ProxyServer {
    pub fn start(config: ProxyConfig) -> Result<Self> {
        config.profile.validate()?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let token = Uuid::new_v4().to_string();
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let workers = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(ProxyState {
            config,
            token: token.clone(),
            in_flight: AtomicUsize::new(0),
            workers: Arc::clone(&workers),
        });
        let thread = thread::spawn(move || accept_loop(listener, state, shutdown_rx));
        Ok(Self {
            address,
            token,
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

impl Drop for ProxyServer {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

struct ProxyState {
    config: ProxyConfig,
    token: String,
    in_flight: AtomicUsize,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
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
            let _ = write_simple_response(&mut stream, status, &reason, &body);
        }
    }
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
        return Err(ProxyFailure::new(
            501,
            "Not Implemented",
            "CONNECT is not supported by this local proxy",
            Some("proxy_request_rejected"),
            json!({"reason": "connect_not_supported"}),
        ));
    }
    let method = canonical_method(&request.method).map_err(|failure| {
        failure.with_audit(
            "proxy_request_rejected",
            json!({"reason": "invalid_method"}),
        )
    })?;
    let target = parse_absolute_http_target(&request.target).map_err(|failure| {
        failure.with_audit(
            "proxy_request_rejected",
            json!({"reason": "invalid_target"}),
        )
    })?;
    let Some(resource) = find_resource(
        &state.config.profile,
        &target.canonical_host_port,
        &method,
        &target.path,
    ) else {
        return Err(ProxyFailure::new(
            403,
            "Forbidden",
            "request is not allowed by this profile",
            Some("proxy_request_denied"),
            json!({
                "profile": state.config.profile.id,
                "reason": "no_matching_resource",
                "method": method,
                "host": target.canonical_host_port,
                "path": target.path,
                "query_present": target.query.is_some(),
            }),
        ));
    };
    let secret = state
        .config
        .secret_backend
        .resolve(&resource.secret_ref)
        .map_err(|_| {
            ProxyFailure::new(
                502,
                "Bad Gateway",
                "secret backend resolution failed",
                Some("proxy_secret_failed"),
                json!({
                    "profile": state.config.profile.id,
                    "resource": resource.id,
                    "method": method,
                    "host": target.canonical_host_port,
                    "path": target.path,
                    "query_present": target.query.is_some(),
                }),
            )
        })?;

    let response = forward_request(&request, &target, &method, secret.expose_to_provider())
        .map_err(|failure| {
            ProxyFailure::new(
                failure.status,
                &failure.reason,
                &failure.body,
                Some("proxy_upstream_failed"),
                json!({
                    "profile": state.config.profile.id,
                    "resource": resource.id,
                    "method": method,
                    "host": target.canonical_host_port,
                    "path": target.path,
                    "query_present": target.query.is_some(),
                    "reason": failure.audit_reason,
                }),
            )
        })?;

    let receipt = issue_proxy_receipt(
        &state.config.profile,
        resource,
        &target,
        &method,
        &request.body,
        response.status_code,
        &state.config.signer,
    )
    .map_err(|_| {
        ProxyFailure::new(
            502,
            "Bad Gateway",
            "receipt issuance failed",
            Some("proxy_receipt_failed"),
            json!({
                "profile": state.config.profile.id,
                "resource": resource.id,
                "method": method,
                "host": target.canonical_host_port,
                "path": target.path,
                "query_present": target.query.is_some(),
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
                "resource": resource.id,
                "method": method,
                "host": target.canonical_host_port,
                "path": target.path,
                "query_present": target.query.is_some(),
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
                    "resource": resource.id,
                    "method": method,
                    "host": target.canonical_host_port,
                    "path": target.path,
                    "query_present": target.query.is_some(),
                }),
            )
        })?;
    stream
        .write_all(&response.bytes)
        .map_err(|_| ProxyFailure::without_audit(504, "Gateway Timeout", "client write failed"))?;
    Ok(())
}

fn read_proxy_request(stream: &mut TcpStream) -> std::result::Result<ProxyRequest, ProxyFailure> {
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

fn parse_absolute_http_target(target: &str) -> std::result::Result<ProxyTarget, ProxyFailure> {
    if !target.starts_with("http://") {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "absolute http URL required",
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
    let rest = &target["http://".len()..];
    let split_at = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..split_at];
    if authority.is_empty() || authority.contains('@') {
        return Err(ProxyFailure::without_audit(
            400,
            "Bad Request",
            "invalid target authority",
        ));
    }
    let canonical_host_port = canonical_host_port(authority)
        .ok_or_else(|| ProxyFailure::without_audit(400, "Bad Request", "invalid target host"))?;
    let (host, port) = split_canonical_host_port(&canonical_host_port)?;
    let remainder = &rest[split_at..];
    let (path, query) = if remainder.is_empty() {
        ("/".to_string(), None)
    } else if let Some(query) = remainder.strip_prefix('?') {
        ("/".to_string(), Some(query.to_string()))
    } else {
        let (path, query) = remainder
            .split_once('?')
            .map(|(path, query)| (path.to_string(), Some(query.to_string())))
            .unwrap_or_else(|| (remainder.to_string(), None));
        (path, query)
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
    Ok(ProxyTarget {
        canonical_host_port,
        host,
        port,
        path,
        query,
        request_target,
    })
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

fn find_resource<'a>(
    profile: &'a ProfileConfig,
    canonical_target_host: &str,
    method: &str,
    path: &str,
) -> Option<&'a HttpResourceConfig> {
    profile.http_resources.iter().find(|resource| {
        canonical_host_port(&resource.host).as_deref() == Some(canonical_target_host)
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

fn forward_request(
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
    profile: &ProfileConfig,
    resource: &HttpResourceConfig,
    target: &ProxyTarget,
    method: &str,
    body: &[u8],
    status_code: Option<u16>,
    signer: &ReceiptSigner,
) -> Result<Receipt> {
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
        resource: resource.id.clone(),
        operation: serde_json::Value::Object(operation),
        payload,
        payload_hash: None,
        idempotency_key: None,
        requested_at: None,
    };
    let policy_hash = profile_policy_hash(profile, resource)?;
    let mut result = BTreeMap::new();
    result.insert("redacted".into(), json!(true));
    result.insert("query_present".into(), json!(target.query.is_some()));
    if let Some(status_code) = status_code {
        result.insert("status_code".into(), json!(status_code));
    }
    let execution = ProviderExecution {
        status: "succeeded".into(),
        provider: "ctxa-http-proxy".into(),
        provider_request_id: Some(format!("proxy_{}", Uuid::new_v4())),
        result,
    };
    signer.issue(
        profile.id.clone(),
        &request,
        crate::receipts::action_hash(&request)?,
        policy_hash,
        None,
        execution,
    )
}

fn profile_policy_hash(profile: &ProfileConfig, resource: &HttpResourceConfig) -> Result<String> {
    let secret_ref_hash = payload_hash(&SecretReferenceEnvelope {
        secret_ref: &resource.secret_ref,
    })?;
    payload_hash(&ProfilePolicyEnvelope {
        profile_id: &profile.id,
        agent: profile.agent.as_deref(),
        resource_id: &resource.id,
        host: &canonical_host_port(&resource.host)
            .ok_or_else(|| AuthorityError::Config("invalid resource host".into()))?,
        methods: &resource.allow.methods,
        path_prefixes: &resource.allow.path_prefixes,
        auth_type: match resource.auth.kind {
            HttpAuthType::Bearer => "bearer",
        },
        secret_ref_hash: &secret_ref_hash,
    })
}

fn bytes_hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn write_simple_response(
    stream: &mut TcpStream,
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
    host: &'a str,
    methods: &'a [String],
    path_prefixes: &'a [String],
    auth_type: &'a str,
    secret_ref_hash: &'a str,
}
