use crate::audit::AuditLog;
use crate::backends::{SecretBackend, SecretLease};
use crate::config::{
    CapabilityGrantConfig, CapabilityProviderAuthConfig, CapabilityProviderConfig,
    CapabilityProviderKind, GrantDelegationConfig, ProfileConfig,
};
use crate::grants::profile_subject;
use crate::models::{ActionRequest, ProviderExecution, Receipt};
use crate::receipts::{action_hash, payload_hash, ReceiptSigner};
use crate::{AuthorityError, Result};
use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use reqwest::{Method, StatusCode, Url};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use uuid::Uuid;

const ADAPTER_VERSION: &str = "ctxa.capability-adapter.v1";

#[derive(Debug, Clone)]
pub struct CapabilityGrantMatch {
    pub grant: CapabilityGrantConfig,
    pub chain: Vec<CapabilityGrantConfig>,
    pub chain_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityReceipt {
    pub provider: String,
    pub capability: String,
    pub resource: String,
    pub grant_id: String,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityExecutionEnvelope {
    pub capability: CapabilityReceipt,
    pub provider_response: Value,
}

#[derive(Debug, Clone)]
pub struct CapabilityExecuteRequest {
    pub profile: String,
    pub provider: String,
    pub capability: String,
    pub resource: String,
    pub operation: Value,
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct CapabilityLease {
    token: SecretLease,
    pub provider: String,
    pub capability: String,
    pub resource: String,
    pub lease_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub credential_ref_hash: String,
}

impl CapabilityLease {
    fn bearer(&self) -> &str {
        self.token.expose_to_provider()
    }
}

pub trait CapabilityIssuer {
    fn issue_lease(
        &self,
        request: &CapabilityExecuteRequest,
        backend: &dyn SecretBackend,
    ) -> Result<CapabilityLease>;

    fn execute(
        &self,
        request: &CapabilityExecuteRequest,
        lease: &CapabilityLease,
    ) -> Result<CapabilityProviderResponse>;
}

#[derive(Debug, Clone)]
pub struct CapabilityProviderResponse {
    pub provider_request_id: Option<String>,
    pub status: StatusCode,
    pub body: Value,
}

pub fn execute_capability(
    profiles: &[ProfileConfig],
    grants: &[CapabilityGrantConfig],
    provider: &CapabilityProviderConfig,
    request: CapabilityExecuteRequest,
    backend: &dyn SecretBackend,
    audit: &AuditLog,
    signer: &ReceiptSigner,
) -> Result<CapabilityExecutionEnvelope> {
    let profile = profiles
        .iter()
        .find(|profile| profile.id == request.profile)
        .ok_or_else(|| {
            AuthorityError::Config(format!("profile {} is not configured", request.profile))
        })?;
    if provider.id != request.provider {
        return Err(AuthorityError::Config(format!(
            "provider {} does not match request provider {}",
            provider.id, request.provider
        )));
    }
    validate_capability_for_provider(provider.kind, &request.capability, &request.resource)?;
    audit.record(
        "capability_requested",
        &capability_audit_data(profile, provider, &request, None, "requested"),
    )?;
    let matched = match matching_capability_grant(
        profile,
        grants,
        &request.provider,
        &request.capability,
        &request.resource,
    )? {
        Some(matched) => matched,
        None => {
            audit.record(
                "capability_denied",
                &capability_audit_data(profile, provider, &request, None, "no_matching_grant"),
            )?;
            return Err(AuthorityError::Denied(format!(
                "profile {} is not granted {} on {}",
                profile.id, request.capability, request.resource
            )));
        }
    };
    audit.record(
        "capability_execution_attempted",
        &capability_audit_data(
            profile,
            provider,
            &request,
            Some(&matched.grant.id),
            "execution_attempted",
        ),
    )?;

    let issuer = ProviderCapabilityIssuer::new(provider.clone())?;
    let lease = match issuer.issue_lease(&request, backend) {
        Ok(lease) => lease,
        Err(err) => {
            audit.record(
                "capability_execution_failed",
                &capability_audit_data(
                    profile,
                    provider,
                    &request,
                    Some(&matched.grant.id),
                    "lease_issue_failed",
                ),
            )?;
            return Err(err);
        }
    };
    let provider_response = match issuer.execute(&request, &lease) {
        Ok(response) => response,
        Err(err) => {
            audit.record(
                "capability_execution_failed",
                &capability_audit_data(
                    profile,
                    provider,
                    &request,
                    Some(&matched.grant.id),
                    "provider_execution_failed",
                ),
            )?;
            return Err(err);
        }
    };
    let receipt = issue_capability_receipt(
        profile,
        provider,
        &request,
        &matched,
        &lease,
        &provider_response,
        signer,
    )?;
    audit.record("capability_receipt", &serde_json::to_value(&receipt)?)?;

    Ok(CapabilityExecutionEnvelope {
        capability: CapabilityReceipt {
            provider: provider.id.clone(),
            capability: request.capability,
            resource: request.resource,
            grant_id: matched.grant.id,
            receipt,
        },
        provider_response: provider_response.body,
    })
}

fn capability_audit_data(
    profile: &ProfileConfig,
    provider: &CapabilityProviderConfig,
    request: &CapabilityExecuteRequest,
    grant_id: Option<&str>,
    reason: &str,
) -> Value {
    json!({
        "profile": profile.id,
        "subject": profile_subject(profile),
        "provider": provider.id,
        "provider_kind": provider_kind_name(provider.kind),
        "capability": request.capability,
        "resource": request.resource,
        "grant_id": grant_id,
        "reason": reason,
    })
}

pub fn validate_capability_grants(
    profiles: &[ProfileConfig],
    providers: &[CapabilityProviderConfig],
    grants: &[CapabilityGrantConfig],
) -> Result<()> {
    let profile_index: HashMap<&str, &ProfileConfig> = profiles
        .iter()
        .map(|profile| (profile.id.as_str(), profile))
        .collect();
    let provider_index: HashMap<&str, &CapabilityProviderConfig> = providers
        .iter()
        .map(|provider| (provider.id.as_str(), provider))
        .collect();
    let grant_index: HashMap<&str, &CapabilityGrantConfig> = grants
        .iter()
        .map(|grant| (grant.id.as_str(), grant))
        .collect();

    for grant in grants {
        let profile = profile_index.get(grant.profile.as_str()).ok_or_else(|| {
            AuthorityError::Config(format!(
                "capability grant {} references missing profile {}",
                grant.id, grant.profile
            ))
        })?;
        let expected_subject = profile_subject(profile);
        if grant.subject != expected_subject {
            return Err(AuthorityError::Config(format!(
                "capability grant {} subject {} does not match profile {} subject {}",
                grant.id, grant.subject, grant.profile, expected_subject
            )));
        }
        let provider = provider_index.get(grant.provider.as_str()).ok_or_else(|| {
            AuthorityError::Config(format!(
                "capability grant {} references missing provider {}",
                grant.id, grant.provider
            ))
        })?;
        if normalized_strings(&grant.capabilities) != grant.capabilities {
            return Err(AuthorityError::Config(format!(
                "capability grant {} capabilities must be sorted and deduplicated",
                grant.id
            )));
        }
        if normalized_strings(&grant.resources) != grant.resources {
            return Err(AuthorityError::Config(format!(
                "capability grant {} resources must be sorted and deduplicated",
                grant.id
            )));
        }
        for capability in &grant.capabilities {
            for resource in &grant.resources {
                validate_capability_for_provider(provider.kind, capability, resource)?;
            }
        }

        if let Some(parent_id) = &grant.parent {
            let _ = capability_grant_chain(grants, &grant.id)?;
            let parent = grant_index.get(parent_id.as_str()).ok_or_else(|| {
                AuthorityError::Config(format!(
                    "capability grant {} references missing parent {}",
                    grant.id, parent_id
                ))
            })?;
            child_capability_grant_is_subset(parent, grant)?;
        }
    }
    Ok(())
}

pub fn matching_capability_grant(
    profile: &ProfileConfig,
    grants: &[CapabilityGrantConfig],
    provider: &str,
    capability: &str,
    resource: &str,
) -> Result<Option<CapabilityGrantMatch>> {
    for grant in grants {
        if grant.profile != profile.id
            || grant.provider != provider
            || !grant.capabilities.iter().any(|item| item == capability)
            || !grant.resources.iter().any(|item| item == resource)
        {
            continue;
        }
        let chain_refs = capability_grant_chain(grants, &grant.id)?;
        let chain: Vec<CapabilityGrantConfig> = chain_refs.into_iter().cloned().collect();
        let chain_hash = capability_grant_chain_hash(&chain)?;
        return Ok(Some(CapabilityGrantMatch {
            grant: grant.clone(),
            chain,
            chain_hash,
        }));
    }
    Ok(None)
}

pub fn capability_grant_chain<'a>(
    grants: &'a [CapabilityGrantConfig],
    grant_id: &str,
) -> Result<Vec<&'a CapabilityGrantConfig>> {
    let index: HashMap<&str, &CapabilityGrantConfig> = grants
        .iter()
        .map(|grant| (grant.id.as_str(), grant))
        .collect();
    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut current_id = grant_id;
    loop {
        if !seen.insert(current_id.to_string()) {
            return Err(AuthorityError::Config(format!(
                "capability grant {grant_id} has a parent cycle"
            )));
        }
        let grant = index.get(current_id).copied().ok_or_else(|| {
            AuthorityError::Config(format!("capability grant {current_id} is not configured"))
        })?;
        chain.push(grant);
        let Some(parent) = &grant.parent else {
            break;
        };
        current_id = parent;
    }
    chain.reverse();
    Ok(chain)
}

pub fn child_capability_grant_is_subset(
    parent: &CapabilityGrantConfig,
    child: &CapabilityGrantConfig,
) -> Result<()> {
    validate_child_capability_subset(parent, child)
}

pub fn capability_delegation(allowed: bool, remaining_depth: u8) -> GrantDelegationConfig {
    GrantDelegationConfig {
        allowed,
        remaining_depth,
    }
}

pub fn normalize_capability_list(values: Vec<String>) -> Vec<String> {
    normalized_strings(&values)
}

pub fn validate_capability_for_provider(
    provider_kind: CapabilityProviderKind,
    capability: &str,
    resource: &str,
) -> Result<()> {
    if !supported_capability(provider_kind, capability) {
        return Err(AuthorityError::Config(format!(
            "{} does not support capability {}",
            provider_kind_name(provider_kind),
            capability
        )));
    }
    let parsed = parse_resource(provider_kind, resource)?;
    if !resource_matches_capability(&parsed, capability) {
        return Err(AuthorityError::Config(format!(
            "resource {resource} is not valid for capability {capability}"
        )));
    }
    Ok(())
}

fn validate_child_capability_subset(
    parent: &CapabilityGrantConfig,
    child: &CapabilityGrantConfig,
) -> Result<()> {
    if !parent.delegation.allowed {
        return Err(AuthorityError::Config(format!(
            "parent capability grant {} does not allow delegation",
            parent.id
        )));
    }
    if parent.delegation.remaining_depth == 0 {
        return Err(AuthorityError::Config(format!(
            "parent capability grant {} has no remaining delegation depth",
            parent.id
        )));
    }
    if child.delegation.remaining_depth >= parent.delegation.remaining_depth {
        return Err(AuthorityError::Config(format!(
            "child capability grant {} delegation depth must be less than parent {}",
            child.id, parent.id
        )));
    }
    if child.provider != parent.provider {
        return Err(AuthorityError::Config(format!(
            "child capability grant {} provider must match parent {}",
            child.id, parent.id
        )));
    }
    for capability in &child.capabilities {
        if !parent
            .capabilities
            .iter()
            .any(|parent_capability| parent_capability == capability)
        {
            return Err(AuthorityError::Config(format!(
                "child capability grant {} capability {} is outside parent {}",
                child.id, capability, parent.id
            )));
        }
    }
    for resource in &child.resources {
        if !parent
            .resources
            .iter()
            .any(|parent_resource| parent_resource == resource)
        {
            return Err(AuthorityError::Config(format!(
                "child capability grant {} resource {} is outside parent {}",
                child.id, resource, parent.id
            )));
        }
    }
    Ok(())
}

fn capability_grant_chain_hash(chain: &[CapabilityGrantConfig]) -> Result<String> {
    let mut hasher = Sha256::new();
    for grant in chain {
        hasher.update(grant.id.as_bytes());
        hasher.update([0]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

#[derive(Debug, Clone)]
struct ProviderCapabilityIssuer {
    provider: CapabilityProviderConfig,
    api_base: Url,
    client: Client,
}

impl ProviderCapabilityIssuer {
    fn new(provider: CapabilityProviderConfig) -> Result<Self> {
        let api_base = Url::parse(&provider.api_base)
            .map_err(|_| AuthorityError::Config("invalid api_base".into()))?;
        Ok(Self {
            provider,
            api_base,
            client: Client::new(),
        })
    }
}

impl CapabilityIssuer for ProviderCapabilityIssuer {
    fn issue_lease(
        &self,
        request: &CapabilityExecuteRequest,
        backend: &dyn SecretBackend,
    ) -> Result<CapabilityLease> {
        let issued_at = Utc::now();
        match &self.provider.auth {
            CapabilityProviderAuthConfig::Bearer { token_ref } => {
                let token = backend.resolve(token_ref)?;
                Ok(CapabilityLease {
                    token,
                    provider: request.provider.clone(),
                    capability: request.capability.clone(),
                    resource: request.resource.clone(),
                    lease_id: format!("lease_{}", Uuid::new_v4()),
                    issued_at,
                    expires_at: None,
                    credential_ref_hash: credential_ref_hash(token_ref)?,
                })
            }
            CapabilityProviderAuthConfig::GithubAppInstallation {
                app_jwt_ref,
                installation_id,
            } => {
                if self.provider.kind != CapabilityProviderKind::Github {
                    return Err(AuthorityError::Config(
                        "GitHub App installation auth requires a GitHub provider".into(),
                    ));
                }
                let jwt = backend.resolve(app_jwt_ref)?;
                let url = self
                    .api_base
                    .join(&format!(
                        "/app/installations/{installation_id}/access_tokens"
                    ))
                    .map_err(|err| {
                        AuthorityError::Provider(format!("invalid GitHub token mint URL: {err}"))
                    })?;
                let response = self
                    .client
                    .post(url)
                    .bearer_auth(jwt.expose_to_provider())
                    .header("Accept", "application/vnd.github+json")
                    .header("User-Agent", "ctxa")
                    .send()
                    .map_err(|err| {
                        AuthorityError::Provider(format!("GitHub token mint failed: {err}"))
                    })?;
                let status = response.status();
                let body: Value = response.json().map_err(|err| {
                    AuthorityError::Provider(format!(
                        "GitHub token mint response was not JSON: {err}"
                    ))
                })?;
                if !status.is_success() {
                    return Err(AuthorityError::Provider(format!(
                        "GitHub token mint returned HTTP {status}"
                    )));
                }
                let token = body.get("token").and_then(Value::as_str).ok_or_else(|| {
                    AuthorityError::Provider("GitHub token mint response omitted token".into())
                })?;
                let expires_at = body
                    .get("expires_at")
                    .and_then(Value::as_str)
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                    .map(|value| value.with_timezone(&Utc));
                Ok(CapabilityLease {
                    token: SecretLease::new(token.to_string()),
                    provider: request.provider.clone(),
                    capability: request.capability.clone(),
                    resource: request.resource.clone(),
                    lease_id: format!("lease_{}", Uuid::new_v4()),
                    issued_at,
                    expires_at,
                    credential_ref_hash: credential_ref_hash(&format!(
                        "{app_jwt_ref}#{installation_id}"
                    ))?,
                })
            }
        }
    }

    fn execute(
        &self,
        request: &CapabilityExecuteRequest,
        lease: &CapabilityLease,
    ) -> Result<CapabilityProviderResponse> {
        let planned = plan_provider_request(self.provider.kind, request)?;
        let mut response = execute_provider_http(&self.client, &self.api_base, lease, planned)?;
        if request.capability == "github.issues.read" {
            response.body = filter_github_issue_response(response.body);
        }
        Ok(response)
    }
}

#[derive(Debug, Clone)]
struct PlannedProviderRequest {
    method: Method,
    path: String,
    query: Vec<(String, String)>,
    body: Option<Value>,
}

fn execute_provider_http(
    client: &Client,
    api_base: &Url,
    lease: &CapabilityLease,
    planned: PlannedProviderRequest,
) -> Result<CapabilityProviderResponse> {
    let mut url = api_base
        .join(&planned.path)
        .map_err(|err| AuthorityError::Provider(format!("invalid provider URL: {err}")))?;
    if !planned.query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in planned.query {
            pairs.append_pair(&key, &value);
        }
    }
    let mut request = client
        .request(planned.method, url)
        .bearer_auth(lease.bearer())
        .header("Accept", "application/json")
        .header("User-Agent", "ctxa");
    if let Some(body) = planned.body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .map_err(|err| AuthorityError::Provider(format!("provider request failed: {err}")))?;
    let status = response.status();
    let provider_request_id = provider_request_id(response.headers());
    let text = response
        .text()
        .map_err(|err| AuthorityError::Provider(format!("provider response read failed: {err}")))?;
    if !status.is_success() {
        return Err(AuthorityError::Provider(format!(
            "provider returned HTTP {status}"
        )));
    }
    let body = if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or_else(|_| json!({ "text": text }))
    };
    Ok(CapabilityProviderResponse {
        provider_request_id,
        status,
        body,
    })
}

fn provider_request_id(headers: &reqwest::header::HeaderMap) -> Option<String> {
    for name in [
        "x-github-request-id",
        "x-request-id",
        "request-id",
        "client-request-id",
    ] {
        if let Some(value) = headers.get(name).and_then(|value| value.to_str().ok()) {
            return Some(value.to_string());
        }
    }
    None
}

fn filter_github_issue_response(body: Value) -> Value {
    match body {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .filter(|item| item.get("pull_request").is_none())
                .collect(),
        ),
        other => other,
    }
}

fn plan_provider_request(
    provider_kind: CapabilityProviderKind,
    request: &CapabilityExecuteRequest,
) -> Result<PlannedProviderRequest> {
    validate_capability_for_provider(provider_kind, &request.capability, &request.resource)?;
    match provider_kind {
        CapabilityProviderKind::Github => plan_github_request(request),
        CapabilityProviderKind::Google => plan_google_request(request),
        CapabilityProviderKind::Microsoft => plan_microsoft_request(request),
    }
}

fn plan_github_request(request: &CapabilityExecuteRequest) -> Result<PlannedProviderRequest> {
    let CapabilityResource::GithubRepo { owner, repo } =
        parse_resource(CapabilityProviderKind::Github, &request.resource)?
    else {
        return Err(AuthorityError::Config("invalid GitHub resource".into()));
    };
    let repo_path = format!("/repos/{}/{}", path_segment(&owner), path_segment(&repo));
    match request.capability.as_str() {
        "github.issues.read" => Ok(PlannedProviderRequest {
            method: Method::GET,
            path: format!("{repo_path}/issues"),
            query: query_from_operation(&request.operation, &["state", "labels", "per_page"])?,
            body: None,
        }),
        "github.issues.create" => Ok(PlannedProviderRequest {
            method: Method::POST,
            path: format!("{repo_path}/issues"),
            query: Vec::new(),
            body: Some(request.payload.clone()),
        }),
        "github.issues.comment" => {
            let issue_number = required_u64(&request.operation, "issue_number")?;
            Ok(PlannedProviderRequest {
                method: Method::POST,
                path: format!("{repo_path}/issues/{issue_number}/comments"),
                query: Vec::new(),
                body: Some(request.payload.clone()),
            })
        }
        "github.prs.read" => Ok(PlannedProviderRequest {
            method: Method::GET,
            path: format!("{repo_path}/pulls"),
            query: query_from_operation(&request.operation, &["state", "per_page"])?,
            body: None,
        }),
        other => Err(AuthorityError::Config(format!(
            "unsupported GitHub capability {other}"
        ))),
    }
}

fn plan_google_request(request: &CapabilityExecuteRequest) -> Result<PlannedProviderRequest> {
    let resource = parse_resource(CapabilityProviderKind::Google, &request.resource)?;
    match (request.capability.as_str(), resource) {
        ("google.gmail.messages.read", CapabilityResource::GoogleGmail) => {
            Ok(PlannedProviderRequest {
                method: Method::GET,
                path: "/gmail/v1/users/me/messages".into(),
                query: query_from_operation(&request.operation, &["q", "labelIds", "maxResults"])?,
                body: None,
            })
        }
        ("google.gmail.drafts.create", CapabilityResource::GoogleGmail) => {
            Ok(PlannedProviderRequest {
                method: Method::POST,
                path: "/gmail/v1/users/me/drafts".into(),
                query: Vec::new(),
                body: Some(request.payload.clone()),
            })
        }
        ("google.gmail.drafts.send", CapabilityResource::GoogleGmail) => {
            Ok(PlannedProviderRequest {
                method: Method::POST,
                path: "/gmail/v1/users/me/drafts/send".into(),
                query: Vec::new(),
                body: Some(request.payload.clone()),
            })
        }
        ("google.calendar.events.read", CapabilityResource::GoogleCalendar { calendar_id }) => {
            Ok(PlannedProviderRequest {
                method: Method::GET,
                path: format!(
                    "/calendar/v3/calendars/{}/events",
                    path_segment(&calendar_id)
                ),
                query: query_from_operation(
                    &request.operation,
                    &["timeMin", "timeMax", "q", "maxResults"],
                )?,
                body: None,
            })
        }
        ("google.calendar.events.create", CapabilityResource::GoogleCalendar { calendar_id }) => {
            Ok(PlannedProviderRequest {
                method: Method::POST,
                path: format!(
                    "/calendar/v3/calendars/{}/events",
                    path_segment(&calendar_id)
                ),
                query: Vec::new(),
                body: Some(request.payload.clone()),
            })
        }
        ("google.drive.files.read", CapabilityResource::GoogleDrive { file_id }) => {
            Ok(PlannedProviderRequest {
                method: Method::GET,
                path: format!("/drive/v3/files/{}", path_segment(&file_id)),
                query: query_from_operation(&request.operation, &["fields"])?,
                body: None,
            })
        }
        ("google.drive.files.update", CapabilityResource::GoogleDrive { file_id }) => {
            Ok(PlannedProviderRequest {
                method: Method::PATCH,
                path: format!("/drive/v3/files/{}", path_segment(&file_id)),
                query: query_from_operation(&request.operation, &["fields"])?,
                body: Some(request.payload.clone()),
            })
        }
        ("google.docs.documents.read", CapabilityResource::GoogleDocs { document_id }) => {
            Ok(PlannedProviderRequest {
                method: Method::GET,
                path: format!("/v1/documents/{}", path_segment(&document_id)),
                query: Vec::new(),
                body: None,
            })
        }
        ("google.docs.documents.update", CapabilityResource::GoogleDocs { document_id }) => {
            Ok(PlannedProviderRequest {
                method: Method::POST,
                path: format!("/v1/documents/{}:batchUpdate", path_segment(&document_id)),
                query: Vec::new(),
                body: Some(request.payload.clone()),
            })
        }
        _ => Err(AuthorityError::Config(format!(
            "resource {} is not valid for capability {}",
            request.resource, request.capability
        ))),
    }
}

fn plan_microsoft_request(request: &CapabilityExecuteRequest) -> Result<PlannedProviderRequest> {
    let resource = parse_resource(CapabilityProviderKind::Microsoft, &request.resource)?;
    match (request.capability.as_str(), resource) {
        ("microsoft.outlook.messages.read", CapabilityResource::MicrosoftOutlook) => {
            Ok(PlannedProviderRequest {
                method: Method::GET,
                path: "/v1.0/me/messages".into(),
                query: query_from_operation(&request.operation, &["$top", "$filter", "$select"])?,
                body: None,
            })
        }
        ("microsoft.outlook.drafts.create", CapabilityResource::MicrosoftOutlook) => {
            Ok(PlannedProviderRequest {
                method: Method::POST,
                path: "/v1.0/me/messages".into(),
                query: Vec::new(),
                body: Some(request.payload.clone()),
            })
        }
        ("microsoft.outlook.messages.send", CapabilityResource::MicrosoftOutlook) => {
            Ok(PlannedProviderRequest {
                method: Method::POST,
                path: "/v1.0/me/sendMail".into(),
                query: Vec::new(),
                body: Some(request.payload.clone()),
            })
        }
        ("microsoft.calendar.events.read", CapabilityResource::MicrosoftCalendar) => {
            Ok(PlannedProviderRequest {
                method: Method::GET,
                path: "/v1.0/me/events".into(),
                query: query_from_operation(&request.operation, &["$top", "$filter", "$select"])?,
                body: None,
            })
        }
        ("microsoft.calendar.events.create", CapabilityResource::MicrosoftCalendar) => {
            Ok(PlannedProviderRequest {
                method: Method::POST,
                path: "/v1.0/me/events".into(),
                query: Vec::new(),
                body: Some(request.payload.clone()),
            })
        }
        ("microsoft.drive.files.read", CapabilityResource::MicrosoftDrive { item_id }) => {
            Ok(PlannedProviderRequest {
                method: Method::GET,
                path: format!("/v1.0/me/drive/items/{}", path_segment(&item_id)),
                query: query_from_operation(&request.operation, &["$select"])?,
                body: None,
            })
        }
        ("microsoft.drive.files.update", CapabilityResource::MicrosoftDrive { item_id }) => {
            Ok(PlannedProviderRequest {
                method: Method::PATCH,
                path: format!("/v1.0/me/drive/items/{}", path_segment(&item_id)),
                query: Vec::new(),
                body: Some(request.payload.clone()),
            })
        }
        _ => Err(AuthorityError::Config(format!(
            "resource {} is not valid for capability {}",
            request.resource, request.capability
        ))),
    }
}

fn issue_capability_receipt(
    profile: &ProfileConfig,
    provider: &CapabilityProviderConfig,
    request: &CapabilityExecuteRequest,
    matched: &CapabilityGrantMatch,
    lease: &CapabilityLease,
    response: &CapabilityProviderResponse,
    signer: &ReceiptSigner,
) -> Result<Receipt> {
    let action_request = ActionRequest {
        id: format!("cap_{}", Uuid::new_v4()),
        agent_id: profile_subject(profile),
        task_id: None,
        capability: request.capability.clone(),
        resource: request.resource.clone(),
        operation: request.operation.clone(),
        payload: request.payload.clone(),
        payload_hash: None,
        idempotency_key: None,
        requested_at: Some(Utc::now()),
    };
    let execution = ProviderExecution {
        status: "succeeded".into(),
        provider: provider.id.clone(),
        provider_request_id: response.provider_request_id.clone(),
        result: BTreeMap::from([
            ("redacted".into(), json!(true)),
            ("adapter_version".into(), json!(ADAPTER_VERSION)),
            ("capability".into(), json!(request.capability)),
            (
                "provider_kind".into(),
                json!(provider_kind_name(provider.kind)),
            ),
            ("grant_id".into(), json!(matched.grant.id)),
            ("grant_chain_hash".into(), json!(matched.chain_hash)),
            ("lease_id".into(), json!(lease.lease_id)),
            (
                "credential_ref_hash".into(),
                json!(lease.credential_ref_hash),
            ),
            ("response_status".into(), json!(response.status.as_u16())),
            (
                "request_body_hash".into(),
                payload_hash(&request.payload).map(Value::String)?,
            ),
        ]),
    };
    signer.issue(
        profile.id.clone(),
        &action_request,
        action_hash(&action_request)?,
        capability_policy_hash(profile, provider, matched, lease)?,
        None,
        execution,
    )
}

fn capability_policy_hash(
    profile: &ProfileConfig,
    provider: &CapabilityProviderConfig,
    matched: &CapabilityGrantMatch,
    lease: &CapabilityLease,
) -> Result<String> {
    let chain: Vec<Value> = matched
        .chain
        .iter()
        .map(|item| {
            json!({
                "id": item.id,
                "parent": item.parent,
                "profile": item.profile,
                "subject": item.subject,
                "provider": item.provider,
                "capabilities": item.capabilities,
                "resources": item.resources,
                "delegation": {
                    "allowed": item.delegation.allowed,
                    "remaining_depth": item.delegation.remaining_depth,
                },
            })
        })
        .collect();
    payload_hash(&json!({
        "type": "ctxa.capability-grant-policy.v1",
        "adapter_version": ADAPTER_VERSION,
        "holder_profile": profile.id,
        "holder_subject": profile_subject(profile),
        "provider": provider.id,
        "provider_kind": provider_kind_name(provider.kind),
        "matched_grant_id": matched.grant.id,
        "chain_ids": matched.chain.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(),
        "chain": chain,
        "credential_ref_hash": lease.credential_ref_hash,
    }))
}

fn credential_ref_hash(reference: &str) -> Result<String> {
    payload_hash(&json!({ "credential_ref": reference }))
}

fn supported_capability(provider_kind: CapabilityProviderKind, capability: &str) -> bool {
    match provider_kind {
        CapabilityProviderKind::Github => matches!(
            capability,
            "github.issues.read"
                | "github.issues.create"
                | "github.issues.comment"
                | "github.prs.read"
        ),
        CapabilityProviderKind::Google => matches!(
            capability,
            "google.gmail.messages.read"
                | "google.gmail.drafts.create"
                | "google.gmail.drafts.send"
                | "google.calendar.events.read"
                | "google.calendar.events.create"
                | "google.drive.files.read"
                | "google.drive.files.update"
                | "google.docs.documents.read"
                | "google.docs.documents.update"
        ),
        CapabilityProviderKind::Microsoft => matches!(
            capability,
            "microsoft.outlook.messages.read"
                | "microsoft.outlook.drafts.create"
                | "microsoft.outlook.messages.send"
                | "microsoft.calendar.events.read"
                | "microsoft.calendar.events.create"
                | "microsoft.drive.files.read"
                | "microsoft.drive.files.update"
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CapabilityResource {
    GithubRepo { owner: String, repo: String },
    GoogleGmail,
    GoogleCalendar { calendar_id: String },
    GoogleDrive { file_id: String },
    GoogleDocs { document_id: String },
    MicrosoftOutlook,
    MicrosoftCalendar,
    MicrosoftDrive { item_id: String },
}

fn parse_resource(
    provider_kind: CapabilityProviderKind,
    resource: &str,
) -> Result<CapabilityResource> {
    match provider_kind {
        CapabilityProviderKind::Github => {
            let rest = resource.strip_prefix("github:").ok_or_else(|| {
                AuthorityError::Config(format!("invalid GitHub resource {resource}"))
            })?;
            let (owner, repo) = rest.split_once('/').ok_or_else(|| {
                AuthorityError::Config(format!("invalid GitHub resource {resource}"))
            })?;
            validate_resource_segment(owner, "GitHub owner")?;
            validate_resource_segment(repo, "GitHub repo")?;
            Ok(CapabilityResource::GithubRepo {
                owner: owner.into(),
                repo: repo.into(),
            })
        }
        CapabilityProviderKind::Google => {
            if resource == "google:gmail" {
                return Ok(CapabilityResource::GoogleGmail);
            }
            if let Some(calendar_id) = resource.strip_prefix("google:calendar/") {
                validate_resource_segment(calendar_id, "Google calendar id")?;
                return Ok(CapabilityResource::GoogleCalendar {
                    calendar_id: calendar_id.into(),
                });
            }
            if let Some(file_id) = resource.strip_prefix("google:drive/") {
                validate_resource_segment(file_id, "Google Drive file id")?;
                return Ok(CapabilityResource::GoogleDrive {
                    file_id: file_id.into(),
                });
            }
            if let Some(document_id) = resource.strip_prefix("google:docs/") {
                validate_resource_segment(document_id, "Google Docs document id")?;
                return Ok(CapabilityResource::GoogleDocs {
                    document_id: document_id.into(),
                });
            }
            Err(AuthorityError::Config(format!(
                "invalid Google resource {resource}"
            )))
        }
        CapabilityProviderKind::Microsoft => {
            if resource == "microsoft:outlook" {
                return Ok(CapabilityResource::MicrosoftOutlook);
            }
            if resource == "microsoft:calendar" {
                return Ok(CapabilityResource::MicrosoftCalendar);
            }
            if let Some(item_id) = resource.strip_prefix("microsoft:drive/") {
                validate_resource_segment(item_id, "Microsoft Drive item id")?;
                return Ok(CapabilityResource::MicrosoftDrive {
                    item_id: item_id.into(),
                });
            }
            Err(AuthorityError::Config(format!(
                "invalid Microsoft resource {resource}"
            )))
        }
    }
}

fn resource_matches_capability(resource: &CapabilityResource, capability: &str) -> bool {
    matches!(
        (resource, capability),
        (
            CapabilityResource::GithubRepo { .. },
            "github.issues.read"
                | "github.issues.create"
                | "github.issues.comment"
                | "github.prs.read"
        ) | (
            CapabilityResource::GoogleGmail,
            "google.gmail.messages.read"
                | "google.gmail.drafts.create"
                | "google.gmail.drafts.send"
        ) | (
            CapabilityResource::GoogleCalendar { .. },
            "google.calendar.events.read" | "google.calendar.events.create"
        ) | (
            CapabilityResource::GoogleDrive { .. },
            "google.drive.files.read" | "google.drive.files.update"
        ) | (
            CapabilityResource::GoogleDocs { .. },
            "google.docs.documents.read" | "google.docs.documents.update"
        ) | (
            CapabilityResource::MicrosoftOutlook,
            "microsoft.outlook.messages.read"
                | "microsoft.outlook.drafts.create"
                | "microsoft.outlook.messages.send"
        ) | (
            CapabilityResource::MicrosoftCalendar,
            "microsoft.calendar.events.read" | "microsoft.calendar.events.create"
        ) | (
            CapabilityResource::MicrosoftDrive { .. },
            "microsoft.drive.files.read" | "microsoft.drive.files.update"
        )
    )
}

fn validate_resource_segment(segment: &str, label: &str) -> Result<()> {
    if segment.is_empty()
        || segment == "."
        || segment == ".."
        || segment.contains('/')
        || segment.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(AuthorityError::Config(format!("invalid {label}")));
    }
    Ok(())
}

fn query_from_operation(operation: &Value, allowed: &[&str]) -> Result<Vec<(String, String)>> {
    if operation.is_null() {
        return Ok(Vec::new());
    }
    let object = operation
        .as_object()
        .ok_or_else(|| AuthorityError::Config("operation must be a JSON object".into()))?;
    let mut query = Vec::new();
    for key in allowed {
        if let Some(value) = object.get(*key) {
            query.push(((*key).to_string(), query_value(value)?));
        }
    }
    Ok(query)
}

fn query_value(value: &Value) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err(AuthorityError::Config(
            "query operation values must be strings, numbers, or booleans".into(),
        )),
    }
}

fn required_u64(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| AuthorityError::Config(format!("operation must include numeric {key}")))
}

fn normalized_strings(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    values
}

fn provider_kind_name(kind: CapabilityProviderKind) -> &'static str {
    match kind {
        CapabilityProviderKind::Github => "github",
        CapabilityProviderKind::Google => "google",
        CapabilityProviderKind::Microsoft => "microsoft",
    }
}

fn path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, CapabilityProviderAuthConfig};

    fn profile(id: &str) -> ProfileConfig {
        ProfileConfig {
            id: id.into(),
            agent: Some(id.into()),
            env_vars: Default::default(),
            http_resources: Vec::new(),
        }
    }

    fn provider(id: &str) -> CapabilityProviderConfig {
        CapabilityProviderConfig {
            id: id.into(),
            kind: CapabilityProviderKind::Github,
            api_base: "https://api.github.com".into(),
            auth: CapabilityProviderAuthConfig::Bearer {
                token_ref: "github-token".into(),
            },
        }
    }

    fn grant(
        id: &str,
        parent: Option<&str>,
        profile: &str,
        capabilities: Vec<&str>,
        resources: Vec<&str>,
        delegation: GrantDelegationConfig,
    ) -> CapabilityGrantConfig {
        CapabilityGrantConfig {
            id: id.into(),
            parent: parent.map(String::from),
            profile: profile.into(),
            subject: profile.into(),
            provider: "github".into(),
            capabilities: capabilities.into_iter().map(String::from).collect(),
            resources: resources.into_iter().map(String::from).collect(),
            delegation,
        }
    }

    #[test]
    fn validates_attenuated_capability_grants() {
        let config = AppConfig {
            profiles: vec![profile("main-agent"), profile("worker-agent")],
            capability_providers: vec![provider("github")],
            capability_grants: vec![
                grant(
                    "github-root",
                    None,
                    "main-agent",
                    vec!["github.issues.create", "github.issues.read"],
                    vec!["github:acme/app"],
                    capability_delegation(true, 2),
                ),
                grant(
                    "github-read",
                    Some("github-root"),
                    "worker-agent",
                    vec!["github.issues.read"],
                    vec!["github:acme/app"],
                    capability_delegation(false, 0),
                ),
            ],
            ..Default::default()
        };

        config.validate().unwrap();
    }

    #[test]
    fn rejects_broader_capability_child_grants() {
        let config = AppConfig {
            profiles: vec![profile("main-agent"), profile("worker-agent")],
            capability_providers: vec![provider("github")],
            capability_grants: vec![
                grant(
                    "github-root",
                    None,
                    "main-agent",
                    vec!["github.issues.read"],
                    vec!["github:acme/app"],
                    capability_delegation(true, 2),
                ),
                grant(
                    "github-write",
                    Some("github-root"),
                    "worker-agent",
                    vec!["github.issues.create"],
                    vec!["github:acme/app"],
                    capability_delegation(false, 0),
                ),
            ],
            ..Default::default()
        };

        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("capability github.issues.create"));
    }

    #[test]
    fn rejects_wrong_resource_for_provider_capability() {
        let err = validate_capability_for_provider(
            CapabilityProviderKind::Google,
            "google.drive.files.read",
            "google:gmail",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not valid"));
    }
}
