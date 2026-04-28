use assert_cmd::Command;
use authority_broker::approvals::ApprovalProvider;
use authority_broker::audit::AuditLog;
use authority_broker::backends::FakeBackend;
use authority_broker::models::{ActionRequest, PolicyDecision, PolicyDecisionKind, Receipt};
use authority_broker::policy::PolicyDocument;
use authority_broker::providers::FakeProvider;
use authority_broker::receipts::{action_hash, ReceiptSigner};
use authority_broker::runtime::BrokerRuntime;
use predicates::prelude::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn ctxa() -> Command {
    Command::cargo_bin("ctxa").expect("ctxa binary")
}

#[test]
fn policy_check_allows_matching_grant() {
    let output = ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            fixture("demo-policy.yaml").to_str().unwrap(),
            "--file",
            fixture("demo-action.json").to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let decision: PolicyDecision = serde_json::from_slice(&output).unwrap();
    assert_eq!(decision.decision, PolicyDecisionKind::Allow);
    assert_eq!(decision.matched_grants, vec!["fake_http_read"]);
}

#[test]
fn policy_check_denies_when_no_grant_matches() {
    let temp = tempfile::tempdir().unwrap();
    let action_path = temp.path().join("denied-action.json");
    fs::write(
        &action_path,
        r#"{
  "id": "act_denied",
  "agent_id": "demo",
  "capability": "http.request",
  "resource": "fake-github",
  "operation": {
    "method": "POST",
    "host": "api.fake-github.local",
    "path": "/repos/ctx-rs/authority-broker/issues/1"
  },
  "payload": {}
}"#,
    )
    .unwrap();

    let output = ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            fixture("demo-policy.yaml").to_str().unwrap(),
            "--file",
            action_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let decision: PolicyDecision = serde_json::from_slice(&output).unwrap();
    assert_eq!(decision.decision, PolicyDecisionKind::Deny);
    assert_eq!(decision.reasons, vec!["no matching grant"]);
}

#[test]
fn policy_check_denies_path_prefix_siblings() {
    let temp = tempfile::tempdir().unwrap();
    let action_path = temp.path().join("sibling-action.json");
    fs::write(
        &action_path,
        r#"{
  "id": "act_sibling",
  "agent_id": "demo",
  "capability": "http.request",
  "resource": "fake-github",
  "operation": {
    "method": "GET",
    "host": "api.fake-github.local",
    "path": "/repos/ctx-rs/authority-broker/issues-admin"
  },
  "payload": {}
}"#,
    )
    .unwrap();

    let output = ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            fixture("demo-policy.yaml").to_str().unwrap(),
            "--file",
            action_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let decision: PolicyDecision = serde_json::from_slice(&output).unwrap();
    assert_eq!(decision.decision, PolicyDecisionKind::Deny);
}

#[test]
fn policy_check_denies_dot_segment_paths() {
    let temp = tempfile::tempdir().unwrap();
    let action_path = temp.path().join("dot-segment-action.json");
    fs::write(
        &action_path,
        r#"{
  "id": "act_dot_segment",
  "agent_id": "demo",
  "capability": "http.request",
  "resource": "fake-github",
  "operation": {
    "method": "GET",
    "host": "api.fake-github.local",
    "path": "/repos/ctx-rs/authority-broker/issues/../settings"
  },
  "payload": {}
}"#,
    )
    .unwrap();

    let output = ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            fixture("demo-policy.yaml").to_str().unwrap(),
            "--file",
            action_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let decision: PolicyDecision = serde_json::from_slice(&output).unwrap();
    assert_eq!(decision.decision, PolicyDecisionKind::Deny);
}

#[test]
fn policy_check_denies_encoded_dot_segment_paths() {
    let temp = tempfile::tempdir().unwrap();
    let action_path = temp.path().join("encoded-dot-segment-action.json");
    fs::write(
        &action_path,
        r#"{
  "id": "act_encoded_dot_segment",
  "agent_id": "demo",
  "capability": "http.request",
  "resource": "fake-github",
  "operation": {
    "method": "GET",
    "host": "api.fake-github.local",
    "path": "/repos/ctx-rs/authority-broker/issues/%2e%2e/settings"
  },
  "payload": {}
}"#,
    )
    .unwrap();

    let output = ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            fixture("demo-policy.yaml").to_str().unwrap(),
            "--file",
            action_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let decision: PolicyDecision = serde_json::from_slice(&output).unwrap();
    assert_eq!(decision.decision, PolicyDecisionKind::Deny);
}

#[test]
fn policy_check_returns_require_approval_for_approval_grant() {
    let output = ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            fixture("approval-required-policy.yaml").to_str().unwrap(),
            "--file",
            fixture("approval-required-action.json").to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let decision: PolicyDecision = serde_json::from_slice(&output).unwrap();
    assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
    assert_eq!(
        decision.matched_grants,
        vec!["fake_mail_send_requires_approval"]
    );
}

#[test]
fn action_request_runs_allowed_action_without_approval_record() {
    let home = tempfile::tempdir().unwrap();
    let output = ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "action",
            "request",
            "--policy",
            fixture("demo-policy.yaml").to_str().unwrap(),
            "--file",
            fixture("demo-action.json").to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let receipt: Receipt = serde_json::from_slice(&output).unwrap();
    assert_eq!(receipt.execution.status, "succeeded");
    assert!(receipt.approval.is_none());
}

#[test]
fn action_request_auto_approves_approval_required_action() {
    let home = tempfile::tempdir().unwrap();
    let output = ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "action",
            "request",
            "--policy",
            fixture("approval-required-policy.yaml").to_str().unwrap(),
            "--file",
            fixture("approval-required-action.json").to_str().unwrap(),
            "--approval",
            "approve",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let receipt: Receipt = serde_json::from_slice(&output).unwrap();
    let approval = receipt.approval.expect("approval receipt");
    assert!(approval.required);
    assert_eq!(approval.approved_by.as_deref(), Some("local-test-approver"));
}

#[test]
fn action_request_requires_explicit_approval_provider_by_default() {
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "action",
            "request",
            "--policy",
            fixture("approval-required-policy.yaml").to_str().unwrap(),
            "--file",
            fixture("approval-required-action.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("approval is required"));
}

#[test]
fn action_request_can_reject_approval_required_action() {
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "action",
            "request",
            "--policy",
            fixture("approval-required-policy.yaml").to_str().unwrap(),
            "--file",
            fixture("approval-required-action.json").to_str().unwrap(),
            "--approval",
            "reject",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("approval rejected"));
}

#[test]
fn action_request_can_reject_approval_required_action_from_env() {
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .env("CTXA_APPROVAL_MODE", "reject")
        .args([
            "action",
            "request",
            "--policy",
            fixture("approval-required-policy.yaml").to_str().unwrap(),
            "--file",
            fixture("approval-required-action.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("approval rejected"));
}

#[test]
fn action_request_rejects_mismatched_supplied_payload_hash() {
    let home = tempfile::tempdir().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut action: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(fixture("demo-action.json")).unwrap()).unwrap();
    action["payload_hash"] = serde_json::Value::String("sha256:not-the-payload".into());
    let action_path = temp.path().join("bad-hash-action.json");
    fs::write(&action_path, serde_json::to_string_pretty(&action).unwrap()).unwrap();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "action",
            "request",
            "--policy",
            fixture("demo-policy.yaml").to_str().unwrap(),
            "--file",
            action_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "payload_hash does not match canonical action",
        ));
}

#[test]
fn policy_check_rejects_unknown_policy_fields() {
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("bad-policy.yaml");
    fs::write(
        &policy_path,
        r#"
version: 1
grants:
  - id: bad
    agent: demo
    capability: http.request
    resource: fake-github
    allow:
      method: [GET]
"#,
    )
    .unwrap();

    ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--file",
            fixture("demo-action.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown field"));
}

#[test]
fn policy_check_rejects_unsupported_policy_versions() {
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("future-policy.yaml");
    fs::write(
        &policy_path,
        r#"
version: 2
grants:
  - id: future
    agent: demo
    capability: http.request
    resource: fake-github
    allow:
      methods: [GET]
      hosts: [api.fake-github.local]
"#,
    )
    .unwrap();

    ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--file",
            fixture("demo-action.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported policy version"));
}

#[test]
fn policy_check_rejects_incomplete_http_grants() {
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("broad-policy.yaml");
    fs::write(
        &policy_path,
        r#"
version: 1
grants:
  - id: broad
    agent: demo
    capability: http.request
    resource: fake-github
    allow: {}
"#,
    )
    .unwrap();

    ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--file",
            fixture("demo-action.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "must specify methods, hosts, and path_prefixes",
        ));
}

#[test]
fn policy_check_rejects_empty_http_path_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("empty-prefix-policy.yaml");
    fs::write(
        &policy_path,
        r#"
version: 1
grants:
  - id: broad
    agent: demo
    capability: http.request
    resource: fake-github
    allow:
      methods: [GET]
      hosts: [api.fake-github.local]
      path_prefixes: ['']
"#,
    )
    .unwrap();

    ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            policy_path.to_str().unwrap(),
            "--file",
            fixture("demo-action.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid path_prefix"));
}

#[test]
fn receipts_verify_accepts_valid_and_rejects_tampering() {
    let home = tempfile::tempdir().unwrap();
    let receipt_path = home.path().join("receipt.json");
    let tampered_path = home.path().join("tampered-receipt.json");

    let output = ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "action",
            "request",
            "--policy",
            fixture("demo-policy.yaml").to_str().unwrap(),
            "--file",
            fixture("demo-action.json").to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    fs::write(&receipt_path, &output).unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["receipts", "verify", receipt_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("receipt verified"));

    let mut receipt: serde_json::Value = serde_json::from_slice(&output).unwrap();
    receipt["execution"]["status"] = serde_json::Value::String("failed".into());
    fs::write(&tampered_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["receipts", "verify", tampered_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "receipt signature verification failed",
        ));
}

#[test]
fn receipts_verify_rejects_unsigned_extra_fields() {
    let home = tempfile::tempdir().unwrap();
    let receipt_path = home.path().join("extra-field-receipt.json");

    let output = ctxa()
        .env("CTXA_HOME", home.path())
        .args([
            "action",
            "request",
            "--policy",
            fixture("demo-policy.yaml").to_str().unwrap(),
            "--file",
            fixture("demo-action.json").to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let mut receipt: serde_json::Value = serde_json::from_slice(&output).unwrap();
    receipt["unsigned_extra"] = serde_json::Value::String("tampered".into());
    fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["receipts", "verify", receipt_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown field"));
}

#[test]
fn init_preserves_existing_config() {
    let home = tempfile::tempdir().unwrap();

    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["agent", "create", "demo"])
        .assert()
        .success();
    ctxa()
        .env("CTXA_HOME", home.path())
        .arg("init")
        .assert()
        .success();

    let config = fs::read_to_string(home.path().join("config.yaml")).unwrap();
    assert!(config.contains("demo"));
}

#[test]
fn runtime_rejects_approval_bound_to_changed_payload() {
    let home = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(home.path().join("audit.sqlite3")).unwrap();
    let policy_text = fs::read_to_string(fixture("approval-required-policy.yaml")).unwrap();
    let policy: PolicyDocument = serde_yaml::from_str(&policy_text).unwrap();
    let action_text = fs::read_to_string(fixture("approval-required-action.json")).unwrap();
    let request: ActionRequest = serde_json::from_str(&action_text).unwrap();
    let approvals = ApprovalProvider::mismatched_payload_for_tests();
    let provider = FakeProvider::new(&request.resource);
    let backend = FakeBackend::new(BTreeMap::from([(
        "default".to_string(),
        "fake-secret-value".to_string(),
    )]));
    let signer = ReceiptSigner::deterministic_for_tests([42; 32]);
    let runtime = BrokerRuntime {
        policy: &policy,
        audit: &audit,
        approvals: &approvals,
        provider: &provider,
        secret_backend: Some(&backend),
        signer: &signer,
    };

    let err = runtime.execute(&request).unwrap_err().to_string();
    assert!(err.contains("approval does not match payload or policy"));
}

#[test]
fn runtime_action_hash_includes_operation() {
    let action_text = fs::read_to_string(fixture("demo-action.json")).unwrap();
    let mut first: ActionRequest = serde_json::from_str(&action_text).unwrap();
    let mut second = first.clone();

    first.id = "act_one".into();
    second.id = "act_two".into();
    second.operation["path"] =
        serde_json::Value::String("/repos/ctx-rs/authority-broker/issues/2".into());

    assert_ne!(action_hash(&first).unwrap(), action_hash(&second).unwrap());
}

#[test]
fn runtime_audits_provider_failures_after_attempt() {
    let home = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(home.path().join("audit.sqlite3")).unwrap();
    let policy_text = fs::read_to_string(fixture("demo-policy.yaml")).unwrap();
    let policy: PolicyDocument = serde_yaml::from_str(&policy_text).unwrap();
    let action_text = fs::read_to_string(fixture("demo-action.json")).unwrap();
    let mut request: ActionRequest = serde_json::from_str(&action_text).unwrap();
    request.operation["force_provider_error"] = serde_json::Value::Bool(true);
    let approvals = ApprovalProvider::reject();
    let provider = FakeProvider::new(&request.resource);
    let backend = FakeBackend::new(BTreeMap::from([(
        "default".to_string(),
        "fake-secret-value".to_string(),
    )]));
    let signer = ReceiptSigner::deterministic_for_tests([42; 32]);
    let runtime = BrokerRuntime {
        policy: &policy,
        audit: &audit,
        approvals: &approvals,
        provider: &provider,
        secret_backend: Some(&backend),
        signer: &signer,
    };

    let err = runtime.execute(&request).unwrap_err().to_string();
    assert!(err.contains("forced fake provider error"));

    let events = audit.list(20).unwrap();
    assert!(events
        .iter()
        .any(|(_, kind, _)| kind == "execution_attempted"));
    assert!(events.iter().any(|(_, kind, _)| kind == "execution_failed"));
}
