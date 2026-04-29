use assert_cmd::Command;
use authority_broker::approvals::ApprovalProvider;
use authority_broker::audit::AuditLog;
use authority_broker::backends::{FakeBackend, SecretLease};
use authority_broker::models::{
    ActionRequest, PolicyDecision, PolicyDecisionKind, ProviderExecution, Receipt,
};
use authority_broker::policy::PolicyDocument;
use authority_broker::providers::{FakeProvider, ProviderAdapter};
use authority_broker::receipts::{action_hash, ReceiptSigner};
use authority_broker::runtime::BrokerRuntime;
use authority_broker::{AuthorityError, Result};
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
fn policy_check_denies_http_query_paths() {
    let temp = tempfile::tempdir().unwrap();
    let action_path = temp.path().join("query-path-action.json");
    fs::write(
        &action_path,
        r#"{
  "id": "act_query_path",
  "agent_id": "demo",
  "capability": "http.request",
  "resource": "fake-github",
  "operation": {
    "method": "GET",
    "host": "api.fake-github.local",
    "path": "/repos/ctx-rs/authority-broker/issues/1?admin=true"
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
fn policy_check_denies_http_query_fields_in_payload() {
    let temp = tempfile::tempdir().unwrap();
    let action_path = temp.path().join("query-payload-action.json");
    fs::write(
        &action_path,
        r#"{
  "id": "act_query_payload",
  "agent_id": "demo",
  "capability": "http.request",
  "resource": "fake-github",
  "operation": {
    "method": "GET",
    "host": "api.fake-github.local",
    "path": "/repos/ctx-rs/authority-broker/issues/1"
  },
  "payload": {
    "query": "admin=true"
  }
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

    let log_output = ctxa()
        .env("CTXA_HOME", home.path())
        .arg("log")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let log_text = String::from_utf8(log_output).unwrap();
    assert!(log_text.contains("approval_failed"), "{log_text}");
    assert!(log_text.contains("execution_skipped"), "{log_text}");
    assert!(!log_text.contains("execution_attempted"), "{log_text}");
}

#[test]
fn action_request_does_not_accept_caller_controlled_approval() {
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
            "approve",
        ])
        .assert()
        .failure();
}

#[test]
fn action_request_ignores_caller_controlled_approval_env() {
    let home = tempfile::tempdir().unwrap();
    ctxa()
        .env("CTXA_HOME", home.path())
        .env("CTXA_APPROVAL_MODE", "approve")
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
fn runtime_can_use_internal_test_approval_provider() {
    let home = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(home.path().join("audit.sqlite3")).unwrap();
    let policy_text = fs::read_to_string(fixture("approval-required-policy.yaml")).unwrap();
    let policy: PolicyDocument = serde_yaml::from_str(&policy_text).unwrap();
    let action_text = fs::read_to_string(fixture("approval-required-action.json")).unwrap();
    let request: ActionRequest = serde_json::from_str(&action_text).unwrap();
    let approvals = ApprovalProvider::auto_approve_for_tests();
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

    let receipt = runtime.execute(&request).unwrap();
    let approval = receipt.approval.expect("approval receipt");
    assert!(approval.required);
    assert_eq!(approval.approved_by.as_deref(), Some("local-test-approver"));

    let events = audit.list(20).unwrap();
    assert!(events.iter().any(|(_, kind, _)| kind == "approval_granted"));
    assert!(events.iter().any(|(_, kind, _)| kind == "action_executed"));
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
fn policy_check_rejects_unsupported_grant_capabilities() {
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("unsupported-capability-policy.yaml");
    fs::write(
        &policy_path,
        r#"
version: 1
grants:
  - id: typo
    agent: demo
    capability: http.requset
    resource: fake-github
    allow:
      methods: [GET]
      hosts: [api.fake-github.local]
      path_prefixes: [/safe]
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
        .stderr(predicate::str::contains("unsupported capability"));
}

#[test]
fn policy_check_rejects_unconstrained_email_grants() {
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("unconstrained-email-policy.yaml");
    fs::write(
        &policy_path,
        r#"
version: 1
grants:
  - id: mail
    agent: demo
    capability: email.send
    resource: fake-mailgun
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
            fixture("approval-required-action.json").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("recipient_domains"));
}

#[test]
fn policy_check_denies_email_recipient_domain_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let action_path = temp.path().join("email-domain-mismatch-action.json");
    fs::write(
        &action_path,
        r#"{
  "id": "act_email_domain_mismatch",
  "agent_id": "demo",
  "capability": "email.send",
  "resource": "fake-mailgun",
  "operation": {
    "to": "attacker@example.net",
    "subject": "Demo approval"
  },
  "payload": {
    "body": "Approval-bound test payload"
  }
}"#,
    )
    .unwrap();

    let output = ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            fixture("approval-required-policy.yaml").to_str().unwrap(),
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
fn policy_check_denies_multi_recipient_email_strings() {
    let temp = tempfile::tempdir().unwrap();
    let action_path = temp.path().join("multi-recipient-email-action.json");
    fs::write(
        &action_path,
        r#"{
  "id": "act_multi_recipient_email",
  "agent_id": "demo",
  "capability": "email.send",
  "resource": "fake-mailgun",
  "operation": {
    "to": "attacker@evil.test, external@example.com",
    "subject": "Demo approval"
  },
  "payload": {
    "body": "Approval-bound test payload"
  }
}"#,
    )
    .unwrap();

    let output = ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            fixture("approval-required-policy.yaml").to_str().unwrap(),
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
fn policy_check_denies_email_cc_and_bcc_fields() {
    let temp = tempfile::tempdir().unwrap();
    let action_path = temp.path().join("cc-email-action.json");
    fs::write(
        &action_path,
        r#"{
  "id": "act_cc_email",
  "agent_id": "demo",
  "capability": "email.send",
  "resource": "fake-mailgun",
  "operation": {
    "to": "external@example.com",
    "cc": "attacker@evil.test",
    "subject": "Demo approval"
  },
  "payload": {
    "body": "Approval-bound test payload"
  }
}"#,
    )
    .unwrap();

    let output = ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            fixture("approval-required-policy.yaml").to_str().unwrap(),
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
fn policy_check_denies_email_recipient_fields_in_payload() {
    let temp = tempfile::tempdir().unwrap();
    let action_path = temp.path().join("payload-cc-email-action.json");
    fs::write(
        &action_path,
        r#"{
  "id": "act_payload_cc_email",
  "agent_id": "demo",
  "capability": "email.send",
  "resource": "fake-mailgun",
  "operation": {
    "to": "external@example.com",
    "subject": "Demo approval"
  },
  "payload": {
    "body": "Approval-bound test payload",
    "cc": "attacker@evil.test"
  }
}"#,
    )
    .unwrap();

    let output = ctxa()
        .args([
            "policy",
            "check",
            "--policy",
            fixture("approval-required-policy.yaml").to_str().unwrap(),
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
fn policy_check_rejects_trailing_slash_http_path_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let policy_path = temp.path().join("trailing-slash-prefix-policy.yaml");
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
      path_prefixes: ['/repos/ctx-rs/authority-broker/issues/']
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
fn receipts_verify_rejects_missing_signed_null_fields() {
    let home = tempfile::tempdir().unwrap();
    let receipt_path = home.path().join("missing-signed-field-receipt.json");

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
    receipt.as_object_mut().unwrap().remove("approval");
    fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["receipts", "verify", receipt_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "receipt missing signed field approval",
        ));
}

#[test]
fn receipts_verify_rejects_duplicate_json_keys() {
    let home = tempfile::tempdir().unwrap();
    let receipt_path = home.path().join("duplicate-key-receipt.json");

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
    let receipt_text = String::from_utf8(output).unwrap();
    let duplicate = receipt_text.replacen(
        r#""redacted": true"#,
        r#""redacted": false,
      "redacted": true"#,
        1,
    );
    assert_ne!(duplicate, receipt_text);
    fs::write(&receipt_path, duplicate).unwrap();

    ctxa()
        .env("CTXA_HOME", home.path())
        .args(["receipts", "verify", receipt_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("duplicate JSON key"));
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
    assert!(err.contains("approval does not match action, payload, or policy"));
}

#[test]
fn runtime_rejects_expired_approvals_before_execution() {
    let home = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(home.path().join("audit.sqlite3")).unwrap();
    let policy_text = fs::read_to_string(fixture("approval-required-policy.yaml")).unwrap();
    let policy: PolicyDocument = serde_yaml::from_str(&policy_text).unwrap();
    let action_text = fs::read_to_string(fixture("approval-required-action.json")).unwrap();
    let request: ActionRequest = serde_json::from_str(&action_text).unwrap();
    let approvals = ApprovalProvider::expired_for_tests();
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
    assert!(err.contains("approval expired"));

    let events = audit.list(20).unwrap();
    assert!(events.iter().any(|(_, kind, _)| kind == "approval_expired"));
    assert!(!events.iter().any(|(_, kind, _)| kind == "approval_granted"));
    assert!(
        events
            .iter()
            .any(|(_, kind, data)| kind == "execution_skipped"
                && data["reason"] == "approval expired")
    );
    assert!(!events
        .iter()
        .any(|(_, kind, _)| kind == "execution_attempted"));
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
    let request: ActionRequest = serde_json::from_str(&action_text).unwrap();
    let approvals = ApprovalProvider::reject();
    let provider = FailingProvider;
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

#[test]
fn runtime_returns_receipt_when_final_audit_write_fails_after_execution() {
    let home = tempfile::tempdir().unwrap();
    let audit_path = home.path().join("audit.sqlite3");
    let audit = AuditLog::open(&audit_path).unwrap();
    let policy_text = fs::read_to_string(fixture("demo-policy.yaml")).unwrap();
    let policy: PolicyDocument = serde_yaml::from_str(&policy_text).unwrap();
    let action_text = fs::read_to_string(fixture("demo-action.json")).unwrap();
    let request: ActionRequest = serde_json::from_str(&action_text).unwrap();
    let approvals = ApprovalProvider::reject();
    let provider = AuditBreakingProvider {
        audit_path: audit_path.clone(),
    };
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

    let receipt = runtime.execute(&request).unwrap();

    assert_eq!(receipt.execution.status, "succeeded");
    assert_eq!(
        receipt.execution.provider_request_id.as_deref(),
        Some("audit-broken-after-execute")
    );
}

struct AuditBreakingProvider {
    audit_path: PathBuf,
}

impl ProviderAdapter for AuditBreakingProvider {
    fn execute(
        &self,
        request: &ActionRequest,
        _secret: Option<&SecretLease>,
    ) -> Result<ProviderExecution> {
        fs::remove_file(&self.audit_path)?;
        fs::create_dir(&self.audit_path)?;
        Ok(ProviderExecution {
            status: "succeeded".into(),
            provider: request.resource.clone(),
            provider_request_id: Some("audit-broken-after-execute".into()),
            result: BTreeMap::from([("redacted".into(), serde_json::Value::Bool(true))]),
        })
    }
}

struct FailingProvider;

impl ProviderAdapter for FailingProvider {
    fn execute(
        &self,
        _request: &ActionRequest,
        _secret: Option<&SecretLease>,
    ) -> Result<ProviderExecution> {
        Err(AuthorityError::Provider(
            "forced fake provider error".into(),
        ))
    }
}
