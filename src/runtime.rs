use crate::approvals::ApprovalProvider;
use crate::audit::AuditLog;
use crate::backends::SecretBackend;
use crate::models::{ActionRequest, PolicyDecisionKind, Receipt};
use crate::policy::PolicyDocument;
use crate::providers::ProviderAdapter;
use crate::receipts::{action_hash, ReceiptSigner};
use crate::{AuthorityError, Result};
use chrono::Utc;
use serde_json::json;

pub struct BrokerRuntime<'a> {
    pub policy: &'a PolicyDocument,
    pub audit: &'a AuditLog,
    pub approvals: &'a ApprovalProvider,
    pub provider: &'a dyn ProviderAdapter,
    pub secret_backend: Option<&'a dyn SecretBackend>,
    pub signer: &'a ReceiptSigner,
}

impl<'a> BrokerRuntime<'a> {
    pub fn execute(&self, request: &ActionRequest) -> Result<Receipt> {
        let payload_hash = action_hash(request)?;
        if let Some(provided_hash) = &request.payload_hash {
            if provided_hash != &payload_hash {
                return Err(AuthorityError::Config(
                    "payload_hash does not match canonical action".into(),
                ));
            }
        }
        let policy_hash = self.policy.hash()?;
        let decision = self.policy.evaluate(request)?;
        self.audit.record(
            "policy_decision",
            &json!({
                "action_request_id": request.id,
                "decision": decision.decision,
                "reasons": decision.reasons,
                "matched_grants": decision.matched_grants,
            }),
        )?;

        let approval = match decision.decision {
            PolicyDecisionKind::Deny => {
                return Err(AuthorityError::Denied(decision.reasons.join(", ")));
            }
            PolicyDecisionKind::Allow => None,
            PolicyDecisionKind::RequireApproval => {
                self.audit.record(
                    "approval_requested",
                    &json!({
                        "action_request_id": request.id,
                        "policy_hash": policy_hash.clone(),
                        "payload_hash": payload_hash.clone(),
                    }),
                )?;
                match self
                    .approvals
                    .request(request, payload_hash.clone(), policy_hash.clone())
                {
                    Ok(Some(record)) => {
                        self.validate_approval_record(
                            request,
                            &record,
                            &payload_hash,
                            &policy_hash,
                        )?;
                        self.audit.record(
                            "approval_granted",
                            &json!({
                                "action_request_id": request.id,
                                "approval_id": record.approval_id.clone(),
                                "approved_by": record.approved_by.clone(),
                            }),
                        )?;
                        Some(record)
                    }
                    Ok(None) => {
                        self.audit.record(
                            "approval_rejected",
                            &json!({
                                "action_request_id": request.id,
                            }),
                        )?;
                        self.audit.record(
                            "execution_skipped",
                            &json!({
                                "action_request_id": request.id,
                                "reason": "approval rejected",
                            }),
                        )?;
                        return Err(AuthorityError::ApprovalFailed("approval rejected".into()));
                    }
                    Err(err) => {
                        self.audit.record(
                            "approval_failed",
                            &json!({
                                "action_request_id": request.id,
                                "reason": "approval unavailable",
                            }),
                        )?;
                        self.audit.record(
                            "execution_skipped",
                            &json!({
                                "action_request_id": request.id,
                                "reason": "approval unavailable",
                            }),
                        )?;
                        return Err(err);
                    }
                }
            }
        };

        let secret = match self.secret_backend {
            Some(backend) => Some(backend.resolve("default")?),
            None => None,
        };
        self.audit.record(
            "execution_attempted",
            &json!({
                "action_request_id": request.id,
                "provider": request.resource,
                "capability": request.capability,
            }),
        )?;
        let execution = match self.provider.execute(request, secret.as_ref()) {
            Ok(execution) => execution,
            Err(err) => {
                self.audit.record(
                    "execution_failed",
                    &json!({
                        "action_request_id": request.id,
                        "provider": request.resource,
                        "capability": request.capability,
                        "error": "provider execution failed",
                    }),
                )?;
                return Err(err);
            }
        };
        let receipt = self.signer.issue(
            "local".into(),
            request,
            payload_hash,
            policy_hash,
            approval.as_ref(),
            execution,
        )?;
        if let Ok(receipt_value) = serde_json::to_value(&receipt) {
            let _ = self.audit.record("action_executed", &receipt_value);
        }
        Ok(receipt)
    }

    fn validate_approval_record(
        &self,
        request: &ActionRequest,
        record: &crate::models::ApprovalRecord,
        payload_hash: &str,
        policy_hash: &str,
    ) -> Result<()> {
        if record.action_request_id != request.id
            || record.payload_hash != payload_hash
            || record.policy_hash != policy_hash
        {
            self.audit.record(
                "execution_skipped",
                &json!({
                    "action_request_id": request.id,
                    "reason": "approval binding mismatch",
                }),
            )?;
            return Err(AuthorityError::ApprovalFailed(
                "approval does not match action, payload, or policy".into(),
            ));
        }
        if record.expires_at <= Utc::now() {
            self.audit.record(
                "approval_expired",
                &json!({
                    "action_request_id": request.id,
                    "approval_id": record.approval_id.clone(),
                    "expired_at": record.expires_at,
                }),
            )?;
            self.audit.record(
                "execution_skipped",
                &json!({
                    "action_request_id": request.id,
                    "reason": "approval expired",
                }),
            )?;
            return Err(AuthorityError::ApprovalFailed("approval expired".into()));
        }

        Ok(())
    }
}
