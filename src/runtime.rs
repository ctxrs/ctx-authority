use crate::approvals::ApprovalProvider;
use crate::audit::AuditLog;
use crate::backends::SecretBackend;
use crate::models::{ActionRequest, PolicyDecisionKind, Receipt};
use crate::policy::PolicyDocument;
use crate::providers::ProviderAdapter;
use crate::receipts::{action_hash, ReceiptSigner};
use crate::{AuthorityError, Result};
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
            PolicyDecisionKind::RequireApproval => Some(
                self.approvals
                    .request(request, payload_hash.clone(), policy_hash.clone())?
                    .ok_or_else(|| AuthorityError::ApprovalFailed("approval rejected".into()))?,
            ),
        };

        if let Some(record) = &approval {
            if record.payload_hash != payload_hash || record.policy_hash != policy_hash {
                return Err(AuthorityError::ApprovalFailed(
                    "approval does not match payload or policy".into(),
                ));
            }
        }

        let secret = match self.secret_backend {
            Some(backend) => {
                let reference = request
                    .operation
                    .get("secret_ref")
                    .and_then(|value| value.as_str())
                    .unwrap_or("default");
                Some(backend.resolve(reference)?)
            }
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
        self.audit.record(
            "action_executed",
            &serde_json::to_value(&receipt).map_err(AuthorityError::Json)?,
        )?;
        Ok(receipt)
    }
}
