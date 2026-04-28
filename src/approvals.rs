use crate::models::{ActionRequest, ApprovalRecord};
use crate::Result;
use chrono::{Duration, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub enum ApprovalMode {
    AutoApproveForTests,
    MismatchedPayloadForTests,
    Reject,
}

#[derive(Debug, Clone)]
pub struct ApprovalProvider {
    mode: ApprovalMode,
}

impl ApprovalProvider {
    pub fn auto_approve_for_tests() -> Self {
        Self {
            mode: ApprovalMode::AutoApproveForTests,
        }
    }

    pub fn reject() -> Self {
        Self {
            mode: ApprovalMode::Reject,
        }
    }

    pub fn mismatched_payload_for_tests() -> Self {
        Self {
            mode: ApprovalMode::MismatchedPayloadForTests,
        }
    }

    pub fn request(
        &self,
        action: &ActionRequest,
        payload_hash: String,
        policy_hash: String,
    ) -> Result<Option<ApprovalRecord>> {
        match self.mode {
            ApprovalMode::AutoApproveForTests | ApprovalMode::MismatchedPayloadForTests => {
                let now = Utc::now();
                Ok(Some(ApprovalRecord {
                    approval_id: format!("appr_{}", Uuid::new_v4()),
                    action_request_id: action.id.clone(),
                    payload_hash: match self.mode {
                        ApprovalMode::MismatchedPayloadForTests => "sha256:changed-payload".into(),
                        ApprovalMode::AutoApproveForTests => payload_hash,
                        ApprovalMode::Reject => unreachable!("reject mode handled separately"),
                    },
                    policy_hash,
                    approved_by: "local-test-approver".into(),
                    approved_at: now,
                    expires_at: now + Duration::minutes(10),
                }))
            }
            ApprovalMode::Reject => Ok(None),
        }
    }
}
