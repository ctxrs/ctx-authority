use thiserror::Error;

pub type Result<T> = std::result::Result<T, AuthorityError>;

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("policy denied action: {0}")]
    Denied(String),
    #[error("approval required: {0}")]
    ApprovalRequired(String),
    #[error("approval failed: {0}")]
    ApprovalFailed(String),
    #[error("secret backend error: {0}")]
    SecretBackend(String),
    #[error("provider error: {0}")]
    Provider(String),
    #[error("receipt error: {0}")]
    Receipt(String),
    #[error("audit error: {0}")]
    Audit(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
}
