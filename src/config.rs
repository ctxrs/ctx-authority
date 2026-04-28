use crate::{AuthorityError, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub home: PathBuf,
    pub config_file: PathBuf,
    pub audit_db: PathBuf,
    pub signing_key: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        if let Ok(home) = std::env::var("CTXA_HOME") {
            return Ok(Self::for_home(PathBuf::from(home)));
        }

        let dirs = ProjectDirs::from("rs", "ctx", "authority-broker").ok_or_else(|| {
            AuthorityError::Config("could not resolve project directories".into())
        })?;
        Ok(Self::for_home(dirs.config_dir().to_path_buf()))
    }

    pub fn for_home(home: PathBuf) -> Self {
        Self {
            config_file: home.join("config.yaml"),
            audit_db: home.join("audit.sqlite3"),
            signing_key: home.join("receipt-signing.key"),
            home,
        }
    }

    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.home)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
    #[serde(default)]
    pub policies: Vec<PolicyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub path: String,
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&text)?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_yaml::to_string(self)?)?;
        Ok(())
    }
}
