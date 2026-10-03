use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub auth: AuthConfig,
    pub general: GeneralConfig,
    pub rules: RulesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub client_id: String,
    #[serde(default = "default_tenant")]
    pub tenant: String,
}

fn default_tenant() -> String {
    "consumers".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum FilterAction {
    DryRun,
    MoveToJunk,
    Delete,
}

impl std::fmt::Display for FilterAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterAction::DryRun => write!(f, "DryRun (Report only, no mailbox changes)"),
            FilterAction::MoveToJunk => write!(f, "MoveToJunk (Move to Junk Email folder)"),
            FilterAction::Delete => write!(f, "Delete (Permanently delete message)"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_action")]
    pub action: FilterAction,
    #[serde(default = "default_watch_interval")]
    pub watch_interval_seconds: u64,
    #[serde(default = "default_max_messages")]
    pub max_messages_per_scan: usize,
    #[serde(default = "default_only_unread")]
    pub only_unread: bool,
}

fn default_action() -> FilterAction {
    FilterAction::DryRun
}

fn default_watch_interval() -> u64 {
    60
}

fn default_max_messages() -> usize {
    50
}

fn default_only_unread() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub whitelisted_domains: Vec<String>,
    #[serde(default)]
    pub blocked_tlds: Vec<String>,
    #[serde(default)]
    pub blocked_sender_domains: Vec<String>,
    #[serde(default)]
    pub blocked_subject_patterns: Vec<String>,
    #[serde(default)]
    pub header_rules: Vec<HeaderRule>,
    #[serde(default)]
    pub spoof_rules: Vec<SpoofRule>,
    #[serde(default)]
    pub recipient_checks: RecipientChecks,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderRule {
    pub name: String,
    pub header: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpoofRule {
    pub brand_name: String,
    pub display_pattern: String,
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecipientChecks {
    #[serde(default)]
    pub flag_if_not_in_to_or_cc: bool,
}

impl AppConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: AppConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn find_config_path() -> PathBuf {
        // Look in current working directory first
        let local = PathBuf::from("config.toml");
        if local.exists() {
            return local;
        }

        // Look next to executable and traverse up parent directories (e.g. target/release -> project root)
        if let Ok(exe_path) = std::env::current_exe() {
            let mut current = exe_path.parent();
            while let Some(dir) = current {
                let candidate = dir.join("config.toml");
                if candidate.exists() {
                    return candidate;
                }
                current = dir.parent();
            }
        }

        // Check user config directory (%APPDATA%/mailcheck/config.toml)
        if let Some(proj_dirs) = directories::ProjectDirs::from("com", "mailcheck", "mailcheck") {
            let candidate = proj_dirs.config_dir().join("config.toml");
            if candidate.exists() {
                return candidate;
            }
        }

        local
    }
}

