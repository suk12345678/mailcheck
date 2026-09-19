use crate::models::{DeviceCodeResponse, StoredToken, TokenResponse};
use chrono::{Duration, Utc};
use colored::Colorize;
use directories::ProjectDirs;
use reqwest::Client;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

const SCOPES: &str = "offline_access User.Read Mail.ReadWrite";
const REDIRECT_URI: &str = "https://login.microsoftonline.com/common/oauth2/nativeclient";

pub struct AuthManager {
    client: Client,
    client_id: String,
    tenant: String,
}

impl AuthManager {
    pub fn new(client_id: String, tenant: String) -> Self {
        Self {
            client: Client::new(),
            client_id,
            tenant,
        }
    }

    fn token_cache_path() -> PathBuf {
        if let Some(proj_dirs) = ProjectDirs::from("com", "mailcheck", "mailcheck") {
            let config_dir = proj_dirs.config_dir();
            let _ = fs::create_dir_all(config_dir);
            return config_dir.join("token.json");
        }
        PathBuf::from(".mailcheck_token.json")
    }

    pub fn load_cached_token() -> Option<StoredToken> {
        let path = Self::token_cache_path();
        if !path.exists() {
            return None;
        }

        let content = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn save_token(token: &StoredToken) -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::token_cache_path();
        let content = serde_json::to_string_pretty(token)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Run the interactive device login flow
    pub async fn run_device_code_login(&self) -> Result<StoredToken, Box<dyn std::error::Error>> {
        if self.client_id.trim().is_empty() {
            return Err("Client ID is missing. Please configure 'auth.client_id' in config.toml or run with --client-id".into());
        }

        let device_code_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/devicecode",
            self.tenant
        );

        let mut params = HashMap::new();
        params.insert("client_id", self.client_id.as_str());
        params.insert("scope", SCOPES);
        params.insert("redirect_uri", REDIRECT_URI);

        let res = self
            .client
            .post(&device_code_url)
            .form(&params)
            .send()
            .await?;

        if !res.status().is_success() {
            let err_text = res.text().await?;
            return Err(format!("Failed to initiate device login: {}", err_text).into());
        }

        let dc_resp: DeviceCodeResponse = res.json().await?;

        println!("\n{}", "=== Microsoft Authentication Required ===".bold().cyan());
        println!("{}", dc_resp.message.bold().yellow());
        println!("\n1. Open:  {}", dc_resp.verification_uri.bright_cyan().underline());
        println!("2. Code:  {}\n", dc_resp.user_code.bright_green().bold());
        println!("Waiting for sign-in completion in your browser...");

        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant
        );

        let mut interval = dc_resp.interval.max(2);
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(dc_resp.expires_in);

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;

            if start.elapsed() > timeout {
                return Err("Device code expired before sign-in completed. Please try again.".into());
            }

            let mut token_params = HashMap::new();
            token_params.insert("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
            token_params.insert("client_id", self.client_id.as_str());
            token_params.insert("device_code", dc_resp.device_code.as_str());
            token_params.insert("redirect_uri", REDIRECT_URI);

            let token_res = self
                .client
                .post(&token_url)
                .form(&token_params)
                .send()
                .await?;

            let body_text = token_res.text().await?;
            let token_resp: TokenResponse = match serde_json::from_str(&body_text) {
                Ok(tr) => tr,
                Err(_) => continue,
            };

            if let Some(err) = token_resp.error {
                match err.as_str() {
                    "authorization_pending" => {
                        print!(".");
                        use std::io::Write;
                        let _ = std::io::stdout().flush();
                        continue;
                    }
                    "slow_down" => {
                        interval += 5;
                        continue;
                    }
                    _ => {
                        let desc = token_resp
                            .error_description
                            .unwrap_or_else(|| "Unknown error".to_string());
                        return Err(format!("Authentication failed: {} - {}", err, desc).into());
                    }
                }
            }

            if let (Some(access_token), Some(refresh_token)) =
                (token_resp.access_token, token_resp.refresh_token)
            {
                let expires_in_secs = token_resp.expires_in.unwrap_or(3600);
                let expires_at = Utc::now() + Duration::seconds(expires_in_secs);

                let stored = StoredToken {
                    access_token,
                    refresh_token,
                    expires_at,
                    account_email: None,
                };

                Self::save_token(&stored)?;
                println!("\n{}", "Successfully authenticated with Microsoft Account!".bold().green());
                return Ok(stored);
            }
        }
    }

    /// Refreshes an expired access token using the stored refresh token
    pub async fn refresh_access_token(
        &self,
        refresh_token_str: &str,
    ) -> Result<StoredToken, Box<dyn std::error::Error>> {
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant
        );

        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("client_id", self.client_id.as_str());
        params.insert("refresh_token", refresh_token_str);
        params.insert("scope", SCOPES);

        let res = self.client.post(&token_url).form(&params).send().await?;

        let body = res.text().await?;
        let token_resp: TokenResponse = serde_json::from_str(&body)?;

        if let Some(err) = token_resp.error {
            let desc = token_resp
                .error_description
                .unwrap_or_else(|| "Unknown error".to_string());
            return Err(format!("Failed to refresh token: {} ({})", err, desc).into());
        }

        let access_token = token_resp
            .access_token
            .ok_or("No access_token returned in refresh response")?;
        let new_refresh_token = token_resp
            .refresh_token
            .unwrap_or_else(|| refresh_token_str.to_string());
        let expires_in_secs = token_resp.expires_in.unwrap_or(3600);
        let expires_at = Utc::now() + Duration::seconds(expires_in_secs);

        let updated = StoredToken {
            access_token,
            refresh_token: new_refresh_token,
            expires_at,
            account_email: None,
        };

        Self::save_token(&updated)?;
        Ok(updated)
    }

    /// Gets an active access token, refreshing automatically if close to expiration
    pub async fn get_valid_access_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        let stored = match Self::load_cached_token() {
            Some(t) => t,
            None => {
                return Err("No saved login found. Please run 'mailcheck auth' first.".into());
            }
        };

        // If expires in less than 2 minutes, refresh it now
        if Utc::now() + Duration::seconds(120) >= stored.expires_at {
            let refreshed = self.refresh_access_token(&stored.refresh_token).await?;
            return Ok(refreshed.access_token);
        }

        Ok(stored.access_token)
    }
}

