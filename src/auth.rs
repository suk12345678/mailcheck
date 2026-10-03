use crate::models::{StoredToken, TokenResponse};
use chrono::{Duration, Utc};
use colored::Colorize;
use directories::ProjectDirs;
use reqwest::Client;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// Dedicated Mailcheck Azure App Registration for Hotmail / Outlook personal accounts
pub const DEFAULT_CLIENT_ID: &str = "b870d6a8-5d6b-4e94-be55-c4a8c58cdbb4";
const SCOPES: &str = "offline_access openid profile https://outlook.office.com/IMAP.AccessAsUser.All";

pub struct AuthManager {
    client: Client,
    client_id: String,
    tenant: String,
}

impl AuthManager {
    pub fn new(client_id: String, tenant: String) -> Self {
        let effective_id = if client_id.trim().is_empty() {
            DEFAULT_CLIENT_ID.to_string()
        } else {
            client_id
        };

        let effective_tenant = if tenant.trim().is_empty() {
            "common".to_string()
        } else {
            tenant
        };

        Self {
            client: Client::new(),
            client_id: effective_id,
            tenant: effective_tenant,
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
        // 1. Check if complete token JSON is provided directly in environment
        if let Ok(json_str) = std::env::var("MAILCHECK_TOKEN_JSON") {
            if let Ok(token) = serde_json::from_str::<StoredToken>(&json_str) {
                return Some(token);
            }
        }

        // 2. Check if refresh token (+ optional email) are passed via environment variables (for cloud containers)
        if let Ok(rt) = std::env::var("MAILCHECK_REFRESH_TOKEN") {
            let email = std::env::var("MAILCHECK_ACCOUNT_EMAIL").ok();
            return Some(StoredToken {
                access_token: String::new(),
                refresh_token: rt,
                expires_at: Utc::now() - Duration::seconds(10), // expired so it forces automatic refresh
                account_email: email,
            });
        }

        // 3. Fallback to local token file on disk
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
        // Gracefully ignore write failures in read-only / stateless container environments
        if let Err(e) = fs::write(&path, content) {
            eprintln!("(Note: Could not cache token to disk at {}: {})", path.display(), e);
        }
        Ok(())
    }

    /// Run the interactive browser-based OAuth 2.0 flow
    pub async fn run_browser_login(&self) -> Result<StoredToken, Box<dyn std::error::Error>> {
        // 1. Bind local TCP listener for OAuth redirect
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_port = listener.local_addr()?.port();
        let redirect_uri = format!("http://localhost:{}", local_port);

        let encoded_redirect: String = url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect();
        let encoded_scope: String = url::form_urlencoded::byte_serialize(SCOPES.as_bytes()).collect();

        let auth_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize?client_id={}&response_type=code&redirect_uri={}&response_mode=query&scope={}",
            self.tenant,
            self.client_id,
            encoded_redirect,
            encoded_scope,
        );

        println!("\n{}", "=== Microsoft Authentication Required ===".bold().cyan());
        println!("Opening your default web browser to sign in with your Microsoft account...");
        println!("If your browser does not open automatically, copy & paste this URL:\n{}\n", auth_url.underline().bright_cyan());

        // Launch default browser on Windows
        let _ = std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", &auth_url])
            .spawn();

        println!("Waiting for sign-in completion in browser (listening on {})...", redirect_uri.yellow());

        // Wait for incoming callback with 3-minute timeout
        let (mut socket, _) = tokio::time::timeout(std::time::Duration::from_secs(180), listener.accept())
            .await
            .map_err(|_| "Sign-in timed out. Please run 'mailcheck auth' again.")??;

        let mut buffer = [0u8; 4096];
        let bytes_read = socket.read(&mut buffer).await?;
        let request_str = String::from_utf8_lossy(&buffer[..bytes_read]);

        let code = extract_query_param(&request_str, "code");
        let error = extract_query_param(&request_str, "error");

        if let Some(err) = error {
            let error_desc = extract_query_param(&request_str, "error_description")
                .unwrap_or_else(|| err.clone());
            let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<!DOCTYPE html><html><body style=\"font-family:sans-serif;text-align:center;padding:50px;\"><h1 style=\"color:red;\">Sign-in Failed</h1><p>Please check terminal.</p></body></html>";
            let _ = socket.write_all(resp.as_bytes()).await;
            return Err(format!("Microsoft sign-in returned error: {}", error_desc).into());
        }

        let code = match code {
            Some(c) => c,
            None => {
                let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\nMissing authorization code.";
                let _ = socket.write_all(resp.as_bytes()).await;
                return Err("Failed to obtain authorization code from Microsoft redirect.".into());
            }
        };

        // Send friendly HTML success page to browser
        let html_success = r#"HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close

<!DOCTYPE html>
<html>
<head>
    <title>Mailcheck - Sign-in Complete</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; text-align: center; padding: 60px 20px; background: #181825; color: #cdd6f4; }
        .box { max-width: 500px; margin: 0 auto; background: #1e1e2e; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.4); }
        h1 { color: #a6e3a1; margin-bottom: 12px; }
        p { color: #a6adc8; font-size: 16px; line-height: 1.5; }
    </style>
</head>
<body>
    <div class="box">
        <h1>&#10004; Authentication Successful!</h1>
        <p>Mailcheck has received your sign-in credentials.</p>
        <p>You can close this tab and return to your terminal.</p>
    </div>
</body>
</html>"#;
        let _ = socket.write_all(html_success.as_bytes()).await;
        let _ = socket.flush().await;

        println!("{}", "Callback received! Finalizing token exchange...".green());

        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant
        );

        let mut token_params = HashMap::new();
        token_params.insert("grant_type", "authorization_code");
        token_params.insert("client_id", self.client_id.as_str());
        token_params.insert("code", code.as_str());
        token_params.insert("redirect_uri", redirect_uri.as_str());
        token_params.insert("scope", SCOPES);

        let token_res = self.client.post(&token_url).form(&token_params).send().await?;
        let body_text = token_res.text().await?;
        let token_resp: TokenResponse = serde_json::from_str(&body_text)?;

        if let Some(err) = token_resp.error {
            let desc = token_resp.error_description.unwrap_or_default();
            return Err(format!("Token exchange failed: {} ({})", err, desc).into());
        }

        let access_token = token_resp.access_token.ok_or("No access_token received")?;
        let refresh_token = token_resp.refresh_token.ok_or("No refresh_token received")?;
        let expires_in_secs = token_resp.expires_in.unwrap_or(3600);
        let expires_at = Utc::now() + Duration::seconds(expires_in_secs);

        let mut account_email = token_resp.id_token.as_deref().and_then(extract_email_from_jwt);

        if account_email.is_none() {
            // Prompt if not present in id_token
            print!("Enter your Hotmail / Outlook email address (e.g. user@hotmail.com): ");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
            let trimmed = input.trim();
            if !trimmed.is_empty() {
                account_email = Some(trimmed.to_string());
            }
        }

        let stored = StoredToken {
            access_token,
            refresh_token,
            expires_at,
            account_email: account_email.clone(),
        };

        Self::save_token(&stored)?;

        if let Some(email) = &account_email {
            println!("\n{}", format!("Successfully authenticated account: {}", email).bold().green());
        } else {
            println!("\n{}", "Successfully authenticated with Microsoft Account!".bold().green());
        }

        Ok(stored)
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

        let old_email = Self::load_cached_token().and_then(|t| t.account_email);
        let account_email = token_resp
            .id_token
            .as_deref()
            .and_then(extract_email_from_jwt)
            .or(old_email);

        let updated = StoredToken {
            access_token,
            refresh_token: new_refresh_token,
            expires_at,
            account_email,
        };

        Self::save_token(&updated)?;
        Ok(updated)
    }

    /// Gets an active access token and the account email address, refreshing automatically if close to expiration
    pub async fn get_valid_token_and_email(&self) -> Result<(String, String), Box<dyn std::error::Error>> {
        let stored = match Self::load_cached_token() {
            Some(t) => t,
            None => {
                return Err("No saved login found. Please run 'mailcheck auth' first.".into());
            }
        };

        let token = if Utc::now() + Duration::seconds(120) >= stored.expires_at {
            self.refresh_access_token(&stored.refresh_token).await?
        } else {
            stored
        };

        let email = token
            .account_email
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::env::var("MAILCHECK_ACCOUNT_EMAIL").ok())
            .unwrap_or_default();
        Ok((token.access_token, email))
    }
}

fn extract_query_param(request: &str, param_name: &str) -> Option<String> {
    let first_line = request.lines().next()?;
    let path = first_line.split_whitespace().nth(1)?;
    let query_str = path.split('?').nth(1)?;
    for pair in query_str.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?;
        let val = parts.next().unwrap_or("");
        if key == param_name {
            let decoded = url::form_urlencoded::parse(val.as_bytes())
                .next()
                .map(|(k, _)| k.into_owned())
                .unwrap_or_else(|| val.to_string());
            return Some(decoded);
        }
    }
    None
}

fn extract_email_from_jwt(id_token: &str) -> Option<String> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    let decoded = URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| STANDARD.decode(parts[1]))
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    v.get("preferred_username")
        .or_else(|| v.get("email"))
        .or_else(|| v.get("upn"))
        .and_then(|u| u.as_str())
        .map(|s| s.to_string())
}
