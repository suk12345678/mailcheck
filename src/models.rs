use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Microsoft OAuth 2.0 Device Code Response
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
    pub message: String,
}

/// Microsoft OAuth 2.0 Token Response
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenResponse {
    pub token_type: Option<String>,
    pub scope: Option<String>,
    pub expires_in: Option<i64>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// Cached Token stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub account_email: Option<String>,
}

/// Response wrapper for Graph API message lists
#[derive(Debug, Clone, Deserialize)]
pub struct GraphMessagesResponse {
    pub value: Vec<GraphMessage>,
    #[serde(rename = "@odata.nextLink")]
    #[allow(dead_code)]
    pub next_link: Option<String>,
}

/// A message returned by the Graph API
#[derive(Debug, Clone, Deserialize)]
pub struct GraphMessage {
    pub id: String,
    #[serde(default)]
    pub subject: Option<String>,
    pub from: Option<Recipient>,
    #[serde(rename = "toRecipients", default)]
    pub to_recipients: Vec<Recipient>,
    #[serde(rename = "ccRecipients", default)]
    pub cc_recipients: Vec<Recipient>,
    #[serde(rename = "internetMessageHeaders", default)]
    pub internet_message_headers: Vec<InternetMessageHeader>,
    #[serde(rename = "receivedDateTime")]
    pub received_date_time: Option<DateTime<Utc>>,
    #[serde(rename = "isRead", default)]
    #[allow(dead_code)]
    pub is_read: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Recipient {
    #[serde(rename = "emailAddress")]
    pub email_address: EmailAddress,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailAddress {
    pub name: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InternetMessageHeader {
    pub name: String,
    pub value: String,
}

/// Request payload for moving a message
#[derive(Debug, Clone, Serialize)]
pub struct MoveMessageRequest {
    #[serde(rename = "destinationId")]
    pub destination_id: String,
}

/// Microsoft Graph user profile
#[derive(Debug, Clone, Deserialize)]
pub struct UserProfile {
    #[allow(dead_code)]
    pub id: Option<String>,
    #[serde(rename = "displayName")]
    #[allow(dead_code)]
    pub display_name: Option<String>,
    #[serde(rename = "userPrincipalName")]
    pub user_principal_name: Option<String>,
    pub mail: Option<String>,
}

/// Outcome of evaluating an email through the rule engine
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub is_spam: bool,
    pub reasons: Vec<String>,
}
