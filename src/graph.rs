use crate::models::{GraphMessage, GraphMessagesResponse, MoveMessageRequest, UserProfile};
use reqwest::{header, Client, StatusCode};

pub struct GraphClient {
    client: Client,
}

impl GraphClient {
    pub fn new(access_token: &str) -> Self {
        let mut headers = header::HeaderMap::new();
        let mut auth_value = header::HeaderValue::from_str(&format!("Bearer {}", access_token))
            .expect("Invalid bearer token header");
        auth_value.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth_value);

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .expect("Failed to build reqwest client");

        Self { client }
    }

    /// Retrieve the current user's profile to determine their email address
    pub async fn get_user_profile(&self) -> Result<UserProfile, Box<dyn std::error::Error>> {
        let url = "https://graph.microsoft.com/v1.0/me";
        let res = self.client.get(url).send().await?;

        if !res.status().is_success() {
            let status = res.status();
            let err = res.text().await?;
            return Err(format!("Graph API error ({}): {}", status, err).into());
        }

        let profile: UserProfile = res.json().await?;
        Ok(profile)
    }

    /// Fetch inbox messages with full headers and sender details
    pub async fn list_inbox_messages(
        &self,
        only_unread: bool,
        max_count: usize,
    ) -> Result<Vec<GraphMessage>, Box<dyn std::error::Error>> {
        let mut query = vec![
            ("$top", max_count.to_string()),
            (
                "$select",
                "id,subject,from,toRecipients,ccRecipients,internetMessageHeaders,receivedDateTime,isRead"
                    .to_string(),
            ),
            ("$orderby", "receivedDateTime desc".to_string()),
        ];

        if only_unread {
            query.push(("$filter", "isRead eq false".to_string()));
        }

        let url = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages";
        let res = self.client.get(url).query(&query).send().await?;

        if !res.status().is_success() {
            let status = res.status();
            let err = res.text().await?;
            return Err(format!("Failed to list inbox messages ({}): {}", status, err).into());
        }

        let resp: GraphMessagesResponse = res.json().await?;
        Ok(resp.value)
    }

    /// Move message to specified folder (e.g. "junkemail" or "deleteditems")
    pub async fn move_message(
        &self,
        message_id: &str,
        destination_folder: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!(
            "https://graph.microsoft.com/v1.0/me/messages/{}/move",
            message_id
        );

        let req = MoveMessageRequest {
            destination_id: destination_folder.to_string(),
        };

        let res = self.client.post(&url).json(&req).send().await?;

        if !res.status().is_success() {
            let status = res.status();
            let err = res.text().await?;
            return Err(format!("Failed to move message ({}): {}", status, err).into());
        }

        Ok(())
    }

    /// Permanently delete a message
    pub async fn delete_message(&self, message_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!(
            "https://graph.microsoft.com/v1.0/me/messages/{}",
            message_id
        );

        let res = self.client.delete(&url).send().await?;

        if res.status() != StatusCode::NO_CONTENT && !res.status().is_success() {
            let status = res.status();
            let err = res.text().await?;
            return Err(format!("Failed to delete message ({}): {}", status, err).into());
        }

        Ok(())
    }
}
