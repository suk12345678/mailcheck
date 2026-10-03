use crate::models::{EmailAddress, GraphMessage, InternetMessageHeader, Recipient};
use chrono::{DateTime, Utc};
use imap::Authenticator;
use native_tls::TlsConnector;
use std::collections::HashSet;
use std::error::Error;

type DynError = Box<dyn Error + Send + Sync>;

const IMAP_HOST: &str = "outlook.office365.com";
const IMAP_PORT: u16 = 993;

pub struct XOAuth2 {
    pub user: String,
    pub token: String,
}

impl Authenticator for XOAuth2 {
    type Response = Vec<u8>;
    fn process(&self, _challenge: &[u8]) -> Self::Response {
        format!("user={}\x01auth=Bearer {}\x01\x01", self.user, self.token).into_bytes()
    }
}

pub struct ImapClient {
    user_email: String,
    access_token: String,
}

impl ImapClient {
    pub fn new(user_email: String, access_token: String) -> Self {
        Self {
            user_email,
            access_token,
        }
    }

    fn connect(&self) -> Result<imap::Session<native_tls::TlsStream<std::net::TcpStream>>, DynError> {
        let tls = TlsConnector::builder().build()?;
        let socket = std::net::TcpStream::connect((IMAP_HOST, IMAP_PORT))?;
        let tls_stream = tls.connect(IMAP_HOST, socket)?;
        let client = imap::Client::new(tls_stream);

        let auth = XOAuth2 {
            user: self.user_email.clone(),
            token: self.access_token.clone(),
        };

        let session = client
            .authenticate("XOAUTH2", &auth)
            .map_err(|(e, _)| -> DynError {
                format!("IMAP authentication failed for {}: {}", self.user_email, e).into()
            })?;

        Ok(session)
    }

    /// Tests that the IMAP session connects and authenticates successfully
    pub fn test_connection(&self) -> Result<String, DynError> {
        let mut session = self.connect()?;
        let mailbox = session.select("INBOX")?;
        let exists = mailbox.exists;
        let _ = session.logout();
        Ok(format!("Connected to INBOX ({} total messages)", exists))
    }

    /// Fetch headers for top messages in INBOX
    pub fn list_inbox_messages(
        &self,
        only_unread: bool,
        max_count: usize,
    ) -> Result<Vec<(u32, GraphMessage)>, DynError> {
        let mut session = self.connect()?;
        session.select("INBOX")?;

        let search_query = if only_unread { "UNSEEN" } else { "ALL" };
        let uids_set: HashSet<u32> = session.uid_search(search_query)?;

        if uids_set.is_empty() {
            let _ = session.logout();
            return Ok(Vec::new());
        }

        let mut uids: Vec<u32> = uids_set.into_iter().collect();
        // Newest UIDs first
        uids.sort_by(|a, b| b.cmp(a));
        uids.truncate(max_count);

        let mut result = Vec::new();

        // Fetch headers for each UID
        for uid in uids {
            let fetches = match session.uid_fetch(uid.to_string(), "(BODY.PEEK[HEADER] FLAGS)") {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Warning: Failed to fetch headers for UID {}: {}", uid, e);
                    continue;
                }
            };

            for fetch in fetches.iter() {
                if let Some(header_bytes) = fetch.header() {
                    let msg = parse_rfc822_headers(uid, header_bytes, fetch.flags());
                    result.push((uid, msg));
                }
            }
        }

        let _ = session.logout();
        Ok(result)
    }

    /// Move message to Junk folder by UID
    pub fn move_message(&self, uid: u32) -> Result<(), DynError> {
        let mut session = self.connect()?;
        session.select("INBOX")?;

        // Microsoft Hotmail/Outlook IMAP folder for junk is usually "Junk"
        let copy_res = session.uid_copy(uid.to_string(), "Junk");
        if copy_res.is_err() {
            // Fallback to "Junk Email" if "Junk" doesn't exist
            session.uid_copy(uid.to_string(), "Junk Email")?;
        }

        session.uid_store(uid.to_string(), "+FLAGS (\\Deleted)")?;
        session.expunge()?;
        let _ = session.logout();
        Ok(())
    }

    /// Permanently delete a message by UID
    pub fn delete_message(&self, uid: u32) -> Result<(), DynError> {
        let mut session = self.connect()?;
        session.select("INBOX")?;
        session.uid_store(uid.to_string(), "+FLAGS (\\Deleted)")?;
        session.expunge()?;
        let _ = session.logout();
        Ok(())
    }
}

fn parse_rfc822_headers(uid: u32, header_bytes: &[u8], flags: &[imap::types::Flag]) -> GraphMessage {
    let (headers, _) = mailparse::parse_headers(header_bytes).unwrap_or((Vec::new(), 0));

    let mut subject = None;
    let mut from = None;
    let mut to_recipients = Vec::new();
    let mut cc_recipients = Vec::new();
    let mut received_date_time = None;
    let mut internet_message_headers = Vec::new();

    for h in &headers {
        let key = h.get_key();
        let val = h.get_value();

        internet_message_headers.push(InternetMessageHeader {
            name: key.clone(),
            value: val.clone(),
        });

        if key.eq_ignore_ascii_case("Subject") {
            subject = Some(val.clone());
        } else if key.eq_ignore_ascii_case("From") {
            if let Ok(addrs) = mailparse::addrparse(&val) {
                if let Some(first) = addrs.first() {
                    match first {
                        mailparse::MailAddr::Single(info) => {
                            from = Some(Recipient {
                                email_address: EmailAddress {
                                    name: info.display_name.clone(),
                                    address: Some(info.addr.clone()),
                                },
                            });
                        }
                        mailparse::MailAddr::Group(group) => {
                            if let Some(first_group) = group.addrs.first() {
                                from = Some(Recipient {
                                    email_address: EmailAddress {
                                        name: first_group.display_name.clone(),
                                        address: Some(first_group.addr.clone()),
                                    },
                                });
                            }
                        }
                    }
                }
            }
            if from.is_none() {
                from = Some(Recipient {
                    email_address: EmailAddress {
                        name: None,
                        address: Some(val.clone()),
                    },
                });
            }
        } else if key.eq_ignore_ascii_case("To") {
            if let Ok(addrs) = mailparse::addrparse(&val) {
                for a in addrs.iter() {
                    match a {
                        mailparse::MailAddr::Single(info) => {
                            to_recipients.push(Recipient {
                                email_address: EmailAddress {
                                    name: info.display_name.clone(),
                                    address: Some(info.addr.clone()),
                                },
                            });
                        }
                        mailparse::MailAddr::Group(group) => {
                            for g in &group.addrs {
                                to_recipients.push(Recipient {
                                    email_address: EmailAddress {
                                        name: g.display_name.clone(),
                                        address: Some(g.addr.clone()),
                                    },
                                });
                            }
                        }
                    }
                }
            }
        } else if key.eq_ignore_ascii_case("Cc") {
            if let Ok(addrs) = mailparse::addrparse(&val) {
                for a in addrs.iter() {
                    match a {
                        mailparse::MailAddr::Single(info) => {
                            cc_recipients.push(Recipient {
                                email_address: EmailAddress {
                                    name: info.display_name.clone(),
                                    address: Some(info.addr.clone()),
                                },
                            });
                        }
                        mailparse::MailAddr::Group(group) => {
                            for g in &group.addrs {
                                cc_recipients.push(Recipient {
                                    email_address: EmailAddress {
                                        name: g.display_name.clone(),
                                        address: Some(g.addr.clone()),
                                    },
                                });
                            }
                        }
                    }
                }
            }
        } else if key.eq_ignore_ascii_case("Date") {
            if let Ok(dt) = DateTime::parse_from_rfc2822(&val) {
                received_date_time = Some(dt.with_timezone(&Utc));
            }
        }
    }

    let is_read = flags.iter().any(|f| matches!(f, imap::types::Flag::Seen));

    GraphMessage {
        id: uid.to_string(),
        subject,
        from,
        to_recipients,
        cc_recipients,
        internet_message_headers,
        received_date_time,
        is_read,
    }
}
