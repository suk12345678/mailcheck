use crate::config::RulesConfig;
use crate::models::{EvaluationResult, GraphMessage};
use regex::Regex;

pub struct RuleEngine {
    config: RulesConfig,
    subject_regexes: Vec<Regex>,
    header_regexes: Vec<(String, String, Regex)>, // (name, header_name, regex)
    spoof_regexes: Vec<(String, Regex, Vec<String>)>, // (brand, regex, allowed_domains)
}

impl RuleEngine {
    pub fn new(config: RulesConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut subject_regexes = Vec::new();
        for pat in &config.blocked_subject_patterns {
            subject_regexes.push(Regex::new(pat)?);
        }

        let mut header_regexes = Vec::new();
        for rule in &config.header_rules {
            header_regexes.push((
                rule.name.clone(),
                rule.header.to_lowercase(),
                Regex::new(&rule.pattern)?,
            ));
        }

        let mut spoof_regexes = Vec::new();
        for rule in &config.spoof_rules {
            spoof_regexes.push((
                rule.brand_name.clone(),
                Regex::new(&rule.display_pattern)?,
                rule.allowed_domains
                    .iter()
                    .map(|d| d.to_lowercase())
                    .collect(),
            ));
        }

        Ok(Self {
            config,
            subject_regexes,
            header_regexes,
            spoof_regexes,
        })
    }

    pub fn evaluate(&self, message: &GraphMessage, user_email: Option<&str>) -> EvaluationResult {
        let mut reasons = Vec::new();

        let sender_address = message
            .from
            .as_ref()
            .and_then(|f| f.email_address.address.as_deref())
            .unwrap_or("")
            .trim()
            .to_lowercase();

        let sender_display = message
            .from
            .as_ref()
            .and_then(|f| f.email_address.name.as_deref())
            .unwrap_or("")
            .trim();

        let sender_domain = sender_address.split('@').nth(1).unwrap_or("");

        // 0. Safety Whitelist: If sender domain is whitelisted, never flag as spam
        for white in &self.config.whitelisted_domains {
            let w_clean = white.trim().to_lowercase();
            if !w_clean.is_empty() && (sender_domain == w_clean || sender_domain.ends_with(&format!(".{}", w_clean))) {
                return EvaluationResult {
                    is_spam: false,
                    reasons: Vec::new(),
                };
            }
        }

        // 1. Check Blocked TLDs
        for tld in &self.config.blocked_tlds {
            let tld_clean = tld.trim().to_lowercase();
            if sender_address.ends_with(&tld_clean) {
                reasons.push(format!(
                    "Blocked TLD '{}' in sender address: {}",
                    tld, sender_address
                ));
            }
        }

        // 2. Check Blocked Sender Domains
        for domain in &self.config.blocked_sender_domains {
            let d_clean = domain.trim().to_lowercase();
            if sender_domain == d_clean {
                reasons.push(format!("Blocked sender domain: {}", domain));
            }
        }

        // 3. Check Subject Patterns
        if let Some(subject) = &message.subject {
            for re in &self.subject_regexes {
                if re.is_match(subject) {
                    reasons.push(format!("Subject matched pattern: /{}/", re.as_str()));
                }
            }
        }

        // 4. Check Display Name Spoofing
        for (brand, re, allowed_domains) in &self.spoof_regexes {
            if re.is_match(sender_display) {
                let is_allowed = allowed_domains
                    .iter()
                    .any(|allowed| sender_domain == allowed || sender_domain.ends_with(&format!(".{}", allowed)));
                if !is_allowed {
                    reasons.push(format!(
                        "Spoofing alert: Display name '{}' impersonates '{}' but sender domain is '{}' (allowed: {:?})",
                        sender_display, brand, sender_domain, allowed_domains
                    ));
                }
            }
        }

        // 5. Check Header Rules
        for (rule_name, target_header, re) in &self.header_regexes {
            for header in &message.internet_message_headers {
                if header.name.to_lowercase() == *target_header {
                    if re.is_match(&header.value) {
                        reasons.push(format!(
                            "Header rule '{}' matched on {}: '{}'",
                            rule_name, header.name, header.value
                        ));
                    }
                }
            }
        }

        // 6. Check Recipient Anomaly (Mass BCC)
        if self.config.recipient_checks.flag_if_not_in_to_or_cc {
            if let Some(u_email) = user_email {
                let target = u_email.trim().to_lowercase();
                let found_in_to = message.to_recipients.iter().any(|r| {
                    r.email_address
                        .address
                        .as_deref()
                        .map(|a| a.trim().to_lowercase() == target)
                        .unwrap_or(false)
                });
                let found_in_cc = message.cc_recipients.iter().any(|r| {
                    r.email_address
                        .address
                        .as_deref()
                        .map(|a| a.trim().to_lowercase() == target)
                        .unwrap_or(false)
                });

                if !found_in_to && !found_in_cc {
                    reasons.push(format!(
                        "Recipient anomaly: user '{}' is not present in To: or Cc: headers",
                        u_email
                    ));
                }
            }
        }

        EvaluationResult {
            is_spam: !reasons.is_empty(),
            reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HeaderRule, RecipientChecks, RulesConfig, SpoofRule};
    use crate::models::{EmailAddress, InternetMessageHeader, Recipient};

    fn sample_config() -> RulesConfig {
        RulesConfig {
            blocked_tlds: vec![".xyz".into(), ".top".into()],
            blocked_sender_domains: vec!["spammer.com".into()],
            blocked_subject_patterns: vec!["(?i)invoice.*attached".into()],
            header_rules: vec![HeaderRule {
                name: "SPF Fail".into(),
                header: "Authentication-Results".into(),
                pattern: "(?i)spf=fail".into(),
            }],
            spoof_rules: vec![SpoofRule {
                brand_name: "Geek Squad".into(),
                display_pattern: "(?i)geek[- ]?squad".into(),
                allowed_domains: vec!["bestbuy.com".into()],
            }],
            recipient_checks: RecipientChecks {
                flag_if_not_in_to_or_cc: true,
            },
        }
    }

    #[test]
    fn test_blocked_tld() {
        let engine = RuleEngine::new(sample_config()).unwrap();
        let msg = GraphMessage {
            id: "1".into(),
            subject: Some("Hello".into()),
            from: Some(Recipient {
                email_address: EmailAddress {
                    name: Some("Promo".into()),
                    address: Some("deals@cheapstuff.xyz".into()),
                },
            }),
            to_recipients: vec![],
            cc_recipients: vec![],
            internet_message_headers: vec![],
            received_date_time: None,
            is_read: false,
        };

        let eval = engine.evaluate(&msg, None);
        assert!(eval.is_spam);
        assert!(eval.reasons[0].contains("Blocked TLD '.xyz'"));
    }

    #[test]
    fn test_spoof_detection() {
        let engine = RuleEngine::new(sample_config()).unwrap();

        // Spoofed Geek Squad
        let spoofed = GraphMessage {
            id: "2".into(),
            subject: Some("Your subscription renewed".into()),
            from: Some(Recipient {
                email_address: EmailAddress {
                    name: Some("Geek Squad Renewal Team".into()),
                    address: Some("billing@random-domain.org".into()),
                },
            }),
            to_recipients: vec![],
            cc_recipients: vec![],
            internet_message_headers: vec![],
            received_date_time: None,
            is_read: false,
        };
        let eval = engine.evaluate(&spoofed, None);
        assert!(eval.is_spam);
        assert!(eval.reasons.iter().any(|r| r.contains("impersonates 'Geek Squad'")));

        // Legitimate Geek Squad
        let legit = GraphMessage {
            id: "3".into(),
            subject: Some("Your Best Buy receipt".into()),
            from: Some(Recipient {
                email_address: EmailAddress {
                    name: Some("Geek Squad Official".into()),
                    address: Some("orders@bestbuy.com".into()),
                },
            }),
            to_recipients: vec![],
            cc_recipients: vec![],
            internet_message_headers: vec![],
            received_date_time: None,
            is_read: false,
        };
        let eval_legit = engine.evaluate(&legit, None);
        assert!(!eval_legit.is_spam);
    }

    #[test]
    fn test_header_rule() {
        let engine = RuleEngine::new(sample_config()).unwrap();
        let msg = GraphMessage {
            id: "4".into(),
            subject: Some("Order Status".into()),
            from: Some(Recipient {
                email_address: EmailAddress {
                    name: Some("Vendor".into()),
                    address: Some("service@vendor.com".into()),
                },
            }),
            to_recipients: vec![],
            cc_recipients: vec![],
            internet_message_headers: vec![InternetMessageHeader {
                name: "Authentication-Results".into(),
                value: "spf=fail (sender IP 1.2.3.4)".into(),
            }],
            received_date_time: None,
            is_read: false,
        };
        let eval = engine.evaluate(&msg, None);
        assert!(eval.is_spam);
        assert!(eval.reasons.iter().any(|r| r.contains("SPF Fail")));
    }
}

