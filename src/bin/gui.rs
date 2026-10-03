#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Color32, RichText, Vec2};
use mailcheck::auth::AuthManager;
use mailcheck::config::{AppConfig, RulesJsonFile};
use mailcheck::engine::RuleEngine;
use mailcheck::imap_client::ImapClient;
use mailcheck::models::GraphMessage;
use std::collections::HashSet;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

// Catppuccin Mocha Color Palette
const COLOR_BG: Color32 = Color32::from_rgb(30, 30, 46);       // #1E1E2E
const COLOR_CARD: Color32 = Color32::from_rgb(37, 37, 56);      // #252538
const COLOR_SURFACE: Color32 = Color32::from_rgb(49, 50, 68);   // #313244
const COLOR_BLUE: Color32 = Color32::from_rgb(137, 180, 250);   // #89B4FA (Primary)
const COLOR_GREEN: Color32 = Color32::from_rgb(166, 227, 161);  // #A6E3A1 (Safe / Whitelist)
const COLOR_RED: Color32 = Color32::from_rgb(243, 139, 168);    // #F38BA8 (Spam / Block)
const COLOR_PEACH: Color32 = Color32::from_rgb(250, 179, 135);  // #FAB387 (Review)
const COLOR_TEXT: Color32 = Color32::from_rgb(205, 214, 244);   // #CDD6F4
const COLOR_MUTED: Color32 = Color32::from_rgb(166, 173, 200);  // #A6ADC8

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    InboxSenders,
    ActiveRules,
    AzureCloud,
}

#[derive(Debug, Clone, PartialEq)]
enum EmailClassification {
    Spam(Vec<String>),
    Safe,
    Review,
}

#[derive(Debug, Clone)]
struct MessageRow {
    uid: u32,
    is_selected: bool,
    sender_name: String,
    sender_email: String,
    sender_domain: String,
    subject: String,
    date_str: String,
    classification: EmailClassification,
    raw_message: GraphMessage,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct AzureExecItem {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "StartTime", default)]
    start_time: String,
    #[serde(rename = "EndTime", default)]
    end_time: String,
}

#[allow(dead_code)]
enum AppEvent {
    ScanStarted,
    ScanCompleted(Result<Vec<MessageRow>, String>),
    MoveCompleted { moved_count: usize, error: Option<String> },
    RulesSynced(Result<String, String>),
    AzureStatusLoaded(Result<Vec<AzureExecItem>, String>),
    CloudScanTriggered(Result<String, String>),
    AuthCompleted(Result<String, String>),
    StatusMessage(String),
}

struct MailcheckGuiApp {
    active_tab: Tab,
    status_text: String,
    account_email: Option<String>,
    is_busy: bool,

    // Tab 1: Inbox Senders
    messages: Vec<MessageRow>,
    filter_text: String,
    scan_count: usize,
    only_unread: bool,

    // Tab 2: Active Rules
    rules: RulesJsonFile,
    filter_blocked: String,
    filter_whitelisted: String,
    selected_blocked: HashSet<String>,
    selected_whitelisted: HashSet<String>,
    new_blocked_input: String,
    new_whitelisted_input: String,

    // Tab 3: Azure Cloud
    azure_executions: Vec<AzureExecItem>,
    is_azure_busy: bool,

    // Channels for background tasks
    tx: Sender<AppEvent>,
    rx: Receiver<AppEvent>,
}

impl MailcheckGuiApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = channel();

        let rules = RulesJsonFile::load_default();
        let cached_email = AuthManager::load_cached_token()
            .and_then(|t| t.account_email)
            .or_else(|| std::env::var("MAILCHECK_ACCOUNT_EMAIL").ok());

        let mut app = Self {
            active_tab: Tab::InboxSenders,
            status_text: "Ready".to_string(),
            account_email: cached_email,
            is_busy: false,

            messages: Vec::new(),
            filter_text: String::new(),
            scan_count: 100,
            only_unread: false,

            rules,
            filter_blocked: String::new(),
            filter_whitelisted: String::new(),
            selected_blocked: HashSet::new(),
            selected_whitelisted: HashSet::new(),
            new_blocked_input: String::new(),
            new_whitelisted_input: String::new(),

            azure_executions: Vec::new(),
            is_azure_busy: false,

            tx,
            rx,
        };

        // Auto-refresh Azure status on startup in background
        app.trigger_refresh_azure();

        app
    }

    fn reclassify_loaded_messages(&mut self) {
        let engine_res = RuleEngine::new(self.rules.to_rules_config());
        if let Ok(engine) = engine_res {
            let email_str = self.account_email.as_deref();
            for msg in &mut self.messages {
                let eval = engine.evaluate(&msg.raw_message, email_str);
                let dom = msg.sender_domain.to_lowercase();
                if eval.is_spam {
                    msg.classification = EmailClassification::Spam(eval.reasons);
                } else if self.rules.whitelisted_domains.iter().any(|w| w.eq_ignore_ascii_case(&dom)) {
                    msg.classification = EmailClassification::Safe;
                } else {
                    msg.classification = EmailClassification::Review;
                }
            }
        }
    }

    fn trigger_scan(&mut self) {
        if self.is_busy {
            return;
        }
        self.is_busy = true;
        self.status_text = format!("Scanning inbox ({} messages)...", self.scan_count);

        let tx = self.tx.clone();
        let scan_count = self.scan_count;
        let only_unread = self.only_unread;
        let rules_file = self.rules.clone();

        thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.send(AppEvent::ScanCompleted(Err(format!("Runtime error: {}", e))));
                    return;
                }
            };

            let res: Result<Vec<MessageRow>, String> = rt.block_on(async {
                let config_path = AppConfig::find_config_path();
                let app_config = AppConfig::load_from_file(&config_path).map_err(|e| e.to_string())?;
                let auth = AuthManager::new(app_config.auth.client_id, app_config.auth.tenant);
                let (token, email) = auth.get_valid_token_and_email().await.map_err(|e| e.to_string())?;

                let client = ImapClient::new(email.clone(), token);
                let raw_items = client
                    .list_inbox_messages(only_unread, scan_count)
                    .map_err(|e| e.to_string())?;

                let engine = RuleEngine::new(rules_file.to_rules_config()).map_err(|e| e.to_string())?;

                let mut rows = Vec::new();
                for (uid, msg) in raw_items {
                    let eval = engine.evaluate(&msg, Some(&email));

                    let sender_address = msg
                        .from
                        .as_ref()
                        .and_then(|f| f.email_address.address.as_deref())
                        .unwrap_or("")
                        .trim()
                        .to_string();

                    let sender_name = msg
                        .from
                        .as_ref()
                        .and_then(|f| f.email_address.name.as_deref())
                        .unwrap_or("")
                        .trim()
                        .to_string();

                    let sender_domain = sender_address.split('@').nth(1).unwrap_or("").to_lowercase();
                    let subject = msg.subject.clone().unwrap_or_else(|| "(No Subject)".to_string());
                    let date_str = msg
                        .received_date_time
                        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_default();

                    let classification = if eval.is_spam {
                        EmailClassification::Spam(eval.reasons)
                    } else if rules_file.whitelisted_domains.iter().any(|w| w.eq_ignore_ascii_case(&sender_domain)) {
                        EmailClassification::Safe
                    } else {
                        EmailClassification::Review
                    };

                    rows.push(MessageRow {
                        uid,
                        is_selected: false,
                        sender_name,
                        sender_email: sender_address,
                        sender_domain,
                        subject,
                        date_str,
                        classification,
                        raw_message: msg,
                    });
                }

                Ok(rows)
            });

            let _ = tx.send(AppEvent::ScanCompleted(res));
        });
    }

    fn trigger_move_selected(&mut self, uids: Vec<u32>) {
        if self.is_busy || uids.is_empty() {
            return;
        }
        self.is_busy = true;
        self.status_text = format!("Moving {} messages to Junk...", uids.len());

        let tx = self.tx.clone();
        thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.send(AppEvent::MoveCompleted {
                        moved_count: 0,
                        error: Some(e.to_string()),
                    });
                    return;
                }
            };

            let res = rt.block_on(async {
                let config_path = AppConfig::find_config_path();
                let app_config = AppConfig::load_from_file(&config_path).map_err(|e| e.to_string())?;
                let auth = AuthManager::new(app_config.auth.client_id, app_config.auth.tenant);
                let (token, email) = auth.get_valid_token_and_email().await.map_err(|e| e.to_string())?;

                let client = ImapClient::new(email, token);
                let mut count = 0;
                for uid in &uids {
                    if let Ok(()) = client.move_message(*uid) {
                        count += 1;
                    }
                }
                Ok(count)
            });

            match res {
                Ok(count) => {
                    let _ = tx.send(AppEvent::MoveCompleted {
                        moved_count: count,
                        error: None,
                    });
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::MoveCompleted {
                        moved_count: 0,
                        error: Some(e),
                    });
                }
            }
        });
    }

    fn trigger_auth(&mut self) {
        if self.is_busy {
            return;
        }
        self.is_busy = true;
        self.status_text = "Opening browser for Microsoft OAuth login...".to_string();

        let tx = self.tx.clone();
        thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.send(AppEvent::AuthCompleted(Err(e.to_string())));
                    return;
                }
            };

            let res = rt.block_on(async {
                let config_path = AppConfig::find_config_path();
                let app_config = AppConfig::load_from_file(&config_path).map_err(|e| e.to_string())?;
                let auth = AuthManager::new(app_config.auth.client_id, app_config.auth.tenant);
                let token = auth.run_browser_login().await.map_err(|e| e.to_string())?;
                Ok(token.account_email.unwrap_or_else(|| "Authenticated".to_string()))
            });

            let _ = tx.send(AppEvent::AuthCompleted(res));
        });
    }

    fn trigger_sync_rules_to_azure(&mut self) {
        if self.is_azure_busy {
            return;
        }
        self.is_azure_busy = true;
        self.status_text = "Syncing rules to Azure Container App Job...".to_string();

        let tx = self.tx.clone();
        let rules_file = self.rules.clone();

        thread::spawn(move || {
            let json = match serde_json::to_string(&rules_file) {
                Ok(j) => j,
                Err(e) => {
                    let _ = tx.send(AppEvent::RulesSynced(Err(e.to_string())));
                    return;
                }
            };

            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            let b64 = STANDARD.encode(json.as_bytes());

            let az_cmd = get_az_command();
            let output = std::process::Command::new(&az_cmd)
                .args([
                    "containerapp",
                    "job",
                    "update",
                    "--name",
                    "job-mailcheck",
                    "--resource-group",
                    "rg-mailcheck",
                    "--set-env-vars",
                    &format!("MAILCHECK_RULES_BASE64={}", b64),
                ])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    let _ = tx.send(AppEvent::RulesSynced(Ok(
                        "Rules successfully synced to Azure Cloud Job!".to_string(),
                    )));
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let _ = tx.send(AppEvent::RulesSynced(Err(format!(
                        "Azure update exited with status {}: {}",
                        out.status, stderr
                    ))));
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::RulesSynced(Err(format!(
                        "Could not run az CLI: {}. Ensure Azure CLI is installed.",
                        e
                    ))));
                }
            }
        });
    }

    fn trigger_refresh_azure(&mut self) {
        if self.is_azure_busy {
            return;
        }
        self.is_azure_busy = true;

        let tx = self.tx.clone();
        thread::spawn(move || {
            let az_cmd = get_az_command();
            let output = std::process::Command::new(&az_cmd)
                .args([
                    "containerapp",
                    "job",
                    "execution",
                    "list",
                    "-n",
                    "job-mailcheck",
                    "-g",
                    "rg-mailcheck",
                    "--query",
                    "[].{Name:name, Status:properties.status, StartTime:properties.startTime, EndTime:properties.endTime}",
                    "-o",
                    "json",
                ])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    match serde_json::from_str::<Vec<AzureExecItem>>(&stdout) {
                        Ok(items) => {
                            let _ = tx.send(AppEvent::AzureStatusLoaded(Ok(items)));
                        }
                        Err(e) => {
                            let _ = tx.send(AppEvent::AzureStatusLoaded(Err(format!("JSON parse error: {}", e))));
                        }
                    }
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let _ = tx.send(AppEvent::AzureStatusLoaded(Err(format!(
                        "az execution list error: {}",
                        stderr
                    ))));
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::AzureStatusLoaded(Err(format!(
                        "Azure CLI error: {}. Ensure az CLI is logged in.",
                        e
                    ))));
                }
            }
        });
    }

    fn trigger_azure_scan_now(&mut self) {
        if self.is_azure_busy {
            return;
        }
        self.is_azure_busy = true;
        self.status_text = "Triggering on-demand Azure scan...".to_string();

        let tx = self.tx.clone();
        thread::spawn(move || {
            let az_cmd = get_az_command();
            let output = std::process::Command::new(&az_cmd)
                .args([
                    "containerapp",
                    "job",
                    "start",
                    "-n",
                    "job-mailcheck",
                    "-g",
                    "rg-mailcheck",
                ])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    let _ = tx.send(AppEvent::CloudScanTriggered(Ok(
                        "On-demand cloud scan triggered successfully!".to_string(),
                    )));
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let _ = tx.send(AppEvent::CloudScanTriggered(Err(format!(
                        "az job start failed: {}",
                        stderr
                    ))));
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::CloudScanTriggered(Err(format!("az error: {}", e))));
                }
            }
        });
    }

    fn process_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                AppEvent::ScanStarted => {
                    self.is_busy = true;
                }
                AppEvent::ScanCompleted(res) => {
                    self.is_busy = false;
                    match res {
                        Ok(rows) => {
                            let spam_cnt = rows.iter().filter(|r| matches!(r.classification, EmailClassification::Spam(_))).count();
                            let safe_cnt = rows.iter().filter(|r| matches!(r.classification, EmailClassification::Safe)).count();
                            let review_cnt = rows.len() - spam_cnt - safe_cnt;
                            self.status_text = format!(
                                "Scan complete: {} messages loaded ({} SPAM, {} SAFE, {} REVIEW)",
                                rows.len(), spam_cnt, safe_cnt, review_cnt
                            );
                            self.messages = rows;
                        }
                        Err(err) => {
                            self.status_text = format!("Scan failed: {}", err);
                        }
                    }
                }
                AppEvent::MoveCompleted { moved_count, error } => {
                    self.is_busy = false;
                    if let Some(err) = error {
                        self.status_text = format!("Error moving messages: {}", err);
                    } else {
                        self.status_text = format!("Successfully moved {} message(s) to Junk!", moved_count);
                        // Remove selected rows that were moved
                        self.messages.retain(|m| !m.is_selected);
                    }
                }
                AppEvent::RulesSynced(res) => {
                    self.is_azure_busy = false;
                    match res {
                        Ok(msg) => self.status_text = msg,
                        Err(e) => self.status_text = format!("Sync failed: {}", e),
                    }
                }
                AppEvent::AzureStatusLoaded(res) => {
                    self.is_azure_busy = false;
                    match res {
                        Ok(items) => {
                            self.azure_executions = items;
                        }
                        Err(e) => {
                            self.status_text = format!("Could not load Azure status: {}", e);
                        }
                    }
                }
                AppEvent::CloudScanTriggered(res) => {
                    self.is_azure_busy = false;
                    match res {
                        Ok(msg) => {
                            self.status_text = msg;
                            self.trigger_refresh_azure();
                        }
                        Err(e) => self.status_text = format!("Scan trigger failed: {}", e),
                    }
                }
                AppEvent::AuthCompleted(res) => {
                    self.is_busy = false;
                    match res {
                        Ok(email) => {
                            self.status_text = format!("Authenticated as: {}", email);
                            self.account_email = Some(email);
                        }
                        Err(e) => {
                            self.status_text = format!("Login failed: {}", e);
                        }
                    }
                }
                AppEvent::StatusMessage(msg) => {
                    self.status_text = msg;
                }
            }
        }
    }
}

fn get_az_command() -> String {
    #[cfg(windows)]
    {
        let std_path = "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az.cmd";
        if std::path::Path::new(std_path).exists() {
            return std_path.to_string();
        }
        "az.cmd".to_string()
    }
    #[cfg(not(windows))]
    {
        "az".to_string()
    }
}

impl eframe::App for MailcheckGuiApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.process_events();

        // Top Navigation Bar
        egui::Frame::new()
            .fill(COLOR_CARD)
            .inner_margin(egui::Margin::symmetric(16, 12))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(RichText::new("Mailcheck").color(COLOR_BLUE).strong().size(20.0));
                    ui.label(RichText::new("Spam Guardian").color(COLOR_MUTED).size(13.0));

                    ui.separator();

                    if let Some(ref email) = self.account_email {
                        ui.label(RichText::new(format!("Connected: {}", email)).color(COLOR_GREEN).size(13.0));
                    } else {
                        ui.label(RichText::new("Not Logged In").color(COLOR_RED).size(13.0));
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(RichText::new("Sign In / Re-auth").color(COLOR_TEXT)).clicked() {
                            self.trigger_auth();
                        }

                        // Tab selectors
                        let azure_btn = ui.selectable_label(self.active_tab == Tab::AzureCloud, "Azure Cloud");
                        if azure_btn.clicked() {
                            self.active_tab = Tab::AzureCloud;
                            self.trigger_refresh_azure();
                        }

                        let rules_btn = ui.selectable_label(self.active_tab == Tab::ActiveRules, "Active Rules");
                        if rules_btn.clicked() {
                            self.active_tab = Tab::ActiveRules;
                        }

                        let senders_btn = ui.selectable_label(self.active_tab == Tab::InboxSenders, "Inbox Senders");
                        if senders_btn.clicked() {
                            self.active_tab = Tab::InboxSenders;
                        }
                    });
                });
            });

        ui.add_space(4.0);

        // Main Tab Content
        match self.active_tab {
            Tab::InboxSenders => self.render_inbox_tab(ui),
            Tab::ActiveRules => self.render_rules_tab(ui),
            Tab::AzureCloud => self.render_azure_tab(ui),
        }

        // Status Bar at Bottom
        ui.add_space(4.0);
        egui::Frame::new()
            .fill(COLOR_CARD)
            .inner_margin(egui::Margin::symmetric(12, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&self.status_text).color(COLOR_MUTED).size(12.0));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let total = self.messages.len();
                        let spam = self.messages.iter().filter(|m| matches!(m.classification, EmailClassification::Spam(_))).count();
                        let safe = self.messages.iter().filter(|m| matches!(m.classification, EmailClassification::Safe)).count();
                        let review = total.saturating_sub(spam + safe);

                        ui.label(RichText::new(format!("Total: {} | Spam: {} | Safe: {} | Review: {}", total, spam, safe, review)).color(COLOR_BLUE).size(12.0).strong());
                    });
                });
            });
    }
}

impl MailcheckGuiApp {
    fn render_inbox_tab(&mut self, ui: &mut egui::Ui) {
        // Controls Bar
        egui::Frame::new()
            .fill(COLOR_CARD)
            .inner_margin(egui::Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Scan:").color(COLOR_MUTED));
                    egui::ComboBox::from_id_salt("scan_count_combo")
                        .selected_text(format!("{} msgs", self.scan_count))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.scan_count, 50, "50 msgs");
                            ui.selectable_value(&mut self.scan_count, 100, "100 msgs");
                            ui.selectable_value(&mut self.scan_count, 250, "250 msgs");
                            ui.selectable_value(&mut self.scan_count, 500, "500 msgs");
                        });

                    ui.checkbox(&mut self.only_unread, "Unread Only");

                    let scan_btn = egui::Button::new(
                        RichText::new(if self.is_busy { "Scanning..." } else { "Scan Inbox" })
                            .color(Color32::BLACK)
                            .strong(),
                    )
                    .fill(COLOR_BLUE);

                    if ui.add_enabled(!self.is_busy, scan_btn).clicked() {
                        self.trigger_scan();
                    }

                    ui.separator();

                    ui.label(RichText::new("Filter:").color(COLOR_MUTED));
                    ui.add(egui::TextEdit::singleline(&mut self.filter_text).hint_text("Search domain, sender, or subject...").desired_width(220.0));

                    if ui.button("Select All [SPAM]").clicked() {
                        for m in &mut self.messages {
                            if matches!(m.classification, EmailClassification::Spam(_)) {
                                m.is_selected = true;
                            }
                        }
                    }

                    if ui.button("Deselect All").clicked() {
                        for m in &mut self.messages {
                            m.is_selected = false;
                        }
                    }
                });
            });

        ui.add_space(6.0);

        // Messages Table
        let filter_lower = self.filter_text.trim().to_lowercase();
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .max_height(ui.available_height() - 65.0)
            .show(ui, |ui| {
                egui::Grid::new("messages_grid")
                    .num_columns(6)
                    .spacing([12.0, 8.0])
                    .striped(true)
                    .show(ui, |ui| {
                        // Header
                        ui.label(RichText::new("Pick").strong().color(COLOR_MUTED));
                        ui.label(RichText::new("Status").strong().color(COLOR_MUTED));
                        ui.label(RichText::new("Domain").strong().color(COLOR_MUTED));
                        ui.label(RichText::new("Sender Display").strong().color(COLOR_MUTED));
                        ui.label(RichText::new("Subject").strong().color(COLOR_MUTED));
                        ui.label(RichText::new("Date").strong().color(COLOR_MUTED));
                        ui.end_row();

                        for msg in &mut self.messages {
                            if !filter_lower.is_empty() {
                                let match_dom = msg.sender_domain.contains(&filter_lower);
                                let match_sender = msg.sender_name.to_lowercase().contains(&filter_lower)
                                    || msg.sender_email.to_lowercase().contains(&filter_lower);
                                let match_sub = msg.subject.to_lowercase().contains(&filter_lower);
                                if !match_dom && !match_sender && !match_sub {
                                    continue;
                                }
                            }

                            ui.checkbox(&mut msg.is_selected, "");

                            match &msg.classification {
                                EmailClassification::Spam(reasons) => {
                                    let tip = reasons.join(", ");
                                    ui.label(RichText::new("SPAM").color(COLOR_RED).strong())
                                        .on_hover_text(tip);
                                }
                                EmailClassification::Safe => {
                                    ui.label(RichText::new("SAFE").color(COLOR_GREEN).strong())
                                        .on_hover_text("Sender domain is whitelisted");
                                }
                                EmailClassification::Review => {
                                    ui.label(RichText::new("REVIEW").color(COLOR_PEACH).strong())
                                        .on_hover_text("Not explicitly blocked or whitelisted");
                                }
                            }

                            ui.label(RichText::new(&msg.sender_domain).color(COLOR_TEXT));

                            let display = if msg.sender_name.is_empty() {
                                &msg.sender_email
                            } else {
                                &msg.sender_name
                            };
                            ui.label(RichText::new(display).color(COLOR_TEXT));
                            ui.label(RichText::new(&msg.subject).color(COLOR_TEXT));
                            ui.label(RichText::new(&msg.date_str).color(COLOR_MUTED));
                            ui.end_row();
                        }
                    });
            });

        // Bottom Action Bar
        egui::Frame::new()
            .fill(COLOR_CARD)
            .inner_margin(egui::Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let mark_spam_btn = egui::Button::new(
                        RichText::new("Mark as SPAM & Block")
                            .color(Color32::BLACK)
                            .strong(),
                    )
                    .fill(COLOR_RED);

                    if ui.add(mark_spam_btn).clicked() {
                        let selected_domains: Vec<String> = self
                            .messages
                            .iter()
                            .filter(|m| m.is_selected && !m.sender_domain.is_empty())
                            .map(|m| m.sender_domain.clone())
                            .collect();

                        for dom in selected_domains {
                            if !self.rules.blocked_domains.contains(&dom) {
                                self.rules.blocked_domains.push(dom.clone());
                            }
                            self.rules.whitelisted_domains.retain(|w| w != &dom);
                        }
                        let _ = self.rules.save_default();
                        self.reclassify_loaded_messages();
                        self.status_text = "Updated rules with selected blocked domains.".to_string();
                    }

                    let mark_safe_btn = egui::Button::new(
                        RichText::new("Mark as SAFE (Whitelist)")
                            .color(Color32::BLACK)
                            .strong(),
                    )
                    .fill(COLOR_GREEN);

                    if ui.add(mark_safe_btn).clicked() {
                        let selected_domains: Vec<String> = self
                            .messages
                            .iter()
                            .filter(|m| m.is_selected && !m.sender_domain.is_empty())
                            .map(|m| m.sender_domain.clone())
                            .collect();

                        for dom in selected_domains {
                            if !self.rules.whitelisted_domains.contains(&dom) {
                                self.rules.whitelisted_domains.push(dom.clone());
                            }
                            self.rules.blocked_domains.retain(|b| b != &dom);
                        }
                        let _ = self.rules.save_default();
                        self.reclassify_loaded_messages();
                        self.status_text = "Updated rules with selected whitelisted domains.".to_string();
                    }

                    ui.separator();

                    let move_btn = egui::Button::new(
                        RichText::new("Move Selected to Junk")
                            .color(Color32::BLACK)
                            .strong(),
                    )
                    .fill(COLOR_PEACH);

                    if ui.add_enabled(!self.is_busy, move_btn).clicked() {
                        let uids: Vec<u32> = self.messages.iter().filter(|m| m.is_selected).map(|m| m.uid).collect();
                        self.trigger_move_selected(uids);
                    }

                    let sweep_btn = egui::Button::new(
                        RichText::new("Sweep All SPAM to Junk")
                            .color(Color32::BLACK)
                            .strong(),
                    )
                    .fill(COLOR_BLUE);

                    if ui.add_enabled(!self.is_busy, sweep_btn).clicked() {
                        let uids: Vec<u32> = self
                            .messages
                            .iter()
                            .filter(|m| matches!(m.classification, EmailClassification::Spam(_)))
                            .map(|m| m.uid)
                            .collect();
                        self.trigger_move_selected(uids);
                    }
                });
            });
    }

    fn render_rules_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Left Panel: Blocked Domains
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() * 0.43);
                egui::Frame::new()
                    .fill(COLOR_CARD)
                    .inner_margin(egui::Margin::symmetric(14, 12))
                    .show(ui, |ui| {
                        ui.heading(RichText::new("Blocked Domains (Auto-Junk)").color(COLOR_RED).size(15.0).strong());
                        ui.label(RichText::new(format!("Total: {}", self.rules.blocked_domains.len())).color(COLOR_MUTED).size(12.0));

                        ui.add_space(4.0);
                        ui.add(egui::TextEdit::singleline(&mut self.filter_blocked).hint_text("Search blocked domains...").desired_width(f32::INFINITY));

                        ui.add_space(4.0);
                        let filter = self.filter_blocked.trim().to_lowercase();
                        egui::ScrollArea::vertical()
                            .id_salt("blocked_scroll")
                            .max_height(ui.available_height() - 130.0)
                            .show(ui, |ui| {
                                let mut to_toggle = Vec::new();
                                for dom in &self.rules.blocked_domains {
                                    if !filter.is_empty() && !dom.to_lowercase().contains(&filter) {
                                        continue;
                                    }
                                    let is_sel = self.selected_blocked.contains(dom);
                                    if ui.selectable_label(is_sel, dom).clicked() {
                                        to_toggle.push(dom.clone());
                                    }
                                }
                                for d in to_toggle {
                                    if self.selected_blocked.contains(&d) {
                                        self.selected_blocked.remove(&d);
                                    } else {
                                        self.selected_blocked.insert(d);
                                    }
                                }
                            });

                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut self.new_blocked_input).hint_text("domain.com").desired_width(140.0));
                            if ui.button("Add").clicked() {
                                let d = self.new_blocked_input.trim().to_lowercase();
                                if !d.is_empty() && !self.rules.blocked_domains.contains(&d) {
                                    self.rules.blocked_domains.push(d.clone());
                                    self.rules.whitelisted_domains.retain(|w| w != &d);
                                    let _ = self.rules.save_default();
                                    self.reclassify_loaded_messages();
                                    self.new_blocked_input.clear();
                                }
                            }
                            if ui.button("Delete").clicked() {
                                self.rules.blocked_domains.retain(|d| !self.selected_blocked.contains(d));
                                self.selected_blocked.clear();
                                let _ = self.rules.save_default();
                                self.reclassify_loaded_messages();
                            }
                        });
                    });
            });

            // Middle Column: Bidirectional Transfer Controls
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() * 0.22);
                ui.add_space(ui.available_height() * 0.3);

                egui::Frame::new()
                    .fill(COLOR_CARD)
                    .inner_margin(egui::Margin::symmetric(10, 16))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            let to_white_btn = egui::Button::new(
                                RichText::new("Whitelist >>")
                                    .color(Color32::BLACK)
                                    .strong(),
                            )
                            .fill(COLOR_GREEN)
                            .min_size(Vec2::new(110.0, 32.0));

                            if ui.add(to_white_btn).on_hover_text("Move selected domains from Blocked to Whitelist").clicked() {
                                let mut moved = 0;
                                for d in &self.selected_blocked {
                                    if !self.rules.whitelisted_domains.contains(d) {
                                        self.rules.whitelisted_domains.push(d.clone());
                                    }
                                    moved += 1;
                                }
                                self.rules.blocked_domains.retain(|d| !self.selected_blocked.contains(d));
                                self.selected_blocked.clear();
                                if moved > 0 {
                                    let _ = self.rules.save_default();
                                    self.reclassify_loaded_messages();
                                }
                            }

                            ui.add_space(14.0);

                            let to_block_btn = egui::Button::new(
                                RichText::new("<< Block")
                                    .color(Color32::BLACK)
                                    .strong(),
                            )
                            .fill(COLOR_RED)
                            .min_size(Vec2::new(110.0, 32.0));

                            if ui.add(to_block_btn).on_hover_text("Move selected domains from Whitelist to Blocked").clicked() {
                                let mut moved = 0;
                                for d in &self.selected_whitelisted {
                                    if !self.rules.blocked_domains.contains(d) {
                                        self.rules.blocked_domains.push(d.clone());
                                    }
                                    moved += 1;
                                }
                                self.rules.whitelisted_domains.retain(|d| !self.selected_whitelisted.contains(d));
                                self.selected_whitelisted.clear();
                                if moved > 0 {
                                    let _ = self.rules.save_default();
                                    self.reclassify_loaded_messages();
                                }
                            }
                        });
                    });
            });

            // Right Panel: Whitelisted Domains
            ui.vertical(|ui| {
                egui::Frame::new()
                    .fill(COLOR_CARD)
                    .inner_margin(egui::Margin::symmetric(14, 12))
                    .show(ui, |ui| {
                        ui.heading(RichText::new("Whitelisted Domains (Safe)").color(COLOR_GREEN).size(15.0).strong());
                        ui.label(RichText::new(format!("Total: {}", self.rules.whitelisted_domains.len())).color(COLOR_MUTED).size(12.0));

                        ui.add_space(4.0);
                        ui.add(egui::TextEdit::singleline(&mut self.filter_whitelisted).hint_text("Search whitelisted domains...").desired_width(f32::INFINITY));

                        ui.add_space(4.0);
                        let filter = self.filter_whitelisted.trim().to_lowercase();
                        egui::ScrollArea::vertical()
                            .id_salt("whitelist_scroll")
                            .max_height(ui.available_height() - 130.0)
                            .show(ui, |ui| {
                                let mut to_toggle = Vec::new();
                                for dom in &self.rules.whitelisted_domains {
                                    if !filter.is_empty() && !dom.to_lowercase().contains(&filter) {
                                        continue;
                                    }
                                    let is_sel = self.selected_whitelisted.contains(dom);
                                    if ui.selectable_label(is_sel, dom).clicked() {
                                        to_toggle.push(dom.clone());
                                    }
                                }
                                for d in to_toggle {
                                    if self.selected_whitelisted.contains(&d) {
                                        self.selected_whitelisted.remove(&d);
                                    } else {
                                        self.selected_whitelisted.insert(d);
                                    }
                                }
                            });

                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut self.new_whitelisted_input).hint_text("domain.com").desired_width(140.0));
                            if ui.button("Add").clicked() {
                                let d = self.new_whitelisted_input.trim().to_lowercase();
                                if !d.is_empty() && !self.rules.whitelisted_domains.contains(&d) {
                                    self.rules.whitelisted_domains.push(d.clone());
                                    self.rules.blocked_domains.retain(|b| b != &d);
                                    let _ = self.rules.save_default();
                                    self.reclassify_loaded_messages();
                                    self.new_whitelisted_input.clear();
                                }
                            }
                            if ui.button("Delete").clicked() {
                                self.rules.whitelisted_domains.retain(|d| !self.selected_whitelisted.contains(d));
                                self.selected_whitelisted.clear();
                                let _ = self.rules.save_default();
                                self.reclassify_loaded_messages();
                            }
                        });
                    });
            });
        });

        ui.add_space(8.0);

        // Bottom Cloud Sync Banner
        egui::Frame::new()
            .fill(COLOR_CARD)
            .inner_margin(egui::Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Azure Cloud Synchronization").strong().color(COLOR_BLUE).size(14.0));
                        ui.label(RichText::new("Sync your local whitelist & blocklist directly to your Azure Container App Job in seconds.").color(COLOR_MUTED).size(12.0));
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let sync_btn = egui::Button::new(
                            RichText::new(if self.is_azure_busy { "Syncing to Azure..." } else { "Sync Rules to Azure Cloud" })
                                .color(Color32::BLACK)
                                .strong(),
                        )
                        .fill(COLOR_BLUE);

                        if ui.add_enabled(!self.is_azure_busy, sync_btn).clicked() {
                            self.trigger_sync_rules_to_azure();
                        }
                    });
                });
            });
    }

    fn render_azure_tab(&mut self, ui: &mut egui::Ui) {
        // Status Header Card
        egui::Frame::new()
            .fill(COLOR_CARD)
            .inner_margin(egui::Margin::symmetric(16, 14))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            let (rect, _) = ui.allocate_exact_size(Vec2::new(12.0, 12.0), egui::Sense::hover());
                            ui.painter().circle_filled(rect.center(), 5.0, COLOR_GREEN);
                            ui.heading(RichText::new("Azure Cloud Guardian (Active)").color(COLOR_GREEN).size(18.0).strong());
                        });
                        ui.label(RichText::new("Job: job-mailcheck | Resource Group: rg-mailcheck (westus)").color(COLOR_TEXT).size(13.0));
                        ui.label(RichText::new("Schedule: Automatically checks inbox every 5 minutes in background ($0.00 / Free tier)").color(COLOR_MUTED).size(12.0));
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let refresh_btn = egui::Button::new(
                            RichText::new(if self.is_azure_busy { "Refreshing..." } else { "Refresh Status" })
                                .color(COLOR_TEXT),
                        )
                        .fill(COLOR_SURFACE);

                        if ui.add_enabled(!self.is_azure_busy, refresh_btn).clicked() {
                            self.trigger_refresh_azure();
                        }

                        let scan_now_btn = egui::Button::new(
                            RichText::new("Run Cloud Scan Now")
                                .color(Color32::BLACK)
                                .strong(),
                        )
                        .fill(COLOR_GREEN);

                        if ui.add_enabled(!self.is_azure_busy, scan_now_btn).clicked() {
                            self.trigger_azure_scan_now();
                        }
                    });
                });
            });

        ui.add_space(8.0);

        // Recent Executions Table
        egui::Frame::new()
            .fill(COLOR_CARD)
            .inner_margin(egui::Margin::symmetric(14, 12))
            .show(ui, |ui| {
                ui.heading(RichText::new("Recent Cloud Executions (Azure)").color(COLOR_BLUE).size(15.0).strong());
                ui.add_space(4.0);

                if self.azure_executions.is_empty() {
                    ui.label(RichText::new("No execution records found or still loading...").color(COLOR_MUTED));
                } else {
                    egui::ScrollArea::vertical()
                        .max_height(ui.available_height() - 40.0)
                        .show(ui, |ui| {
                            egui::Grid::new("azure_grid")
                                .num_columns(4)
                                .spacing([20.0, 10.0])
                                .striped(true)
                                .show(ui, |ui| {
                                    ui.label(RichText::new("Execution Name").strong().color(COLOR_MUTED));
                                    ui.label(RichText::new("Status").strong().color(COLOR_MUTED));
                                    ui.label(RichText::new("Start Time (UTC)").strong().color(COLOR_MUTED));
                                    ui.label(RichText::new("End Time (UTC)").strong().color(COLOR_MUTED));
                                    ui.end_row();

                                    for ex in &self.azure_executions {
                                        ui.label(RichText::new(&ex.name).color(COLOR_TEXT));

                                        let status_color = match ex.status.as_str() {
                                            "Succeeded" => COLOR_GREEN,
                                            "Running" => COLOR_BLUE,
                                            "Failed" => COLOR_RED,
                                            _ => COLOR_MUTED,
                                        };
                                        ui.label(RichText::new(&ex.status).color(status_color).strong());
                                        ui.label(RichText::new(&ex.start_time).color(COLOR_TEXT));
                                        ui.label(RichText::new(&ex.end_time).color(COLOR_TEXT));
                                        ui.end_row();
                                    }
                                });
                        });
                }
            });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 740.0])
            .with_min_inner_size([880.0, 520.0])
            .with_title("Mailcheck - Cross-Platform Spam Guardian"),
        ..Default::default()
    };

    eframe::run_native(
        "Mailcheck",
        options,
        Box::new(|cc| {
            // Apply dark theme visuals
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = COLOR_BG;
            visuals.window_fill = COLOR_BG;
            visuals.override_text_color = Some(COLOR_TEXT);
            cc.egui_ctx.set_visuals(visuals);

            Ok(Box::new(MailcheckGuiApp::new(cc)))
        }),
    )
}
