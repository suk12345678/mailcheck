use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use mailcheck::auth::AuthManager;
use mailcheck::config::{AppConfig, FilterAction};
use mailcheck::engine::RuleEngine;
use mailcheck::imap_client::ImapClient;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "mailcheck",
    version = "0.2.0",
    about = "Fast, standalone spam filtering CLI for Hotmail / Outlook.com using IMAP & XOAUTH2"
)]
struct Cli {
    /// Path to config file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with your Microsoft / Hotmail account via browser sign-in
    Auth {
        /// Microsoft OAuth Client ID (optional override)
        #[arg(long)]
        client_id: Option<String>,
    },

    /// Scan inbox messages and process detected spam
    Scan {
        /// Force Dry-Run mode (evaluate and report without making changes)
        #[arg(long)]
        dry_run: bool,

        /// Override action to take on detected spam
        #[arg(short, long, value_enum)]
        action: Option<CliAction>,

        /// Maximum number of messages to inspect
        #[arg(short, long)]
        top: Option<usize>,

        /// Include read messages (default is unread only)
        #[arg(long)]
        include_read: bool,
    },

    /// Run continuously as a background watcher
    Watch {
        /// Polling interval in seconds (overrides config.toml)
        #[arg(short, long)]
        interval: Option<u64>,

        /// Force Dry-Run mode while watching
        #[arg(long)]
        dry_run: bool,
    },

    /// Display all currently loaded spam filtering rules
    Rules,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum CliAction {
    DryRun,
    MoveToJunk,
    Delete,
}

impl From<CliAction> for FilterAction {
    fn from(a: CliAction) -> Self {
        match a {
            CliAction::DryRun => FilterAction::DryRun,
            CliAction::MoveToJunk => FilterAction::MoveToJunk,
            CliAction::Delete => FilterAction::Delete,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config_path = cli.config.unwrap_or_else(AppConfig::find_config_path);
    let app_config = match AppConfig::load_from_file(&config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!(
                "{} Could not load configuration file ({}): {}",
                "Warning:".yellow().bold(),
                config_path.display(),
                err
            );
            eprintln!("Please ensure 'config.toml' is present in the current directory.");
            return Ok(());
        }
    };

    match cli.command {
        Commands::Auth { client_id } => {
            let effective_client_id = client_id
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| app_config.auth.client_id.clone());

            let auth = AuthManager::new(effective_client_id, app_config.auth.tenant);
            let token = auth.run_browser_login().await?;

            if let Some(email) = token.account_email {
                println!("\nTesting IMAP connection to outlook.office365.com...");
                let test_res = tokio::task::spawn_blocking(move || {
                    let client = ImapClient::new(email, token.access_token);
                    client.test_connection()
                })
                .await?;

                match test_res {
                    Ok(info) => println!("{} {}", "IMAP Connection Verified:".bold().green(), info),
                    Err(e) => eprintln!("{} {}", "Warning: Initial IMAP test reported:".yellow().bold(), e),
                }
            }
        }

        Commands::Rules => {
            println!("\n{}", "=== Active Spam Rules ===".bold().cyan());
            println!("{}: {:?}", "Whitelisted Domains".bold().green(), app_config.rules.whitelisted_domains);
            println!("{}: {:?}", "Blocked TLDs".bold(), app_config.rules.blocked_tlds);
            println!("{}: {:?}", "Blocked Domains".bold(), app_config.rules.blocked_sender_domains);
            println!("{}: {:?}", "Blocked Subject Regex".bold(), app_config.rules.blocked_subject_patterns);
            println!("\n{}:", "Header Rules".bold());
            for r in &app_config.rules.header_rules {
                println!("  - [{}] Header '{}' matches /{}/", r.name.cyan(), r.header, r.pattern);
            }
            println!("\n{}:", "Spoofing Rules".bold());
            for s in &app_config.rules.spoof_rules {
                println!(
                    "  - Brand '{}' (pattern: /{}/), allowed domains: {:?}",
                    s.brand_name.yellow(),
                    s.display_pattern,
                    s.allowed_domains
                );
            }
            println!(
                "\n{}: flag_if_not_in_to_or_cc = {}\n",
                "Recipient Anomaly Check".bold(),
                app_config.rules.recipient_checks.flag_if_not_in_to_or_cc
            );
        }

        Commands::Scan {
            dry_run,
            action,
            top,
            include_read,
        } => {
            let effective_action = if dry_run {
                FilterAction::DryRun
            } else if let Some(act) = action {
                act.into()
            } else {
                app_config.general.action
            };

            let max_messages = top.unwrap_or(app_config.general.max_messages_per_scan);
            let only_unread = if include_read { false } else { app_config.general.only_unread };

            run_scan(&app_config, effective_action, max_messages, only_unread).await?;
        }

        Commands::Watch { interval, dry_run } => {
            let effective_action = if dry_run {
                FilterAction::DryRun
            } else {
                app_config.general.action
            };

            let wait_secs = interval.unwrap_or(app_config.general.watch_interval_seconds);
            println!(
                "{}",
                format!(
                    "Starting mailcheck watcher (Interval: {}s, Action: {})... Press Ctrl+C to stop.",
                    wait_secs, effective_action
                )
                .bold()
                .cyan()
            );

            loop {
                if let Err(e) = run_scan(
                    &app_config,
                    effective_action,
                    app_config.general.max_messages_per_scan,
                    app_config.general.only_unread,
                )
                .await
                {
                    eprintln!("{} Scan error: {}", "Error:".red().bold(), e);
                }

                tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;
            }
        }
    }

    Ok(())
}

async fn run_scan(
    app_config: &AppConfig,
    action: FilterAction,
    max_messages: usize,
    only_unread: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = AuthManager::new(app_config.auth.client_id.clone(), app_config.auth.tenant.clone());
    let (token, email) = auth.get_valid_token_and_email().await?;

    if email.is_empty() {
        return Err("No account email stored. Please run 'mailcheck auth' to sign in.".into());
    }

    println!(
        "\n{}",
        format!(
            "--- Scanning Inbox [{}] (Mode: {}, Top: {}, Unread Only: {}) ---",
            email, action, max_messages, only_unread
        )
        .bold()
        .cyan()
    );

    let client_email = email.clone();
    let client_token = token.clone();

    // Fetch messages over IMAP
    let messages = tokio::task::spawn_blocking(move || {
        let client = ImapClient::new(client_email, client_token);
        client.list_inbox_messages(only_unread, max_messages)
    })
    .await?
    .map_err(|e| -> Box<dyn std::error::Error> { e })?;

    let engine = RuleEngine::new(app_config.rules.clone())?;

    if messages.is_empty() {
        println!("No messages found matching criteria.");
        return Ok(());
    }

    let mut spam_count = 0;
    let mut clean_count = 0;

    for (uid, msg) in &messages {
        let sender_str = msg
            .from
            .as_ref()
            .map(|f| {
                format!(
                    "\"{}\" <{}>",
                    f.email_address.name.as_deref().unwrap_or(""),
                    f.email_address.address.as_deref().unwrap_or("")
                )
            })
            .unwrap_or_else(|| "Unknown Sender".into());

        let subject_str = msg.subject.as_deref().unwrap_or("(No Subject)");

        let eval = engine.evaluate(msg, Some(&email));

        if eval.is_spam {
            spam_count += 1;
            println!("\n{}", "⚠️  SPAM DETECTED".red().bold());
            println!("  UID:     {}", uid);
            println!("  From:    {}", sender_str.yellow());
            println!("  Subject: {}", subject_str.bold());
            if let Some(date) = msg.received_date_time {
                println!("  Date:    {}", date.to_rfc2822());
            }
            println!("  Triggers:");
            for r in &eval.reasons {
                println!("    • {}", r.red());
            }

            match action {
                FilterAction::DryRun => {
                    println!("  Action:  {}", "[DRY RUN] Would move to Junk folder".bright_blue());
                }
                FilterAction::MoveToJunk => {
                    print!("  Action:  Moving to Junk folder... ");
                    let move_email = email.clone();
                    let move_token = token.clone();
                    let target_uid = *uid;
                    let res = tokio::task::spawn_blocking(move || {
                        let client = ImapClient::new(move_email, move_token);
                        client.move_message(target_uid)
                    })
                    .await?;

                    match res {
                        Ok(_) => println!("{}", "Done".green().bold()),
                        Err(e) => println!("{} {}", "Failed:".red().bold(), e),
                    }
                }
                FilterAction::Delete => {
                    print!("  Action:  Permanently deleting message... ");
                    let del_email = email.clone();
                    let del_token = token.clone();
                    let target_uid = *uid;
                    let res = tokio::task::spawn_blocking(move || {
                        let client = ImapClient::new(del_email, del_token);
                        client.delete_message(target_uid)
                    })
                    .await?;

                    match res {
                        Ok(_) => println!("{}", "Deleted".green().bold()),
                        Err(e) => println!("{} {}", "Failed:".red().bold(), e),
                    }
                }
            }
        } else {
            clean_count += 1;
        }
    }

    println!("\n{}", "--- Scan Summary ---".bold());
    println!("Total Inspected: {}", messages.len());
    println!("Clean:           {}", clean_count.to_string().green());
    println!("Spam Detected:   {}", spam_count.to_string().red().bold());
    println!();

    Ok(())
}
