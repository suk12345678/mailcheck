# mailcheck 🦀✉️

A fast, lightweight, and customizable Rust CLI anti-spam tool for **Hotmail / Outlook.com** accounts using the **Microsoft Graph API**.

---

## Features

- **Modern Authentication (OAuth 2.0)**: Uses the secure Microsoft Device Code Flow (`https://microsoft.com/devicelogin`). Authenticate once in your browser; tokens are cached and auto-refreshed locally.
- **Top-Level Domain (TLD) Filtering**: Instantly flags senders ending in `.xyz`, `.top`, `.icu`, `.buzz`, `.click`, `.shop`, `.cfd`, `.rest`, etc.
- **Brand Impersonation & Spoof Detection**: Catches emails pretending to be "Geek Squad", "McAfee", "Norton", "PayPal", "Amazon", etc., whose actual sender domain does not match the official domain.
- **RFC822 Header Inspection**: Inspects `Authentication-Results` for `spf=fail` and `dmarc=fail` flags.
- **Subject Regex Filtering**: Blocks typical phishing lures ("invoice attached", "order confirmed #...", "account suspension").
- **Safety First (`DryRun` Mode)**: Defaults to Dry-Run so you can inspect what would be caught before moving or deleting anything.
- **Background Watcher**: Run `mailcheck watch` to monitor your inbox automatically every 60 seconds.

---

## 1. Quick Setup: Microsoft Azure Client ID

Because Microsoft permanently deprecated Basic Authentication for Hotmail / Outlook.com, a free standard **Azure Application Client ID** is needed:

1. Sign in to the [Azure Portal - App registrations](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) (using your personal Microsoft account).
2. Click **New registration**:
   - **Name**: `Mailcheck`
   - **Supported account types**: Select **Personal Microsoft accounts only** (or *Accounts in any organizational directory and personal Microsoft accounts*).
   - **Redirect URI**: Select **Public client/native (mobile & desktop)** and enter: `https://login.microsoftonline.com/common/oauth2/nativeclient`
3. Click **Register**.
4. Go to **Authentication** in the left sidebar:
   - Scroll down to **Advanced settings** -> **Allow public client flows**.
   - Set **Enable the following mobile and desktop flows** to **Yes**.
   - Click **Save**.
5. Copy the **Application (client) ID** from the **Overview** page.

---

## 2. Authenticating

Paste your `client_id` into `config.toml` under `[auth]` or authenticate directly:

```powershell
.\target\release\mailcheck.exe auth --client-id YOUR_AZURE_CLIENT_ID
```

The CLI will display:
```
1. Open:  https://microsoft.com/devicelogin
2. Code:  ABCD-EFGH
Waiting for sign-in completion in your browser...
```

Once you enter the code and approve in your browser, `mailcheck` securely saves the token in `%APPDATA%\mailcheck\token.json` and refreshes it automatically in the future.

---

## 3. Usage Examples

### View Active Rules
```powershell
.\target\release\mailcheck.exe rules
```

### Dry Run Scan (Default & Safe)
Inspects the last 50 unread inbox messages and reports what triggers without modifying anything:
```powershell
.\target\release\mailcheck.exe scan --dry-run
```

### Move Detected Spam to Junk Email
```powershell
.\target\release\mailcheck.exe scan --action move-to-junk
```

### Permanently Delete Detected Spam
```powershell
.\target\release\mailcheck.exe scan --action delete
```

### Scan More Messages or Include Read Mail
```powershell
.\target\release\mailcheck.exe scan --top 100 --include-read
```

### Run as a Background Watcher
Monitors your inbox every 60 seconds (or custom interval):
```powershell
.\target\release\mailcheck.exe watch --interval 60
```

---

## 4. Customizing Rules (`config.toml`)

Edit `config.toml` to add more domains, regex patterns, or brands:

```toml
[general]
action = "DryRun" # Change to "MoveToJunk" when ready

[rules]
blocked_tlds = [".xyz", ".top", ".icu", ".buzz", ".click", ".shop"]

[[rules.spoof_rules]]
brand_name = "PayPal"
display_pattern = "(?i)paypal"
allowed_domains = ["paypal.com"]
```

