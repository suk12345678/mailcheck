<#
.SYNOPSIS
    mailcheck-local.ps1 - Local spam scanner and cleaner for Outlook Desktop.
    Connects directly to your local Outlook session with zero Azure / OAuth setup required.

.EXAMPLE
    .\mailcheck-local.ps1 -Mode DryRun
    .\mailcheck-local.ps1 -Mode MoveToJunk -MaxMessages 100
    .\mailcheck-local.ps1 -Mode Delete -MaxMessages 50
    .\mailcheck-local.ps1 -Watch -IntervalSeconds 60
#>

[CmdletBinding()]
param(
    [ValidateSet("DryRun", "MoveToJunk", "Delete")]
    [string]$Mode = "DryRun",

    [int]$MaxMessages = 500,

    [switch]$IncludeRead = $false,

    [switch]$Watch = $false,

    [int]$IntervalSeconds = 60
)

# ==============================================================================
# 1. SAFETY WHITELIST: These domains are NEVER touched, regardless of headers!
# ==============================================================================
$script:WhitelistedDomains = @(
    "linkedin.com",
    "schwab.com",
    "costco.com",
    "discover.com",
    "farmers.com",
    "interactivebrokers.com",
    "robinhood.com",
    "apple.com",
    "appleid.com",
    "privaterelay.appleid.com",
    "icloud.com",
    "zillow.com",
    "glassdoor.com",
    "wsj.com"
)

# ==============================================================================
# 2. SPECIFIC SENDER DOMAINS TO DROP (Newsletters / Blasts you requested to drop)
# ==============================================================================
$script:BlockedSenderDomains = @(
    "proxymity.io",
    "506investorgroup.com",
    "beehiiv.com",
    "mail.beehiiv.com",
    "threadloom.news",
    "vesta.threadloom.news",
    "digital.metamail.com",
    "av.vc"
)

# ==============================================================================
# 3. SPAM TOP-LEVEL DOMAINS (TLDs)
# ==============================================================================
$script:BlockedTLDs = @(
    ".xyz", ".top", ".icu", ".buzz", ".click", ".shop",
    ".cfd", ".rest", ".quest", ".cam", ".sbs", ".monster",
    ".cyou", ".mom", ".beauty", ".skin", ".link"
)

# ==============================================================================
# 4. PHISHING PATTERNS
# ==============================================================================
$script:SubjectPatterns = @(
    "(?i)invoice.*attached",
    "(?i)your order.*confirmed.*#\d{4,}",
    "(?i)account suspension notice",
    "(?i)urgent notification.*password expired",
    "(?i)bitcoin.*wallet.*transfer",
    "(?i)renewal confirmation.*subscription"
)

$script:SpoofRules = @(
    @{
        Brand = "Geek Squad"
        Pattern = "(?i)geek[- ]?squad"
        AllowedDomains = @("bestbuy.com", "geeksquad.com")
    },
    @{
        Brand = "McAfee"
        Pattern = "(?i)mcafee"
        AllowedDomains = @("mcafee.com")
    },
    @{
        Brand = "Norton"
        Pattern = "(?i)norton"
        AllowedDomains = @("norton.com", "geneseego.com", "lifelock.com")
    },
    @{
        Brand = "PayPal"
        Pattern = "(?i)paypal"
        AllowedDomains = @("paypal.com", "intl.paypal.com")
    },
    @{
        Brand = "Amazon"
        Pattern = "(?i)amazon( customer service| order| support)?"
        AllowedDomains = @("amazon.com", "amazon.co.uk", "amazon.ca")
    }
)

function Get-SenderSmtpAddress($mailItem) {
    try {
        if ($mailItem.SenderEmailType -eq "SMTP" -and $mailItem.SenderEmailAddress) {
            return $mailItem.SenderEmailAddress
        }
        if ($mailItem.Sender) {
            $exchUser = $mailItem.Sender.GetExchangeUser()
            if ($exchUser -and $exchUser.PrimarySmtpAddress) {
                return $exchUser.PrimarySmtpAddress
            }
        }
        $prop = $mailItem.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x0C1F001F")
        if ($prop) { return $prop }
    } catch {}
    return $mailItem.SenderEmailAddress
}

function Evaluate-Message($mailItem) {
    $reasons = [System.Collections.Generic.List[string]]::new()

    $senderAddress = (Get-SenderSmtpAddress $mailItem)
    if ($senderAddress) { $senderAddress = $senderAddress.Trim().ToLower() } else { $senderAddress = "" }

    $senderName = $mailItem.SenderName
    if (-not $senderName) { $senderName = "" }

    $subject = $mailItem.Subject
    if (-not $subject) { $subject = "(No Subject)" }

    $domain = ""
    if ($senderAddress -match "@([^@]+)$") {
        $domain = $matches[1].ToLower()
    }

    # STEP 0: SAFETY WHITELIST
    # If the domain is whitelisted, NEVER flag as spam!
    foreach ($wl in $script:WhitelistedDomains) {
        if ($domain -eq $wl -or $domain.EndsWith(".$wl")) {
            return @{
                IsSpam        = $false
                Reasons       = @()
                Sender        = if ($senderName) { "$senderName <$senderAddress>" } else { $senderAddress }
                Subject       = $subject
                ReceivedTime  = $mailItem.ReceivedTime
            }
        }
    }

    # STEP 1: Specific Blocked Sender Domains (Newsletters / Unwanted blasts)
    foreach ($bd in $script:BlockedSenderDomains) {
        if ($domain -eq $bd -or $domain.EndsWith(".$bd")) {
            $reasons.Add("Blocked sender domain: $domain")
            break
        }
    }

    # STEP 2: Blocked Spam TLDs
    foreach ($tld in $script:BlockedTLDs) {
        if ($senderAddress.EndsWith($tld.ToLower())) {
            $reasons.Add("Blocked TLD '$tld' in sender: $senderAddress")
            break
        }
    }

    # STEP 3: Phishing Subject Patterns
    foreach ($pat in $script:SubjectPatterns) {
        if ($subject -match $pat) {
            $reasons.Add("Subject matched suspicious pattern: $pat")
            break
        }
    }

    # STEP 4: Brand Impersonation / Spoofing
    foreach ($rule in $script:SpoofRules) {
        if ($senderName -match $rule.Pattern) {
            $isAllowed = $false
            foreach ($allowed in $rule.AllowedDomains) {
                if ($domain -eq $allowed -or $domain.EndsWith(".$allowed")) {
                    $isAllowed = $true
                    break
                }
            }
            if (-not $isAllowed) {
                $reasons.Add("Spoofing: Display name '$senderName' impersonates '$($rule.Brand)' but sender domain is '$domain'")
            }
        }
    }

    # STEP 5: Spammer Pattern in domain (e.g. -----mail.random.com)
    if ($domain -match "-----mail\.") {
        $reasons.Add("Spam pattern in domain: $domain")
    }

    return @{
        IsSpam        = ($reasons.Count -gt 0)
        Reasons       = $reasons
        Sender        = if ($senderName) { "$senderName <$senderAddress>" } else { $senderAddress }
        Subject       = $subject
        ReceivedTime  = $mailItem.ReceivedTime
    }
}

function Run-Scan {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "   mailcheck (Local Outlook Mode) - Scan Started" -ForegroundColor Cyan
    Write-Host "   Mode: $Mode | Max: $MaxMessages | Unread Only: $(-not $IncludeRead)" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan

    try {
        $outlook = New-Object -ComObject Outlook.Application
    } catch {
        Write-Error "Could not connect to Outlook. Please make sure Outlook is installed."
        return
    }

    $namespace = $outlook.GetNamespace("MAPI")
    try { $namespace.Logon("", "", $false, $false) } catch {}
    $inbox = $namespace.GetDefaultFolder(6) # olFolderInbox
    $junkFolder = $namespace.GetDefaultFolder(23) # olFolderJunk

    $items = $inbox.Items
    $items.Sort("[ReceivedTime]", $true) # Newest first

    if (-not $IncludeRead) {
        $items = $items.Restrict("[UnRead] = True")
    }

    $totalToInspect = [Math]::Min($MaxMessages, $items.Count)
    Write-Host "Found $($items.Count) qualifying messages. Inspecting up to $totalToInspect..." -ForegroundColor Gray

    $spamCount = 0
    $cleanCount = 0
    $processedCount = 0

    # Collect items into an array first so moving/deleting does not disrupt index
    $itemsToProcess = [System.Collections.Generic.List[object]]::new()
    for ($i = 1; $i -le $totalToInspect; $i++) {
        $item = $items.Item($i)
        if ($item -and $item.MessageClass -eq "IPM.Note") {
            $itemsToProcess.Add($item)
        }
    }

    foreach ($mail in $itemsToProcess) {
        $processedCount++
        $eval = Evaluate-Message $mail

        if ($eval.IsSpam) {
            $spamCount++
            Write-Host ""
            Write-Host "[!] SPAM DETECTED" -ForegroundColor Red -BackgroundColor Black
            Write-Host "    From:    $($eval.Sender)" -ForegroundColor Yellow
            Write-Host "    Subject: $($eval.Subject)" -ForegroundColor White
            Write-Host "    Date:    $($eval.ReceivedTime)" -ForegroundColor DarkGray
            Write-Host "    Triggers:" -ForegroundColor DarkYellow
            foreach ($r in $eval.Reasons) {
                Write-Host "      - $r" -ForegroundColor Red
            }

            switch ($Mode) {
                "DryRun" {
                    Write-Host "    Action:  [DRY RUN] Would move to Junk Email" -ForegroundColor Cyan
                }
                "MoveToJunk" {
                    Write-Host "    Action:  Moving to Junk Email folder... " -NoNewline -ForegroundColor Yellow
                    try {
                        $null = $mail.Move($junkFolder)
                        Write-Host "DONE" -ForegroundColor Green
                    } catch {
                        Write-Host "FAILED: $_" -ForegroundColor Red
                    }
                }
                "Delete" {
                    Write-Host "    Action:  Permanently deleting... " -NoNewline -ForegroundColor Yellow
                    try {
                        $null = $mail.Delete()
                        Write-Host "DELETED" -ForegroundColor Green
                    } catch {
                        Write-Host "FAILED: $_" -ForegroundColor Red
                    }
                }
            }
        } else {
            $cleanCount++
        }
    }

    Write-Host ""
    Write-Host "---------------- Scan Summary ----------------" -ForegroundColor Cyan
    Write-Host "Total Inspected: $processedCount"
    Write-Host "Clean Messages:  $cleanCount" -ForegroundColor Green
    Write-Host "Spam Detected:   $spamCount" -ForegroundColor Red
    Write-Host "----------------------------------------------" -ForegroundColor Cyan
    Write-Host ""

    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($items) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($inbox) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($junkFolder) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($namespace) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook) | Out-Null
}

if ($Watch) {
    Write-Host "Running in Watch mode every $IntervalSeconds seconds. Press Ctrl+C to exit." -ForegroundColor Yellow
    while ($true) {
        Run-Scan
        Start-Sleep -Seconds $IntervalSeconds
    }
} else {
    Run-Scan
}

