<#
.SYNOPSIS
    mailcheck-cleaner.ps1 - Local Outlook Desktop Spam Cleaner
    Directly automates Outlook MAPI without any cloud or Azure setup.
#>

[CmdletBinding()]
param(
    [ValidateSet("DryRun", "MoveToJunk", "Delete")]
    [string]$Mode = "MoveToJunk",

    [int]$MaxMessages = 500,

    [switch]$IncludeRead = $false,

    [switch]$Watch = $false,

    [int]$IntervalSeconds = 60
)

# 1. SAFETY WHITELIST: These are NEVER flagged as spam
$WhitelistedDomains = @(
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

# 2. SPECIFIC SENDER DOMAINS TO PURGE
$BlockedSenderDomains = @(
    "proxymity.io",
    "506investorgroup.com",
    "beehiiv.com",
    "mail.beehiiv.com",
    "threadloom.news",
    "vesta.threadloom.news",
    "digital.metamail.com",
    "av.vc"
)

# 3. SPAM TOP-LEVEL DOMAINS
$BlockedTLDs = @(
    ".xyz", ".top", ".icu", ".buzz", ".click", ".shop",
    ".cfd", ".rest", ".quest", ".cam", ".sbs", ".monster",
    ".cyou", ".mom", ".beauty", ".skin", ".link"
)

# 4. SUSPICIOUS PHISHING SUBJECT PATTERNS
$SubjectPatterns = @(
    "(?i)invoice.*attached",
    "(?i)your order.*confirmed.*#\d{4,}",
    "(?i)account suspension notice",
    "(?i)urgent notification.*password expired",
    "(?i)bitcoin.*wallet.*transfer",
    "(?i)renewal confirmation.*subscription"
)

# 5. BRAND SPOOFING RULES
$SpoofRules = @(
    @{ Brand = "Geek Squad"; Pattern = "(?i)geek[- ]?squad"; AllowedDomains = @("bestbuy.com", "geeksquad.com") },
    @{ Brand = "McAfee";     Pattern = "(?i)mcafee";        AllowedDomains = @("mcafee.com") },
    @{ Brand = "Norton";     Pattern = "(?i)norton";        AllowedDomains = @("norton.com", "geneseego.com", "lifelock.com") },
    @{ Brand = "PayPal";     Pattern = "(?i)paypal";        AllowedDomains = @("paypal.com", "intl.paypal.com") },
    @{ Brand = "Amazon";     Pattern = "(?i)amazon( customer service| order| support)?"; AllowedDomains = @("amazon.com", "amazon.co.uk", "amazon.ca") }
)

function Get-SenderSmtp($mailItem) {
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

function Check-Message($mailItem) {
    $reasons = [System.Collections.Generic.List[string]]::new()

    $addr = (Get-SenderSmtp $mailItem)
    if ($addr) { $addr = $addr.Trim().ToLower() } else { $addr = "" }

    $name = $mailItem.SenderName
    if (-not $name) { $name = "" }

    $subj = $mailItem.Subject
    if (-not $subj) { $subj = "(No Subject)" }

    $domain = ""
    if ($addr -match "@([^@]+)$") {
        $domain = $matches[1].ToLower()
    }

    # STEP 0: WHITELIST (Immediate pass)
    foreach ($wl in $WhitelistedDomains) {
        if ($domain -eq $wl -or $domain.EndsWith(".$wl")) {
            return @{ IsSpam = $false; Reasons = @(); Sender = "$name <$addr>"; Subject = $subj; Date = $mailItem.ReceivedTime }
        }
    }

    # STEP 1: BLOCKED DOMAINS
    foreach ($bd in $BlockedSenderDomains) {
        if ($domain -eq $bd -or $domain.EndsWith(".$bd")) {
            $reasons.Add("Blocked sender domain: $domain")
            break
        }
    }

    # STEP 2: BLOCKED TLDS
    foreach ($tld in $BlockedTLDs) {
        if ($addr.EndsWith($tld.ToLower())) {
            $reasons.Add("Blocked TLD '$tld' in sender: $addr")
            break
        }
    }

    # STEP 3: SUBJECT PATTERNS
    foreach ($pat in $SubjectPatterns) {
        if ($subj -match $pat) {
            $reasons.Add("Subject pattern match: $pat")
            break
        }
    }

    # STEP 4: SPOOFING
    foreach ($rule in $SpoofRules) {
        if ($name -match $rule.Pattern) {
            $ok = $false
            foreach ($allowed in $rule.AllowedDomains) {
                if ($domain -eq $allowed -or $domain.EndsWith(".$allowed")) {
                    $ok = $true
                    break
                }
            }
            if (-not $ok) {
                $reasons.Add("Impersonation: Display name '$name' mimics '$($rule.Brand)' from '$domain'")
            }
        }
    }

    # STEP 5: SPAMMER DOMAIN PATTERN (-----mail.)
    if ($domain -match "-----mail\.") {
        $reasons.Add("Known spam domain pattern: $domain")
    }

    return @{
        IsSpam  = ($reasons.Count -gt 0)
        Reasons = $reasons
        Sender  = "$name <$addr>"
        Subject = $subj
        Date    = $mailItem.ReceivedTime
    }
}

function Execute-Clean {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "   mailcheck Cleaner - Running" -ForegroundColor Cyan
    Write-Host "   Mode: $Mode | Max: $MaxMessages | Unread Only: $(-not $IncludeRead)" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan

    $outlook = New-Object -ComObject Outlook.Application
    $ns = $outlook.GetNamespace("MAPI")
    $inbox = $ns.GetDefaultFolder(6)   # olFolderInbox
    $junk = $ns.GetDefaultFolder(23)   # olFolderJunk

    # First filter unread, then sort newest first
    $items = $inbox.Items
    if (-not $IncludeRead) {
        $items = $items.Restrict("[UnRead] = True")
    }
    $items.Sort("[ReceivedTime]", $true)

    $count = [Math]::Min($MaxMessages, $items.Count)
    Write-Host "Evaluating top $count messages..." -ForegroundColor Gray

    # Snapshot items to avoid mutation shifting
    $toProcess = [System.Collections.Generic.List[object]]::new()
    for ($i = 1; $i -le $count; $i++) {
        $item = $items.Item($i)
        if ($item -and $item.MessageClass -eq "IPM.Note") {
            $toProcess.Add($item)
        }
    }

    $spamCount = 0
    $cleanCount = 0

    foreach ($m in $toProcess) {
        $eval = Check-Message $m
        if ($eval.IsSpam) {
            $spamCount++
            Write-Host ""
            Write-Host "[!] SPAM DETECTED" -ForegroundColor Red
            Write-Host "    From:    $($eval.Sender)" -ForegroundColor Yellow
            Write-Host "    Subject: $($eval.Subject)" -ForegroundColor White
            Write-Host "    Date:    $($eval.Date)" -ForegroundColor DarkGray
            foreach ($r in $eval.Reasons) {
                Write-Host "    Reason:  $r" -ForegroundColor Magenta
            }

            if ($Mode -eq "DryRun") {
                Write-Host "    Action:  [DRY RUN] Would move to Junk Email" -ForegroundColor Cyan
            } elseif ($Mode -eq "MoveToJunk") {
                Write-Host "    Action:  Moving to Junk Email... " -NoNewline -ForegroundColor Yellow
                try {
                    $null = $m.Move($junk)
                    Write-Host "MOVED" -ForegroundColor Green
                } catch {
                    Write-Host "FAILED: $_" -ForegroundColor Red
                }
            } elseif ($Mode -eq "Delete") {
                Write-Host "    Action:  Permanently deleting... " -NoNewline -ForegroundColor Yellow
                try {
                    $null = $m.Delete()
                    Write-Host "DELETED" -ForegroundColor Green
                } catch {
                    Write-Host "FAILED: $_" -ForegroundColor Red
                }
            }
        } else {
            $cleanCount++
        }
    }

    Write-Host ""
    Write-Host "---------------- Summary ----------------" -ForegroundColor Cyan
    Write-Host "Total Inspected: $($toProcess.Count)"
    Write-Host "Clean (Kept):    $cleanCount" -ForegroundColor Green
    Write-Host "Spam (Moved):    $spamCount" -ForegroundColor Red
    Write-Host "-----------------------------------------" -ForegroundColor Cyan
    Write-Host ""

    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($items) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($inbox) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($junk) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ns) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook) | Out-Null
}

if ($Watch) {
    Write-Host "Watching inbox every $IntervalSeconds seconds. Press Ctrl+C to stop." -ForegroundColor Yellow
    while ($true) {
        Execute-Clean
        Start-Sleep -Seconds $IntervalSeconds
    }
} else {
    Execute-Clean
}

