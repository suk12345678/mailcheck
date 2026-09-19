$outlook = New-Object -ComObject Outlook.Application
$namespace = $outlook.GetNamespace("MAPI")
$inbox = $namespace.GetDefaultFolder(6)
$items = $inbox.Items.Restrict("[UnRead] = True")
$items.Sort("[ReceivedTime]", $true)

$sampleSize = [Math]::Min(200, $items.Count)
Write-Host "Analyzing top $sampleSize unread messages..." -ForegroundColor Cyan

$domains = @{}
$senders = @{}

for ($i = 1; $i -le $sampleSize; $i++) {
    $mail = $items.Item($i)
    if ($mail) {
        $addr = $mail.SenderEmailAddress
        if ($addr) {
            if ($senders.ContainsKey($addr)) {
                $senders[$addr]++
            } else {
                $senders[$addr] = 1
            }

            if ($addr -match "@([^@]+)$") {
                $d = $matches[1].ToLower()
                if ($domains.ContainsKey($d)) {
                    $domains[$d]++
                } else {
                    $domains[$d] = 1
                }
            }
        }
    }
}

Write-Host "`nTop Sender Domains in Unread Mail:" -ForegroundColor Yellow
$domains.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15 | Format-Table -Property @{Name="Domain";Expression={$_.Key}}, @{Name="Count";Expression={$_.Value}} -AutoSize

Write-Host "Top Specific Senders:" -ForegroundColor Yellow
$senders.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15 | Format-Table -Property @{Name="Sender";Expression={$_.Key}}, @{Name="Count";Expression={$_.Value}} -AutoSize

[System.Runtime.InteropServices.Marshal]::ReleaseComObject($items) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($inbox) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($namespace) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook) | Out-Null

