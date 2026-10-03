#Requires -Version 5.1
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$script:RulesPath = if ($PSScriptRoot) { Join-Path $PSScriptRoot "rules.json" } else { Join-Path (Get-Location).Path "rules.json" }

function Load-Rules {
    if (Test-Path $script:RulesPath) {
        try {
            $json = Get-Content $script:RulesPath -Raw | ConvertFrom-Json
            return $json
        } catch {}
    }
    return [PSCustomObject]@{
        whitelisted_domains = @("linkedin.com", "schwab.com", "costco.com", "discover.com", "farmers.com", "interactivebrokers.com", "robinhood.com", "apple.com", "icloud.com")
        blocked_domains = @("proxymity.io", "506investorgroup.com", "beehiiv.com", "mail.beehiiv.com", "threadloom.news", "vesta.threadloom.news", "digital.metamail.com", "av.vc")
        blocked_tlds = @(".xyz", ".top", ".icu", ".buzz", ".click", ".shop", ".cfd", ".rest", ".cam")
        blocked_subject_patterns = @("(?i)invoice.*attached", "(?i)your order.*confirmed.*#\d{4,}", "(?i)account suspension notice")
    }
}

function Save-Rules($rulesObj) {
    $jsonText = $rulesObj | ConvertTo-Json -Depth 5
    Set-Content -Path $script:RulesPath -Value $jsonText -Encoding UTF8
}

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Mailcheck - Anti-Spam Inbox Manager" Height="780" Width="1200" MinHeight="650" MinWidth="950"
        WindowStartupLocation="CenterScreen"
        Background="#181825" Foreground="#CDD6F4" FontFamily="Segoe UI" FontSize="15">
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Background" Value="#313244"/>
            <Setter Property="Foreground" Value="#CDD6F4"/>
            <Setter Property="BorderBrush" Value="#45475A"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="12,7"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Margin" Value="4"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="4">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#45475A"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter Property="Background" Value="#585B70"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="#1E1E2E"/>
            <Setter Property="Foreground" Value="#CDD6F4"/>
            <Setter Property="BorderBrush" Value="#45475A"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="CaretBrush" Value="#CDD6F4"/>
        </Style>
        <Style TargetType="TabItem">
            <Setter Property="Foreground" Value="#A6ADC8"/>
            <Setter Property="Padding" Value="18,10"/>
            <Setter Property="FontSize" Value="15"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TabItem">
                        <Border Name="Border" Background="#1E1E2E" BorderBrush="#313244" BorderThickness="0,0,1,1" CornerRadius="4,4,0,0" Margin="0,0,2,0">
                            <ContentPresenter ContentSource="Header" Margin="12,6"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#313244"/>
                                <Setter Property="Foreground" Value="#89B4FA"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="DataGrid">
            <Setter Property="Background" Value="#1E1E2E"/>
            <Setter Property="Foreground" Value="#CDD6F4"/>
            <Setter Property="BorderBrush" Value="#313244"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
            <Setter Property="HorizontalGridLinesBrush" Value="#313244"/>
            <Setter Property="SelectionMode" Value="Extended"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="CanUserAddRows" Value="False"/>
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="RowHeight" Value="34"/>
        </Style>
        <Style TargetType="DataGridRow">
            <Setter Property="Background" Value="#1E1E2E"/>
            <Setter Property="Foreground" Value="#CDD6F4"/>
            <Setter Property="BorderThickness" Value="0,0,0,1"/>
            <Setter Property="BorderBrush" Value="#313244"/>
            <Style.Triggers>
                <DataTrigger Binding="{Binding Status}" Value="SPAM">
                    <Setter Property="Background" Value="#361D26"/>
                    <Setter Property="Foreground" Value="#F8B4C4"/>
                </DataTrigger>
                <DataTrigger Binding="{Binding Status}" Value="SAFE">
                    <Setter Property="Background" Value="#193324"/>
                    <Setter Property="Foreground" Value="#B5EDB7"/>
                </DataTrigger>
                <DataTrigger Binding="{Binding Status}" Value="REVIEW">
                    <Setter Property="Background" Value="#2A2624"/>
                    <Setter Property="Foreground" Value="#FDE2B8"/>
                </DataTrigger>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#45475A"/>
                </Trigger>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#585B70"/>
                    <Setter Property="Foreground" Value="#FFFFFF"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="#252538"/>
            <Setter Property="Foreground" Value="#89B4FA"/>
            <Setter Property="Padding" Value="10,8"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
            <Setter Property="BorderBrush" Value="#313244"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="FontSize" Value="14"/>
        </Style>
        <Style TargetType="DataGridCell">
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridCell">
                        <Border Background="{TemplateBinding Background}" BorderThickness="0">
                            <ContentPresenter VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid Margin="12">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Top Header -->
        <Border Grid.Row="0" Background="#1E1E2E" Padding="14" CornerRadius="6" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Orientation="Vertical">
                    <TextBlock Text="Mailcheck - Spam &amp; Sender Manager" FontSize="22" FontWeight="Bold" Foreground="#89B4FA"/>
                    <TextBlock Name="TxtAccountInfo" Text="Connected to Outlook Desktop" FontSize="13" Foreground="#A6ADC8" Margin="0,4,0,0"/>
                </StackPanel>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="Scan Count:" VerticalAlignment="Center" Foreground="#A6ADC8" FontSize="14" Margin="0,0,8,0"/>
                    <ComboBox Name="CmbScanCount" Width="95" FontSize="14" Margin="0,0,10,0" SelectedIndex="1">
                        <ComboBoxItem Content="100"/>
                        <ComboBoxItem Content="250"/>
                        <ComboBoxItem Content="500"/>
                        <ComboBoxItem Content="1000"/>
                    </ComboBox>
                    <Button Name="BtnRefresh" Content="Scan Inbox" Background="#89B4FA" Foreground="#11111B" FontWeight="Bold" FontSize="14" Padding="16,8"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Main Content Tabs -->
        <TabControl Grid.Row="1" Background="#1E1E2E" BorderBrush="#313244">
            <!-- TAB 1: Senders List -->
            <TabItem Header="Inbox Senders">
                <Grid Margin="8">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <!-- Filter Bar -->
                    <Grid Grid.Row="0" Margin="0,0,0,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBox Name="TxtFilter" Text="" Margin="0,0,8,0" Height="36" FontSize="14" VerticalContentAlignment="Center" Tag="Search domain, sender, or subject..."/>
                        <StackPanel Grid.Column="1" Orientation="Horizontal">
                            <Button Name="BtnSelectAllSpam" Content="Select All [SPAM]" Background="#45475A" FontSize="13" Padding="12,7"/>
                            <Button Name="BtnClearSelection" Content="Deselect All" Background="#45475A" FontSize="13" Padding="12,7"/>
                        </StackPanel>
                    </Grid>

                    <!-- Senders Grid -->
                    <DataGrid Name="GridSenders" Grid.Row="1">
                        <DataGrid.Columns>
                            <DataGridCheckBoxColumn Binding="{Binding IsSelected, UpdateSourceTrigger=PropertyChanged}" Width="50">
                                <DataGridCheckBoxColumn.HeaderTemplate>
                                    <DataTemplate>
                                        <TextBlock Text="Pick" HorizontalAlignment="Center" FontWeight="Bold"/>
                                    </DataTemplate>
                                </DataGridCheckBoxColumn.HeaderTemplate>
                            </DataGridCheckBoxColumn>
                            <DataGridTextColumn Header="Status" Binding="{Binding StatusText}" Width="95" IsReadOnly="True">
                                <DataGridTextColumn.ElementStyle>
                                    <Style TargetType="TextBlock">
                                        <Setter Property="FontWeight" Value="Bold"/>
                                        <Setter Property="HorizontalAlignment" Value="Center"/>
                                        <Style.Triggers>
                                            <DataTrigger Binding="{Binding Status}" Value="SPAM">
                                                <Setter Property="Foreground" Value="#F38BA8"/>
                                            </DataTrigger>
                                            <DataTrigger Binding="{Binding Status}" Value="SAFE">
                                                <Setter Property="Foreground" Value="#A6E3A1"/>
                                            </DataTrigger>
                                            <DataTrigger Binding="{Binding Status}" Value="REVIEW">
                                                <Setter Property="Foreground" Value="#FAB387"/>
                                            </DataTrigger>
                                        </Style.Triggers>
                                    </Style>
                                </DataGridTextColumn.ElementStyle>
                            </DataGridTextColumn>
                            <DataGridTextColumn Header="Count" Binding="{Binding Count}" Width="65" IsReadOnly="True"/>
                            <DataGridTextColumn Header="Sender Domain" Binding="{Binding Domain}" Width="190" IsReadOnly="True"/>
                            <DataGridTextColumn Header="Sender Name / Address" Binding="{Binding SenderDisplay}" Width="280" IsReadOnly="True"/>
                            <DataGridTextColumn Header="Latest Subject" Binding="{Binding LatestSubject}" Width="*" IsReadOnly="True"/>
                            <DataGridTextColumn Header="Date" Binding="{Binding LatestDateFormatted}" Width="150" IsReadOnly="True"/>
                        </DataGrid.Columns>
                    </DataGrid>

                    <!-- Action Bar -->
                    <Border Grid.Row="2" Background="#252538" Padding="10" CornerRadius="6" Margin="0,10,0,0">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                                <Button Name="BtnMarkSpam" Content="Mark as SPAM &amp; Block" Background="#F38BA8" Foreground="#11111B" FontWeight="Bold" FontSize="14" Padding="14,8"/>
                                <Button Name="BtnMarkSafe" Content="Mark as SAFE (Whitelist)" Background="#A6E3A1" Foreground="#11111B" FontWeight="Bold" FontSize="14" Padding="14,8"/>
                            </StackPanel>
                            <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                                <Button Name="BtnMoveToJunk" Content="Move Selected to Junk" Background="#FAB387" Foreground="#11111B" FontWeight="Bold" FontSize="14" Padding="14,8"/>
                                <Button Name="BtnRunSweep" Content="Sweep Entire Inbox" Background="#89B4FA" Foreground="#11111B" FontWeight="Bold" FontSize="14" Padding="14,8"/>
                            </StackPanel>
                        </Grid>
                    </Border>
                </Grid>
            </TabItem>

            <!-- TAB 2: Rules Editor -->
            <TabItem Header="Active Rules">
                <Grid Margin="12">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>

                    <!-- Blocked Domains Panel -->
                    <Border Grid.Column="0" Background="#252538" Padding="14" CornerRadius="6" Margin="0,0,8,0">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>
                            <TextBlock Text="Blocked Domains (Auto-Moved to Junk)" FontSize="15" FontWeight="Bold" Foreground="#F38BA8" Margin="0,0,0,10"/>
                            <ListBox Name="ListBlockedDomains" Grid.Row="1" FontSize="14" Background="#1E1E2E" Foreground="#CDD6F4" BorderBrush="#313244"/>
                            <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,10,0,0">
                                <TextBox Name="TxtNewBlocked" Width="220" Height="34" FontSize="14" VerticalContentAlignment="Center" Margin="0,0,8,0"/>
                                <Button Name="BtnAddBlocked" Content="Add" FontSize="13" Padding="12,6"/>
                                <Button Name="BtnRemoveBlocked" Content="Remove Selected" FontSize="13" Padding="12,6"/>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <!-- Whitelisted Domains Panel -->
                    <Border Grid.Column="1" Background="#252538" Padding="14" CornerRadius="6" Margin="8,0,0,0">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>
                            <TextBlock Text="Whitelisted Domains (Safe / Protected)" FontSize="15" FontWeight="Bold" Foreground="#A6E3A1" Margin="0,0,0,10"/>
                            <ListBox Name="ListWhitelistedDomains" Grid.Row="1" FontSize="14" Background="#1E1E2E" Foreground="#CDD6F4" BorderBrush="#313244"/>
                            <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,10,0,0">
                                <TextBox Name="TxtNewWhitelisted" Width="220" Height="34" FontSize="14" VerticalContentAlignment="Center" Margin="0,0,8,0"/>
                                <Button Name="BtnAddWhitelisted" Content="Add" FontSize="13" Padding="12,6"/>
                                <Button Name="BtnRemoveWhitelisted" Content="Remove Selected" FontSize="13" Padding="12,6"/>
                            </StackPanel>
                        </Grid>
                    </Border>
                </Grid>
            </TabItem>
        </TabControl>

        <!-- Status Bar -->
        <Border Grid.Row="3" Background="#1E1E2E" Padding="10,6" CornerRadius="4" Margin="0,8,0,0">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock Name="TxtStatus" Text="Ready" Foreground="#A6ADC8" FontSize="13"/>
                <TextBlock Name="TxtStats" Grid.Column="1" Text="" Foreground="#89B4FA" FontSize="13" FontWeight="SemiBold"/>
            </Grid>
        </Border>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [System.Windows.Markup.XamlReader]::Load($reader)

# Element References
$btnRefresh = $window.FindName("BtnRefresh")
$cmbScanCount = $window.FindName("CmbScanCount")
$txtFilter = $window.FindName("TxtFilter")
$gridSenders = $window.FindName("GridSenders")
$btnMarkSpam = $window.FindName("BtnMarkSpam")
$btnMarkSafe = $window.FindName("BtnMarkSafe")
$btnMoveToJunk = $window.FindName("BtnMoveToJunk")
$btnRunSweep = $window.FindName("BtnRunSweep")
$btnSelectAllSpam = $window.FindName("BtnSelectAllSpam")
$btnClearSelection = $window.FindName("BtnClearSelection")
$txtAccountInfo = $window.FindName("TxtAccountInfo")
$txtStatus = $window.FindName("TxtStatus")
$txtStats = $window.FindName("TxtStats")

$listBlockedDomains = $window.FindName("ListBlockedDomains")
$txtNewBlocked = $window.FindName("TxtNewBlocked")
$btnAddBlocked = $window.FindName("BtnAddBlocked")
$btnRemoveBlocked = $window.FindName("BtnRemoveBlocked")

$listWhitelistedDomains = $window.FindName("ListWhitelistedDomains")
$txtNewWhitelisted = $window.FindName("TxtNewWhitelisted")
$btnAddWhitelisted = $window.FindName("BtnAddWhitelisted")
$btnRemoveWhitelisted = $window.FindName("BtnRemoveWhitelisted")

# Data Models
$script:CurrentRules = Load-Rules
$script:AllSenders = [System.Collections.ObjectModel.ObservableCollection[PSCustomObject]]::new()
$script:OutlookApp = $null

function Init-RulesLists {
    $listBlockedDomains.Items.Clear()
    foreach ($d in ($script:CurrentRules.blocked_domains | Sort-Object)) {
        $listBlockedDomains.Items.Add($d) | Out-Null
    }
    $listWhitelistedDomains.Items.Clear()
    foreach ($w in ($script:CurrentRules.whitelisted_domains | Sort-Object)) {
        $listWhitelistedDomains.Items.Add($w) | Out-Null
    }
}

function Get-DomainClassification($domain, $senderAddress, $subject) {
    if (-not $domain) { return "REVIEW" }

    foreach ($wl in $script:CurrentRules.whitelisted_domains) {
        if ($domain -eq $wl -or $domain.EndsWith(".$wl")) {
            return "SAFE"
        }
    }

    foreach ($bd in $script:CurrentRules.blocked_domains) {
        if ($domain -eq $bd -or $domain.EndsWith(".$bd")) {
            return "SPAM"
        }
    }

    foreach ($tld in $script:CurrentRules.blocked_tlds) {
        if ($senderAddress.EndsWith($tld.ToLower())) {
            return "SPAM"
        }
    }

    if ($domain -match "-----mail\.") {
        return "SPAM"
    }

    return "REVIEW"
}

function Get-OutlookSession {
    if (-not $script:OutlookApp) {
        try {
            $script:OutlookApp = [System.Runtime.InteropServices.Marshal]::GetActiveObject("Outlook.Application")
        } catch {
            try {
                $script:OutlookApp = New-Object -ComObject Outlook.Application
            } catch {
                Get-CimInstance Win32_Process -Filter "Name = 'OUTLOOK.EXE'" | Where-Object { $_.CommandLine -like "*-Embedding*" } | ForEach-Object {
                    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                }
                Start-Sleep -Milliseconds 500
                $script:OutlookApp = New-Object -ComObject Outlook.Application
            }
        }
    }
    $ns = $script:OutlookApp.GetNamespace("MAPI")
    try {
        $ns.Logon("", "", $false, $false)
    } catch {}
    return $ns
}

function Refresh-Inbox {
    $txtStatus.Text = "Scanning Outlook Inbox..."
    $btnRefresh.IsEnabled = $false

    try {
        $ns = Get-OutlookSession
        $inbox = $ns.GetDefaultFolder(6)
        $account = $ns.Accounts | Select-Object -First 1
        if ($account) {
            $accName = if ($account.SmtpAddress) { $account.SmtpAddress } else { $account.DisplayName }
            $txtAccountInfo.Text = "Account: $accName | Total Unread in Inbox: $($inbox.UnReadItemCount)"
        }

        $scanMax = 100
        if ($cmbScanCount.SelectedItem -and $cmbScanCount.SelectedItem.Content) {
            $scanMax = [int]$cmbScanCount.SelectedItem.Content
        } elseif ($cmbScanCount.Text) {
            $scanMax = [int]$cmbScanCount.Text
        }
        $items = $inbox.Items.Restrict("[UnRead] = True")
        $items.Sort("[ReceivedTime]", $true)

        $count = [Math]::Min($scanMax, $items.Count)
        $senderMap = @{}

        for ($i = 1; $i -le $count; $i++) {
            $mail = $items.Item($i)
            if ($mail -and $mail.MessageClass -eq "IPM.Note") {
                $addr = $mail.SenderEmailAddress
                if ($mail.SenderEmailType -eq "SMTP" -and $mail.SenderEmailAddress) {
                    $addr = $mail.SenderEmailAddress
                } elseif ($mail.Sender) {
                    try {
                        $ex = $mail.Sender.GetExchangeUser()
                        if ($ex -and $ex.PrimarySmtpAddress) { $addr = $ex.PrimarySmtpAddress }
                    } catch {}
                }

                if (-not $addr) { $addr = "Unknown" }
                $addr = $addr.Trim().ToLower()

                $name = $mail.SenderName
                if (-not $name) { $name = $addr }

                $domain = ""
                if ($addr -match "@([^@]+)$") {
                    $domain = $matches[1].ToLower()
                }

                $key = if ($domain) { $domain } else { $addr }

                if (-not $senderMap.ContainsKey($key)) {
                    $senderMap[$key] = [PSCustomObject]@{
                        Key          = $key
                        Domain       = $domain
                        SenderDisplay = "$name <$addr>"
                        Count        = 1
                        LatestSubject = $mail.Subject
                        LatestDate   = $mail.ReceivedTime
                        IsSelected   = $false
                    }
                } else {
                    $senderMap[$key].Count++
                }
            }
        }

        $script:AllSenders.Clear()
        foreach ($k in ($senderMap.Keys | Sort-Object { $senderMap[$_].Count } -Descending)) {
            $row = $senderMap[$k]
            $cls = Get-DomainClassification $row.Domain $row.SenderDisplay $row.LatestSubject
            $statusBadge = switch ($cls) {
                "SPAM" { "[SPAM]" }
                "SAFE" { "[SAFE]" }
                default { "[REVIEW]" }
            }

            $script:AllSenders.Add([PSCustomObject]@{
                IsSelected          = ($cls -eq "SPAM") # auto-select spam by default
                Status              = $cls
                StatusText          = $statusBadge
                Count               = $row.Count
                Domain              = $row.Domain
                SenderDisplay       = $row.SenderDisplay
                LatestSubject       = $row.LatestSubject
                LatestDateFormatted = $row.LatestDate.ToString("MM/dd/yyyy HH:mm")
            })
        }

        $gridSenders.ItemsSource = $script:AllSenders
        $txtStatus.Text = "Scan finished: $($senderMap.Count) unique senders evaluated from top $count messages."
        $txtStats.Text = "$($script:AllSenders.Count) Senders Loaded"
    } catch {
        $txtStatus.Text = "Error scanning Outlook: $_"
    } finally {
        $btnRefresh.IsEnabled = $true
    }
}

# Search/Filter
$txtFilter.Add_TextChanged({
    $q = $txtFilter.Text.Trim().ToLower()
    if ([string]::IsNullOrWhiteSpace($q)) {
        $gridSenders.ItemsSource = $script:AllSenders
    } else {
        $filtered = $script:AllSenders | Where-Object {
            $_.Domain.ToLower().Contains($q) -or
            $_.SenderDisplay.ToLower().Contains($q) -or
            $_.LatestSubject.ToLower().Contains($q) -or
            $_.StatusText.ToLower().Contains($q)
        }
        $gridSenders.ItemsSource = $filtered
    }
})

# Select All Spam Button
$btnSelectAllSpam.Add_Click({
    foreach ($item in $gridSenders.ItemsSource) {
        if ($item.Status -eq "SPAM") { $item.IsSelected = $true }
    }
    $gridSenders.Items.Refresh()
})

# Deselect All Button
$btnClearSelection.Add_Click({
    foreach ($item in $gridSenders.ItemsSource) {
        $item.IsSelected = $false
    }
    $gridSenders.Items.Refresh()
})

# Mark as SPAM Action
$btnMarkSpam.Add_Click({
    $selected = @($gridSenders.ItemsSource | Where-Object { $_.IsSelected })
    if ($selected.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please check the box next to at least one sender.", "No Selection", "OK", "Information")
        return
    }

    $added = 0
    foreach ($item in $selected) {
        $dom = $item.Domain
        if ($dom -and -not ($script:CurrentRules.blocked_domains -contains $dom)) {
            $script:CurrentRules.blocked_domains += $dom
            $added++
        }
        # remove from whitelist if present
        $script:CurrentRules.whitelisted_domains = @($script:CurrentRules.whitelisted_domains | Where-Object { $_ -ne $dom })
    }

    Save-Rules $script:CurrentRules
    Init-RulesLists

    $resp = [System.Windows.MessageBox]::Show("Added $added domain(s) to Blocked list in rules.json!`n`nWould you like to move their messages to Junk Email right now?", "Rule Saved", "YesNo", "Question")
    if ($resp -eq "Yes") {
        $btnMoveToJunk.RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Button]::ClickEvent)))
    } else {
        Refresh-Inbox
    }
})

# Mark as SAFE Action
$btnMarkSafe.Add_Click({
    $selected = @($gridSenders.ItemsSource | Where-Object { $_.IsSelected })
    if ($selected.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please check the box next to at least one sender.", "No Selection", "OK", "Information")
        return
    }

    $added = 0
    foreach ($item in $selected) {
        $dom = $item.Domain
        if ($dom -and -not ($script:CurrentRules.whitelisted_domains -contains $dom)) {
            $script:CurrentRules.whitelisted_domains += $dom
            $added++
        }
        # remove from blocked if present
        $script:CurrentRules.blocked_domains = @($script:CurrentRules.blocked_domains | Where-Object { $_ -ne $dom })
    }

    Save-Rules $script:CurrentRules
    Init-RulesLists

    [System.Windows.MessageBox]::Show("Added $added domain(s) to Whitelist in rules.json!`nThey will be safely preserved.", "Whitelist Saved", "OK", "Information")
    Refresh-Inbox
})

# Move Selected to Junk
$btnMoveToJunk.Add_Click({
    $selected = @($gridSenders.ItemsSource | Where-Object { $_.IsSelected })
    if ($selected.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please select at least one sender to move.", "No Selection", "OK", "Information")
        return
    }

    $targetDomains = @($selected | ForEach-Object { $_.Domain })

    $txtStatus.Text = "Moving messages to Junk Email folder..."
    $btnMoveToJunk.IsEnabled = $false

    try {
        $ns = Get-OutlookSession
        $inbox = $ns.GetDefaultFolder(6)
        $junk = $ns.GetDefaultFolder(23)

        $items = $inbox.Items.Restrict("[UnRead] = True")
        $items.Sort("[ReceivedTime]", $true)

        $scanMax = 100
        if ($cmbScanCount.SelectedItem -and $cmbScanCount.SelectedItem.Content) {
            $scanMax = [int]$cmbScanCount.SelectedItem.Content
        } elseif ($cmbScanCount.Text) {
            $scanMax = [int]$cmbScanCount.Text
        }
        $count = [Math]::Min($scanMax, $items.Count)
        $toMove = [System.Collections.Generic.List[object]]::new()

        for ($i = 1; $i -le $count; $i++) {
            $m = $items.Item($i)
            if ($m -and $m.MessageClass -eq "IPM.Note") {
                $addr = $m.SenderEmailAddress
                if ($addr -match "@([^@]+)$") {
                    $d = $matches[1].ToLower()
                    if ($targetDomains -contains $d) {
                        $toMove.Add($m)
                    }
                }
            }
        }

        $moved = 0
        foreach ($mail in $toMove) {
            try {
                $mail.Move($junk) | Out-Null
                $moved++
            } catch {}
        }

        $txtStatus.Text = "Successfully moved $moved message(s) to Junk Email folder!"
        [System.Windows.MessageBox]::Show("Cleaned $moved message(s) and moved them to Junk Email.", "Sweep Finished", "OK", "Information")
        Refresh-Inbox
    } catch {
        $txtStatus.Text = "Error moving messages: $_"
    } finally {
        $btnMoveToJunk.IsEnabled = $true
    }
})

# Sweep Entire Inbox Button
$btnRunSweep.Add_Click({
    $confirm = [System.Windows.MessageBox]::Show("This will scan the top 500 unread messages in your inbox and move all messages matching your Blocked list to Junk.`n`nProceed?", "Run Sweep", "YesNo", "Question")
    if ($confirm -ne "Yes") { return }

    $txtStatus.Text = "Running full sweep against inbox..."
    try {
        $ns = Get-OutlookSession
        $inbox = $ns.GetDefaultFolder(6)
        $junk = $ns.GetDefaultFolder(23)

        $items = $inbox.Items.Restrict("[UnRead] = True")
        $items.Sort("[ReceivedTime]", $true)

        $count = [Math]::Min(500, $items.Count)
        $toMove = [System.Collections.Generic.List[object]]::new()

        for ($i = 1; $i -le $count; $i++) {
            $m = $items.Item($i)
            if ($m -and $m.MessageClass -eq "IPM.Note") {
                $addr = $m.SenderEmailAddress
                if ($addr -match "@([^@]+)$") {
                    $d = $matches[1].ToLower()
                    $isWhitelisted = $false
                    foreach ($wl in $script:CurrentRules.whitelisted_domains) {
                        if ($d -eq $wl -or $d.EndsWith(".$wl")) { $isWhitelisted = $true; break }
                    }
                    if (-not $isWhitelisted) {
                        $isBlocked = $false
                        foreach ($bd in $script:CurrentRules.blocked_domains) {
                            if ($d -eq $bd -or $d.EndsWith(".$bd")) { $isBlocked = $true; break }
                        }
                        if ($isBlocked) { $toMove.Add($m) }
                    }
                }
            }
        }

        $moved = 0
        foreach ($mail in $toMove) {
            try {
                $mail.Move($junk) | Out-Null
                $moved++
            } catch {}
        }

        [System.Windows.MessageBox]::Show("Sweep complete! Moved $moved spam message(s) to Junk Email.", "Sweep Done", "OK", "Information")
        Refresh-Inbox
    } catch {
        $txtStatus.Text = "Error during sweep: $_"
    }
})

# Rule Editor Handlers
$btnAddBlocked.Add_Click({
    $dom = $txtNewBlocked.Text.Trim().ToLower()
    if ($dom -and -not ($script:CurrentRules.blocked_domains -contains $dom)) {
        $script:CurrentRules.blocked_domains += $dom
        $script:CurrentRules.whitelisted_domains = @($script:CurrentRules.whitelisted_domains | Where-Object { $_ -ne $dom })
        Save-Rules $script:CurrentRules
        Init-RulesLists
        $txtNewBlocked.Clear()
    }
})

$btnRemoveBlocked.Add_Click({
    $sel = $listBlockedDomains.SelectedItem
    if ($sel) {
        $script:CurrentRules.blocked_domains = @($script:CurrentRules.blocked_domains | Where-Object { $_ -ne $sel })
        Save-Rules $script:CurrentRules
        Init-RulesLists
    }
})

$btnAddWhitelisted.Add_Click({
    $dom = $txtNewWhitelisted.Text.Trim().ToLower()
    if ($dom -and -not ($script:CurrentRules.whitelisted_domains -contains $dom)) {
        $script:CurrentRules.whitelisted_domains += $dom
        $script:CurrentRules.blocked_domains = @($script:CurrentRules.blocked_domains | Where-Object { $_ -ne $dom })
        Save-Rules $script:CurrentRules
        Init-RulesLists
        $txtNewWhitelisted.Clear()
    }
})

$btnRemoveWhitelisted.Add_Click({
    $sel = $listWhitelistedDomains.SelectedItem
    if ($sel) {
        $script:CurrentRules.whitelisted_domains = @($script:CurrentRules.whitelisted_domains | Where-Object { $_ -ne $sel })
        Save-Rules $script:CurrentRules
        Init-RulesLists
    }
})

$btnRefresh.Add_Click({ Refresh-Inbox })

# Window Load
$window.Add_Loaded({
    Init-RulesLists
    $window.Dispatcher.BeginInvoke([Action]{
        Refresh-Inbox
    }, [System.Windows.Threading.DispatcherPriority]::Background)
})

[void]$window.ShowDialog()
