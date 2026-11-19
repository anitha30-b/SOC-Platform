param(
    [Parameter(Mandatory = $true)]
    [string]$ApiUrl,

    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(Mandatory = $true)]
    [string]$EndpointId
)

$ErrorActionPreference = "Stop"

Write-Host "Collecting Windows System Hardening checks..."

$controls = @()

# Windows Defender Antivirus
$defender = Get-MpComputerStatus

$defenderOk = (
    $defender.AMServiceEnabled -and
    $defender.AntivirusEnabled -and
    $defender.RealTimeProtectionEnabled -and
    $defender.BehaviorMonitorEnabled -and
    $defender.IoavProtectionEnabled -and
    $defender.AntispywareEnabled
)

$controls += [PSCustomObject]@{
    control_id      = "windows-defender-antivirus"
    control_name    = "Windows Defender Antivirus"
    category        = "Endpoint Protection"
    status          = if ($defenderOk) { "PASS" } else { "FAIL" }
    observed_value  = "AMServiceEnabled=$($defender.AMServiceEnabled); AntivirusEnabled=$($defender.AntivirusEnabled); RealTimeProtectionEnabled=$($defender.RealTimeProtectionEnabled); BehaviorMonitorEnabled=$($defender.BehaviorMonitorEnabled); IoavProtectionEnabled=$($defender.IoavProtectionEnabled); AntispywareEnabled=$($defender.AntispywareEnabled)"
    details         = "Windows Defender Antivirus protection state."
}

# Windows Firewall profiles
$firewallProfiles = @(Get-NetFirewallProfile)

foreach ($profile in $firewallProfiles) {
    $controls += [PSCustomObject]@{
        control_id      = "windows-firewall-profile-$($profile.Name.ToLower())"
        control_name    = "Windows Firewall - $($profile.Name) Profile"
        category        = "Network Protection"
        status          = if ($profile.Enabled) { "PASS" } else { "FAIL" }
        observed_value  = "Enabled=$($profile.Enabled); DefaultInboundAction=$($profile.DefaultInboundAction); DefaultOutboundAction=$($profile.DefaultOutboundAction)"
        details         = "Windows Firewall profile configuration."
    }
}

# User Account Control
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$enableLua = Get-ItemPropertyValue -Path $uacPath -Name "EnableLUA"
$consentPrompt = Get-ItemPropertyValue -Path $uacPath -Name "ConsentPromptBehaviorAdmin"
$secureDesktop = Get-ItemPropertyValue -Path $uacPath -Name "PromptOnSecureDesktop"

$uacOk = (
    $enableLua -eq 1 -and
    $secureDesktop -eq 1
)

$controls += [PSCustomObject]@{
    control_id      = "windows-uac"
    control_name    = "User Account Control"
    category        = "Access Control"
    status          = if ($uacOk) { "PASS" } else { "FAIL" }
    observed_value  = "EnableLUA=$enableLua; ConsentPromptBehaviorAdmin=$consentPrompt; PromptOnSecureDesktop=$secureDesktop"
    details         = "User Account Control configuration."
}

# Remote Desktop
$rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$denyRdp = Get-ItemPropertyValue -Path $rdpPath -Name "fDenyTSConnections"

$controls += [PSCustomObject]@{
    control_id      = "windows-rdp"
    control_name    = "Remote Desktop"
    category        = "Remote Access"
    status          = if ($denyRdp -eq 1) { "PASS" } else { "FAIL" }
    observed_value  = "fDenyTSConnections=$denyRdp"
    details         = "Remote Desktop is considered hardened when inbound RDP connections are disabled."
}

# Windows Update service
$wuauserv = Get-Service -Name "wuauserv"

$controls += [PSCustomObject]@{
    control_id      = "windows-update-service"
    control_name    = "Windows Update Service"
    category        = "Patch Management"
    status          = if ($wuauserv.Status -eq "Running") { "PASS" } else { "WARN" }
    observed_value  = "Status=$($wuauserv.Status); StartType=$($wuauserv.StartType)"
    details         = "Windows Update service state."
}

Write-Host "Collected controls:" $controls.Count

$payload = @{
    endpoint_id = $EndpointId
    controls    = $controls
} | ConvertTo-Json -Depth 8

Write-Host "Payload size:" $payload.Length "bytes"
Write-Host "Sending System Hardening data..."

$headers = @{
    "X-API-Key"    = $ApiKey
    "Content-Type" = "application/json"
}

$response = Invoke-RestMethod `
    -Uri "$ApiUrl/client/endpoints/system-hardening" `
    -Method Post `
    -Headers $headers `
    -Body $payload

Write-Host "System Hardening ingestion successful:"
$response | ConvertTo-Json -Depth 5
