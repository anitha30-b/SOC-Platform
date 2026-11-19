param(
    [Parameter(Mandatory = $true)]
    [string]$ApiUrl,

    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(Mandatory = $true)]
    [string]$EndpointId
)

$ErrorActionPreference = "Stop"

Write-Host "Collecting Windows endpoint identity..."

$computer = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$bios = Get-CimInstance Win32_BIOS

$networkAdapter = Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4Address -and
        $_.NetAdapter.Status -eq "Up" -and
        $_.NetAdapter.HardwareInterface
    } |
    Select-Object -First 1

$ipAddress = if ($networkAdapter) {
    $networkAdapter.IPv4Address.IPAddress
} else {
    $null
}

$macAddress = if ($networkAdapter) {
    $networkAdapter.NetAdapter.MacAddress
} else {
    $null
}

$payload = @{
    endpoint_id = $EndpointId
    agent_id    = if ($bios.SerialNumber) {
        $bios.SerialNumber.Trim()
    } else {
        $EndpointId
    }
    hostname    = $computer.Name
    ip_address  = $ipAddress
    mac_address = $macAddress
    os_name     = $os.Caption
    os_version  = $os.Version
    device_type = "server"
    status      = "ONLINE"
} | ConvertTo-Json -Depth 5

$headers = @{
    "X-API-Key" = $ApiKey
    "Content-Type" = "application/json"
}

Write-Host "Registering Windows endpoint..."

$response = Invoke-RestMethod `
    -Uri "$($ApiUrl.TrimEnd('/'))/client/endpoints/register" `
    -Method Post `
    -Headers $headers `
    -Body $payload

Write-Host "Windows endpoint registration successful:"
$response | ConvertTo-Json -Depth 5
