param(
    [Parameter(Mandatory = $true)]
    [string]$ApiUrl,

    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(Mandatory = $true)]
    [string]$EndpointId
)

$ErrorActionPreference = "Stop"

$services = Get-CimInstance Win32_Service | ForEach-Object {
    [PSCustomObject]@{
        service_name = $_.Name
        display_name = $_.DisplayName
        status       = $_.State
        startup_type = $_.StartMode
        executable   = $_.PathName
        command_line = $_.PathName
        username     = $_.StartName
        pid          = if ($_.ProcessId -gt 0) { [int]$_.ProcessId } else { $null }
    }
}

$payload = @{
    endpoint_id = $EndpointId
    services    = @($services)
} | ConvertTo-Json -Depth 5

$headers = @{
    "X-API-Key" = $ApiKey
    "Content-Type" = "application/json"
}

$response = Invoke-RestMethod `
    -Uri "$ApiUrl/client/endpoints/services" `
    -Method Post `
    -Headers $headers `
    -Body $payload

$response | ConvertTo-Json -Depth 5
