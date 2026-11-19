param(
    [Parameter(Mandatory = $true)]
    [string]$ApiUrl,

    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(Mandatory = $true)]
    [string]$EndpointId
)

$ErrorActionPreference = "Stop"

$rules = @(Get-NetFirewallRule -ErrorAction Stop | ForEach-Object {
    $rule = $_

    $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
    $applicationFilter = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    $serviceFilter = $rule | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        instance_id         = [string]$rule.InstanceID
        rule_name           = [string]$rule.Name
        display_name        = [string]$rule.DisplayName
        description         = [string]$rule.Description
        enabled             = if ($null -ne $rule.Enabled) { [bool]$rule.Enabled } else { $null }
        direction           = [string]$rule.Direction
        action              = [string]$rule.Action
        profile             = [string]$rule.Profile
        protocol            = if ($portFilter) { [string]$portFilter.Protocol } else { $null }
        local_port          = if ($portFilter) { [string]$portFilter.LocalPort } else { $null }
        remote_port         = if ($portFilter) { [string]$portFilter.RemotePort } else { $null }
        local_address       = if ($addressFilter) { [string]$addressFilter.LocalAddress } else { $null }
        remote_address      = if ($addressFilter) { [string]$addressFilter.RemoteAddress } else { $null }
        program             = if ($applicationFilter) { [string]$applicationFilter.Program } else { $null }
        service_name        = if ($serviceFilter) { [string]$serviceFilter.Service } else { $null }
        policy_store_source = [string]$rule.PolicyStoreSource
    }
})

$payload = @{
    endpoint_id      = $EndpointId
    snapshot_complete = $true
    rules            = @($rules)
} | ConvertTo-Json -Depth 8

$headers = @{
    "X-API-Key"   = $ApiKey
    "Content-Type" = "application/json"
}

$response = Invoke-RestMethod `
    -Uri "$ApiUrl/client/endpoints/firewall" `
    -Method Post `
    -Headers $headers `
    -Body $payload

$response | ConvertTo-Json -Depth 5
