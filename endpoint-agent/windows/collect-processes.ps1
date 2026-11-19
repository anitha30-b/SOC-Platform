param(
    [Parameter(Mandatory = $true)]
    [string]$ApiUrl,

    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(Mandatory = $true)]
    [string]$EndpointId
)

$ErrorActionPreference = "Stop"

$processes = Get-CimInstance Win32_Process | ForEach-Object {
    $owner = $null
    $ownerResult = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue

    if ($ownerResult -and $ownerResult.ReturnValue -eq 0) {
        if ($ownerResult.Domain) {
            $owner = "$($ownerResult.Domain)\$($ownerResult.User)"
        }
        else {
            $owner = $ownerResult.User
        }
    }

    [PSCustomObject]@{
        pid            = [int]$_.ProcessId
        parent_pid     = if ($_.ParentProcessId -gt 0) { [int]$_.ParentProcessId } else { $null }
        name           = $_.Name
        executable     = $_.ExecutablePath
        command_line   = $_.CommandLine
        username       = $owner
        status         = "Running"
        cpu_percent    = $null
        memory_percent = $null
    }
}

$payload = @{
    endpoint_id = $EndpointId
    processes   = @($processes)
} | ConvertTo-Json -Depth 5

$headers = @{
    "X-API-Key"   = $ApiKey
    "Content-Type" = "application/json"
}

$response = Invoke-RestMethod `
    -Uri "$ApiUrl/client/endpoints/processes" `
    -Method Post `
    -Headers $headers `
    -Body $payload

$response | ConvertTo-Json -Depth 5
