param(
    [Parameter(Mandatory = $true)]
    [string]$ApiUrl,

    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(Mandatory = $true)]
    [string]$EndpointId
)

$ErrorActionPreference = "Stop"

Write-Host "Collecting Windows Server Configuration..."

$computer = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$bios = Get-CimInstance Win32_BIOS
$processor = Get-CimInstance Win32_Processor | Select-Object -First 1
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"

$memoryTotalGb = if ($computer.TotalPhysicalMemory) {
    [math]::Round(
        $computer.TotalPhysicalMemory / 1GB,
        2
    )
} else {
    $null
}

$diskTotalGb = if ($disk.Size) {
    [math]::Round(
        $disk.Size / 1GB,
        2
    )
} else {
    $null
}

$diskFreeGb = if ($disk.FreeSpace) {
    [math]::Round(
        $disk.FreeSpace / 1GB,
        2
    )
} else {
    $null
}

$diskUsagePercent = if ($disk.Size -and $disk.FreeSpace -ne $null) {
    [math]::Round(
        (($disk.Size - $disk.FreeSpace) / $disk.Size) * 100,
        2
    )
} else {
    $null
}

$bootTime = $os.LastBootUpTime
$uptimeSeconds = if ($bootTime) {
    [int64]((Get-Date) - $bootTime).TotalSeconds
} else {
    $null
}

$uptime = if ($uptimeSeconds -ne $null) {
    $timeSpan = New-TimeSpan -Seconds $uptimeSeconds

    if ($timeSpan.Days -gt 0) {
        "{0}d {1}h {2}m {3}s" -f `
            $timeSpan.Days,
            $timeSpan.Hours,
            $timeSpan.Minutes,
            $timeSpan.Seconds
    } elseif ($timeSpan.Hours -gt 0) {
        "{0}h {1}m {2}s" -f `
            $timeSpan.Hours,
            $timeSpan.Minutes,
            $timeSpan.Seconds
    } else {
        "{0}m {1}s" -f `
            $timeSpan.Minutes,
            $timeSpan.Seconds
    }
} else {
    $null
}

$timezone = try {
    (Get-TimeZone).Id
} catch {
    $null
}

$powerPlan = try {
    $activePlan = powercfg /getactivescheme 2>$null

    if ($activePlan) {
        [string]$activePlan
    } else {
        $null
    }
} catch {
    $null
}

$payload = @{
    endpoint_id          = $EndpointId
    hostname             = $computer.Name
    os_name              = $os.Caption
    os_version           = $os.Version
    architecture         = $os.OSArchitecture
    processor            = $processor.Name
    memory_total_gb      = $memoryTotalGb
    disk_total_gb        = $diskTotalGb
    disk_free_gb         = $diskFreeGb
    disk_usage_percent   = $diskUsagePercent
    uptime_seconds       = $uptimeSeconds
    uptime               = $uptime
    timezone             = $timezone
    domain_or_workgroup  = $computer.Domain
    windows_edition      = $os.Caption
    power_plan           = $powerPlan
} | ConvertTo-Json -Depth 8

Write-Host "Payload size:" $payload.Length "bytes"
Write-Host "Sending Server Configuration data..."

$headers = @{
    "X-API-Key"   = $ApiKey
    "Content-Type" = "application/json"
}

$response = Invoke-RestMethod `
    -Uri "$ApiUrl/client/endpoints/server-configuration" `
    -Method Post `
    -Headers $headers `
    -Body $payload

Write-Host "Server Configuration ingestion successful:"
$response | ConvertTo-Json -Depth 5
