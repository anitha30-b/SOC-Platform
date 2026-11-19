param(
    [Parameter(Mandatory = $true)]
    [string]$ApiUrl,

    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(Mandatory = $true)]
    [string]$EndpointId,

    [ValidateRange(1, 1000)]
    [int]$MaxEventsPerLog = 100,

    # COLLECTOR_LOG_SELECTION
    [ValidateSet("Security", "System", "Application")]
    [string[]]$LogNames = @("Security", "System", "Application")
)

# COLLECTOR_EXECUTION_SAFEGUARDS
$collectorHasher = [System.Security.Cryptography.SHA256]::Create()
try {
    $collectorHashBytes = $collectorHasher.ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($EndpointId.ToLowerInvariant())
    )
    $collectorLockId = [System.BitConverter]::ToString(
        $collectorHashBytes
    ).Replace("-", "")
}
finally {
    $collectorHasher.Dispose()
}

$collectorMutex = [System.Threading.Mutex]::new(
    $false,
    "Global\SOCPlatform.WindowsEvents.$collectorLockId"
)
if ($null -eq $collectorMutex) {
    throw "Unable to create collector lock."
}
$collectorMutexHeld = $false

try {
    try {
        $collectorMutexHeld = $collectorMutex.WaitOne(0)
    }
    catch [System.Threading.AbandonedMutexException] {
        # The previous process ended; this process now owns the mutex.
        $collectorMutexHeld = $true
    }

    if (-not $collectorMutexHeld) {
        Write-Host "Collector skipped: another run owns this endpoint's checkpoint lock."
        return
    }

# COLLECTOR EXECUTION REPORTING
$runId = [guid]::NewGuid().ToString()
$runStartedAt = [DateTime]::UtcNow
$runStatus = "FAILED" # COLLECTOR_STATUS_COMPLETION_GUARD
$runErrorDetails = [System.Collections.Generic.List[string]]::new()
$headers = @{ "X-API-Key" = $ApiKey; "Content-Type" = "application/json; charset=utf-8" }
$events = [System.Collections.Generic.List[object]]::new()
$collectionErrors = [System.Collections.Generic.List[string]]::new()
$acceptedTotal = 0
$duplicateTotal = 0
try {
$ErrorActionPreference = "Stop"

$logs = @("Security", "System", "Application")
$checkpointDirectory = Join-Path $env:ProgramData "SOCPlatform\WindowsEventCheckpoints"
$checkpointPath = Join-Path $checkpointDirectory "$EndpointId.json"

New-Item -ItemType Directory -Path $checkpointDirectory -Force | Out-Null

$checkpoints = @{}
foreach ($logName in $logs) {
    $checkpoints[$logName] = [long]0
}

if (Test-Path $checkpointPath) {
    try {
        $saved = Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json
        foreach ($logName in $logs) {
            $property = $saved.PSObject.Properties[$logName]
            if ($property -and $null -ne $property.Value) {
                $checkpoints[$logName] = [long]$property.Value
            }
        }
    }
    catch {
        throw "Checkpoint file is invalid. Collection stopped to prevent skipped events: $($_.Exception.Message)"
    }
}

$events = [System.Collections.Generic.List[object]]::new()
$pendingCheckpoints = @{}
$collectionErrors = [System.Collections.Generic.List[string]]::new()

function Get-WindowsEventSeverity {
    param(
        [string]$LogName,
        [int]$EventId,
        [string]$Level
    )

    if ($LogName -eq "Security") {
        switch ($EventId) {
            1102 { return "CRITICAL" }
            { $_ -in 4625, 4720, 4728, 4732, 4756 } { return "HIGH" }
            4672 { return "MEDIUM" }
            { $_ -in 4798, 5379 } { return "LOW" }
            4624 { return "INFO" }
        }
    }

    switch -Regex ($Level) {
        "^Critical$" { return "CRITICAL" }
        "^Error$"    { return "HIGH" }
        "^Warning$"  { return "MEDIUM" }
        default      { return "INFO" }
    }
}

foreach ($logName in $LogNames) {
    $lastRecordId = [long]$checkpoints[$logName]
    Write-Host "Collecting new $logName events after Record ID $lastRecordId..."

    try {
        $xpath = "*[System[EventRecordID > $lastRecordId]]"
        $records = @(
            Get-WinEvent -LogName $logName `
                -FilterXPath $xpath `
                -Oldest `
                -MaxEvents $MaxEventsPerLog `
                -ErrorAction Stop
        )
    }
    catch {
        if ($_.Exception.Message -match "No events were found|No matching events") {
            $records = @()
        }
        else {
            $collectionErrors.Add("$logName`: $($_.Exception.Message)")
            Write-Warning "Unable to collect $logName`: $($_.Exception.Message)"
            continue
        }
    }

    # Process oldest records first to prevent skipping events during backlog collection.
    $records = @($records | Sort-Object { [long]$_.RecordId })

    $maxRecordId = $lastRecordId

    foreach ($record in $records) {
        $recordId = [long]$record.RecordId
        if ($recordId -gt $maxRecordId) {
            $maxRecordId = $recordId
        }

        $message = [string]$record.Message
        if ([string]::IsNullOrWhiteSpace($message)) {
            $message = "Windows event $($record.Id) from $logName"
        }

        if ($message.Length -gt 10000) {
            $message = $message.Substring(0, 10000)
        }

        # Remove control characters that can invalidate HTTP headers or JSON.
        $message = [regex]::Replace($message, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', ' ')

        $timestamp = $record.TimeCreated.ToUniversalTime().ToString("o")
        $severity = Get-WindowsEventSeverity `
            -LogName $logName `
            -EventId ([int]$record.Id) `
            -Level ([string]$record.LevelDisplayName)

        $events.Add(@{
            event_id    = "$logName`:$recordId"
            timestamp   = $timestamp
            event_type  = "windows_$($logName.ToLower())_event"
            severity    = $severity
            message     = $message
            target      = [string]$record.MachineName
            endpoint_id = $EndpointId
            raw_event   = @{
                log_name         = $logName
                provider_name    = [string]$record.ProviderName
                event_id         = [int]$record.Id
                record_id        = $recordId
                level            = [string]$record.LevelDisplayName
                task             = [string]$record.TaskDisplayName
                opcode           = [string]$record.OpcodeDisplayName
                machine_name     = [string]$record.MachineName
                time_created_utc = $timestamp
                message          = $message
            }
        })
    }

    $pendingCheckpoints[$logName] = $maxRecordId
    Write-Host "Collected $($records.Count) new records from $logName."
}

if ($events.Count -eq 0) {
    if ($collectionErrors.Count -gt 0) {
        throw "One or more logs could not be collected. No events submitted; checkpoints unchanged."
    }

    Write-Host "No new Windows events. Checkpoints remain unchanged."
    $runStatus = "SUCCESS"
    return
}

$headers = @{
    "X-API-Key" = $ApiKey
    "Content-Type" = "application/json; charset=utf-8"
}

$acceptedTotal = 0
$duplicateTotal = 0
$batchSize = 100

for ($offset = 0; $offset -lt $events.Count; $offset += $batchSize) {
    $end = [Math]::Min($offset + $batchSize - 1, $events.Count - 1)
    $batch = @($events.GetRange($offset, $end - $offset + 1))

    $payload = @{
        events = $batch
    } | ConvertTo-Json -Depth 8

    $response = Invoke-RestMethod `
        -Uri "$($ApiUrl.TrimEnd('/'))/telemetry/ingest" `
        -Method Post -TimeoutSec 20 `
        -Headers $headers `
        -Body ([System.Text.Encoding]::UTF8.GetBytes($payload))

    if (
        [int]$response.received -ne $batch.Count -or
        ([int]$response.accepted + [int]$response.duplicates) -ne $batch.Count
    ) {
        throw "API did not confirm the complete batch. Checkpoints were not advanced."
    }

    $acceptedTotal += [int]$response.accepted
    $duplicateTotal += [int]$response.duplicates

    Write-Host "Batch submitted: received=$($response.received), accepted=$($response.accepted), duplicates=$($response.duplicates)"
}

# Advance only logs whose collection succeeded, and only after all batches succeed.
foreach ($logName in $logs) {
    if ($null -ne $pendingCheckpoints[$logName]) {
        $checkpoints[$logName] = [long]$pendingCheckpoints[$logName]
    }
}

$tempPath = "$checkpointPath.tmp"
$checkpoints | ConvertTo-Json | Set-Content -LiteralPath $tempPath -Encoding UTF8
Move-Item -LiteralPath $tempPath -Destination $checkpointPath -Force

if ($collectionErrors.Count -gt 0) {
    $runStatus = "PARTIAL"
} else {
    $runStatus = "SUCCESS"
}

Write-Host ""
Write-Host "Incremental Windows Event Collection Summary"
Write-Host "Collected: $($events.Count)"
Write-Host "Accepted: $acceptedTotal"
Write-Host "Duplicates: $duplicateTotal"
Write-Host "Collection errors: $($collectionErrors.Count)"
Write-Host "Checkpoint: $checkpointPath"

if ($collectionErrors.Count -gt 0) {
    $collectionErrors | ForEach-Object { Write-Warning $_ }
}

}
catch {
    $runStatus = "FAILED"
    $runErrorDetails.Add($_.Exception.Message)
    throw
}
finally {
    if ($collectionErrors.Count -gt 0) {
        $runErrorDetails.AddRange([string[]]$collectionErrors.ToArray())
        if ($runStatus -eq "SUCCESS") { $runStatus = "PARTIAL" }
    }

    if ($runStatus -eq "FAILED" -and $runErrorDetails.Count -eq 0) {
        $runErrorDetails.Add("Collector ended before completing collection and delivery confirmation.")
    }

    $runCompletedAt = [DateTime]::UtcNow
    $errorCount = $runErrorDetails.Count
    $errorDetails = ($runErrorDetails -join "`n")
    if ($errorDetails.Length -gt 4000) {
        $errorDetails = $errorDetails.Substring(0, 4000)
    }

    try {
        $report = @{
            run_id = $runId
            endpoint_id = $EndpointId
            started_at = $runStartedAt.ToString("o")
            completed_at = $runCompletedAt.ToString("o")
            status = $runStatus
            collected_count = $events.Count
            accepted_count = $acceptedTotal
            duplicate_count = $duplicateTotal
            error_count = $errorCount
            error_details = if ($errorDetails) { $errorDetails } else { $null }
        } | ConvertTo-Json -Depth 5

        $reportResponse = Invoke-RestMethod `
            -Uri "$($ApiUrl.TrimEnd('/'))/telemetry/execution-runs" `
            -Method Post -TimeoutSec 20 `
            -Headers $headers `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($report)) `
            -ErrorAction Stop

        Write-Host "Execution report submitted: run=$runId status=$runStatus created=$($reportResponse.created)"
    }
    catch {
        Write-Warning "Execution report could not be submitted. Run ID: $runId. Error: $($_.Exception.Message)"
    }
}


}
finally {
    try {
        if ($collectorMutexHeld) {
            $collectorMutex.ReleaseMutex()
        }
    }
    finally {
        $collectorMutex.Dispose()
    }
}