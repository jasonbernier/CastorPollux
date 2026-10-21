$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath 'C:\CastorPolluxInput\trace-config.json' -Raw | ConvertFrom-Json
$target = Join-Path 'C:\CastorPolluxInput' $config.binary
$destination = 'C:\CastorPolluxOutput\trace.json'
$events = [System.Collections.Generic.List[object]]::new()
$seen = [System.Collections.Generic.HashSet[int]]::new()
$started = Get-Date
$exitCode = $null
$status = 'failed'
try {
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $config.sha256) {
        throw 'Target binary hash differs from the prepared trace job'
    }
    $options = @{ FilePath = $target; PassThru = $true; WorkingDirectory = 'C:\CastorPolluxInput' }
    if ($config.arguments.Count -gt 0) { $options.ArgumentList = [string[]]$config.arguments }
    $process = Start-Process @options
    $rootPid = [int]$process.Id
    $events.Add(@{ type = 'process_start'; timestamp = (Get-Date).ToString('o'); pid = $rootPid;
                   parent_pid = 0; name = $config.binary })
    $seen.Add($rootPid) | Out-Null
    $deadline = (Get-Date).AddSeconds([int]$config.timeout_seconds)
    do {
        $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
        $known = @($rootPid)
        do {
            $before = $known.Count
            foreach ($item in $all) {
                if ($known -contains [int]$item.ParentProcessId -and $known -notcontains [int]$item.ProcessId) {
                    $known += [int]$item.ProcessId
                }
            }
        } while ($known.Count -gt $before)
        foreach ($item in $all) {
            if ($known -contains [int]$item.ProcessId -and -not $seen.Contains([int]$item.ProcessId)) {
                $seen.Add([int]$item.ProcessId) | Out-Null
                $events.Add(@{ type = 'process_start'; timestamp = (Get-Date).ToString('o');
                               pid = [int]$item.ProcessId; parent_pid = [int]$item.ParentProcessId;
                               name = [string]$item.Name; command_line = [string]$item.CommandLine })
            }
        }
        foreach ($connection in @(Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
            if ($known -contains [int]$connection.OwningProcess -and $connection.State -eq 'Established') {
                $events.Add(@{ type = 'tcp_connection'; timestamp = (Get-Date).ToString('o');
                               pid = [int]$connection.OwningProcess;
                               remote_address = [string]$connection.RemoteAddress;
                               remote_port = [int]$connection.RemotePort })
            }
        }
        Start-Sleep -Milliseconds 250
        $process.Refresh()
    } while (-not $process.HasExited -and (Get-Date) -lt $deadline)
    if ($process.HasExited) { $exitCode = $process.ExitCode; $status = 'completed' }
    else {
        & taskkill.exe /PID $rootPid /T /F | Out-Null
        $status = 'timed_out'
    }
}
catch {
    $events.Add(@{ type = 'monitor_error'; timestamp = (Get-Date).ToString('o'); message = $_.Exception.Message })
}
finally {
    @{ schema = 1; status = $status; started_at = $started.ToString('o');
       finished_at = (Get-Date).ToString('o'); exit_code = $exitCode; events = @($events);
       note = 'Sampled process and TCP metadata inside Windows Sandbox; not an API-level trace.' } |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $destination -Encoding utf8
}
