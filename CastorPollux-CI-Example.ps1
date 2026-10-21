param(
    [Parameter(Mandatory = $true)][string]$CastorPolluxExe,
    [Parameter(Mandatory = $true)][string]$ConfigPath
)

$configFile = (Resolve-Path -LiteralPath $ConfigPath).Path
$config = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
$summary = if ([IO.Path]::IsPathRooted($config.summary)) {
    $config.summary
} else {
    Join-Path (Split-Path -Parent $configFile) $config.summary
}
$argumentLine = '--batch "' + $configFile + '"'
$process = Start-Process -FilePath (Resolve-Path -LiteralPath $CastorPolluxExe).Path `
    -ArgumentList $argumentLine -WindowStyle Hidden -Wait -PassThru
if (Test-Path -LiteralPath $summary) {
    Get-Content -LiteralPath $summary -Raw
}
exit $process.ExitCode
