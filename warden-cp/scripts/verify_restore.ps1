param(
    [string]$BaseUrl = "http://127.0.0.1:7878",
    [Parameter(Mandatory = $true)]
    [string]$ApiKey
)

$ErrorActionPreference = "Stop"

$headers = @{ Authorization = "Bearer $ApiKey" }
$result = Invoke-RestMethod -Headers $headers -Uri "$BaseUrl/v1/audit/verify"
if (-not $result.ok) {
    throw "Audit chain verification failed: $($result | ConvertTo-Json -Compress)"
}

Write-Host "Audit chain verified."
