param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath,
    [string]$ComposeFile = "deploy/postgres/docker-compose.yml",
    [string]$EnvFile = "deploy/postgres/.env"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $BackupPath)) {
    throw "Backup not found: $BackupPath"
}

Get-Content -Raw -Path $BackupPath |
    docker compose --env-file $EnvFile -f $ComposeFile exec -T postgres psql -U warden_cp warden_cp

Write-Host "Restored $BackupPath"
