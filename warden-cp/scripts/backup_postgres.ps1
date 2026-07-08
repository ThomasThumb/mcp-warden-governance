param(
    [string]$ComposeFile = "deploy/postgres/docker-compose.yml",
    [string]$EnvFile = "deploy/postgres/.env",
    [string]$OutputDir = "backups"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupPath = Join-Path $OutputDir "warden_cp_$timestamp.sql"

docker compose --env-file $EnvFile -f $ComposeFile exec -T postgres pg_dump -U warden_cp warden_cp |
    Set-Content -Encoding utf8 -Path $backupPath

Write-Host "Wrote $backupPath"
