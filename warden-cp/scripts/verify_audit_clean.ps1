param(
    [string]$ControlPlaneManifest = "$PSScriptRoot\..\Cargo.toml",
    [string]$GatewayManifest = "$PSScriptRoot\..\..\mcp-warden\mcp-warden\Cargo.toml"
)

$ErrorActionPreference = "Stop"

Write-Host "Checking warden-cp default SQLite build..."
cargo check --manifest-path $ControlPlaneManifest

Write-Host "Checking warden-cp production Postgres build..."
cargo check --manifest-path $ControlPlaneManifest --no-default-features --features postgres

Write-Host "Auditing warden-cp lockfile without ignores..."
Push-Location (Split-Path -Parent $ControlPlaneManifest)
try {
    cargo audit
}
finally {
    Pop-Location
}

Write-Host "Checking mcp-warden gateway..."
cargo check --manifest-path $GatewayManifest

Write-Host "Auditing mcp-warden gateway lockfile without ignores..."
Push-Location (Split-Path -Parent $GatewayManifest)
try {
    cargo audit
}
finally {
    Pop-Location
}
