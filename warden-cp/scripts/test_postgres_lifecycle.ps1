#requires -Version 7.0
param(
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9./_:@-]*$')]
    [string]$Image = "warden-postgres:security",
    [ValidateRange(2, 5)]
    [int]$Cycles = 3,
    # Only needed on hosts whose default Docker address pools are exhausted.
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$')]
    [string]$Subnet
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$project = "warden-pg-lifecycle-$([guid]::NewGuid().ToString('N').Substring(0, 12))"
$tempDir = Join-Path ([IO.Path]::GetTempPath()) $project
$null = New-Item -ItemType Directory -Path $tempDir
$overridePath = Join-Path $tempDir "compose.test.yml"
$envPath = Join-Path $tempDir "empty.env"
$override = "services:`n  postgres:`n    image: $Image`n"
if ($Subnet) {
    $override += "networks:`n  database:`n    ipam:`n      config:`n        - subnet: $Subnet`n"
}
[IO.File]::WriteAllText($overridePath, $override)
[IO.File]::WriteAllText($envPath, "")
$composeArgs = @(
    "compose", "--project-name", $project, "--env-file", $envPath,
    "-f", (Join-Path $repoRoot "warden-cp/deploy/postgres/docker-compose.yml"),
    "-f", $overridePath
)

# Supply disposable credentials and fail-closed required application settings.
# The application is never started; do not print interpolated configuration.
$testEnv = @{
    POSTGRES_DB = "lifecycle_test"
    POSTGRES_USER = "lifecycle_test"
    POSTGRES_PASSWORD = [guid]::NewGuid().ToString("N")
    WARDEN_CP_ALLOW_INSECURE_NON_LOOPBACK = "false"
    WARDEN_REQUIRE_EXTERNAL_SIGNER = "true"
}
$savedEnv = @{}
foreach ($name in $testEnv.Keys) {
    $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    [Environment]::SetEnvironmentVariable($name, $testEnv[$name], "Process")
}

function Invoke-Docker([string[]]$Arguments) {
    $output = & docker @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker failed (exit $LASTEXITCODE): $($output -join "`n")"
    }
    return $output
}

function Invoke-Compose([string[]]$Arguments) {
    Invoke-Docker ($composeArgs + $Arguments)
}

function Invoke-Sql([string]$Sql) {
    $result = Invoke-Compose @(
        "exec", "-T", "postgres", "psql", "-X", "-At", "-v", "ON_ERROR_STOP=1",
        "-U", "lifecycle_test", "-d", "lifecycle_test", "-c", $Sql
    )
    return ($result -join "`n").Trim()
}

function Wait-Postgres {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        $null = & docker @composeArgs exec -T postgres pg_isready -h 127.0.0.1 -U lifecycle_test -d lifecycle_test 2>&1
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "PostgreSQL did not become ready within 60 seconds"
}

$failed = $false
try {
    # Override only the prebuilt image and optional test-network subnet. All
    # runtime permissions, entrypoint, data volume and tmpfs settings come from
    # the real deployment profile; the application service is never started.
    Invoke-Compose @("up", "--detach", "--no-deps", "--no-build", "--pull", "never", "postgres") | Out-Host
    Wait-Postgres
    $containerId = ((Invoke-Compose @("ps", "--quiet", "postgres")) -join "").Trim()
    $info = ((Invoke-Docker @("inspect", $containerId)) -join "`n") | ConvertFrom-Json
    $actualCaps = @($info.HostConfig.CapAdd | ForEach-Object { $_ -replace '^CAP_', '' } | Sort-Object)
    $expectedCaps = @("CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID" | Sort-Object)
    if (($actualCaps -join ",") -ne ($expectedCaps -join ",") -or
        $info.HostConfig.CapDrop -notcontains "ALL" -or
        -not $info.HostConfig.ReadonlyRootfs -or
        $info.HostConfig.SecurityOpt -notcontains "no-new-privileges:true" -or
        @($info.HostConfig.PortBindings.PSObject.Properties).Count -ne 0) {
        throw "The lifecycle test must retain restricted permissions and no published port: caps=$($actualCaps -join ','); drop=$($info.HostConfig.CapDrop -join ','); readonly=$($info.HostConfig.ReadonlyRootfs); security=$($info.HostConfig.SecurityOpt -join ','); ports=$($info.HostConfig.PortBindings | ConvertTo-Json -Compress)"
    }
    $null = Invoke-Sql "CREATE TABLE lifecycle_probe (cycle integer PRIMARY KEY)"
    for ($cycle = 1; $cycle -le $Cycles; $cycle++) {
        $null = Invoke-Sql "INSERT INTO lifecycle_probe VALUES ($cycle)"
        $stopSince = [DateTimeOffset]::UtcNow.ToString("O")
        # Exercise normal Compose/Docker stop. Do not substitute pg_ctl or
        # weaken capabilities: either would conceal the signal-forwarding bug.
        if ($cycle % 2 -eq 1) {
            Invoke-Compose @("stop", "postgres") | Out-Host
        }
        else {
            Invoke-Docker @("stop", $containerId) | Out-Host
        }
        $info = ((Invoke-Docker @("inspect", $containerId)) -join "`n") | ConvertFrom-Json
        $logs = (Invoke-Docker @("logs", "--since", $stopSince, $containerId)) -join "`n"
        if ($info.State.Status -ne "exited" -or $info.State.ExitCode -ne 0 -or
            $info.State.OOMKilled -or
            $logs -notmatch "received fast shutdown request" -or
            $logs -notmatch "database system is shut down") {
            throw "Cycle $cycle did not shut down cleanly (exit $($info.State.ExitCode)):`n$logs"
        }
        Invoke-Compose @("start", "postgres") | Out-Host
        Wait-Postgres
        $restartedId = ((Invoke-Compose @("ps", "--quiet", "postgres")) -join "").Trim()
        if ($restartedId -ne $containerId) { throw "The restart must reuse the same container and data volume" }
        $persisted = Invoke-Sql "SELECT string_agg(cycle::text, ',' ORDER BY cycle) FROM lifecycle_probe"
        if ($persisted -ne ((1..$cycle) -join ",")) { throw "Cycle $cycle lost committed data: $persisted" }
        $info = ((Invoke-Docker @("inspect", $containerId)) -join "`n") | ConvertFrom-Json
        $logs = (Invoke-Docker @("logs", "--since", $info.State.StartedAt, $containerId)) -join "`n"
        if ($logs -match "not properly shut down|automatic recovery in progress") {
            throw "Cycle $cycle required crash recovery:`n$logs"
        }
        Write-Host "Cycle ${cycle}: clean SIGINT shutdown, exit 0, restart without crash recovery, committed rows preserved."
    }
    $pidOne = (Invoke-Docker @("exec", $containerId, "cat", "/proc/1/comm")) -join ""
    $pidOneUid = (Invoke-Docker @("exec", $containerId, "grep", "^Uid:", "/proc/1/status")) -join ""
    if ($pidOne -ne "postgres" -or $pidOneUid -notmatch '^Uid:\s+70\s+70\s+70\s+70\s*$') {
        throw "PostgreSQL must run directly as PID 1 with UID 70"
    }
    Write-Host "PostgreSQL lifecycle passed ($Cycles cycles, PID 1: $pidOne)."
}
catch {
    $failed = $true
    throw
}
finally {
    # The project name is generated internally; this can only remove the
    # disposable containers, network and data volume created by this test.
    & docker @composeArgs down --volumes --timeout 20 2>&1 | Out-Host
    $cleanupExit = $LASTEXITCODE
    foreach ($name in $testEnv.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], "Process")
    }
    Remove-Item -LiteralPath $overridePath, $envPath
    Remove-Item -LiteralPath $tempDir
    if ($cleanupExit -ne 0 -and -not $failed) { throw "Disposable Compose project cleanup failed" }
}
