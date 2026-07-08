param()

$ErrorActionPreference = "Stop"

$bucket = $env:AUDIT_ANCHOR_S3_BUCKET
$prefix = $env:AUDIT_ANCHOR_S3_PREFIX
$retentionDays = if ($env:AUDIT_ANCHOR_S3_RETENTION_DAYS) {
    [int]$env:AUDIT_ANCHOR_S3_RETENTION_DAYS
} else {
    365
}

if ([string]::IsNullOrWhiteSpace($bucket)) {
    throw "AUDIT_ANCHOR_S3_BUCKET is required"
}
if ([string]::IsNullOrWhiteSpace($prefix)) {
    $prefix = "warden-cp/audit-anchor"
}
$prefix = $prefix.Trim("/")

$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
if ($request.version -ne 1) {
    throw "unsupported audit anchor adapter protocol version"
}

switch ($request.action) {
    "publish" {
        if ($null -eq $request.record) {
            throw "publish requires record"
        }
        $seq = [int64]$request.record.seq
        if ($seq -lt 1) {
            throw "record seq must be positive"
        }
        $key = "{0}/seq-{1:D20}.json" -f $prefix, $seq
        $tmp = New-TemporaryFile
        try {
            $request.record |
                ConvertTo-Json -Depth 16 -Compress |
                Set-Content -LiteralPath $tmp.FullName -NoNewline -Encoding UTF8
            $retainUntil = (Get-Date).ToUniversalTime().AddDays($retentionDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
            aws s3api put-object `
                --bucket $bucket `
                --key $key `
                --body $tmp.FullName `
                --object-lock-mode COMPLIANCE `
                --object-lock-retain-until-date $retainUntil `
                --content-type application/json `
                1>$null
            @{ ok = $true; key = $key } | ConvertTo-Json -Compress
        } finally {
            Remove-Item -LiteralPath $tmp.FullName -Force -ErrorAction SilentlyContinue
        }
    }
    "latest" {
        $list = aws s3api list-objects-v2 `
            --bucket $bucket `
            --prefix "$prefix/seq-" `
            --query "sort_by(Contents,&Key)[-1].Key" `
            --output text
        if ([string]::IsNullOrWhiteSpace($list) -or $list.Trim() -eq "None") {
            @{ record = $null } | ConvertTo-Json -Compress
            return
        }
        $tmp = New-TemporaryFile
        try {
            aws s3api get-object --bucket $bucket --key $list.Trim() $tmp.FullName 1>$null
            $record = Get-Content -LiteralPath $tmp.FullName -Raw | ConvertFrom-Json
            @{ record = $record } | ConvertTo-Json -Depth 16 -Compress
        } finally {
            Remove-Item -LiteralPath $tmp.FullName -Force -ErrorAction SilentlyContinue
        }
    }
    default {
        throw "unsupported audit anchor adapter action: $($request.action)"
    }
}
