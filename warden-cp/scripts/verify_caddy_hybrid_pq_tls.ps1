param(
    [string]$CaddyImage = "caddy:2.11.4",
    [string]$GoImage = "golang:1.26-bookworm",
    [int]$HostPort = 18443
)

$ErrorActionPreference = "Stop"

$id = [Guid]::NewGuid().ToString("N").Substring(0, 12)
$containerName = "warden-cp-caddy-pq-$id"
$tempDir = Join-Path ([IO.Path]::GetTempPath()) "warden-cp-caddy-pq-$id"
New-Item -ItemType Directory -Path $tempDir | Out-Null

$caddyfile = @"
{
	admin off
}

localhost:8443 {
	tls internal {
		protocols tls1.3
		curves x25519mlkem768
	}

	respond "warden-cp caddy pq tls ok"
}
"@

$goProbe = @'
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsConfig := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // Test-only: Caddy's internal CA is container-local.
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", "localhost:8443", tlsConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TLS handshake failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	fmt.Printf("version=%s\n", tls.VersionName(state.Version))
	fmt.Printf("cipher_suite=%s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("curve=%s\n", state.CurveID.String())

	if state.Version != tls.VersionTLS13 {
		fmt.Fprintf(os.Stderr, "expected TLS 1.3, got %s\n", tls.VersionName(state.Version))
		os.Exit(2)
	}
	if state.CurveID != tls.X25519MLKEM768 {
		fmt.Fprintf(os.Stderr, "expected X25519MLKEM768, got %s\n", state.CurveID.String())
		os.Exit(3)
	}

	req, err := http.NewRequest(http.MethodGet, "https://localhost:8443/", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request create failed: %v\n", err)
		os.Exit(4)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HTTPS request failed: %v\n", err)
		os.Exit(5)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("status=%s\n", resp.Status)
	fmt.Printf("body=%s\n", string(body))
	if resp.StatusCode != http.StatusOK {
		os.Exit(6)
	}
}
'@

Set-Content -Path (Join-Path $tempDir "Caddyfile") -Value $caddyfile -Encoding UTF8
Set-Content -Path (Join-Path $tempDir "verify_hybrid_pq_tls.go") -Value $goProbe -Encoding UTF8

try {
    Write-Host "Caddy image:"
    docker run --rm --entrypoint caddy $CaddyImage version

    Write-Host "Go image:"
    docker run --rm $GoImage go version

    Write-Host "Formatting generated Caddy config..."
    docker run --rm -v "${tempDir}:/etc/caddy" --entrypoint caddy $CaddyImage fmt --overwrite /etc/caddy/Caddyfile | Out-Host

    Write-Host "Validating Caddy config..."
    docker run --rm -v "${tempDir}:/etc/caddy:ro" --entrypoint caddy $CaddyImage adapt --config /etc/caddy/Caddyfile --validate | Out-Host

    Write-Host "Starting disposable Caddy server..."
    docker run -d --name $containerName -p "127.0.0.1:${HostPort}:8443" -v "${tempDir}:/etc/caddy:ro" --entrypoint caddy $CaddyImage run --config /etc/caddy/Caddyfile --adapter caddyfile | Out-Host
    Start-Sleep -Seconds 3

    Write-Host "Probing TLS with Go client restricted to X25519MLKEM768..."
    docker run --rm --network "container:$containerName" -v "${tempDir}:/work:ro" -w /work $GoImage go run verify_hybrid_pq_tls.go
}
finally {
    docker rm -f $containerName 2>$null | Out-Null
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
