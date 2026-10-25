param([switch]$Public)

$ErrorActionPreference = 'Stop'
$Host.UI.RawUI.WindowTitle = if ($Public) { 'ASL Demo (public link)' } else { 'ASL Demo' }

$Root   = Split-Path -Parent $PSScriptRoot
$Port   = 8000
$Local  = "http://127.0.0.1:$Port"
$Model  = 'qwen2.5:7b'

function Say($text, $color = 'Gray') { Write-Host "  $text" -ForegroundColor $color }

function Test-Url($url) {
    try { Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 | Out-Null; return $true }
    catch { return $false }
}

function Wait-Url($url, $seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (Test-Url $url) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Find-Exe($name, $candidates) {
    foreach ($path in $candidates) { if ($path -and (Test-Path $path)) { return $path } }
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

Write-Host ''
Write-Host '  ASL - Adaptive Security Layer' -ForegroundColor Cyan
Write-Host ''

$ollama = Find-Exe 'ollama' @("$env:LOCALAPPDATA\Programs\Ollama\ollama.exe")
$live = $false
if (-not $ollama) {
    Say 'Ollama not found: the demo will use the built-in mock agent.' Yellow
} else {
    if (-not (Test-Url 'http://127.0.0.1:11434/api/tags')) {
        Say 'Starting Ollama...'
        Start-Process -FilePath $ollama -ArgumentList 'serve' -WindowStyle Hidden
    }
    if (Wait-Url 'http://127.0.0.1:11434/api/tags' 30) {
        $tags = (Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/tags' -UseBasicParsing).Content
        if ($tags -match [regex]::Escape($Model)) {
            Say "Ollama ready with $Model" Green
            $live = $true
        } else {
            Say "Ollama is running but $Model is not downloaded." Yellow
            Say "Run once:  ollama pull $Model   (the demo uses the mock agent until then)" Yellow
        }
    } else {
        Say 'Ollama did not answer: the demo will use the built-in mock agent.' Yellow
    }
}

if (Test-Url "$Local/health") {
    Say "ASL is already running on http://localhost:$Port" Green
} else {
    $python = Find-Exe 'python' @("$Root\.venv\Scripts\python.exe", "$Root\..\.venv\Scripts\python.exe")
    if (-not $python) {
        Say 'Python was not found. Create the virtual environment first (see README).' Red
        Read-Host '  Press Enter to close'
        exit 1
    }
    $serverArgs = @('-m', 'app.main', '--port', "$Port")
    if ($live) { $serverArgs += '--live-model' }
    $env:PYTHONIOENCODING = 'utf-8'
    Say 'Starting the ASL server...'
    Start-Process -FilePath $python -ArgumentList $serverArgs -WorkingDirectory $Root -WindowStyle Minimized
    if (-not (Wait-Url "$Local/health" 60)) {
        Say 'The ASL server did not start. Check its window for the error.' Red
        Read-Host '  Press Enter to close'
        exit 1
    }
    Say "ASL is running on http://localhost:$Port" Green
}

Start-Process "http://localhost:$Port/?demo"

if (-not $Public) {
    Write-Host ''
    Say 'The demo is open in your browser. You can close this window.' Cyan
    Start-Sleep -Seconds 4
    exit 0
}

$cloudflared = Find-Exe 'cloudflared' @("${env:ProgramFiles(x86)}\cloudflared\cloudflared.exe",
                                        "$env:ProgramFiles\cloudflared\cloudflared.exe")
if (-not $cloudflared) {
    Say 'cloudflared is not installed, so there is no public link.' Yellow
    Say 'Install it with:  winget install --id Cloudflare.cloudflared' Yellow
    Read-Host '  Press Enter to close'
    exit 1
}

$log = Join-Path $env:TEMP 'asl_tunnel.log'
Remove-Item $log -ErrorAction SilentlyContinue
Say 'Opening a public link through Cloudflare...'
$tunnel = Start-Process -FilePath $cloudflared -ArgumentList 'tunnel', '--url', $Local `
          -RedirectStandardError $log -NoNewWindow -PassThru

$url = $null
for ($i = 0; $i -lt 45 -and -not $url; $i++) {
    Start-Sleep -Seconds 1
    if (Test-Path $log) {
        $hit = Select-String -Path $log -Pattern 'https://[a-z0-9-]+\.trycloudflare\.com' | Select-Object -First 1
        if ($hit) { $url = $hit.Matches[0].Value }
    }
    if ($tunnel.HasExited) { break }
}

if (-not $url) {
    Say "No public link came back. Details: $log" Red
    if (-not $tunnel.HasExited) { Stop-Process -Id $tunnel.Id -Force }
    Read-Host '  Press Enter to close'
    exit 1
}

try { Set-Clipboard -Value $url } catch {}
Write-Host ''
Write-Host '  Public link (copied to the clipboard):' -ForegroundColor Cyan
Write-Host "    $url" -ForegroundColor Green
Write-Host ''
Say 'Anyone with this link can use the demo while this window stays open.'
Say 'It can take up to a minute before the link starts working.'
Say 'Close this window (or press Ctrl+C) to take the link down.'

try { Wait-Process -Id $tunnel.Id }
finally { if (-not $tunnel.HasExited) { Stop-Process -Id $tunnel.Id -Force } }
