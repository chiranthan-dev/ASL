$Port = 8000

$owners = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
          Select-Object -ExpandProperty OwningProcess -Unique
foreach ($id in $owners) {
    $proc = Get-Process -Id $id -ErrorAction SilentlyContinue
    if ($proc -and $proc.ProcessName -like 'python*') {
        Stop-Process -Id $id -Force
        Write-Host "  stopped the ASL server (pid $id)"
    }
}

Get-CimInstance Win32_Process -Filter "Name = 'cloudflared.exe'" |
    Where-Object { $_.CommandLine -match "--url\s+\S*:$Port" } | ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force
        Write-Host "  stopped the public link (pid $($_.ProcessId))"
    }

Write-Host '  done'
Start-Sleep -Seconds 2
