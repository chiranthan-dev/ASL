$here    = $PSScriptRoot
$desktop = [Environment]::GetFolderPath('Desktop')
$shell   = New-Object -ComObject WScript.Shell
$icon    = Join-Path $here 'asl.ico'

function New-Shortcut($name, $extra, $style) {
    $lnk = $shell.CreateShortcut((Join-Path $desktop "$name.lnk"))
    $lnk.TargetPath       = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $lnk.Arguments        = "-NoProfile -ExecutionPolicy Bypass -File `"$here\start_demo.ps1`" $extra".Trim()
    $lnk.WorkingDirectory = Split-Path -Parent $here
    $lnk.WindowStyle      = $style
    $lnk.Description      = "$name - Adaptive Security Layer"
    if (Test-Path $icon) { $lnk.IconLocation = "$icon,0" }
    $lnk.Save()
    Write-Host "  created $desktop\$name.lnk"
}

New-Shortcut 'ASL Demo' '' 1
New-Shortcut 'ASL Demo (public link)' '-Public' 1
