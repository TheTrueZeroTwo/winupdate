$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Scripts = Get-ChildItem -Path $Root -Filter '*.ps1' -File

if (-not $Scripts) { throw 'No PowerShell scripts found at repository root.' }

foreach ($Script in $Scripts) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($Script.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        $summary = ($errors | ForEach-Object { "$($_.Extent.StartLineNumber):$($_.Extent.StartColumnNumber) $($_.Message)" }) -join [Environment]::NewLine
        throw "PowerShell parser errors in $($Script.Name):$([Environment]::NewLine)$summary"
    }
}

$Readme = Get-Content -Raw -Path (Join-Path $Root 'README.md')
if ($Readme -notmatch 'menu\.ps1' -or $Readme -notmatch 'README\.md' -or $Readme -notmatch 'try \{ iex \(irm \$u\)') {
    throw 'README is missing the menu.ps1 one-liner with README fallback.'
}

$Menu = Get-Content -Raw -Path (Join-Path $Root 'menu.ps1')
'Invoke-WinUpdate.ps1','Install-Winget.ps1','DiskCheck.ps1','Get-SystemSnapshot.ps1','Get-EventSummary.ps1','Get-NetworkInfo.ps1','Test-NetworkConnectivity.ps1','Repair-Windows.ps1','Install-Task.ps1' | ForEach-Object {
    if ($Menu -notmatch [regex]::Escape($_)) { throw "menu.ps1 does not reference $_" }
}

$InstallTask = Get-Content -Raw -Path (Join-Path $Root 'Install-Task.ps1')
if ($InstallTask -notmatch 'Register-ScheduledTask' -or $InstallTask -notmatch '-EncodedCommand') {
    throw 'Install-Task.ps1 must register a scheduled task using an encoded remote-run command.'
}

Write-Host "PASS: PowerShell parser check passed for $($Scripts.Count) scripts."
