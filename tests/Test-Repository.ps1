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

# Regression test: remote scripts must receive named parameters as a hashtable,
# not as a positional string array such as @('-RebootMode','Never').
. (Join-Path $Root 'Common.ps1')

function Get-WumWebText {
    param([Parameter(Mandatory = $true)][string]$Uri)

    if ($Uri -like '*/Invoke-WinUpdate.ps1') {
        return @'
param(
    [ValidateSet('Never','IfNeeded','Always')]
    [string]$RebootMode = 'Never',
    [switch]$IncludeWinget,
    [switch]$InstallWingetIfMissing,
    [switch]$SkipWindowsUpdate
)
[PSCustomObject]@{
    RebootMode = $RebootMode
    IncludeWinget = [bool]$IncludeWinget
    InstallWingetIfMissing = [bool]$InstallWingetIfMissing
    SkipWindowsUpdate = [bool]$SkipWindowsUpdate
}
'@
    }

    if ($Uri -like '*/Install-Winget.ps1') {
        return @'
param(
    [ValidateSet('Ensure','Repair')]
    [string]$Mode = 'Ensure'
)
[PSCustomObject]@{ Mode = $Mode }
'@
    }

    throw "Unexpected mock URL: $Uri"
}

$option1 = Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -Parameters @{ RebootMode = 'Never' }
if ($option1.RebootMode -ne 'Never') { throw 'Menu option 1 parameter binding regression.' }

$option2 = Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -Parameters @{ RebootMode = 'IfNeeded' }
if ($option2.RebootMode -ne 'IfNeeded') { throw 'Menu option 2 parameter binding regression.' }

$option3 = Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -Parameters @{
    RebootMode = 'Never'
    IncludeWinget = $true
    InstallWingetIfMissing = $true
}
if ($option3.RebootMode -ne 'Never' -or -not $option3.IncludeWinget -or -not $option3.InstallWingetIfMissing) {
    throw 'Menu option 3 parameter binding regression.'
}

$option4 = Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -Parameters @{
    SkipWindowsUpdate = $true
    IncludeWinget = $true
    InstallWingetIfMissing = $true
}
if (-not $option4.SkipWindowsUpdate -or -not $option4.IncludeWinget -or -not $option4.InstallWingetIfMissing) {
    throw 'Menu option 4 parameter binding regression.'
}

$option5 = Invoke-WumRemoteScript -Name 'Install-Winget.ps1' -Parameters @{ Mode = 'Repair' }
if ($option5.Mode -ne 'Repair') { throw 'Menu option 5 parameter binding regression.' }

# Backward compatibility for already-created scheduled tasks and older calls.
$legacy = Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -ArgumentList @(
    '-RebootMode','Never','-IncludeWinget','-InstallWingetIfMissing'
)
if ($legacy.RebootMode -ne 'Never' -or -not $legacy.IncludeWinget -or -not $legacy.InstallWingetIfMissing) {
    throw 'Legacy ArgumentList conversion regression.'
}

Write-Host 'PASS: remote named-parameter binding tests passed for menu options 1-5.'
