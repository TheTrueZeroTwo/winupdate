param(
    [string]$BaseUrl
)

$ErrorActionPreference = 'Stop'

if ($BaseUrl -and -not [string]::IsNullOrWhiteSpace($BaseUrl)) {
    $env:WINUPDATE_BASEURL = $BaseUrl.TrimEnd('/')
}

$defaultBaseUrl = 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main'
if (-not $env:WINUPDATE_BASEURL -or [string]::IsNullOrWhiteSpace($env:WINUPDATE_BASEURL)) {
    $env:WINUPDATE_BASEURL = $defaultBaseUrl
}

function Set-BootstrapTls {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls } catch { }
}

function Get-BootstrapWebText {
    param([Parameter(Mandatory=$true)][string]$Uri)
    Set-BootstrapTls
    $oldProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        try {
            return [string](Invoke-WebRequest -Uri $Uri -UseBasicParsing -ErrorAction Stop).Content
        } catch {
            $wc = New-Object System.Net.WebClient
            try {
                $wc.Headers.Add('User-Agent', 'WinUpdateMspHelperMenu/1.0')
                return $wc.DownloadString($Uri)
            } finally {
                $wc.Dispose()
            }
        }
    } finally {
        $ProgressPreference = $oldProgressPreference
    }
}

$commonUrl = "$($env:WINUPDATE_BASEURL.TrimEnd('/'))/Common.ps1"
$commonCode = Get-BootstrapWebText -Uri $commonUrl
. ([ScriptBlock]::Create($commonCode))

function Show-WumLaunchCommands {
    Write-WumSection 'One-line commands'
    Write-Host 'Recommended elevated PowerShell one-liner with built-in fallback:' -ForegroundColor Yellow
    Write-Host (Get-WumMenuOneLiner -BaseUrl $env:WINUPDATE_BASEURL.TrimEnd('/')) -ForegroundColor White
    Write-Host ''
    Write-Host 'Short form for newer PowerShell:' -ForegroundColor Yellow
    Write-Host "iex (irm '$($env:WINUPDATE_BASEURL.TrimEnd('/'))/menu.ps1')" -ForegroundColor White
    Write-Host ''
    Write-Host 'Older Windows PowerShell fallback:' -ForegroundColor Yellow
    Write-Host "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; iex ((New-Object Net.WebClient).DownloadString('$($env:WINUPDATE_BASEURL.TrimEnd('/'))/menu.ps1'))" -ForegroundColor White
    Write-Host ''
    Write-Host 'README fallback / instructions:' -ForegroundColor Yellow
    Write-Host (Get-WumReadmeUrl -BaseUrl $env:WINUPDATE_BASEURL.TrimEnd('/')) -ForegroundColor White
    Write-Host ''
    Write-Host 'Custom web mirror for this session:' -ForegroundColor Yellow
    Write-Host '$env:WINUPDATE_BASEURL=''https://YOUR-WEB-SERVER/winupdate''; iex (irm "$env:WINUPDATE_BASEURL/menu.ps1")' -ForegroundColor White
}

if (-not (Test-WumAdmin)) {
    Write-WumErrorLine 'Not running as administrator.'
    Write-Host ''
    Write-Host 'Open PowerShell as Administrator and run:' -ForegroundColor Yellow
    Write-Host (Get-WumMenuOneLiner -BaseUrl $env:WINUPDATE_BASEURL.TrimEnd('/')) -ForegroundColor White
    Write-Host ''
    Write-Host 'README fallback:' -ForegroundColor Yellow
    Write-Host (Get-WumReadmeUrl -BaseUrl $env:WINUPDATE_BASEURL.TrimEnd('/')) -ForegroundColor White
    return
}

$menuLog = Start-WumLog -Name 'menu'

try {
    do {
        Clear-Host
        Write-Host 'WinUpdate MSP Helper' -ForegroundColor Cyan
        Write-Host 'Remote-run menu. Scripts execute from the web in memory. Only logs/reports/system changes persist.' -ForegroundColor DarkGray
        Write-Host 'No repo script files are written to the client computer by the menu or helper scripts.' -ForegroundColor DarkGray
        Write-Host "Base URL: $($env:WINUPDATE_BASEURL.TrimEnd('/'))" -ForegroundColor DarkGray
        Write-Host "Log root: $(Get-WumLogPath)" -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '  1) Windows Update - install, no reboot'
        Write-Host '  2) Windows Update - install, reboot only if pending'
        Write-Host '  3) Windows Update + Winget app upgrades - no reboot'
        Write-Host '  4) Winget app upgrades only'
        Write-Host '  5) Install or repair Winget/App Installer'
        Write-Host '  6) Disk health / free-space check'
        Write-Host '  7) System snapshot report'
        Write-Host '  8) Event log error summary'
        Write-Host '  9) Network/VPN connectivity check - asks for IPs/hosts'
        Write-Host ' 10) Network adapter/IP snapshot'
        Write-Host ' 11) Repair Windows components - DISM/SFC, optional WU reset'
        Write-Host ' 12) Install scheduled task for remote-run updates/checks'
        Write-Host ' 13) Open local log folder'
        Write-Host ' 14) Show one-line commands and README fallback'
        Write-Host '  0) Exit'
        Write-Host ''
        $choice = Read-Host 'Select an option'

        try {
            switch ($choice) {
                '1' { Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -Parameters @{ RebootMode = 'Never' } ; Pause-WumConsole }
                '2' { Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -Parameters @{ RebootMode = 'IfNeeded' } ; Pause-WumConsole }
                '3' { Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -Parameters @{ RebootMode = 'Never'; IncludeWinget = $true; InstallWingetIfMissing = $true } ; Pause-WumConsole }
                '4' { Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -Parameters @{ SkipWindowsUpdate = $true; IncludeWinget = $true; InstallWingetIfMissing = $true } ; Pause-WumConsole }
                '5' { Invoke-WumRemoteScript -Name 'Install-Winget.ps1' -Parameters @{ Mode = 'Repair' } ; Pause-WumConsole }
                '6' { Invoke-WumRemoteScript -Name 'DiskCheck.ps1' ; Pause-WumConsole }
                '7' { Invoke-WumRemoteScript -Name 'Get-SystemSnapshot.ps1' ; Pause-WumConsole }
                '8' { Invoke-WumRemoteScript -Name 'Get-EventSummary.ps1' ; Pause-WumConsole }
                '9' { Invoke-WumRemoteScript -Name 'Test-NetworkConnectivity.ps1' ; Pause-WumConsole }
                '10' { Invoke-WumRemoteScript -Name 'Get-NetworkInfo.ps1' ; Pause-WumConsole }
                '11' {
                    $repairParameters = @{}
                    $reset = Read-Host 'Reset Windows Update cache too? This renames SoftwareDistribution/catroot2. (y/N)'
                    if ($reset -match '^(y|yes)$') { $repairParameters.ResetWindowsUpdate = $true }
                    $dns = Read-Host 'Flush DNS cache too? (y/N)'
                    if ($dns -match '^(y|yes)$') { $repairParameters.FlushDns = $true }
                    Invoke-WumRemoteScript -Name 'Repair-Windows.ps1' -Parameters $repairParameters
                    Pause-WumConsole
                }
                '12' {
                    $taskParameters = @{}
                    Write-WumSection 'Scheduled task setup'
                    Write-Host 'Actions: UpdateNoReboot, UpdateIfNeeded, UpdateWithWingetNoReboot, WingetOnly, SystemSnapshot, DiskCheck' -ForegroundColor DarkGray
                    $taskAction = Read-Host 'Task action [UpdateIfNeeded]'
                    if (-not [string]::IsNullOrWhiteSpace($taskAction)) { $taskParameters.TaskAction = $taskAction.Trim() }
                    $freq = Read-Host 'Frequency: Daily, Weekly, Startup, Once [Weekly]'
                    if (-not [string]::IsNullOrWhiteSpace($freq)) { $taskParameters.Frequency = $freq.Trim() }
                    $at = Read-Host 'Time, 24-hour HH:mm [03:00]'
                    if (-not [string]::IsNullOrWhiteSpace($at)) { $taskParameters.At = $at.Trim() }
                    $day = Read-Host 'Day of week for weekly tasks [Sunday]'
                    if (-not [string]::IsNullOrWhiteSpace($day)) { $taskParameters.DayOfWeek = $day.Trim() }
                    $name = Read-Host 'Task name [WinUpdate MSP Helper - Remote Updates]'
                    if (-not [string]::IsNullOrWhiteSpace($name)) { $taskParameters.TaskName = $name.Trim() }
                    $currentUser = Read-Host 'Run as current user instead of SYSTEM? Winget works better as current user. (y/N)'
                    if ($currentUser -match '^(y|yes)$') { $taskParameters.RunAsCurrentUser = $true }
                    $force = Read-Host 'Replace existing task without another prompt? (y/N)'
                    if ($force -match '^(y|yes)$') { $taskParameters.Force = $true }
                    Invoke-WumRemoteScript -Name 'Install-Task.ps1' -Parameters $taskParameters
                    Pause-WumConsole
                }
                '13' {
                    $logPath = Get-WumLogPath
                    New-WumDirectory -Path $logPath
                    Invoke-Item $logPath
                    Pause-WumConsole
                }
                '14' { Show-WumLaunchCommands ; Pause-WumConsole }
                '0' { }
                default { Write-WumWarn 'Invalid option.' ; Pause-WumConsole }
            }
        } catch {
            Write-WumErrorLine $_.Exception.Message
            Pause-WumConsole
        }
    } while ($choice -ne '0')
} finally {
    Stop-WumLog
}
