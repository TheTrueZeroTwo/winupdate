param(
    [string]$TaskName = 'WinUpdate MSP Helper - Remote Updates',

    [ValidateSet('Daily','Weekly','Startup','Once')]
    [string]$Frequency = 'Weekly',

    [string]$At = '03:00',

    [ValidateSet('Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday')]
    [string]$DayOfWeek = 'Sunday',

    [ValidateSet('UpdateNoReboot','UpdateIfNeeded','UpdateWithWingetNoReboot','WingetOnly','SystemSnapshot','DiskCheck')]
    [string]$TaskAction = 'UpdateIfNeeded',

    [switch]$RunAsCurrentUser,
    [switch]$Force,
    [string]$BaseUrl
)

$ErrorActionPreference = 'Stop'
if ($BaseUrl -and -not [string]::IsNullOrWhiteSpace($BaseUrl)) { $env:WINUPDATE_BASEURL = $BaseUrl.TrimEnd('/') }
$baseUrl = if ($env:WINUPDATE_BASEURL) { $env:WINUPDATE_BASEURL.TrimEnd('/') } else { 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main' }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls } catch { }
$wc = New-Object Net.WebClient
try {
    $wc.Headers.Add('User-Agent', 'WinUpdateMspHelper/1.0')
    $commonCode = $wc.DownloadString("$baseUrl/Common.ps1")
} finally {
    $wc.Dispose()
}
. ([ScriptBlock]::Create($commonCode))

function Get-WumScheduledPayload {
    param(
        [Parameter(Mandatory=$true)][string]$BaseUrl,
        [Parameter(Mandatory=$true)][string]$TaskAction
    )

    $scriptName = $null
    $parametersExpr = '@{}'

    switch ($TaskAction) {
        'UpdateNoReboot' {
            $scriptName = 'Invoke-WinUpdate.ps1'
            $parametersExpr = "@{ RebootMode = 'Never' }"
        }
        'UpdateIfNeeded' {
            $scriptName = 'Invoke-WinUpdate.ps1'
            $parametersExpr = "@{ RebootMode = 'IfNeeded' }"
        }
        'UpdateWithWingetNoReboot' {
            $scriptName = 'Invoke-WinUpdate.ps1'
            $parametersExpr = "@{ RebootMode = 'Never'; IncludeWinget = `$true; InstallWingetIfMissing = `$true }"
        }
        'WingetOnly' {
            $scriptName = 'Invoke-WinUpdate.ps1'
            $parametersExpr = "@{ SkipWindowsUpdate = `$true; IncludeWinget = `$true; InstallWingetIfMissing = `$true }"
        }
        'SystemSnapshot' {
            $scriptName = 'Get-SystemSnapshot.ps1'
            $parametersExpr = '@{}'
        }
        'DiskCheck' {
            $scriptName = 'DiskCheck.ps1'
            $parametersExpr = '@{}'
        }
        default { throw "Unsupported task action: $TaskAction" }
    }

    $escapedBase = $BaseUrl.Replace("'", "''")
    $payload = @"
`$ErrorActionPreference='Stop'
try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls } catch { }
`$env:WINUPDATE_BASEURL='$escapedBase'
`$wc=New-Object Net.WebClient
try {
    `$wc.Headers.Add('User-Agent','WinUpdateMspHelperScheduledTask/1.0')
    `$common=`$wc.DownloadString('$escapedBase/Common.ps1')
} finally {
    try { `$wc.Dispose() } catch { }
}
. ([ScriptBlock]::Create(`$common))
Invoke-WumRemoteScript -Name '$scriptName' -Parameters $parametersExpr
"@
    return $payload
}

function New-WumTaskTrigger {
    param(
        [string]$Frequency,
        [string]$At,
        [string]$DayOfWeek
    )

    switch ($Frequency) {
        'Daily' {
            $time = [datetime]::Parse($At)
            return New-ScheduledTaskTrigger -Daily -At $time
        }
        'Weekly' {
            $time = [datetime]::Parse($At)
            return New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DayOfWeek -At $time
        }
        'Startup' {
            return New-ScheduledTaskTrigger -AtStartup
        }
        'Once' {
            $when = [datetime]::Parse($At)
            if ($when -lt (Get-Date)) { $when = $when.AddDays(1) }
            return New-ScheduledTaskTrigger -Once -At $when
        }
        default { throw "Unsupported frequency: $Frequency" }
    }
}

$log = Start-WumLog -Name 'install-scheduled-task'
try {
    Assert-WumAdmin
    Write-WumSection 'Install scheduled task'
    Write-Host 'The scheduled task stores only the task definition and a PowerShell encoded command.' -ForegroundColor DarkGray
    Write-Host 'It does not save the repo scripts locally. At run time it loads Common.ps1 and the selected action from the configured web URL.' -ForegroundColor DarkGray

    Write-Host "Task name: $TaskName"
    Write-Host "Action:    $TaskAction"
    Write-Host "Schedule:  $Frequency $At $DayOfWeek"
    Write-Host "Base URL:  $baseUrl"

    $payload = Get-WumScheduledPayload -BaseUrl $baseUrl -TaskAction $TaskAction
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    $taskActionObj = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
    $trigger = New-WumTaskTrigger -Frequency $Frequency -At $At -DayOfWeek $DayOfWeek

    $settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew

    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        if (-not $Force) {
            $replace = Read-Host "Scheduled task already exists. Replace it? (y/N)"
            if ($replace -notmatch '^(y|yes)$') {
                Write-WumWarn 'Leaving existing scheduled task unchanged.'
                return
            }
        }
        Write-WumStep 'Removing existing scheduled task'
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    }

    if ($RunAsCurrentUser) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-WumWarn 'Registering as the current interactive user. This is better for winget actions, but it may not run when nobody is logged on.'
        $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Highest
    } else {
        Write-WumStep 'Registering as SYSTEM with highest privileges'
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    }

    Register-ScheduledTask -TaskName $TaskName -Action $taskActionObj -Trigger $trigger -Settings $settings -Principal $principal -Description "WinUpdate MSP Helper remote action: $TaskAction from $baseUrl" -Force | Out-Null

    Write-WumSection 'Scheduled task installed'
    Get-ScheduledTask -TaskName $TaskName | Format-List TaskName, TaskPath, State, Author, Description
    Write-Host ''
    Write-Host 'Run now from an elevated PowerShell prompt:' -ForegroundColor Yellow
    Write-Host "Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor White
} finally {
    Stop-WumLog
}
