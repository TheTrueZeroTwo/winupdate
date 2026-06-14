# WinUpdate MSP Helper - shared in-memory helpers
# This file is intended to be loaded from a trusted raw HTTPS URL.

if ($global:WinUpdateMspCommonLoaded) { return }
$global:WinUpdateMspCommonLoaded = $true

$global:WinUpdateMspDefaultBaseUrl = 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main'
$global:WinUpdateMspAllowedScripts = @(
    'Common.ps1',
    'menu.ps1',
    'Invoke-WinUpdate.ps1',
    'Install-Winget.ps1',
    'DiskCheck.ps1',
    'Get-SystemSnapshot.ps1',
    'Get-EventSummary.ps1',
    'Get-NetworkInfo.ps1',
    'Repair-Windows.ps1',
    'Install-Task.ps1',
    'Test-NetworkConnectivity.ps1'
)

function Set-WumTls {
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.SecurityProtocolType]::Tls12 -bor
            [Net.SecurityProtocolType]::Tls11 -bor
            [Net.SecurityProtocolType]::Tls
    } catch {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
    }
}

function Get-WumBaseUrl {
    if ($env:WINUPDATE_BASEURL -and -not [string]::IsNullOrWhiteSpace($env:WINUPDATE_BASEURL)) {
        return $env:WINUPDATE_BASEURL.TrimEnd('/')
    }
    return $global:WinUpdateMspDefaultBaseUrl
}

function Get-WumRootPath {
    if ($env:ProgramData -and -not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        return (Join-Path $env:ProgramData 'WinUpdateMspHelper')
    }
    return (Join-Path $env:TEMP 'WinUpdateMspHelper')
}

function Get-WumLogPath {
    return (Join-Path (Get-WumRootPath) 'Logs')
}

function New-WumDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Start-WumLog {
    param([string]$Name = 'session')
    $logRoot = Get-WumLogPath
    New-WumDirectory -Path $logRoot
    $safeName = ($Name -replace '[^a-zA-Z0-9_.-]', '_')
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $path = Join-Path $logRoot ("$stamp-$safeName.log")
    $global:WinUpdateMspLastLog = $path
    try {
        Start-Transcript -Path $path -Append -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning "Unable to start transcript log: $($_.Exception.Message)"
    }
    Write-Host "Log: $path" -ForegroundColor DarkGray
    return $path
}

function Stop-WumLog {
    try { Stop-Transcript | Out-Null } catch { }
}

function Write-WumSection {
    param([Parameter(Mandatory = $true)][string]$Title)
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan
}

function Write-WumStep {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-WumWarn {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-WumErrorLine {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[X] $Message" -ForegroundColor Red
}

function Test-WumAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Assert-WumAdmin {
    if (-not (Test-WumAdmin)) {
        throw "This helper must be run from an elevated PowerShell session.`nRight-click PowerShell and choose Run as administrator, then run the one-line command again."
    }
}

function Get-WumWebText {
    param([Parameter(Mandatory = $true)][string]$Uri)
    Set-WumTls
    $oldProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        try {
            $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -ErrorAction Stop
            return [string]$response.Content
        } catch {
            $wc = New-Object System.Net.WebClient
            try {
                $wc.Headers.Add('User-Agent', 'WinUpdateMspHelper/1.0')
                return $wc.DownloadString($Uri)
            } finally {
                $wc.Dispose()
            }
        }
    } finally {
        $ProgressPreference = $oldProgressPreference
    }
}

function ConvertTo-WumParameterHashtable {
    param([object[]]$ArgumentList = @())

    $parameters = @{}
    for ($index = 0; $index -lt $ArgumentList.Count; $index++) {
        $token = $ArgumentList[$index]
        if (-not ($token -is [string]) -or $token -notmatch '^-([A-Za-z][A-Za-z0-9_-]*)$') {
            throw "Unsupported positional remote-script argument at index ${index}: $token. Use named parameters."
        }

        $name = $Matches[1]
        $hasValue = $false
        $value = $true

        if (($index + 1) -lt $ArgumentList.Count) {
            $next = $ArgumentList[$index + 1]
            if (-not (($next -is [string]) -and $next -match '^-([A-Za-z][A-Za-z0-9_-]*)$')) {
                $value = $next
                $hasValue = $true
            }
        }

        $parameters[$name] = $value
        if ($hasValue) { $index++ }
    }

    return $parameters
}

function Invoke-WumRemoteScript {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Invoke-WinUpdate.ps1','Install-Winget.ps1','DiskCheck.ps1','Get-SystemSnapshot.ps1','Get-EventSummary.ps1','Get-NetworkInfo.ps1','Repair-Windows.ps1','Install-Task.ps1','Test-NetworkConnectivity.ps1','menu.ps1')]
        [string]$Name,

        [hashtable]$Parameters = @{},

        # Backward compatibility for older menu/task calls. Named tokens are
        # converted to a hashtable before invoking the remote script.
        [object[]]$ArgumentList = @()
    )

    if ($Parameters.Count -gt 0 -and $ArgumentList.Count -gt 0) {
        throw 'Use either -Parameters or -ArgumentList, not both.'
    }

    $baseUrl = Get-WumBaseUrl
    $url = "$baseUrl/$Name"
    Write-WumSection "Loading remote script: $Name"
    Write-Host "Source: $url" -ForegroundColor DarkGray
    $code = Get-WumWebText -Uri $url
    if ([string]::IsNullOrWhiteSpace($code)) {
        throw "Remote script was empty: $url"
    }

    $scriptBlock = [ScriptBlock]::Create($code)

    if ($Parameters.Count -gt 0) {
        & $scriptBlock @Parameters
        return
    }

    if ($ArgumentList.Count -gt 0) {
        $convertedParameters = ConvertTo-WumParameterHashtable -ArgumentList $ArgumentList
        & $scriptBlock @convertedParameters
        return
    }

    & $scriptBlock
}

function Invoke-WumNativeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [switch]$IgnoreExitCode
    )

    Write-Host (">> {0} {1}" -f $FilePath, ($Arguments -join ' ')) -ForegroundColor DarkGray
    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and -not $IgnoreExitCode) {
        throw "Command failed with exit code ${exitCode}: $FilePath $($Arguments -join ' ')"
    }
    return $exitCode
}

function Test-WumPendingReboot {
    $pending = $false
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )

    foreach ($path in $paths) {
        if (Test-Path $path) { $pending = $true }
    }

    try {
        $sessionManager = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
        if ($sessionManager.PendingFileRenameOperations) { $pending = $true }
    } catch { }

    try {
        $active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction Stop).ComputerName
        $pendingName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction Stop).ComputerName
        if ($active -and $pendingName -and ($active -ne $pendingName)) { $pending = $true }
    } catch { }

    return $pending
}

function Get-WumOsSummary {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Caption      = $os.Caption
            Version      = $os.Version
            BuildNumber  = $os.BuildNumber
            InstallDate  = $os.InstallDate
            LastBoot     = $os.LastBootUpTime
            UptimeDays   = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
        }
    } catch {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Caption      = 'Unknown'
            Version      = 'Unknown'
            BuildNumber  = 'Unknown'
            InstallDate  = $null
            LastBoot     = $null
            UptimeDays   = $null
        }
    }
}

function Save-WumJson {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $root = Join-Path (Get-WumRootPath) 'Reports'
    New-WumDirectory -Path $root
    $safeName = ($Name -replace '[^a-zA-Z0-9_.-]', '_')
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $path = Join-Path $root ("$stamp-$safeName.json")
    $InputObject | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding UTF8
    Write-Host "Report: $path" -ForegroundColor DarkGray
    return $path
}

function Get-WumMenuOneLiner {
    param([string]$BaseUrl = (Get-WumBaseUrl))

    $base = $BaseUrl.TrimEnd('/')
    $u = "$base/menu.ps1"
    $r = "$base/README.md"

    return ('$u=' + "'$u'" + '; $r=' + "'$r'" + '; try { iex (irm $u) } catch { try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; iex ((New-Object Net.WebClient).DownloadString($u)) } catch { Write-Host ("Failed to load menu. Open README: " + $r) -ForegroundColor Yellow; throw } }')
}

function Get-WumReadmeUrl {
    param([string]$BaseUrl = (Get-WumBaseUrl))
    return "$($BaseUrl.TrimEnd('/'))/README.md"
}

function Pause-WumConsole {
    param([string]$Message = 'Press Enter to continue')
    try { [void](Read-Host $Message) } catch { }
}

Set-WumTls
