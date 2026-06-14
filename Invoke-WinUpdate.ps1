param(
    [ValidateSet('Never','IfNeeded','Always')]
    [string]$RebootMode = 'Never',

    [switch]$IncludeWinget,
    [switch]$InstallWingetIfMissing,
    [switch]$SkipWindowsUpdate,
    [switch]$SkipModuleInstall,
    [switch]$SkipMicrosoftUpdate
)

$ErrorActionPreference = 'Stop'

$baseUrl = if ($env:WINUPDATE_BASEURL) { $env:WINUPDATE_BASEURL.TrimEnd('/') } else { 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main' }
$commonCode = (New-Object Net.WebClient).DownloadString("$baseUrl/Common.ps1")
. ([ScriptBlock]::Create($commonCode))

$policyStatus = Set-WumProcessExecutionPolicy

$log = Start-WumLog -Name 'windows-update'
try {
    Assert-WumAdmin
    Write-WumSection 'PowerShell execution policy'
    if ($policyStatus.Success) {
        Write-WumStep "Process-only policy: $($policyStatus.Process); effective policy: $($policyStatus.Effective)"
        Write-Host 'This change lasts only for the current PowerShell process.' -ForegroundColor DarkGray
        if ($policyStatus.MachinePolicy -notin @('', 'Undefined') -or $policyStatus.UserPolicy -notin @('', 'Undefined')) {
            Write-WumWarn "Group Policy is configured (MachinePolicy=$($policyStatus.MachinePolicy), UserPolicy=$($policyStatus.UserPolicy)). It may override Process scope."
        }
    } else {
        Write-WumWarn "Could not set process-only Bypass: $($policyStatus.Error)"
    }

    Write-WumSection 'Windows update helper'
    Get-WumOsSummary | Format-List

    if (-not $SkipWindowsUpdate) {
        Write-WumSection 'PowerShell module: PSWindowsUpdate'
        if (-not $SkipModuleInstall) {
            try {
                Write-WumStep 'Ensuring NuGet package provider is available'
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
            } catch {
                Write-WumWarn "NuGet provider check failed: $($_.Exception.Message)"
            }

            try {
                Write-WumStep 'Ensuring PSGallery is trusted for this install'
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            } catch {
                Write-WumWarn "Could not set PSGallery trust policy: $($_.Exception.Message)"
            }

            Write-WumStep 'Installing or updating PSWindowsUpdate'
            Install-Module -Name PSWindowsUpdate -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
        }

        try {
            Import-Module PSWindowsUpdate -Force -ErrorAction Stop
        } catch {
            $policySummary = (Get-ExecutionPolicy -List | Out-String).Trim()
            throw "PSWindowsUpdate could not be imported. Process-scope Bypass was requested, but a Group Policy or security control may still be blocking module scripts.`n$policySummary`nOriginal error: $($_.Exception.Message)"
        }

        if (-not $SkipMicrosoftUpdate) {
            try {
                Write-WumStep 'Registering Microsoft Update service'
                Add-WUServiceManager -MicrosoftUpdate -Confirm:$false -ErrorAction Stop | Out-Null
            } catch {
                Write-WumWarn "Microsoft Update service registration warning: $($_.Exception.Message)"
            }
        }

        Write-WumStep 'Scanning available updates'
        try {
            if ($SkipMicrosoftUpdate) {
                Get-WindowsUpdate -ErrorAction Stop | Format-Table -AutoSize
            } else {
                Get-WindowsUpdate -MicrosoftUpdate -ErrorAction Stop | Format-Table -AutoSize
            }
        } catch {
            Write-WumWarn "Update scan warning: $($_.Exception.Message)"
        }

        Write-WumStep 'Installing Windows/Microsoft updates without automatic reboot'
        if ($SkipMicrosoftUpdate) {
            Install-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
        } else {
            Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
        }
    } else {
        Write-WumWarn 'Skipping Windows Update by request.'
    }

    if ($IncludeWinget) {
        Write-WumSection 'Winget application upgrades'
        $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        if (-not $winget -and $InstallWingetIfMissing) {
            Invoke-WumRemoteScript -Name 'Install-Winget.ps1' -Parameters @{ Mode = 'Ensure' }
            $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        }

        if (-not $winget) {
            Write-WumWarn 'winget.exe was not found. Use menu option 5 to install or repair App Installer.'
        } else {
            Write-WumStep 'Updating winget sources'
            Invoke-WumNativeCommand -FilePath $winget.Source -Arguments @('source','update') -IgnoreExitCode | Out-Null

            Write-WumStep 'Upgrading installed applications with winget'
            $args = @(
                'upgrade','--all',
                '--silent',
                '--accept-source-agreements',
                '--accept-package-agreements',
                '--disable-interactivity'
            )
            $exit = Invoke-WumNativeCommand -FilePath $winget.Source -Arguments $args -IgnoreExitCode
            if ($exit -ne 0) {
                Write-WumWarn "winget exited with code $exit. Some apps may require manual handling. Review the log."
            }
        }
    }

    Write-WumSection 'Reboot status'
    $pendingReboot = Test-WumPendingReboot
    Write-Host "Pending reboot: $pendingReboot"

    if ($RebootMode -eq 'Always') {
        Write-WumWarn 'RebootMode=Always. Restarting now.'
        Restart-Computer -Force
    } elseif ($RebootMode -eq 'IfNeeded' -and $pendingReboot) {
        Write-WumWarn 'A reboot is pending. Restarting now.'
        Restart-Computer -Force
    } elseif ($RebootMode -eq 'IfNeeded') {
        Write-WumStep 'No reboot is pending. Not restarting.'
    } else {
        Write-WumStep 'RebootMode=Never. Not restarting.'
    }
} finally {
    Stop-WumLog
}
