param(
    [switch]$SkipDism,
    [switch]$SkipSfc,
    [switch]$ResetWindowsUpdate,
    [switch]$FlushDns
)

$ErrorActionPreference = 'Stop'
$baseUrl = if ($env:WINUPDATE_BASEURL) { $env:WINUPDATE_BASEURL.TrimEnd('/') } else { 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main' }
$commonCode = (New-Object Net.WebClient).DownloadString("$baseUrl/Common.ps1")
. ([ScriptBlock]::Create($commonCode))

$log = Start-WumLog -Name 'repair-windows'
try {
    Assert-WumAdmin
    Write-WumSection 'Windows component repair'

    if (-not $SkipDism) {
        Write-WumStep 'Running DISM component store restorehealth'
        Invoke-WumNativeCommand -FilePath 'dism.exe' -Arguments @('/Online','/Cleanup-Image','/RestoreHealth') -IgnoreExitCode | Out-Null
    }

    if (-not $SkipSfc) {
        Write-WumStep 'Running system file checker'
        Invoke-WumNativeCommand -FilePath 'sfc.exe' -Arguments @('/scannow') -IgnoreExitCode | Out-Null
    }

    if ($ResetWindowsUpdate) {
        Write-WumSection 'Reset Windows Update components'
        $services = @('bits','wuauserv','appidsvc','cryptsvc')
        foreach ($svc in $services) {
            try {
                Write-WumStep "Stopping $svc"
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            } catch { }
        }

        $sd = Join-Path $env:SystemRoot 'SoftwareDistribution'
        $cr = Join-Path $env:SystemRoot 'System32\catroot2'
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        foreach ($path in @($sd,$cr)) {
            if (Test-Path $path) {
                $newName = "$(Split-Path $path -Leaf).bak-$stamp"
                try {
                    Write-WumStep "Renaming $path to $newName"
                    Rename-Item -Path $path -NewName $newName -ErrorAction Stop
                } catch {
                    Write-WumWarn "Could not rename ${path}: $($_.Exception.Message)"
                }
            }
        }

        foreach ($svc in $services) {
            try {
                Write-WumStep "Starting $svc"
                Start-Service -Name $svc -ErrorAction SilentlyContinue
            } catch { }
        }
    } else {
        Write-WumWarn 'Windows Update component reset was skipped. Re-run with -ResetWindowsUpdate if needed.'
    }

    if ($FlushDns) {
        Write-WumStep 'Flushing DNS cache'
        Invoke-WumNativeCommand -FilePath 'ipconfig.exe' -Arguments @('/flushdns') -IgnoreExitCode | Out-Null
    }

    Write-WumSection 'Repair complete'
    Write-Host "Pending reboot: $(Test-WumPendingReboot)"
} finally {
    Stop-WumLog
}
