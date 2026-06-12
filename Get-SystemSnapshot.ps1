param()

$ErrorActionPreference = 'Stop'
$baseUrl = if ($env:WINUPDATE_BASEURL) { $env:WINUPDATE_BASEURL.TrimEnd('/') } else { 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main' }
$commonCode = (New-Object Net.WebClient).DownloadString("$baseUrl/Common.ps1")
. ([ScriptBlock]::Create($commonCode))

$log = Start-WumLog -Name 'system-snapshot'
try {
    Assert-WumAdmin
    Write-WumSection 'System snapshot'

    $os = Get-WumOsSummary
    $bios = Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, SerialNumber, ReleaseDate
    $cs = Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory, Domain, UserName
    $cpu = Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
    $ramGB = if ($cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { $null }
    $hotfixes = @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, Description, InstalledOn, InstalledBy)
    $services = @(Get-Service | Where-Object { $_.Status -ne 'Running' -and $_.StartType -eq 'Automatic' } | Select-Object -First 50 Name, DisplayName, Status, StartType)
    $pendingReboot = Test-WumPendingReboot

    $summary = [PSCustomObject]@{
        OS            = $os
        Computer      = $cs
        RamGB         = $ramGB
        BIOS          = $bios
        CPU           = $cpu
        PendingReboot = $pendingReboot
        RecentHotfix  = $hotfixes
        AutoServicesNotRunning = $services
    }

    Write-WumSection 'OS'
    $os | Format-List
    Write-WumSection 'Computer'
    $cs | Select-Object Manufacturer, Model, Domain, UserName, @{Name='RamGB';Expression={$ramGB}} | Format-List
    Write-WumSection 'BIOS'
    $bios | Format-List
    Write-WumSection 'CPU'
    $cpu | Format-Table -AutoSize
    Write-WumSection 'Recent hotfixes'
    $hotfixes | Format-Table -AutoSize
    Write-WumSection 'Automatic services not running'
    $services | Format-Table -AutoSize
    Write-WumSection 'Pending reboot'
    Write-Host $pendingReboot

    Save-WumJson -InputObject $summary -Name 'system-snapshot' | Out-Null
} finally {
    Stop-WumLog
}
