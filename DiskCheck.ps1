param(
    [int]$LowFreePercent = 15
)

$ErrorActionPreference = 'Stop'
$baseUrl = if ($env:WINUPDATE_BASEURL) { $env:WINUPDATE_BASEURL.TrimEnd('/') } else { 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main' }
$commonCode = (New-Object Net.WebClient).DownloadString("$baseUrl/Common.ps1")
. ([ScriptBlock]::Create($commonCode))

$log = Start-WumLog -Name 'disk-check'
try {
    Assert-WumAdmin
    Write-WumSection 'Disk health and free space'

    $volumes = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        $sizeGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
        $freeGB = if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 2) } else { 0 }
        $freePct = if ($_.Size -gt 0) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 2) } else { 0 }
        [PSCustomObject]@{
            Drive       = $_.DeviceID
            Label       = $_.VolumeName
            FileSystem  = $_.FileSystem
            SizeGB      = $sizeGB
            FreeGB      = $freeGB
            FreePercent = $freePct
            LowFree     = ($freePct -lt $LowFreePercent)
        }
    }

    $physical = Get-CimInstance Win32_DiskDrive | ForEach-Object {
        [PSCustomObject]@{
            Index        = $_.Index
            Model        = $_.Model
            Serial       = $_.SerialNumber
            Interface    = $_.InterfaceType
            MediaType    = $_.MediaType
            SizeGB       = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { $null }
            Status       = $_.Status
            Partitions   = $_.Partitions
        }
    }

    $storageDisks = @()
    try {
        $storageDisks = Get-PhysicalDisk | Select-Object FriendlyName, SerialNumber, MediaType, BusType, HealthStatus, OperationalStatus, Size
    } catch {
        Write-WumWarn "Get-PhysicalDisk failed: $($_.Exception.Message)"
    }

    Write-WumSection 'Volumes'
    $volumes | Format-Table -AutoSize

    Write-WumSection 'Physical disks'
    $physical | Format-Table -AutoSize

    if ($storageDisks) {
        Write-WumSection 'Storage health'
        $storageDisks | Format-Table -AutoSize
    }

    $report = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Date         = Get-Date
        Volumes      = $volumes
        Disks        = $physical
        StorageDisks = $storageDisks
    }
    Save-WumJson -InputObject $report -Name 'disk-check' | Out-Null

    $low = @($volumes | Where-Object { $_.LowFree })
    if ($low.Count -gt 0) {
        Write-WumWarn "Low disk space found on: $($low.Drive -join ', ')"
    } else {
        Write-WumStep 'No low free-space volumes found.'
    }
} finally {
    Stop-WumLog
}
