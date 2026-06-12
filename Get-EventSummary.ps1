param(
    [int]$Hours = 24,
    [int]$MaxEvents = 80
)

$ErrorActionPreference = 'Stop'
$baseUrl = if ($env:WINUPDATE_BASEURL) { $env:WINUPDATE_BASEURL.TrimEnd('/') } else { 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main' }
$commonCode = (New-Object Net.WebClient).DownloadString("$baseUrl/Common.ps1")
. ([ScriptBlock]::Create($commonCode))

$log = Start-WumLog -Name 'event-summary'
try {
    Assert-WumAdmin
    Write-WumSection "Event log errors and warnings - last $Hours hours"

    $start = (Get-Date).AddHours(-1 * $Hours)
    $logs = @('System','Application')
    $events = foreach ($logName in $logs) {
        try {
            Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=$start; Level=@(1,2,3)} -ErrorAction Stop |
                Select-Object TimeCreated, LogName, LevelDisplayName, ProviderName, Id, Message
        } catch {
            Write-WumWarn "Could not read $logName log: $($_.Exception.Message)"
        }
    }

    $events = @($events | Sort-Object TimeCreated -Descending | Select-Object -First $MaxEvents)
    $grouped = $events | Group-Object LogName, ProviderName, Id, LevelDisplayName | Sort-Object Count -Descending | Select-Object -First 25

    Write-WumSection 'Top repeated events'
    $grouped | Select-Object Count, Name | Format-Table -AutoSize

    Write-WumSection 'Newest events'
    $events | Select-Object TimeCreated, LogName, LevelDisplayName, ProviderName, Id, @{Name='Message';Expression={($_.Message -replace "`r|`n", ' ') -replace '\s+', ' '}} | Format-Table -Wrap -AutoSize

    $report = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Date         = Get-Date
        Since        = $start
        TopRepeated  = $grouped
        NewestEvents = $events
    }
    Save-WumJson -InputObject $report -Name 'event-summary' | Out-Null
} finally {
    Stop-WumLog
}
