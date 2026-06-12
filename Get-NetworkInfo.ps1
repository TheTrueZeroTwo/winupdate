param(
    [string[]]$Targets = @('1.1.1.1','8.8.8.8','microsoft.com')
)

$ErrorActionPreference = 'Stop'
$baseUrl = if ($env:WINUPDATE_BASEURL) { $env:WINUPDATE_BASEURL.TrimEnd('/') } else { 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main' }
$commonCode = (New-Object Net.WebClient).DownloadString("$baseUrl/Common.ps1")
. ([ScriptBlock]::Create($commonCode))

$log = Start-WumLog -Name 'network-check'
try {
    Assert-WumAdmin
    Write-WumSection 'Network quick check'

    $adapters = Get-NetAdapter | Sort-Object Status, Name | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress
    $ip = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, IPv4DefaultGateway, DNSServer
    $routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object InterfaceAlias, NextHop, RouteMetric, ifMetric

    Write-WumSection 'Adapters'
    $adapters | Format-Table -AutoSize

    Write-WumSection 'IP configuration'
    $ip | Format-List

    Write-WumSection 'Default routes'
    $routes | Format-Table -AutoSize

    $pingResults = foreach ($target in $Targets) {
        try {
            $ok = Test-Connection -ComputerName $target -Count 2 -Quiet -ErrorAction Stop
            [PSCustomObject]@{ Target=$target; Ping=$ok }
        } catch {
            [PSCustomObject]@{ Target=$target; Ping=$false }
        }
    }

    Write-WumSection 'Connectivity tests'
    $pingResults | Format-Table -AutoSize

    Write-WumSection 'DNS client cache sample'
    try { Get-DnsClientCache | Select-Object -First 20 Entry, Name, Type, Data | Format-Table -AutoSize } catch { Write-WumWarn $_.Exception.Message }

    $report = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Date         = Get-Date
        Adapters     = $adapters
        IPConfig     = $ip
        DefaultRoutes = $routes
        Pings        = $pingResults
    }
    Save-WumJson -InputObject $report -Name 'network-check' | Out-Null
} finally {
    Stop-WumLog
}
