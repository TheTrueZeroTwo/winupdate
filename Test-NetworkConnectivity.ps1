param(
    [string[]]$Targets = @(),
    [int[]]$Ports = @(443,3389,445,53,80),
    [switch]$SkipTrace,
    [switch]$NoPrompt
)

$ErrorActionPreference = 'Stop'
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

function Split-WumInputList {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    return @($Text -split '[,;\s]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
}

function Convert-WumPortList {
    param([object[]]$Values)
    $out = @()
    foreach ($v in $Values) {
        $n = 0
        if ([int]::TryParse([string]$v, [ref]$n) -and $n -gt 0 -and $n -le 65535) { $out += $n }
    }
    return @($out | Select-Object -Unique)
}

function Test-WumIsIpAddress {
    param([string]$Value)
    $addr = $null
    return [System.Net.IPAddress]::TryParse($Value, [ref]$addr)
}

function Resolve-WumTargetAddress {
    param([string]$Target)
    if (Test-WumIsIpAddress -Value $Target) { return $Target }
    try {
        $resolved = Resolve-DnsName -Name $Target -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
        if ($resolved) { return $resolved.IPAddress }
    } catch { }
    try {
        $entry = [System.Net.Dns]::GetHostEntry($Target)
        $addr = $entry.AddressList | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1
        if ($addr) { return $addr.IPAddressToString }
    } catch { }
    return $null
}

function Test-WumTcpPort {
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][int]$Port,
        [int]$TimeoutMs = 3000
    )
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($Target, $Port, $null, $null)
        $success = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $success) { return $false }
        $client.EndConnect($iar)
        return $client.Connected
    } catch {
        return $false
    } finally {
        try { $client.Close() } catch { }
    }
}

function Get-WumVpnLikeAdapters {
    $patterns = 'vpn|wireguard|tailscale|zerotier|openvpn|tap|tun|anyconnect|cisco|fortinet|forticlient|globalprotect|pangp|sonicwall|netextender|zscaler|checkpoint|pulse|juniper|nord|surfshark|proton|mullvad'
    try {
        Get-NetAdapter -ErrorAction Stop |
            Where-Object { $_.Name -match $patterns -or $_.InterfaceDescription -match $patterns } |
            Sort-Object Status, Name |
            Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, ifIndex
    } catch {
        @()
    }
}

$log = Start-WumLog -Name 'network-vpn-connectivity'
try {
    Assert-WumAdmin
    Write-WumSection 'Network / VPN connectivity check'
    Write-Host 'This checks adapters, default routes, DNS, ping, TCP ports, and optional trace routes.' -ForegroundColor DarkGray
    Write-Host 'Use this for VPN clients, site-to-site networks, RDP hosts, domain controllers, file servers, printers, and gateways.' -ForegroundColor DarkGray

    if (($Targets.Count -eq 0) -and (-not $NoPrompt)) {
        Write-Host ''
        Write-Host 'Enter one or more IPs or hostnames separated by spaces or commas.' -ForegroundColor Yellow
        Write-Host 'Examples: 10.0.0.1 10.0.10.5 server01.domain.local vpn.company.com 8.8.8.8' -ForegroundColor DarkGray
        $targetInput = Read-Host 'Targets to test'
        $Targets = Split-WumInputList -Text $targetInput
    }

    if (($Ports.Count -eq 0) -and (-not $NoPrompt)) {
        $Ports = @(443,3389,445,53,80)
    } elseif (-not $NoPrompt) {
        Write-Host ''
        $portInput = Read-Host "TCP ports to test, comma/space separated [default: $($Ports -join ',')]"
        $customPorts = Convert-WumPortList -Values (Split-WumInputList -Text $portInput)
        if ($customPorts.Count -gt 0) { $Ports = @($customPorts) }
    }

    if ($Targets.Count -eq 0) {
        Write-WumWarn 'No custom targets were provided. Using public defaults and any detected default gateways/DNS servers.'
        $autoTargets = @('1.1.1.1','8.8.8.8','microsoft.com')
        try {
            $autoTargets += @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | Select-Object -ExpandProperty NextHop)
        } catch { }
        try {
            $autoTargets += @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
        } catch { }
        $Targets = @($autoTargets | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    }

    $Targets = @($Targets | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    $Ports = Convert-WumPortList -Values $Ports

    Write-WumSection 'Active adapters'
    $adapters = @()
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop | Sort-Object Status, Name | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, ifIndex)
        $adapters | Format-Table -AutoSize
    } catch {
        Write-WumWarn "Could not read adapters: $($_.Exception.Message)"
    }

    Write-WumSection 'VPN-like adapters'
    $vpnAdapters = @(Get-WumVpnLikeAdapters)
    if ($vpnAdapters.Count -gt 0) {
        $vpnAdapters | Format-Table -AutoSize
    } else {
        Write-WumWarn 'No VPN-like adapter names/descriptions were detected. This does not always mean no VPN is active.'
    }

    Write-WumSection 'IP configuration'
    $ipConfig = @()
    try {
        $ipConfig = @(Get-NetIPConfiguration | Select-Object InterfaceAlias, InterfaceIndex, IPv4Address, IPv6Address, IPv4DefaultGateway, DNSServer)
        $ipConfig | Format-List
    } catch {
        Write-WumWarn "Could not read IP configuration: $($_.Exception.Message)"
    }

    Write-WumSection 'Default routes'
    $routes = @()
    try {
        $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Sort-Object RouteMetric, ifMetric | Select-Object InterfaceAlias, InterfaceIndex, NextHop, RouteMetric, ifMetric)
        $routes | Format-Table -AutoSize
    } catch {
        Write-WumWarn "Could not read default routes: $($_.Exception.Message)"
    }

    Write-WumSection 'DNS server quick test'
    $dnsServers = @()
    try {
        $dnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.ServerAddresses.Count -gt 0 } |
            Select-Object InterfaceAlias, InterfaceIndex, ServerAddresses)
        $dnsServers | Format-Table -AutoSize
    } catch {
        Write-WumWarn "Could not read DNS client server list: $($_.Exception.Message)"
    }

    Write-WumSection 'Target tests'
    $results = @()
    foreach ($target in $Targets) {
        Write-Host ''
        Write-Host "Target: $target" -ForegroundColor Cyan
        $resolvedIp = Resolve-WumTargetAddress -Target $target
        if ($resolvedIp) { Write-Host "Resolved IP: $resolvedIp" -ForegroundColor DarkGray } else { Write-WumWarn 'Could not resolve target to an IP address.' }

        $pingOk = $false
        $pingMs = $null
        try {
            $pingReply = Test-Connection -ComputerName $target -Count 2 -ErrorAction Stop | Select-Object -First 1
            if ($pingReply) {
                $pingOk = $true
                if ($pingReply.ResponseTime -ne $null) { $pingMs = $pingReply.ResponseTime }
            }
        } catch { }
        Write-Host ("Ping: {0}{1}" -f $pingOk, $(if ($pingMs -ne $null) { " (${pingMs}ms)" } else { '' }))

        $route = $null
        if ($resolvedIp) {
            try {
                $route = Find-NetRoute -RemoteIPAddress $resolvedIp -ErrorAction Stop | Select-Object -First 1 InterfaceAlias, InterfaceIndex, NextHop, RouteMetric, ifMetric, Route
                if ($route) { $route | Format-List }
            } catch {
                Write-WumWarn "Could not determine route to ${resolvedIp}: $($_.Exception.Message)"
            }
        }

        foreach ($port in $Ports) {
            $tcpOk = Test-WumTcpPort -Target $target -Port $port
            Write-Host ("TCP {0}: {1}" -f $port, $tcpOk)
            $results += [PSCustomObject]@{
                Target      = $target
                ResolvedIP  = $resolvedIp
                Ping        = $pingOk
                PingMs      = $pingMs
                TcpPort     = $port
                TcpOpen     = $tcpOk
                RouteIface  = if ($route) { $route.InterfaceAlias } else { $null }
                RouteNextHop = if ($route) { $route.NextHop } else { $null }
                Date        = Get-Date
            }
        }

        if (-not $SkipTrace) {
            $doTrace = if ($NoPrompt) { $false } else { (Read-Host "Run tracert for $target? Slow on some networks. (y/N)") -match '^(y|yes)$' }
            if ($doTrace) {
                Write-WumSection "Trace route: $target"
                Invoke-WumNativeCommand -FilePath 'tracert.exe' -Arguments @('-d', $target) -IgnoreExitCode | Out-Null
            }
        }
    }

    Write-WumSection 'Summary'
    $results | Sort-Object Target, TcpPort | Format-Table Target, ResolvedIP, Ping, TcpPort, TcpOpen, RouteIface, RouteNextHop -AutoSize

    $report = [PSCustomObject]@{
        ComputerName  = $env:COMPUTERNAME
        Date          = Get-Date
        BaseUrl       = Get-WumBaseUrl
        Targets       = $Targets
        Ports         = $Ports
        Adapters      = $adapters
        VpnAdapters   = $vpnAdapters
        IPConfig      = $ipConfig
        DefaultRoutes = $routes
        DnsServers    = $dnsServers
        Results       = $results
    }
    Save-WumJson -InputObject $report -Name 'network-vpn-connectivity' | Out-Null
} finally {
    Stop-WumLog
}
