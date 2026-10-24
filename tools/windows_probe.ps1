param(
    [ValidateSet('Inspect', 'Probe')][string]$Action = 'Inspect',
    [string]$Gateway = '192.168.31.1',
    [string]$Ip = '',
    [int]$InterfaceIndex = 0,
    [ValidateRange(1, 100)][int]$Count = 10,
    [ValidateRange(100, 10000)][int]$TimeoutMs = 1500,
    [ValidateRange(0, 10000)][int]$IntervalMs = 500
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Test-SameSubnet {
    param([string]$Left, [string]$Right, [int]$PrefixLength)
    $leftBytes = [System.Net.IPAddress]::Parse($Left).GetAddressBytes()
    $rightBytes = [System.Net.IPAddress]::Parse($Right).GetAddressBytes()
    for ($byteIndex = 0; $byteIndex -lt 4; $byteIndex++) {
        $bits = [Math]::Min(8, [Math]::Max(0, $PrefixLength - 8 * $byteIndex))
        $mask = (255 -shl (8 - $bits)) -band 255
        if (($leftBytes[$byteIndex] -band $mask) -ne ($rightBytes[$byteIndex] -band $mask)) {
            return $false
        }
    }
    return $true
}

function Get-DirectInterface {
    $candidates = @(
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
            $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource -and
            ($InterfaceIndex -eq 0 -or $_.InterfaceIndex -eq $InterfaceIndex) -and
            $_.IPAddress -ne $Gateway -and
            (Test-SameSubnet $_.IPAddress $Gateway $_.PrefixLength)
        } | Where-Object {
            (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).ConnectionState -eq 'Connected'
        }
    )
    $interfaces = @($candidates | Select-Object -ExpandProperty InterfaceIndex -Unique)
    if ($interfaces.Count -eq 0) {
        throw "No connected IPv4 interface is on the gateway subnet: $Gateway"
    }
    if ($interfaces.Count -gt 1) {
        throw "Multiple interfaces reach the gateway. Specify --interface-index ($($interfaces -join ', '))."
    }
    return $candidates | Sort-Object PrefixLength -Descending | Select-Object -First 1
}

function Get-SelectedRoute {
    param([string]$Destination)
    $found = @(Find-NetRoute -RemoteIPAddress $Destination)
    $route = $found | Where-Object { $_.PSObject.Properties.Name -contains 'NextHop' } | Select-Object -First 1
    $source = $found | Where-Object { $_.PSObject.Properties.Name -contains 'IPAddress' } | Select-Object -First 1
    if ($null -eq $route -or $null -eq $source) { throw 'Route selection returned no usable route.' }
    return @{
        gateway = [string]$route.NextHop
        interface_index = [int]$route.InterfaceIndex
        source_ip = [string]$source.IPAddress
        prefix = [string]$route.DestinationPrefix
    }
}

function Assert-DirectRoute {
    param([string]$Destination, [int]$ExpectedInterface)
    $selected = Get-SelectedRoute $Destination
    if ($selected.gateway -ne $Gateway -or $selected.interface_index -ne $ExpectedInterface) {
        throw "Selected route does not use requested gateway/interface: $($selected | ConvertTo-Json -Compress)"
    }
    return $selected
}

function Get-PingSamples {
    $ping = [System.Net.NetworkInformation.Ping]::new()
    try {
        for ($sampleIndex = 0; $sampleIndex -lt $Count; $sampleIndex++) {
            try {
                $reply = $ping.Send($Ip, $TimeoutMs)
                $rtt = $null
                if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                    $rtt = [double]$reply.RoundtripTime
                }
                @{ rtt_ms = $rtt; detail = [string]$reply.Status }
            } catch {
                @{ rtt_ms = $null; detail = $_.Exception.Message }
            }
            if ($sampleIndex -lt ($Count - 1) -and $IntervalMs -gt 0) {
                Start-Sleep -Milliseconds $IntervalMs
            }
        }
    } finally { $ping.Dispose() }
}

$result = @{ status = 'error'; error = ''; route_verified = $false; route_created = $false; cleanup_status = 'not_needed' }
$createdRoute = $null
$mutex = $null
$ownsMutex = $false
try {
    $parsedGateway = [System.Net.IPAddress]::Parse($Gateway)
    if ($parsedGateway.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Gateway must be IPv4.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $adapter = Get-DirectInterface
    $selectedIndex = [int]$adapter.InterfaceIndex
    $result.gateway = $Gateway
    $result.interface_index = $selectedIndex
    $result.interface_alias = [string]$adapter.InterfaceAlias
    $result.source_ip = [string]$adapter.IPAddress
    $result.is_admin = $isAdmin
    if ($Action -eq 'Inspect') {
        $result.routes_before = @(
            Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore |
                Select-Object DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, Protocol
        )
        $result.status = 'ok'
    } else {
        if (-not $isAdmin) { throw 'Run the terminal as Administrator to add temporary host routes.' }
        $parsedIp = [System.Net.IPAddress]::Parse($Ip)
        if ($parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or $Ip -eq $Gateway) {
            throw 'Target must be an IPv4 address distinct from the gateway.'
        }
        $mutex = [System.Threading.Mutex]::new($false, "Global\IPPureTester-$Ip")
        try { $ownsMutex = $mutex.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] { $ownsMutex = $true }
        if (-not $ownsMutex) { throw 'Another test is already using this target.' }
        $prefix = "$Ip/32"
        $existing = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object DestinationPrefix -eq $prefix)
        $result.target_routes_before = @($existing | Select-Object DestinationPrefix, NextHop, InterfaceIndex, RouteMetric)
        $conflicts = @($existing | Where-Object { $_.NextHop -ne $Gateway -or $_.InterfaceIndex -ne $selectedIndex })
        if ($conflicts.Count -gt 0) { throw 'Conflicting /32 route exists; existing routes were preserved.' }
        if ($existing.Count -eq 0) {
            $leaseSeconds = [Math]::Ceiling(($Count * ($TimeoutMs + $IntervalMs)) / 1000) + 180
            $routeLifetime = [TimeSpan]::FromSeconds($leaseSeconds)
            $createdRoute = New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $selectedIndex -NextHop $Gateway `
                -RouteMetric 1 -PolicyStore ActiveStore -ValidLifetime $routeLifetime -PreferredLifetime $routeLifetime
            $result.route_created = $true
            $result.route_lease_seconds = $leaseSeconds
        }
        $selected = Assert-DirectRoute $Ip $selectedIndex
        $result.source_ip = $selected.source_ip
        $result.route_before = $selected
        $result.ping_samples = @(Get-PingSamples)
        $result.route_after = Assert-DirectRoute $Ip $selectedIndex
        $result.route_verified = $true
        $result.status = 'ok'
    }
} catch {
    $result.error = $_.Exception.Message
} finally {
    if ($null -ne $createdRoute) {
        try {
            $createdRoute | Remove-NetRoute -Confirm:$false
            $result.cleanup_status = 'removed'
        } catch {
            $result.cleanup_status = 'failed'
            $result.status = 'error'
            $result.error += " Route cleanup failed: $($_.Exception.Message)"
        }
    }
    if ($ownsMutex) { $mutex.ReleaseMutex() }
    if ($null -ne $mutex) { $mutex.Dispose() }
}
$result | ConvertTo-Json -Depth 10 -Compress
