<#
.SYNOPSIS
    Run Eric Zimmerman's tools against a mounted forensic image and lay the
    output out for the Douglas DFIR artifact review application.

.DESCRIPTION
    Given a mounted image (typically a drive letter from FTK Imager / Arsenal
    Image Mounter / a VHD attach), this script invokes:

        AmcacheParser, AppCompatCacheParser, EvtxECmd, JLECmd, LECmd,
        MFTECmd, PECmd, RBCmd, SBECmd, SrumECmd, SumECmd

    against the appropriate paths inside that image, writing each tool's CSV
    output to:

        <OutputRoot>\hosts\<HostName>\artifacts\

    which is exactly the layout Douglas expects. A case.json and host.json
    are written automatically so the case opens with no further setup.

.PARAMETER ImagePath
    Root of the mounted image. Examples:
        E:\
        F:\
        \\?\C:\mnt\evidence

    The script expects to find Windows\ underneath this path (i.e. it should
    be the root of the C:\ volume from the imaged system).

.PARAMETER OutputRoot
    Where the case directory tree should be written. Will be created if it
    does not exist.

.PARAMETER HostName
    Display name for this host inside Douglas. Defaults to the computer
    name pulled from the image's SYSTEM hive -- see Get-ImageHostName.

.PARAMETER CaseId
    Optional case identifier written into case.json. Defaults to a stamp
    like "case-20260515-093000".

.PARAMETER ToolsRoot
    Folder containing the Zimmerman *.exe binaries. If not supplied, the
    script tries these in order:
        $env:EZTOOLS
        C:\Tools\ZimmermanTools
        C:\Tools\ZimmermanTools\net9
        C:\Tools\ZimmermanTools\net6
        the script's own directory

.PARAMETER ToolFilter
    Optional list of tool names to limit to (case-insensitive). Valid values:
    amcache, shimcache, evtx, jumplist, lnk, mft, prefetch, recyclebin,
    recmd, shellbags, srum, sum. Example:
        -ToolFilter mft,evtx,prefetch
    If omitted, all EZ Tools are run. Hayabusa is controlled separately via
    -RunHayabusa and is unaffected by this filter.

.PARAMETER MapsPath
    Path to the EvtxECmd Maps folder. If not supplied, the default `<ToolsRoot>\EvtxECmd\Maps`
    is used. Specifying a custom path is useful if you maintain a curated map set.

.PARAMETER RECmdBatch
    Path to the RECmd batch file (.reb) to apply when RECmd runs. If omitted,
    the script looks for these in order under <ToolsRoot>:
        BatchExamples\Kroll_Batch.reb     (default; comprehensive DFIR set)
        BatchExamples\DFIRBatch.reb       (leaner, triage-focused set)
        BatchExamples\RECmd_Batch_MC.reb  (Mark Hallman's batch)
        any *.reb in BatchExamples\
    If none is found and -RECmdBatch wasn't passed, RECmd is skipped.
    Note: Kroll_Batch.reb is preferred when present; pass -RECmdBatch
    explicitly to force a different one (e.g. DFIRBatch.reb).

    The Kroll_Batch.reb file ships with the standard EZ Tools distribution.
    If you don't have it, grab it from:
        https://github.com/EricZimmerman/RECmd/tree/master/BatchExamples

.PARAMETER RunHayabusa
    Also run Hayabusa (sigma-based event log detector) against the image's
    evtx logs and emit a Douglas-compatible CSV named `hayabusa_timeline.csv`.
    Hayabusa is a separate project (Yamato-Security/hayabusa) -- not part of
    EZ Tools -- but Douglas already understands its CSV schema.

.PARAMETER RunBitsParser
    Also run BitsParser against the image's BITS queue manager databases at
    ProgramData\Microsoft\Network\Downloader\. BitsParser is a community
    tool (not part of EZ Tools); the script looks for BitsParser.exe under
    <ToolsRoot>\BitsParser\ or accepts an explicit -BitsParserPath. Argument
    set in this script targets the most common variant; analysts using a
    different fork may need to adjust the argv.

.PARAMETER BitsParserPath
    Explicit path to BitsParser.exe. Overrides the auto-detect search.

.PARAMETER Operator
    Analyst handle (e.g. "j.kowalski@corp") recorded in host.json's
    triage block. Surfaces in Douglas's host-overview "Triage Collection"
    card. Leave blank to omit.

.PARAMETER CollectionMethod
    Free-form description of how the artifacts were obtained, e.g.
    "KAPE -> EZ Tools" (default) or "Velociraptor offline collection".
    Recorded in host.json's triage block.

.PARAMETER HayabusaPath
    Full path to the Hayabusa executable (e.g.
    C:\Tools\hayabusa-3.3.0-win-x64\hayabusa-3.3.0-win-x64.exe). If omitted
    and -RunHayabusa is set, the script searches for hayabusa*.exe under
    `$env:HAYABUSA`, then `C:\Tools\hayabusa*`, then `<ToolsRoot>\hayabusa*`.

.PARAMETER HayabusaMinLevel
    Minimum severity threshold for Hayabusa detections. One of
    informational, low, medium, high, critical. Default: low.
    Lower means more rows, higher means fewer.

.PARAMETER UpdateHayabusaRules
    If set, runs `hayabusa update-rules` before scanning so the Sigma rule
    set is current. Requires network access. Default: do not update.

.EXAMPLE
    .\Run-ZimmermanTools.ps1 -ImagePath E:\ -OutputRoot C:\Cases\Acme-2025

    Process drive E:\ as the mounted image, write output to C:\Cases\Acme-2025.

.EXAMPLE
    .\Run-ZimmermanTools.ps1 -ImagePath E:\ -OutputRoot C:\Cases\Acme-2025 `
        -HostName WS-FIN-014 -ToolFilter mft,evtx,prefetch

    Same, but override the host name and only run three tools.

.EXAMPLE
    .\Run-ZimmermanTools.ps1 -ImagePath E:\ -OutputRoot C:\Cases\Acme-2025 `
        -RunHayabusa -HayabusaMinLevel medium

    Run the full EZ Tools set plus Hayabusa at medium+ severity.

.EXAMPLE
    .\Run-ZimmermanTools.ps1 -ImagePath E:\ -OutputRoot C:\Cases\Acme-2025 `
        -RECmdBatch C:\Tools\ZimmermanTools\net9\RECmd\BatchExamples\Kroll_Batch.reb

    Run with an explicit RECmd batch file. RECmd is run automatically when
    a .reb file is available; this just overrides the auto-discovered one.

.NOTES
    Designed to feed Douglas (the DFIR artifact reviewer). After this script
    finishes, point Douglas at the OutputRoot and click Import case.

    Tested against EZ Tools .NET 9 builds, current as of 2026-05.
    Source documentation:
        https://ericzimmerman.github.io/
        https://github.com/EricZimmerman/
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ImagePath,
    [Parameter(Mandatory)][string]$OutputRoot,
    [string]$HostName,
    [string]$CaseId,
    [string]$ToolsRoot,
    [string[]]$ToolFilter,
    [string]$MapsPath,
    [string]$RECmdBatch,
    [switch]$RunHayabusa,
    [string]$HayabusaPath,
    [ValidateSet('informational','low','medium','high','critical')]
    [string]$HayabusaMinLevel = 'low',
    [switch]$UpdateHayabusaRules,
    # BitsParser is a community tool (not part of EZ Tools) that parses
    # BITS queue manager databases. The DFIR value is high -- attackers
    # use BITS for resilient downloads -- but the binary isn't bundled
    # with EZ Tools, so we gate it behind an opt-in flag.
    [switch]$RunBitsParser,
    [string]$BitsParserPath,
    # Triage collection metadata, surfaced in the host overview's
    # "Triage Collection" card. These are pure analyst-supplied
    # strings; the preprocessor passes them through to host.json
    # unchanged. Defaults are inferred or left empty.
    [string]$Operator,
    [string]$CollectionMethod = 'KAPE -> EZ Tools'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------- console helpers ----------

# Status helpers. Write-Host output goes to the console window AND (when
# the script runs with redirected output under the Go server) is captured
# into the stream the server reads -- so a single Write-Host reaches both
# the console and the browser panel. No extra stdout marker is needed;
# emitting one caused every status line to appear twice.
function Write-Section { param([string]$Msg)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkGray
    Write-Host $Msg -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkGray
}
function Write-Step { param([string]$Msg)
    Write-Host "  [$([DateTime]::Now.ToString('HH:mm:ss'))] $Msg" -ForegroundColor White
}
function Write-Skip { param([string]$Msg)
    Write-Host "  skip: $Msg" -ForegroundColor DarkYellow
}
function Write-Ok { param([string]$Msg)
    Write-Host "  ok:   $Msg" -ForegroundColor Green
}
function Write-Fail { param([string]$Msg)
    Write-Host "  FAIL: $Msg" -ForegroundColor Red
}

# ---------- tools discovery ----------

# Map of tool id => expected exe basename. Order matters only for display.
$ToolExe = [ordered]@{
    amcache      = 'AmcacheParser.exe'
    shimcache    = 'AppCompatCacheParser.exe'
    evtx         = 'EvtxECmd.exe'
    jumplist     = 'JLECmd.exe'
    lnk          = 'LECmd.exe'
    mft          = 'MFTECmd.exe'
    prefetch     = 'PECmd.exe'
    recyclebin   = 'RBCmd.exe'
    recmd        = 'RECmd.exe'
    shellbags    = 'SBECmd.exe'
    srum         = 'SrumECmd.exe'
    sum          = 'SumECmd.exe'
}

function Resolve-ToolsRoot {
    param([string]$Hint)
    $candidates = @()
    if ($Hint)            { $candidates += $Hint }
    if ($env:EZTOOLS)     { $candidates += $env:EZTOOLS }
    $candidates += @(
        'C:\Tools\ZimmermanTools\net9',
        'C:\Tools\ZimmermanTools\net6',
        'C:\Tools\ZimmermanTools',
        (Split-Path -Parent $PSCommandPath)
    )
    foreach ($c in $candidates) {
        if (-not $c) { continue }
        if (Test-Path $c) {
            # Heuristic: directory contains at least one of the known exes anywhere below.
            $hit = Get-ChildItem -LiteralPath $c -Filter 'MFTECmd.exe' -Recurse -ErrorAction SilentlyContinue |
                   Select-Object -First 1
            if ($hit) { return (Resolve-Path $c).Path }
        }
    }
    throw "Could not locate Zimmerman tools. Pass -ToolsRoot, set `$env:EZTOOLS, or install to C:\Tools\ZimmermanTools."
}

# Find each tool's executable. Recursive so .NET 9 subfolders are picked up.
function Find-Tool {
    param([string]$Root, [string]$ExeName)
    $hit = Get-ChildItem -LiteralPath $Root -Filter $ExeName -Recurse -File -ErrorAction SilentlyContinue |
           Select-Object -First 1
    if ($hit) { return $hit.FullName } else { return $null }
}

# Hayabusa ships with a version-stamped exe name (hayabusa-3.3.0-win-x64.exe).
# Probe a small set of likely locations until we find one. Caller may also
# pass an explicit -HayabusaPath which short-circuits this discovery.
function Find-Hayabusa {
    param([string]$Hint, [string]$ToolsRoot)
    $candidates = @()
    if ($Hint)           { $candidates += $Hint }
    if ($env:HAYABUSA)   { $candidates += $env:HAYABUSA }
    $candidates += @(
        'C:\Tools',
        'C:\Tools\Hayabusa',
        'C:\Tools\hayabusa',
        $ToolsRoot,
        (Split-Path -Parent $PSCommandPath)
    )
    foreach ($c in $candidates) {
        if (-not $c) { continue }
        if (Test-Path -LiteralPath $c -PathType Leaf) {
            # User pointed straight at the exe
            if ($c -like '*hayabusa*.exe') { return (Resolve-Path -LiteralPath $c).Path }
            continue
        }
        if (-not (Test-Path -LiteralPath $c -PathType Container)) { continue }
        $hit = Get-ChildItem -LiteralPath $c -Filter 'hayabusa*.exe' -Recurse -File -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -notlike '*hayabusa-evtx*' } |
               Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

# ---------- host name discovery ----------

# Pulls ComputerName from the SYSTEM hive on the mounted image. Best-effort;
# falls back to a stamp if the hive is unreachable or locked.
function Get-ImageHostName {
    param([string]$ImageRoot)
    $systemHive = Join-Path $ImageRoot 'Windows\System32\config\SYSTEM'
    if (-not (Test-Path -LiteralPath $systemHive)) {
        return $null
    }
    # We'd ideally parse the hive offline. The cheapest reliable trick is to
    # `reg load` the hive into HKLM\TEMP_*, read ComputerName, unload. This
    # requires admin and a writable hive copy. If we can't, give up and let
    # the user pass -HostName.
    $tmpKey = "TEMP_DOUGLAS_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    try {
        & reg.exe load "HKLM\$tmpKey" $systemHive 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { return $null }
        try {
            $sel = (Get-ItemProperty -Path "HKLM:\$tmpKey\Select" -Name Current -ErrorAction Stop).Current
            $cs  = "ControlSet{0:000}" -f $sel
            $hn  = (Get-ItemProperty -Path "HKLM:\$tmpKey\$cs\Control\ComputerName\ComputerName" -Name ComputerName -ErrorAction Stop).ComputerName
            return $hn
        } finally {
            & reg.exe unload "HKLM\$tmpKey" 2>$null | Out-Null
        }
    } catch {
        return $null
    }
}

# Get-ImageOSInfo reads the SOFTWARE hive offline to extract OS string,
# build, and InstallationType (which tells us workstation vs server SKU).
# Returns a hashtable @{ os, build, installationType } or $null on failure.
# Used to populate richer host.json fields than ComputerName alone.
function Get-ImageOSInfo {
    param([string]$ImageRoot)
    $softwareHive = Join-Path $ImageRoot 'Windows\System32\config\SOFTWARE'
    if (-not (Test-Path -LiteralPath $softwareHive)) { return $null }
    $tmpKey = "TEMP_DOUGLAS_SW_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    try {
        & reg.exe load "HKLM\$tmpKey" $softwareHive 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { return $null }
        try {
            $cv = Get-ItemProperty -Path "HKLM:\$tmpKey\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
            # Build a friendly OS string. ProductName already says e.g.
            # "Windows 10 Pro" or "Windows Server 2019 Datacenter". For
            # Windows 11 the registry still says "Windows 10" -- check
            # CurrentBuild >= 22000 to correct.
            $product = $cv.ProductName
            if ($product -match 'Windows 10' -and [int]($cv.CurrentBuild) -ge 22000) {
                $product = $product -replace 'Windows 10', 'Windows 11'
            }
            return @{
                os               = $product
                build            = "$($cv.CurrentBuild).$($cv.UBR)"
                installationType = $cv.InstallationType  # "Client" | "Server" | "Server Core"
                displayVersion   = $cv.DisplayVersion    # e.g. "22H2"
            }
        } finally {
            & reg.exe unload "HKLM\$tmpKey" 2>$null | Out-Null
        }
    } catch {
        return $null
    }
}

# ---------- offline-registry probes for host-overview blocks ----------
# Each function loads the relevant hive into HKLM\TEMP_*, reads the
# values it needs, unloads. They share the load-on-failure-return-null
# pattern of Get-ImageHostName / Get-ImageOSInfo above. Designed to be
# called once at the end of the script to populate host.json's identity
# and network blocks; unavailable values just produce $null and the
# block gets omitted from the JSON.

# Get-ImageArch returns "x64" or "x86" by inspecting the SOFTWARE hive's
# CurrentVersion\Identifier (or falls back to "ProgramFilesDir (x86)"
# existence). Returns $null if neither signal is available.
function Get-ImageArch {
    param([string]$ImageRoot)
    # Cheap filesystem heuristic first: the existence of "Program Files (x86)"
    # is a definitive x64 signal that doesn't require hive loading.
    if (Test-Path -LiteralPath (Join-Path $ImageRoot 'Program Files (x86)')) {
        return 'x64'
    }
    if (Test-Path -LiteralPath (Join-Path $ImageRoot 'Program Files')) {
        return 'x86'
    }
    return $null
}

# Get-ImageTimeZone reads SYSTEM\ControlSet\Control\TimeZoneInformation
# and returns a friendly string like "UTC-05:00 (EST)". Returns $null
# on failure. Note that ActiveTimeBias stores minutes-from-UTC negated
# (e.g. EST=300 means UTC-05:00), which the calculation here inverts
# to produce the conventional UTC offset display.
function Get-ImageTimeZone {
    param([string]$ImageRoot)
    $systemHive = Join-Path $ImageRoot 'Windows\System32\config\SYSTEM'
    if (-not (Test-Path -LiteralPath $systemHive)) { return $null }
    $tmpKey = "TEMP_DOUGLAS_TZ_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    try {
        & reg.exe load "HKLM\$tmpKey" $systemHive 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { return $null }
        try {
            $sel = (Get-ItemProperty -Path "HKLM:\$tmpKey\Select" -Name Current -ErrorAction Stop).Current
            $cs  = "ControlSet{0:000}" -f $sel
            $tz = Get-ItemProperty -Path "HKLM:\$tmpKey\$cs\Control\TimeZoneInformation" -ErrorAction Stop

            # ActiveTimeBias is signed minutes; positive = west of UTC.
            $bias = [int]$tz.ActiveTimeBias
            $sign = if ($bias -ge 0) { '-' } else { '+' }
            $hh = [Math]::Floor([Math]::Abs($bias) / 60)
            $mm = [Math]::Abs($bias) % 60
            $offset = "UTC{0}{1:00}:{2:00}" -f $sign, $hh, $mm

            # TimeZoneKeyName is the friendly tag, e.g. "Eastern Standard Time"
            $name = $tz.TimeZoneKeyName
            if ($name) {
                # Abbreviate common ones to fit in the card -- full names are
                # too long. Falls through to using the full name otherwise.
                $abbr = switch -Wildcard ($name) {
                    'Eastern Standard*'   { 'EST'; break }
                    'Central Standard*'   { 'CST'; break }
                    'Mountain Standard*'  { 'MST'; break }
                    'Pacific Standard*'   { 'PST'; break }
                    'GMT Standard*'       { 'GMT'; break }
                    'Central European*'   { 'CET'; break }
                    'Eastern European*'   { 'EET'; break }
                    'Greenwich Standard*' { 'GMT'; break }
                    default               { $name }
                }
                return "$offset ($abbr)"
            }
            return $offset
        } finally {
            & reg.exe unload "HKLM\$tmpKey" 2>$null | Out-Null
        }
    } catch {
        return $null
    }
}

# Get-ImageNetworkInfo reads TCP/IP interface configs from the SYSTEM
# hive. Returns a hashtable with ipv4[], mac[], gateway, dns[]. Pulls
# from every non-loopback interface; analysts with multi-NIC servers
# get the full set.
#
# Caveat: the SYSTEM hive holds the *persisted* config, not the live
# DHCP-assigned values. For a workstation that was DHCP-leased at
# collection time, the dhcp* fields hold the lease values, which is
# typically what we want. Statically-configured interfaces use the
# Address/SubnetMask/DefaultGateway fields instead.
function Get-ImageNetworkInfo {
    param([string]$ImageRoot)
    $systemHive = Join-Path $ImageRoot 'Windows\System32\config\SYSTEM'
    if (-not (Test-Path -LiteralPath $systemHive)) { return $null }
    $tmpKey = "TEMP_DOUGLAS_NET_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    try {
        & reg.exe load "HKLM\$tmpKey" $systemHive 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { return $null }
        try {
            $sel = (Get-ItemProperty -Path "HKLM:\$tmpKey\Select" -Name Current -ErrorAction Stop).Current
            $cs  = "ControlSet{0:000}" -f $sel
            $ifBase = "HKLM:\$tmpKey\$cs\Services\Tcpip\Parameters\Interfaces"

            $ipv4 = @()
            $mac  = @()
            $gw   = ''
            $dns  = @()

            # Each interface lives under a GUID subkey. Iterate every one.
            # Track counts so a downstream caller can report *why* network
            # came back empty (no interface subkeys at all vs. interfaces
            # present but none carrying a usable address -- common on
            # DHCP-leased images where the persisted hive has 0.0.0.0).
            $interfaces = Get-ChildItem -Path $ifBase -ErrorAction SilentlyContinue
            $script:DouglasNetIfCount = ($interfaces | Measure-Object).Count
            foreach ($iface in $interfaces) {
                $props = Get-ItemProperty -Path $iface.PSPath -ErrorAction SilentlyContinue
                if (-not $props) { continue }

                # Prefer DHCP-assigned values when present; fall back to static.
                $addr = if ($props.DhcpIPAddress -and $props.DhcpIPAddress -ne '0.0.0.0') {
                    $props.DhcpIPAddress
                } elseif ($props.IPAddress) {
                    # Static IPAddress is a string[] -- pick first non-empty.
                    ($props.IPAddress | Where-Object { $_ -and $_ -ne '0.0.0.0' } | Select-Object -First 1)
                } else { $null }

                if ($addr) {
                    $ipv4 += $addr
                    # First interface's gateway wins -- multi-gw scenarios are rare
                    # on workstations and analysts can drill in to artifacts if
                    # they need the full table.
                    if (-not $gw) {
                        if ($props.DhcpDefaultGateway) { $gw = $props.DhcpDefaultGateway }
                        elseif ($props.DefaultGateway -is [array] -and $props.DefaultGateway.Count -gt 0) {
                            $gw = $props.DefaultGateway[0]
                        }
                    }
                    # DNS likewise: NameServer (static) and DhcpNameServer (dhcp)
                    # are space-separated strings.
                    $dnsRaw = if ($props.NameServer) { $props.NameServer }
                              elseif ($props.DhcpNameServer) { $props.DhcpNameServer }
                              else { $null }
                    if ($dnsRaw) {
                        foreach ($d in ($dnsRaw -split '\s+')) {
                            if ($d -and ($dns -notcontains $d)) { $dns += $d }
                        }
                    }
                }
            }

            # MAC addresses live under the NetworkCards key, indexed by enum.
            # The ServiceName field cross-references back to the Interfaces
            # subkey GUID. Simpler: just grab every Description+Adapter that
            # has a MAC-like value attached. For now, pull from the
            # NetworkAdapters list under Enum (which most KAPE collections
            # include). If nothing's there, leave mac empty -- the card
            # gracefully hides empty fields.
            $netCards = "HKLM:\$tmpKey\$cs\Control\NetworkCards"
            $cards = Get-ChildItem -Path $netCards -ErrorAction SilentlyContinue
            foreach ($card in $cards) {
                $cardProps = Get-ItemProperty -Path $card.PSPath -ErrorAction SilentlyContinue
                # The MAC lives in the corresponding interface's adapter
                # under HKLM:\TEMP\ControlSet001\Enum\..., which we don't
                # reliably have. Leave mac empty for now -- can be filled
                # in by live-machine probes when those land.
            }

            if ($ipv4.Count -eq 0 -and -not $gw -and $dns.Count -eq 0) {
                return $null
            }
            return @{
                ipv4    = $ipv4
                mac     = $mac
                gateway = $gw
                dns     = $dns
            }
        } finally {
            & reg.exe unload "HKLM\$tmpKey" 2>$null | Out-Null
        }
    } catch {
        return $null
    }
}

# Get-ImageDomain reads the AD/workgroup membership from the SYSTEM hive's
# Tcpip parameters. Returns the domain name or "WORKGROUP" string when
# the host wasn't domain-joined. Returns $null on failure.
function Get-ImageDomain {
    param([string]$ImageRoot)
    $systemHive = Join-Path $ImageRoot 'Windows\System32\config\SYSTEM'
    if (-not (Test-Path -LiteralPath $systemHive)) { return $null }
    $tmpKey = "TEMP_DOUGLAS_DOM_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    try {
        & reg.exe load "HKLM\$tmpKey" $systemHive 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { return $null }
        try {
            $sel = (Get-ItemProperty -Path "HKLM:\$tmpKey\Select" -Name Current -ErrorAction Stop).Current
            $cs  = "ControlSet{0:000}" -f $sel
            # Domain is set when joined; empty string when workgroup-only.
            $p = Get-ItemProperty -Path "HKLM:\$tmpKey\$cs\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue
            if ($p -and $p.Domain) { return $p.Domain }
            return $null
        } finally {
            & reg.exe unload "HKLM\$tmpKey" 2>$null | Out-Null
        }
    } catch {
        return $null
    }
}

# Get-LastBootFromEventLog reads the System EVTX for the most recent
# event 6005 ("event log service started") which fires very early in
# boot. Returns an ISO 8601 UTC string or $null if the EVTX isn't
# available or no 6005 events are present.
#
# Note: this runs after EvtxECmd has produced its CSV, since we don't
# want to re-parse the EVTX ourselves. The CSV has the timestamps in
# its TimeCreated column.
function Get-LastBootFromEventCsv {
    param([string]$EvtxCsv)
    if (-not (Test-Path -LiteralPath $EvtxCsv)) { return $null }
    try {
        # Stream the CSV looking for the most recent EventId=6005 row.
        # We don't sort the whole file -- just track the max timestamp.
        $maxTs = $null
        Import-Csv -LiteralPath $EvtxCsv -ErrorAction Stop | ForEach-Object {
            if ($_.EventId -eq '6005' -or $_.EventId -eq 6005) {
                $ts = $_.TimeCreated
                if ($ts -and ($null -eq $maxTs -or $ts -gt $maxTs)) {
                    $maxTs = $ts
                }
            }
        }
        return $maxTs
    } catch {
        return $null
    }
}

# Get-DirectorySize returns the on-disk size of a directory tree as a
# uint64 byte count. Used for the triage collection's sizeBytes field.
function Get-DirectorySize {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $total = 0
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object { $total += $_.Length }
        return [uint64]$total
    } catch {
        return $null
    }
}

# ---------- generic tool invocation ----------

# Run an EZ tool, capture stdout+stderr into the transcript, and report
# success/failure. Returns $true on exit code 0, $false otherwise.
function Invoke-Tool {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string[]]$Args,
        [Parameter(Mandatory)][string]$LogPath
    )
    # Step tracking. $script:DouglasStepTotal is set once in main (the
    # count of selected tools); $script:DouglasStepNum increments here.
    # We emit a structured marker on its own line that the Go server
    # parses out of the stream (like DOUGLAS_RESULT_CASE_DIR=). Format:
    #   DOUGLAS_STEP=<n>/<total>|<label>
    # The marker is written to BOTH the streamed output (for the server)
    # and is intentionally cheap so it flushes promptly -- it's emitted
    # at tool START, before the tool's own (buffered) output, so the UI
    # can show "Step n/total: <tool>" and start its stall timer even
    # while a long tool (RECmd) runs silently.
    # StrictMode-safe access: under Set-StrictMode -Version Latest, reading
    # an unset variable throws. Test-Path on the variable provider lets us
    # default cleanly even if these were somehow never initialized.
    $curNum = if (Test-Path variable:script:DouglasStepNum) { $script:DouglasStepNum } else { 0 }
    $script:DouglasStepNum = $curNum + 1
    $total = if (Test-Path variable:script:DouglasStepTotal) { $script:DouglasStepTotal } else { 0 }
    if (-not $total) { $total = 0 }
    # Emit the marker via Write-Output -> PowerShell success stream ->
    # the Go server's redirected StdoutPipe. Write-Output does NOT write
    # to the console screen buffer (unlike [Console]::Out.WriteLine, which
    # prints to the visible window), so these internal markers stay out of
    # the console. Return-value pollution is avoided because Invoke-Tool no
    # longer returns via the pipeline -- it sets $script:LastToolOk (see
    # end of function) and callers read that.
    Write-Output "DOUGLAS_STEP=$($script:DouglasStepNum)/$total|$Label"

    # Quote any args that contain whitespace so the logged command line is
    # copy-pasteable. The PowerShell 5.1-compatible -join operator works
    # everywhere; Join-String is 7.0+ only.
    $quotedArgs = $Args | ForEach-Object {
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }
    $cmdLine = "$Exe " + ($quotedArgs -join ' ')

    Add-Content -LiteralPath $LogPath -Value "`n[$([DateTime]::Now.ToString('o'))] $Label"
    Add-Content -LiteralPath $LogPath -Value "  cmd: $cmdLine"

    # Output routing (three sinks, now correctly separated):
    #
    #  1. LOG FILE (run-zimmerman.log) -- every raw line, verbatim.
    #  2. STDOUT PIPE (Go server / browser) -- the DOUGLAS_TOOL| heartbeat,
    #     via Write-Output (success stream -> redirected pipe). This does
    #     NOT print to the console screen.
    #  3. CONSOLE WINDOW -- only the in-place spinner pulse (Write-Host with
    #     \r). Raw tool output is NOT echoed to the console.
    #
    # CRITICAL: under $ErrorActionPreference='Stop', a tool writing to
    # stderr (merged via 2>&1) would terminate the script. Relax to
    # 'Continue' for just the external call, then restore.
    $code = 0
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $spinner = '|','/','-','\'
    $spinIdx = 0
    $lineCount = 0
    $toolStart = Get-Date
    $lastPulse = Get-Date
    try {
        & $Exe @Args 2>&1 | ForEach-Object {
            $line = $_
            $lineCount++
            # Strip ANSI/VT color escapes (RECmd, Hayabusa emit them).
            $clean = [regex]::Replace([string]$line, "$([char]27)\[[0-9;]*m", '')
            try {
                # (1) full output -> log file
                Add-Content -LiteralPath $LogPath -Value "  | $clean"
            } catch {}
            # (2) heartbeat -> stdout pipe via Write-Output (NOT console)
            Write-Output "DOUGLAS_TOOL|$clean"
            # (3) console: in-place spinner pulse, throttled to ~4x/sec.
            $now = Get-Date
            if (($now - $lastPulse).TotalMilliseconds -ge 250) {
                $lastPulse = $now
                $spinIdx = ($spinIdx + 1) % 4
                $elapsed = ('{0:mm\:ss}' -f ($now - $toolStart))
                try {
                    Write-Host ("`r    {0} {1}  {2}  ({3} lines)        " -f `
                        $spinner[$spinIdx], $Label, $elapsed, $lineCount) `
                        -NoNewline -ForegroundColor DarkGray
                } catch {}
            }
        }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEAP
    }
    if ($null -eq $code) { $code = 0 }
    # Clear the pulse line so the final ok/FAIL line starts clean.
    try { Write-Host ("`r" + (' ' * 70) + "`r") -NoNewline } catch {}
    Add-Content -LiteralPath $LogPath -Value "  exit: $code"

    # Report success via a script-scoped flag, NOT a pipeline return.
    # Because this function now emits DOUGLAS_* markers via Write-Output
    # (so they reach the server without printing to the console), a
    # `return $true` would be just one more object in the output stream --
    # callers can't distinguish it from the markers. Setting a script var
    # sidesteps that entirely. Callers read $script:LastToolOk.
    if ($code -eq 0) {
        Write-Ok "$Label (exit 0)"
        $script:LastToolOk = $true
    } else {
        Write-Fail "$Label (exit $code) -- see transcript for details"
        $script:LastToolOk = $false
    }
}

# ---------- main ----------

$startedAt = Get-Date

# Normalize image root and ensure it points at a Windows install
$ImagePath = (Resolve-Path -LiteralPath $ImagePath).Path
if ($ImagePath -notmatch '[\\/]$') { $ImagePath = $ImagePath + '\' }
$winDir = Join-Path $ImagePath 'Windows'
if (-not (Test-Path -LiteralPath $winDir)) {
    throw "ImagePath '$ImagePath' does not contain a Windows directory. Are you pointing at the C:\ root of the imaged system?"
}

# Resolve tools
$ToolsRoot = Resolve-ToolsRoot -Hint $ToolsRoot
Write-Section "Zimmerman tools driver"
Write-Step "Image root:     $ImagePath"
Write-Step "Tools root:     $ToolsRoot"
Write-Step "Output root:    $OutputRoot"

# Determine host name
if (-not $HostName) {
    $HostName = Get-ImageHostName -ImageRoot $ImagePath
    if (-not $HostName) {
        $HostName = "HOST-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
        Write-Step "Host name:      $HostName (auto-generated; pass -HostName to override)"
    } else {
        Write-Step "Host name:      $HostName (read from SYSTEM hive)"
    }
} else {
    Write-Step "Host name:      $HostName"
}

if (-not $CaseId) {
    $CaseId = "case-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
}
Write-Step "Case id:        $CaseId"

# Sanitize host name for path use (drop disallowed Windows filename chars)
$safeHost = ($HostName -replace '[\\/:*?"<>| ]', '_')

# Build the Douglas layout
$caseDir   = Join-Path $OutputRoot $CaseId
$hostDir   = Join-Path $caseDir "hosts\$safeHost"
$artDir    = Join-Path $hostDir 'artifacts'
$logDir    = Join-Path $hostDir 'logs'
$null = New-Item -ItemType Directory -Force -Path $artDir
$null = New-Item -ItemType Directory -Force -Path $logDir

$transcript = Join-Path $logDir 'run-zimmerman.log'
"=== Run-ZimmermanTools.ps1 transcript ===`nImage:    $ImagePath`nHost:     $HostName`nCase:     $CaseId`nStarted:  $($startedAt.ToString('o'))" |
    Set-Content -LiteralPath $transcript

# Determine which tools to run
$allTools = $ToolExe.Keys
if ($ToolFilter -and $ToolFilter.Count -gt 0) {
    $filter = $ToolFilter | ForEach-Object { $_.ToLowerInvariant() }
    $selected = $allTools | Where-Object { $filter -contains $_ }
    if (-not $selected) {
        throw "ToolFilter $([string]::Join(',', $ToolFilter)) matched none of: $([string]::Join(',', $allTools))"
    }
} else {
    $selected = @($allTools)
}
Write-Step "Tools to run:   $([string]::Join(', ', $selected))"

# Resolve every tool path up-front. Missing tools become a skip, not a failure.
$toolPath = @{}
foreach ($t in $selected) {
    $exe = Find-Tool -Root $ToolsRoot -ExeName $ToolExe[$t]
    if ($exe) {
        $toolPath[$t] = $exe
    } else {
        Write-Skip "$($ToolExe[$t]) not found under $ToolsRoot (skipping $t)"
    }
}

# Step tracking for the UI progress bar. The total is the number of tools
# whose binary was found -- the upper bound on Invoke-Tool calls. Some may
# still self-skip inside their block when the source data is absent (e.g.
# no Prefetch dir), so the final step number can legitimately come in
# under the total; the UI treats "n/total" as "n done of up-to total",
# not a strict denominator. DouglasStepNum is incremented inside
# Invoke-Tool. Note: some tools (RECmd, Hayabusa) issue more than one
# Invoke-Tool call (e.g. Hayabusa update-rules + csv-timeline); those are
# rare and only nudge the count slightly past total, which the UI clamps.
$script:DouglasStepTotal = $toolPath.Count
$script:DouglasStepNum = 0
# Network probe diagnostic counter -- initialized here so it always
# exists even if Get-ImageNetworkInfo bails before its interface loop
# (under Set-StrictMode, reading an unset variable is a terminating
# error). Get-ImageNetworkInfo overwrites this with the real count when
# it reaches the loop; the call site reads it to distinguish "no
# interfaces found" from "interfaces present but no usable IP".
$script:DouglasNetIfCount = 0

# Common image paths we'll need
$systemHive    = Join-Path $ImagePath 'Windows\System32\config\SYSTEM'
$softwareHive  = Join-Path $ImagePath 'Windows\System32\config\SOFTWARE'
$amcachePath   = Join-Path $ImagePath 'Windows\AppCompat\Programs\Amcache.hve'
$evtxDir       = Join-Path $ImagePath 'Windows\System32\winevt\Logs'
$mftPath       = Join-Path $ImagePath '$MFT'
$prefetchDir   = Join-Path $ImagePath 'Windows\Prefetch'
$recycleBin    = Join-Path $ImagePath '$Recycle.Bin'
$srumDbDir     = Join-Path $ImagePath 'Windows\System32\sru'
$sumDir        = Join-Path $ImagePath 'Windows\System32\LogFiles\Sum'
$userProfiles  = Join-Path $ImagePath 'Users'

# ---------- run each tool ----------

Write-Section "Running tools"

# MFTECmd -- requires the raw $MFT
if ($toolPath.ContainsKey('mft')) {
    if (Test-Path -LiteralPath $mftPath) {
        Write-Step "MFTECmd ($mftPath)"
        Invoke-Tool -Label 'MFTECmd' -Exe $toolPath['mft'] -LogPath $transcript -Args @(
            '-f', $mftPath,
            '--csv', $artDir,
            '--csvf', 'MFTECmd_Output.csv'
        )
    } else {
        Write-Skip ('MFTECmd: $MFT not found at ' + $mftPath + ' (NTFS root not directly accessible?)')
    }

    # USN journal ($J). The change journal is a running log of filesystem
    # operations (create/delete/rename/data-overwrite) with timestamps --
    # invaluable for catching files that were created and later deleted
    # (staging + cleanup) that the $MFT alone may no longer reflect.
    #
    # $J lives as the :$J alternate data stream of $Extend\$UsnJrnl. On a
    # mounted image the raw stream is addressed as "...\$Extend\$UsnJrnl:$J".
    # We pass -m <$MFT> so MFTECmd can resolve each record's parent
    # file-reference to a full path (without it you get entry names but no
    # parent path). Whether the ADS is exposed depends on the mount; if
    # it's not present we skip cleanly.
    $usnPath = Join-Path $ImagePath '$Extend\$UsnJrnl:$J'
    # Test-Path can't stat an ADS by itself, so probe the parent file and
    # let MFTECmd report if the stream is unreadable.
    $usnParent = Join-Path $ImagePath '$Extend\$UsnJrnl'
    if (Test-Path -LiteralPath $usnParent) {
        Write-Step ('MFTECmd USN journal ($Extend\$UsnJrnl:$J)')
        $usnArgs = @('-f', $usnPath, '--csv', $artDir, '--csvf', 'MFTECmd_UsnJrnl_Output.csv')
        if (Test-Path -LiteralPath $mftPath) {
            $usnArgs += @('-m', $mftPath)
        }
        Invoke-Tool -Label 'MFTECmd-USN' -Exe $toolPath['mft'] -LogPath $transcript -Args $usnArgs
    } else {
        Write-Skip ('MFTECmd USN: $Extend\$UsnJrnl not found (mount may not expose it, or journal disabled)')
    }
}

# AmcacheParser -- Amcache.hve
if ($toolPath.ContainsKey('amcache')) {
    if (Test-Path -LiteralPath $amcachePath) {
        Write-Step "AmcacheParser"
        Invoke-Tool -Label 'AmcacheParser' -Exe $toolPath['amcache'] -LogPath $transcript -Args @(
            '-f', $amcachePath,
            '-i',                          # include file entries for Programs entries
            '--csv', $artDir,
            '--csvf', 'Amcache.csv',       # base name; tool emits e.g. Amcache_UnassociatedFileEntries.csv
            '--nl'                         # ignore transaction logs to avoid dirty-hive locks
        )
    } else {
        Write-Skip "AmcacheParser: Amcache.hve not found at $amcachePath"
    }
}

# AppCompatCacheParser -- SYSTEM hive
if ($toolPath.ContainsKey('shimcache')) {
    if (Test-Path -LiteralPath $systemHive) {
        Write-Step "AppCompatCacheParser"
        Invoke-Tool -Label 'AppCompatCacheParser' -Exe $toolPath['shimcache'] -LogPath $transcript -Args @(
            '-f', $systemHive,
            '--csv', $artDir,
            '--csvf', 'SYSTEM_AppCompatCache.csv',
            '--nl'
        )
    } else {
        Write-Skip "AppCompatCacheParser: SYSTEM hive not found at $systemHive"
    }
}

# EvtxECmd -- recurse winevt\Logs
if ($toolPath.ContainsKey('evtx')) {
    if (Test-Path -LiteralPath $evtxDir) {
        Write-Step "EvtxECmd ($evtxDir)"
        $args = @(
            '-d', $evtxDir,
            '--csv', $artDir,
            '--csvf', 'EvtxECmd_Output.csv'
        )
        if ($MapsPath) {
            $args += @('--maps', $MapsPath)
        }
        Invoke-Tool -Label 'EvtxECmd' -Exe $toolPath['evtx'] -LogPath $transcript -Args $args
    } else {
        Write-Skip "EvtxECmd: $evtxDir not found"
    }
}

# PECmd -- Prefetch directory
if ($toolPath.ContainsKey('prefetch')) {
    if (Test-Path -LiteralPath $prefetchDir) {
        Write-Step "PECmd ($prefetchDir)"
        Invoke-Tool -Label 'PECmd' -Exe $toolPath['prefetch'] -LogPath $transcript -Args @(
            '-d', $prefetchDir,
            '--csv', $artDir,
            '--csvf', 'PECmd_Output.csv'
        )
    } else {
        Write-Skip "PECmd: $prefetchDir not found (Windows Server / disabled prefetch?)"
    }
}

# RBCmd -- Recycle Bin (every user's $I files)
if ($toolPath.ContainsKey('recyclebin')) {
    if (Test-Path -LiteralPath $recycleBin) {
        Write-Step "RBCmd (`$Recycle.Bin)"
        Invoke-Tool -Label 'RBCmd' -Exe $toolPath['recyclebin'] -LogPath $transcript -Args @(
            '-d', $recycleBin,
            '--csv', $artDir,
            '--csvf', 'RBCmd_Output.csv'
        )
    } else {
        Write-Skip "RBCmd: $recycleBin not found"
    }
}

# LECmd -- collect .lnk files from common locations under each user
if ($toolPath.ContainsKey('lnk')) {
    if (Test-Path -LiteralPath $userProfiles) {
        Write-Step "LECmd (Users\*\AppData\Roaming\Microsoft\Windows\Recent\*)"
        Invoke-Tool -Label 'LECmd' -Exe $toolPath['lnk'] -LogPath $transcript -Args @(
            '-d', $userProfiles,
            '--csv', $artDir,
            '--csvf', 'LECmd_Output.csv'
        )
    } else {
        Write-Skip "LECmd: $userProfiles not found"
    }
}

# JLECmd -- Jump Lists; same Users tree, tool will recurse and find them
if ($toolPath.ContainsKey('jumplist')) {
    if (Test-Path -LiteralPath $userProfiles) {
        Write-Step "JLECmd (Users\*\AppData\Roaming\Microsoft\Windows\Recent\{Automatic,Custom}Destinations)"
        # Without --csvf, JLECmd writes its native pair:
        #   JLECmd_AutomaticDestinations.csv  (system-managed lists)
        #   JLECmd_CustomDestinations.csv     (app-managed lists)
        # Douglas registers these as separate artifact types since the
        # schemas differ slightly (Auto has Hostname/FileSize, Custom
        # has Name). The previous --csvf JLECmd_Output.csv override
        # produced a filename Douglas didn't recognise.
        Invoke-Tool -Label 'JLECmd' -Exe $toolPath['jumplist'] -LogPath $transcript -Args @(
            '-d', $userProfiles,
            '--csv', $artDir
        )
    } else {
        Write-Skip "JLECmd: $userProfiles not found"
    }
}

# SBECmd -- shellbags, recursive across user hives
if ($toolPath.ContainsKey('shellbags')) {
    if (Test-Path -LiteralPath $userProfiles) {
        Write-Step "SBECmd ($userProfiles)"
        Invoke-Tool -Label 'SBECmd' -Exe $toolPath['shellbags'] -LogPath $transcript -Args @(
            '-d', $userProfiles,
            '--csv', $artDir,
            '--nl'
        )
    } else {
        Write-Skip "SBECmd: $userProfiles not found"
    }
}

# RECmd -- registry batch analysis across every hive on the image.
# Requires a .reb batch file. We try to locate Kroll_Batch.reb under the
# tools root if the user didn't pass -RECmdBatch.
if ($toolPath.ContainsKey('recmd')) {
    # Resolve the batch file to use.
    $batchToUse = $null
    if ($RECmdBatch) {
        # Explicit override -- must exist
        if (Test-Path -LiteralPath $RECmdBatch -PathType Leaf) {
            $batchToUse = (Resolve-Path -LiteralPath $RECmdBatch).Path
        } else {
            Write-Skip "RECmd: -RECmdBatch '$RECmdBatch' not found; skipping registry analysis"
        }
    } else {
        # Auto-discover under <ToolsRoot>\<...>\BatchExamples\
        $recmdDir = Split-Path -Parent $toolPath['recmd']
        $searchRoots = @(
            (Join-Path $recmdDir 'BatchExamples'),
            (Join-Path $ToolsRoot 'BatchExamples'),
            (Join-Path $ToolsRoot 'RECmd\BatchExamples')
        )
        $preferred = @('Kroll_Batch.reb', 'DFIRBatch.reb', 'RECmd_Batch_MC.reb')
        foreach ($root in $searchRoots) {
            if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
            foreach ($name in $preferred) {
                $candidate = Join-Path $root $name
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    $batchToUse = $candidate
                    break
                }
            }
            if ($batchToUse) { break }
            # Fall back to any .reb in this folder
            $any = Get-ChildItem -LiteralPath $root -Filter '*.reb' -File -ErrorAction SilentlyContinue |
                   Select-Object -First 1
            if ($any) {
                $batchToUse = $any.FullName
                break
            }
        }
        if (-not $batchToUse) {
            Write-Skip "RECmd: no batch (.reb) file found under tools root. Pass -RECmdBatch <path> or place Kroll_Batch.reb under <ToolsRoot>\BatchExamples\."
        }
    }

    if ($batchToUse) {
        Write-Step "RECmd batch=$([IO.Path]::GetFileName($batchToUse))  (recursing image; this can take several minutes)"
        # -d <image root>     : recurse the whole image looking for hives
        # --bn <batch>        : the .reb batch file to apply
        # --csv <outDir>      : output directory
        # --csvf <name>       : force a stable filename Douglas recognises
        # --nl                : ignore transaction logs on dirty hives
        # NOTE: RECmd has a -q (quiet) flag in its docs, but some builds
        # reject it as an unrecognized argument. It is purely cosmetic
        # (suppresses processing chatter; the CSV output is identical), so
        # we omit it for compatibility across RECmd versions.
        # RECmd discovers SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat etc.
        # automatically by walking the directory tree.
        Invoke-Tool -Label 'RECmd' -Exe $toolPath['recmd'] -LogPath $transcript -Args @(
            '-d', $ImagePath,
            '--bn', $batchToUse,
            '--csv', $artDir,
            '--csvf', 'RECmd_Batch.csv',
            '--nl'
        )
        # RECmd exits 0 even when it finds no hives (e.g. "Could not access
        # all files ... rerun with Administrator privileges / Total hives
        # found: 0"). That leaves no RECmd_Batch.csv, which means no
        # registry artifact and no User Activity views downstream -- a
        # silent gap unless we check for the output file explicitly.
        $recmdOut = Join-Path $artDir 'RECmd_Batch.csv'
        if (-not (Test-Path -LiteralPath $recmdOut)) {
            Write-Skip "RECmd produced no RECmd_Batch.csv -- registry artifacts (incl. User Activity) will be absent. Most common cause: not running as Administrator, or the image mount doesn't expose locked hive files. Check the RECmd output above for 'rerun with Administrator privileges'."
        }
    }
}

# SrumECmd -- SRUDB.dat + SOFTWARE hive for resolution
if ($toolPath.ContainsKey('srum')) {
    $srumDb = Join-Path $srumDbDir 'SRUDB.dat'
    if (Test-Path -LiteralPath $srumDb) {
        Write-Step "SrumECmd"
        $args = @('-f', $srumDb, '--csv', $artDir)
        if (Test-Path -LiteralPath $softwareHive) {
            $args += @('-r', $softwareHive)
        } else {
            Write-Skip "SrumECmd: SOFTWARE hive missing; network names won't resolve"
        }
        Invoke-Tool -Label 'SrumECmd' -Exe $toolPath['srum'] -LogPath $transcript -Args $args
        $ok = $script:LastToolOk
        if (-not $ok) {
            # The most common failure mode here is "dirty database" -- surface a
            # pointer to the repair procedure rather than just failing silently.
            Write-Host "  hint: SRUDB.dat may be 'dirty'. Copy it to a writable location and run:" -ForegroundColor Yellow
            Write-Host "        esentutl.exe /r sru /i"   -ForegroundColor Yellow
            Write-Host "        esentutl.exe /p SRUDB.dat" -ForegroundColor Yellow
            Write-Host "        then re-run this script with -ToolFilter srum and point -ImagePath at the repaired copy." -ForegroundColor Yellow
        }
    } else {
        Write-Skip "SrumECmd: SRUDB.dat not found at $srumDb"
    }
}

# SumECmd -- Software Usage Metrics, Server-only artifact
if ($toolPath.ContainsKey('sum')) {
    if (Test-Path -LiteralPath $sumDir) {
        Write-Step "SumECmd ($sumDir)"
        Invoke-Tool -Label 'SumECmd' -Exe $toolPath['sum'] -LogPath $transcript -Args @(
            '-d', $sumDir,
            '--csv', $artDir
        )
    } else {
        Write-Skip "SumECmd: $sumDir not found (this is normal -- SUM is a Windows Server artifact)"
    }
}

# Hayabusa -- Sigma-based event log detection (optional, behind -RunHayabusa).
# Not part of EZ Tools, but Douglas recognises its CSV schema directly.
# Output filename matches the recognition pattern in internal/ingest/types.go.
if ($RunHayabusa) {
    Write-Section "Hayabusa"
    $hayaExe = Find-Hayabusa -Hint $HayabusaPath -ToolsRoot $ToolsRoot
    if (-not $hayaExe) {
        Write-Skip "Hayabusa not found. Pass -HayabusaPath, set `$env:HAYABUSA, or install under C:\Tools\hayabusa*."
    } elseif (-not (Test-Path -LiteralPath $evtxDir)) {
        Write-Skip "Hayabusa: $evtxDir not found on the image"
    } else {
        Write-Step "Hayabusa exe:  $hayaExe"
        $hayaDir = Split-Path -Parent $hayaExe

        # Rules / config live next to the exe by default. Verify they exist
        # so we can give a clear error if the user grabbed only the binary.
        $rulesDir  = Join-Path $hayaDir 'rules'
        $configDir = Join-Path $hayaDir 'rules\config'
        if (-not (Test-Path -LiteralPath $rulesDir)) {
            Write-Skip "Hayabusa: rules/ not found next to the exe at $rulesDir. Re-extract the full release zip."
        } else {
            # Optionally refresh rules before scanning. Needs network.
            if ($UpdateHayabusaRules) {
                Write-Step "Hayabusa: updating rules (network required)"
                Push-Location -LiteralPath $hayaDir
                try {
                    Invoke-Tool -Label 'hayabusa update-rules' -Exe $hayaExe -LogPath $transcript -Args @('update-rules')
                } finally {
                    Pop-Location
                }
            }

            $hayaOut = Join-Path $artDir 'hayabusa_timeline.csv'
            Write-Step "Hayabusa csv-timeline (min-level=$HayabusaMinLevel)"
            # --no-wizard : skip the interactive setup wizard (essential for unattended runs)
            # --no-summary: skip the in-terminal results summary (faster, cleaner log)
            # -C          : clobber existing output file
            # -U          : timestamps in UTC for cross-host correlation
            # -q          : quiet display (no launch banner)
            # -Q          : quiet errors (don't dump huge per-file failure logs)
            # -m          : minimum severity filter
            #
            # Hayabusa expects its rules/ and config/ to be relative to the
            # current working directory by default. Push-Location to the
            # exe's folder before invoking so `./rules` resolves correctly,
            # regardless of where the user invoked this script from.
            Push-Location -LiteralPath $hayaDir
            try {
                Invoke-Tool -Label 'hayabusa csv-timeline' -Exe $hayaExe -LogPath $transcript -Args @(
                    'csv-timeline',
                    '-d', $evtxDir,
                    '-o', $hayaOut,
                    '-m', $HayabusaMinLevel,
                    '-c', $configDir,
                    '--no-wizard',
                    '--no-summary',
                    '-C', '-U', '-q', '-Q'
                )
            } finally {
                Pop-Location
            }
        }
    }
}

# BitsParser -- BITS queue manager database analysis (optional, behind
# -RunBitsParser). Not part of EZ Tools; community-maintained variants
# include fishyfacedotnet/BitsParser (Python) and various .exe builds.
# We accept either via -BitsParserPath and shell out with the most-common
# argument set; analysts who use a different fork should tweak this
# block to match their tool's flags.
#
# Output filename matches Douglas's recognition pattern
# (*BitsParser*.csv).
if ($RunBitsParser) {
    Write-Section "BitsParser"
    $bitsExe = $null
    if ($BitsParserPath) {
        if (Test-Path -LiteralPath $BitsParserPath) {
            $bitsExe = $BitsParserPath
        } else {
            Write-Skip "BitsParser: -BitsParserPath '$BitsParserPath' not found"
        }
    } else {
        # Try common install locations.
        $candidates = @(
            (Join-Path $ToolsRoot 'BitsParser\BitsParser.exe'),
            (Join-Path $ToolsRoot 'BitsParser.exe'),
            'C:\Tools\BitsParser\BitsParser.exe',
            'C:\Tools\BitsParser.exe'
        )
        foreach ($c in $candidates) {
            if ($c -and (Test-Path -LiteralPath $c)) { $bitsExe = $c; break }
        }
        if (-not $bitsExe) {
            Write-Skip "BitsParser not found. Pass -BitsParserPath or place BitsParser.exe under <ToolsRoot>\BitsParser\."
        }
    }

    $bitsDir = Join-Path $ImagePath 'ProgramData\Microsoft\Network\Downloader'
    if ($bitsExe -and -not (Test-Path -LiteralPath $bitsDir)) {
        Write-Skip "BitsParser: $bitsDir not found on the image (no BITS state to parse)"
    } elseif ($bitsExe) {
        $bitsOut = Join-Path $artDir 'BitsParser_Output.csv'
        Write-Step "BitsParser ($bitsDir)"
        # Argument set tracked here for the most common BitsParser variant.
        # If your fork uses different flags, change this argv -- the only
        # contract Douglas cares about is the *BitsParser*.csv output name.
        Invoke-Tool -Label 'BitsParser' -Exe $bitsExe -LogPath $transcript -Args @(
            '--input', $bitsDir,
            '--output', $bitsOut,
            '--format', 'csv'
        )
    }
}

# ---------- write Douglas metadata ----------

Write-Section "Writing Douglas metadata"

# case.json
$caseJsonPath = Join-Path $caseDir 'case.json'
@{
    id        = $CaseId
    name      = $CaseId
    createdAt = $startedAt.ToUniversalTime().ToString('o')
    analyst   = $env:USERNAME
} | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $caseJsonPath -Encoding UTF8
Write-Step "case.json -> $caseJsonPath"

# host.json - infer OS / role hints from offline hives where possible.
$osInfo = Get-ImageOSInfo -ImageRoot $ImagePath
$osText = 'Windows'
$role   = 'Workstation'
$tag    = 'WS'
if ($osInfo) {
    $osText = $osInfo.os
    if ($osInfo.displayVersion) { $osText = "$osText $($osInfo.displayVersion)" }
    # InstallationType is "Client" for workstation SKUs and "Server" /
    # "Server Core" for server SKUs. Server with a Domain Controller role
    # also has a Sum dir we can use as a secondary signal.
    if ($osInfo.installationType -match 'Server') {
        if (Test-Path $sumDir) {
            $role = 'Domain Controller'
            $tag  = 'DC'
        } else {
            $role = 'Server'
            $tag  = 'SRV'
        }
    } else {
        $role = 'Workstation'
        $tag  = 'WS'
    }
} elseif (Test-Path $sumDir) {
    # Fallback: only the SUM directory is available; tag as DC.
    $role = 'Domain Controller'
    $tag  = 'DC'
}

# ----- Phase-1 host-overview blocks -----
# Each probe returns either populated data or $null. We compose the
# blocks below; nulls become omitted properties via ConvertTo-Json's
# default behavior (with empty hashtables being the explicit way to
# include a block, and not adding the key at all being the way to omit).

# Identity: most fields come from $osInfo and probes against the SYSTEM
# hive. Hostname has been resolved earlier; arch and time zone from
# offline probes.
$archProbe = Get-ImageArch     -ImageRoot $ImagePath
$tzProbe   = Get-ImageTimeZone -ImageRoot $ImagePath
$domProbe  = Get-ImageDomain   -ImageRoot $ImagePath

$identity = @{ hostname = $HostName }
if ($domProbe)              { $identity.domain    = $domProbe; $identity.fqdn = "$HostName.$domProbe".ToLower() }
if ($osInfo -and $osInfo.os){ $identity.os        = $osInfo.os }
if ($osInfo -and $osInfo.displayVersion) { $identity.osVersion = $osInfo.displayVersion }
if ($osInfo -and $osInfo.build) { $identity.build = $osInfo.build }
if ($archProbe)             { $identity.arch      = $archProbe }
if ($tzProbe)               { $identity.timeZone  = $tzProbe }

# Surface probe gaps. These offline reads (reg.exe load of SYSTEM/NTUSER)
# need admin + an accessible image. When they come back empty the host
# overview silently shows a fallback hostname and blank cards, so call it
# out here -- the most common cause is running without Administrator
# rights or an image mount that doesn't expose locked hive files.
if (-not $tzProbe) {
    Write-Skip "Time zone not read from SYSTEM hive (offline probe failed -- admin rights / image access?)"
}
if ($HostName -like 'HOST-*') {
    Write-Skip "Host name not read from SYSTEM hive; using generated fallback '$HostName' (admin rights / image access?)"
}

# Network: from offline registry. Returns $null when no usable entries
# were found; we omit the whole block in that case.
$netProbe = Get-ImageNetworkInfo -ImageRoot $ImagePath
if (-not $netProbe) {
    $ifSeen = if (Test-Path variable:script:DouglasNetIfCount) { $script:DouglasNetIfCount } else { 0 }
    if ($null -eq $ifSeen -or $ifSeen -eq 0) {
        Write-Skip "Network config not read: no interface subkeys under Tcpip\Parameters\Interfaces (hive unreadable / admin rights / image access?)"
    } else {
        Write-Skip "Network config not read: $ifSeen interface(s) found but none had a usable IP in the persisted hive (DHCP-leased image stores 0.0.0.0 until renewed -- this is expected for some captures)"
    }
}

# Hardware: offline reads are unreliable for CPU/RAM/disk specs (the
# HARDWARE hive is volatile and usually not captured by KAPE). The
# lastBoot field is the only thing we reliably populate offline -- and
# even that requires EvtxECmd output to be present, since we read it
# from the parsed EVTX CSV rather than re-parsing the binary log.
$lastBoot = $null
$evtxCsv  = Join-Path $artDir 'EvtxECmd_Output.csv'
if (Test-Path -LiteralPath $evtxCsv) {
    $lastBoot = Get-LastBootFromEventCsv -EvtxCsv $evtxCsv
}
$hardware = $null
if ($lastBoot) {
    $hardware = @{ lastBoot = $lastBoot }
}

# Triage: pull what we know from the run itself. Operator and method
# come from the analyst-supplied parameters; targets, timestamps, and
# size come from this script's invocation context.
$collectionSize = Get-DirectorySize -Path $hostDir
$triage = @{
    method      = $CollectionMethod
    startedAt   = $startedAt.ToUniversalTime().ToString('o')
    completedAt = (Get-Date).ToUniversalTime().ToString('o')
}
if ($Operator)         { $triage.operator  = $Operator }
if ($ToolFilter -and $ToolFilter.Count -gt 0) {
    # When filtered, surface what the analyst actually ran rather than
    # "everything". When not filtered, omit the field -- absence means
    # "default set".
    $triage.targets   = @($ToolFilter)
}
if ($collectionSize)   { $triage.sizeBytes = $collectionSize }

$hostJsonPath = Join-Path $hostDir 'host.json'
$payload = @{
    id          = $safeHost
    name        = $HostName
    os          = $osText
    role        = $role
    tag         = $tag
    triageStart = $startedAt.ToUniversalTime().ToString('o')
    identity    = $identity
    triage      = $triage
}
if ($netProbe)  { $payload.network  = $netProbe }
if ($hardware)  { $payload.hardware = $hardware }

$payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $hostJsonPath -Encoding UTF8
Write-Step "host.json -> $hostJsonPath"

# ---------- summary ----------

$endedAt = Get-Date
$elapsed = $endedAt - $startedAt
"`nFinished: $($endedAt.ToString('o'))  (elapsed $($elapsed.ToString()))" | Add-Content -LiteralPath $transcript

Write-Section "Done"
$produced = Get-ChildItem -LiteralPath $artDir -Filter *.csv -ErrorAction SilentlyContinue
if ($produced) {
    Write-Host "Output ($($produced.Count) CSVs in $artDir):" -ForegroundColor Cyan
    foreach ($f in $produced) {
        $sz = if ($f.Length -gt 1MB) { ('{0:N1} MB' -f ($f.Length / 1MB)) }
              elseif ($f.Length -gt 1KB) { ('{0:N1} KB' -f ($f.Length / 1KB)) }
              else { ('{0} B' -f $f.Length) }
        Write-Host ("  {0,-44}  {1,10}" -f $f.Name, $sz)
    }
} else {
    Write-Fail "No CSVs were produced. Check the transcript at $transcript"
}

Write-Host ""
Write-Host "Open this in Douglas:" -ForegroundColor Cyan
Write-Host "  $caseDir" -ForegroundColor White
Write-Host ""
Write-Host "Transcript: $transcript" -ForegroundColor DarkGray

# Machine-readable marker for Douglas's preprocess wizard. When the wizard
# runs this script as a subprocess, the Go work function scans the streamed
# output for this exact prefix and uses the path as the case dir to open.
# Format is deliberately stable + greppable; do not change without
# also updating internal/preprocess/runner.go (parseResultMarker).
Write-Host "DOUGLAS_RESULT_CASE_DIR=$caseDir"
