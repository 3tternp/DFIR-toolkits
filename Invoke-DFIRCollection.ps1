<#
.SYNOPSIS
    3tternp DFIR Toolkit - Windows Digital Forensic Collection & Triage (single script).
    Author: 3tternp (https://github.com/3tternp)

.DESCRIPTION
    Runs a complete live-response forensic process on a Windows host:
      1. Case setup, transcript and chain-of-custody record
      2. Optional memory capture (external tool, e.g. WinPmem)
      3. Volatile data   - processes (hash/signature/owner), modules, network, DNS, ARP, sessions
      4. System state    - OS, users/groups, software, services, drivers, Defender, audit policy, WinRE
      5. Persistence     - scheduled tasks (+XML), Run keys & 20+ ASEP locations, WMI, BITS, startup
      6. Event logs      - raw .evtx export + parsed CSV of high-value event IDs
      7. Artefacts       - registry hives, Prefetch, Amcache, SRUM, PSReadLine, browser history,
                           LNK/JumpLists, AnyDesk/TeamViewer traces, WER, Defender MPLog (VSS for locked files)
      8. File inventory  - executables/scripts in user-writable paths with SHA-256 + Authenticode
      9. Samples         - suspicious binaries copied as inert .bin_ files
     10. Analysis        - rule engine + IOC matching -> prioritised findings (MITRE ATT&CK)
     11. Report          - HTML report, findings CSV/JSON, SUMMARY.txt
     12. Integrity       - SHA-256 manifest of every file, ZIP + ZIP hash

    The script is READ-ONLY with respect to the system under investigation: it does not delete,
    kill, quarantine or modify anything. It only writes into -OutputRoot.

.PARAMETER OutputRoot   Where the case folder is written (use external/USB drive when possible).
.PARAMETER CaseId       Case reference used in folder names and reports.
.PARAMETER Examiner     Person running the collection (chain of custody).
.PARAMETER DaysBack     Look-back window for logs, new files and services (default 30).
.PARAMETER IocFile      Optional CSV/text file of extra IOCs: lines "type,value" where type is
                        ip | domain | sha256 | string | path_regex | regkey
.PARAMETER MemoryTool   Optional full path to a memory acquisition tool (e.g. winpmem_mini_x64.exe).
.PARAMETER SkipEventLogs, SkipRegistryHives, SkipBrowser, SkipSamples, NoZip   Reduce scope.
.PARAMETER MaxSampleMB  Do not copy samples larger than this (default 50).

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-DFIRCollection.ps1 -CaseId CASE-2026-003 -Examiner "Your Name" -OutputRoot E:\Evidence

.NOTES
    Run from an elevated PowerShell (Administrator). Windows PowerShell 5.1 or PowerShell 7.
    Output may contain sensitive data (browser history, registry hives) - handle as evidence.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = "$env:SystemDrive\DFIR",
    [string]$CaseId = ("CASE-" + (Get-Date -Format 'yyyyMMdd-HHmmss')),
    [string]$Examiner = "$env:USERDOMAIN\$env:USERNAME",
    [int]$DaysBack = 30,
    [string]$IocFile,
    [string]$MemoryTool,
    [switch]$SkipEventLogs,
    [switch]$SkipRegistryHives,
    [switch]$SkipBrowser,
    [switch]$SkipSamples,
    [int]$MaxSampleMB = 50,
    [switch]$NoZip
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$ScriptVersion         = '1.0.0'
$StartTime             = Get-Date
$Since                 = $StartTime.AddDays(-$DaysBack)
$HostName              = $env:COMPUTERNAME
$Stamp                 = $StartTime.ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$Root                  = Join-Path $OutputRoot ("{0}_{1}_{2}" -f $CaseId, $HostName, $Stamp)
$MemDir                = $Root + '_memory'

$Dirs = [ordered]@{
    Case        = '00_case'
    Volatile    = '01_volatile'
    System      = '02_system'
    Persistence = '03_persistence'
    EventLogs   = '04_eventlogs'
    Artifacts   = '05_artifacts'
    Files       = '06_file_inventory'
    Samples     = '07_samples_DO_NOT_EXECUTE'
    Analysis    = '08_analysis'
}
foreach ($k in @($Dirs.Keys)) {
    $p = Join-Path $Root $Dirs[$k]
    New-Item -ItemType Directory -Path $p -Force | Out-Null
    $Dirs[$k] = $p
}
$LogFile = Join-Path $Dirs.Case 'collection.log'

# --------------------------------------------------------------------------------------------
#  Helpers
# --------------------------------------------------------------------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8
    $color = 'Gray'
    if ($Level -eq 'WARN') { $color = 'Yellow' } elseif ($Level -eq 'ERROR') { $color = 'Red' } elseif ($Level -eq 'STEP') { $color = 'Cyan' }
    Write-Host $line -ForegroundColor $color
}

$Script:StepResults = New-Object System.Collections.Generic.List[object]
function Invoke-Step {
    param([string]$Name, [scriptblock]$Block)
    Write-Log "==> $Name" 'STEP'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $status = 'OK'
    try { & $Block } catch { $status = 'ERROR'; Write-Log ("{0} failed at line {1}: {2}" -f $Name, $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message) 'ERROR' }
    $sw.Stop()
    $Script:StepResults.Add([pscustomobject]@{ Step = $Name; Status = $status; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) })
}

function Save-Csv {
    param($InputObject, [string]$Path)
    $items = New-Object System.Collections.ArrayList
    if ($null -ne $InputObject) {
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) { foreach ($i in $InputObject) { if ($null -ne $i) { [void]$items.Add($i) } } }
        else { [void]$items.Add($InputObject) }
    }
    if ($items.Count -eq 0) { '' | Out-File -LiteralPath $Path -Encoding UTF8; return }
    $items | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

function Save-Cmd {
    # Run a native command line and save its output
    param([string]$CommandLine, [string]$Path)
    try {
        $out = & cmd.exe /c "$CommandLine 2>&1"
        $out | Out-File -LiteralPath $Path -Encoding UTF8 -Width 4096
    } catch { Write-Log "Command failed: $CommandLine - $($_.Exception.Message)" 'WARN' }
}

function Get-SafeName { param([string]$Path) return ($Path -replace '^[A-Za-z]:\\', '' -replace '[\\/:*?"<>|]', '_') }

$Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Script:CopyLog = New-Object System.Collections.Generic.List[object]
function Copy-Evidence {
    # Copy a file, falling back to a Volume Shadow Copy read (esentutl /vss) for locked files.
    param([string]$Source, [string]$DestDir, [string]$DestName)
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { return $null }
    if (-not (Test-Path -LiteralPath $DestDir)) { New-Item -ItemType Directory -Path $DestDir -Force | Out-Null }
    if (-not $DestName) { $DestName = Get-SafeName $Source }
    $dst = Join-Path $DestDir $DestName
    $i = 1
    while (Test-Path -LiteralPath $dst) { $dst = Join-Path $DestDir ("{0}_{1}" -f $i, $DestName); $i++ }
    $method = 'Copy-Item'
    try {
        Copy-Item -LiteralPath $Source -Destination $dst -Force -ErrorAction Stop
    } catch {
        $method = 'esentutl-vss'
        if ($Script:IsAdmin) { & esentutl.exe /y "$Source" /d "$dst" /vss 2>&1 | Out-Null }
    }
    if (Test-Path -LiteralPath $dst) {
        $src = Get-Item -LiteralPath $Source -Force -ErrorAction SilentlyContinue
        $h = $null; try { $h = (Get-FileHash -LiteralPath $dst -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
        $Script:CopyLog.Add([pscustomobject]@{
            Source = $Source; Destination = $dst.Replace($Root, '.'); Method = $method; SHA256 = $h
            Size = $(if ($src) { $src.Length } else { $null })
            SourceCreatedUtc = $(if ($src) { $src.CreationTimeUtc } else { $null })
            SourceModifiedUtc = $(if ($src) { $src.LastWriteTimeUtc } else { $null })
            SourceAccessedUtc = $(if ($src) { $src.LastAccessTimeUtc } else { $null })
        })
        return $dst
    }
    Write-Log "Could not copy $Source" 'WARN'
    return $null
}

$Script:FileInfoCache = @{}
function Get-FileInfoEx {
    # Hash + Authenticode + version info for a file (cached)
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $Path = [Environment]::ExpandEnvironmentVariables($Path.Trim('"'))
    if ($Script:FileInfoCache.ContainsKey($Path)) { return $Script:FileInfoCache[$Path] }
    $o = [ordered]@{ Path = $Path; Exists = $false; Size = $null; CreatedUtc = $null; ModifiedUtc = $null; SHA256 = $null
                     SigStatus = $null; Signer = $null; OriginalFilename = $null; CompanyName = $null; FileDescription = $null }
    try {
        $f = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not $f.PSIsContainer) {
            $o.Exists = $true; $o.Size = $f.Length; $o.CreatedUtc = $f.CreationTimeUtc; $o.ModifiedUtc = $f.LastWriteTimeUtc
            if ($f.Length -lt 200MB) { try { $o.SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { } }
            try {
                $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
                $o.SigStatus = [string]$s.Status
                if ($s.SignerCertificate) { $o.Signer = ($s.SignerCertificate.Subject -replace '^CN=([^,]+).*$', '$1') }
            } catch { }
            try {
                $vi = $f.VersionInfo
                $o.OriginalFilename = $vi.OriginalFilename; $o.CompanyName = $vi.CompanyName; $o.FileDescription = $vi.FileDescription
            } catch { }
        }
    } catch { }
    $obj = [pscustomobject]$o
    $Script:FileInfoCache[$Path] = $obj
    return $obj
}

function Get-ExeFromCommand {
    # Extract the executable path from a command line / ImagePath
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Cmd.Trim())
    $c = $c -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$env:SystemRoot\" -replace '^(?i)system32\\', "$env:SystemRoot\System32\"
    if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { return $c.Substring(1, $e - 1) } }
    $m = [regex]::Match($c, '^(?i)(.+?\.(exe|dll|sys|com|bat|cmd|ps1|vbs|js|hta|scr|cpl))(\s|$|,)')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

# Paths an unprivileged user (or malware) can write to
$UserWritableRx = '(?i)(\\Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents|Music|Pictures|Videos|Contacts|Favorites)\\|\\Users\\Public\\|\\ProgramData\\|\\Windows\\Temp\\|\\Windows\\SystemTemp\\|\\PerfLogs\\|\\Windows\\Tasks\\|\\Windows\\Tracing\\|\\\$Recycle\.Bin\\|\\Users\\[^\\]+\\[^\\]+\.exe$|\\Windows\\EdgeUpdate\\)'
$ScriptHostRx   = '(?i)\b(wscript|cscript|mshta|rundll32|regsvr32|powershell|pwsh|cmd|certutil|bitsadmin|msiexec|installutil|regasm|regsvcs|cmstp|forfiles)(\.exe)?\b'
$SuspCmdRx      = '(?i)(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|-w(indowstyle)?\s+h(idden)?|iex\b|invoke-expression|downloadstring|downloadfile|invoke-webrequest|\biwr\b|start-bitstransfer|frombase64string|add-mppreference|set-mppreference|net\.webclient|http[s]?://\d{1,3}(\.\d{1,3}){3}|copyfromscreen|-ep\s+bypass|-executionpolicy\s+bypass)'
$SystemNames    = @('svchost.exe','lsass.exe','csrss.exe','smss.exe','wininit.exe','winlogon.exe','services.exe','explorer.exe','taskhostw.exe','runtimebroker.exe','dllhost.exe','conhost.exe','spoolsv.exe','searchindexer.exe','searchhost.exe','searchfilterhost.exe','searchprotocolhost.exe','aggregatorhost.exe','wudfhost.exe','startmenuexperiencehost.exe','sihost.exe','ctfmon.exe','audiodg.exe','fontdrvhost.exe','dwm.exe','lsm.exe','msmpeng.exe','securityhealthservice.exe','wmiprvse.exe','rundll32.exe','regsvr32.exe','notepad.exe','nvdisplay.container.exe','googleupdate.exe','microsoftedgeupdate.exe','onedrive.exe')
$LolbinOrig     = @('notepad.exe','calc.exe','mshta.exe','rundll32.exe','regsvr32.exe','wscript.exe','cscript.exe','cmd.exe','powershell.exe','msbuild.exe','installutil.exe','regasm.exe','regsvcs.exe','certutil.exe','bitsadmin.exe','cmstp.exe','msiexec.exe','autoit3.exe','kxetray.exe','werfault.exe','dllhost.exe','svchost.exe')
$MiningPorts    = @(3333, 3334, 3335, 4444, 5555, 6666, 7777, 8888, 9999, 10128, 10343, 14433, 14444, 20580, 45560, 45700)
$RmmRx          = '(?i)(anydesk|teamviewer|screenconnect|connectwise|rustdesk|atera|splashtop|ngrok|netsupport|remcos|logmein|gotoassist|supremo|ammyy|radmin|dwservice|tightvnc|ultravnc|realvnc|meshagent|action1|level\.io|zoho assist)'

# --------------------------------------------------------------------------------------------
#  IOC set (defaults from a 2026 loader/cryptominer investigation) - extend with -IocFile
# --------------------------------------------------------------------------------------------
$IocDb = @{
    ip      = @('87.58.216.204','222.34.45.61','134.156.34.81','139.180.209.157','108.181.196.50')
    domain  = @('golden-age.shop','xai830k.com','singularity-drop.com','blorvexium924q.com','blubbernet909c.com','drallomatrix221p.com','dribbelnode600x.com','flanterix501k.top','flatterbyte609x.com','flibberflux982.top','glonktronix778.top','gnubbelzius77.top','kramselwobble407.top','krizzbyte804m.com','krontabyte144.top','morbixmesh901r.top','muffelgrid642r.com','mumpfcore559x.com','plixatron660v.com','plubberflux333.top','quasselbyte884r.com','schnorxelbit990.top','snirxbyte720m.com','trasselcore118.top','trummelnet552p.com','tutspace576c.com','vortexelium812q.com','vyntrazoid663k.com','wobblenode315q.top','yapptronic455z.top','zapptronikx771m.com','zizzlecore287k.com','zorbitalmesh773x.com')
    sha256  = @('5F7FD3A66470D95CC86EFAAF861A08BB6480050EE01F0E789E7F4E1E985D788D','BCB5EEAF124A60C161040E3F45F789145780707A869BE4B51A57CD96B974DDF8','39F43D9CBB067C81797BF46E0B5A8470F36FEB011BB74FCEABC147FC34C89150','0F9BC66562907AB86412E7F375596E93449B40836B12343D6D6AAE82D0E7D72F')
    string  = @('mrebtkrF5v','minefleet','golden-age.shop','87.58.216.204','Sapphire_Miner','--webview-exe-name=SearchHost.exe')
    path_regex = @('\\ProgramData\\[a-z]{12}\\[a-z]{12}\.exe$','\\Windows\\SystemTemp\\[a-z]{12}\.sys$','\\Temp\\\d{5,}0101\\','\\Win-v4\d\.exe$','kxetray\.exe','(?-i)\\AppData\\Roaming\\(?=[^\\]*\d)(?=[^\\]*[A-Z])[A-Za-z0-9]{5,12}\\(?=[^\\]*[A-Z])(?=[^\\]*[a-z])[A-Za-z0-9]{8,16}\.exe$','\\ProgramData\\Google\\(Browser|Update)\\','(?-i)\\ProgramData\\(?:Alice|Antique|Aquamarine|Aqua|Azure|Beige|Bisque|Black|Blanched|Almond|Blue|Violet|Brown|Burly|Wood|Cadet|Chartreuse|Chocolate|Coral|Cornflower|Cornsilk|Crimson|Cyan|Dark|Deep|Pink|Sky|Dim|Gray|Grey|Dodger|Fire|Brick|Floral|White|Forest|Green|Fuchsia|Gainsboro|Ghost|Goldenrod|Gold|Honey|Dew|Hot|Indian|Red|Indigo|Ivory|Khaki|Lavender|Blush|Lawn|Lemon|Chiffon|Light|Lime|Linen|Magenta|Maroon|Medium|Orchid|Purple|Sea|Slate|Spring|Turquoise|Midnight|Mint|Cream|Misty|Rose|Moccasin|Navajo|Navy|Old|Lace|Olive|Drab|Orange|Pale|Papaya|Whip|Peach|Puff|Peru|Plum|Powder|Rosy|Royal|Saddle|Salmon|Sandy|Shell|Sienna|Silver|Snow|Steel|Tan|Teal|Thistle|Tomato|Wheat|Yellow){3,}\\')
    regkey  = @('HKLM:\SOFTWARE\$SHconfig','HKCU:\SOFTWARE\$SHconfig')
}
if ($IocFile -and (Test-Path -LiteralPath $IocFile)) {
    foreach ($line in Get-Content -LiteralPath $IocFile) {
        if ($line -match '^\s*#' -or $line -notmatch ',') { continue }
        $t, $v = $line.Split(',', 2)
        $t = $t.Trim().ToLower(); $v = $v.Trim()
        if ($IocDb.ContainsKey($t) -and $v) { $IocDb[$t] += $(if ($t -eq 'sha256') { $v.ToUpper() } else { $v }) }
    }
}
$IocIpSet   = @{}; foreach ($x in $IocDb.ip) { $IocIpSet[$x] = $true }
$IocHashSet = @{}; foreach ($x in $IocDb.sha256) { $IocHashSet[$x.ToUpper()] = $true }

# --------------------------------------------------------------------------------------------
#  Findings engine
# --------------------------------------------------------------------------------------------
$Script:Findings = New-Object System.Collections.Generic.List[object]
$SevRank = @{ Critical = 5; High = 4; Medium = 3; Low = 2; Info = 1 }
function Add-Finding {
    param([ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity, [string]$Category, [string]$Title,
          [string]$Detail, [string]$Evidence, [string]$Mitre = '')
    $Script:Findings.Add([pscustomobject]@{
        Severity = $Severity; Rank = $SevRank[$Severity]; Category = $Category; Title = $Title
        Detail = $Detail; Evidence = $Evidence; MITRE = $Mitre })
}
function Test-IocText {
    param([string]$Text)
    if (-not $Text) { return $null }
    foreach ($s in $IocDb.string) { if ($Text.IndexOf($s, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return "string:$s" } }
    foreach ($d in $IocDb.domain) { if ($Text.IndexOf($d, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return "domain:$d" } }
    foreach ($i in $IocDb.ip)     { if ($Text.Contains($i)) { return "ip:$i" } }
    foreach ($r in $IocDb.path_regex) { if ($Text -match $r) { return "path:$r" } }
    return $null
}
function Test-ExeSuspicious {
    # Returns @(severity, reason) for an executable path, or $null when benign-looking
    param([string]$ExePath)
    if (-not $ExePath) { return $null }
    $fi = Get-FileInfoEx $ExePath
    $name = Split-Path $ExePath -Leaf
    $ioc = Test-IocText $ExePath
    if ($fi -and $fi.SHA256 -and $IocHashSet.ContainsKey($fi.SHA256)) { return @('Critical', "SHA-256 matches known IOC ($($fi.SHA256))") }
    if ($ioc) { return @('Critical', "Matches IOC pattern $ioc") }
    if ($ExePath -match $UserWritableRx) {
        if ($fi -and $fi.SigStatus -eq 'Valid') {
            if ($fi.OriginalFilename -and ($fi.OriginalFilename -replace '\.mui$', '') -ne $name -and ($fi.OriginalFilename -replace '\.exe$', '') -ne ($name -replace '\.exe$', '')) {
                $sevR = 'Medium'
                if ($LolbinOrig -contains $fi.OriginalFilename.ToLower() -or $SystemNames -contains $fi.OriginalFilename.ToLower()) { $sevR = 'High' }
                return @($sevR, "Signed binary renamed: OriginalFilename '$($fi.OriginalFilename)' runs as '$name' from user-writable path (possible side-loading / LOLBin host)")
            }
            if ($SystemNames -contains $name.ToLower()) { return @('High', "Windows/vendor process name '$name' running from user-writable path (signed by $($fi.Signer))") }
            return @('Low', "Signed ($($fi.Signer)) but located in user-writable path")
        }
        $st = 'missing'; if ($fi -and $fi.Exists) { $st = $fi.SigStatus }
        if ($SystemNames -contains $name.ToLower()) { return @('Critical', "Masquerading as '$name' from user-writable path (signature: $st)") }
        return @('High', "Unsigned/invalid binary in user-writable path (signature: $st)")
    }
    if ($SystemNames -contains $name.ToLower() -and $ExePath -notmatch '(?i)^[A-Z]:\\(Windows|Program Files|Program Files \(x86\))\\') {
        return @('High', "System process name '$name' outside Windows/Program Files")
    }
    if ($ExePath -match '(?i)\\Windows\\(System32|SysWOW64)?\\?[^\\]+\.exe$' -and $fi -and $fi.Exists -and $fi.SigStatus -ne 'Valid' -and $fi.CreatedUtc -gt $Since.ToUniversalTime()) {
        return @('High', "Recently created unsigned executable in Windows directory (created $($fi.CreatedUtc) UTC)")
    }
    return $null
}

Write-Log "3tternp DFIR collector v$ScriptVersion - case $CaseId - host $HostName - examiner $Examiner"
if (-not $Script:IsAdmin) { Write-Log 'NOT running as Administrator - collection will be incomplete (Security log, hives, VSS copies, other users).' 'WARN' }
try { Start-Transcript -LiteralPath (Join-Path $Dirs.Case 'transcript.txt') -Force | Out-Null } catch { }

# --------------------------------------------------------------------------------------------
#  0. Case record
# --------------------------------------------------------------------------------------------
Invoke-Step 'Case record' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    @(
        "CASE ID          : $CaseId"
        "EXAMINER         : $Examiner"
        "HOST             : $HostName"
        "DOMAIN/WORKGROUP : $($cs.Domain)"
        "OS               : $($os.Caption) $($os.Version) build $($os.BuildNumber)"
        "LOCAL TIME       : $($StartTime.ToString('yyyy-MM-dd HH:mm:ss zzz'))"
        "UTC TIME         : $($StartTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))Z"
        "TIME ZONE        : $((Get-TimeZone).Id)"
        "LAST BOOT        : $($os.LastBootUpTime)"
        "RUN AS           : $env:USERDOMAIN\$env:USERNAME (admin=$($Script:IsAdmin))"
        "SCRIPT           : $PSCommandPath v$ScriptVersion"
        "SCRIPT SHA256    : $(try { (Get-FileHash -LiteralPath $PSCommandPath).Hash } catch { 'n/a' })"
        "LOOKBACK         : $DaysBack days (since $($Since.ToString('yyyy-MM-dd HH:mm')))"
        "OUTPUT           : $Root"
    ) | Out-File (Join-Path $Dirs.Case 'case_info.txt') -Encoding UTF8
    Save-Cmd 'w32tm /query /status' (Join-Path $Dirs.Case 'time_source.txt')
}

# --------------------------------------------------------------------------------------------
#  1. Memory (most volatile - first)
# --------------------------------------------------------------------------------------------
if ($MemoryTool) {
    Invoke-Step 'Memory acquisition' {
        if (-not (Test-Path -LiteralPath $MemoryTool)) { throw "Memory tool not found: $MemoryTool" }
        New-Item -ItemType Directory -Path $MemDir -Force | Out-Null
        $memFile = Join-Path $MemDir "$HostName-memory.raw"
        Write-Log "Acquiring memory with $MemoryTool -> $memFile (ensure free space >= RAM size)"
        & $MemoryTool $memFile 2>&1 | Out-File (Join-Path $Dirs.Case 'memory_tool_output.txt') -Encoding UTF8
        if (Test-Path -LiteralPath $memFile) {
            $mh = (Get-FileHash -LiteralPath $memFile -Algorithm SHA256).Hash
            "$mh  $memFile" | Out-File (Join-Path $Dirs.Case 'memory_hash.txt') -Encoding UTF8
            Write-Log "Memory image SHA256 $mh"
        }
    }
}

# --------------------------------------------------------------------------------------------
#  2. Volatile data
# --------------------------------------------------------------------------------------------
$Script:Procs = @()
Invoke-Step 'Processes (hash, signature, owner, command line)' {
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($p in Get-CimInstance Win32_Process) {
        $owner = $null
        try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop; if ($o.User) { $owner = "$($o.Domain)\$($o.User)" } } catch { }
        $fi = Get-FileInfoEx $p.ExecutablePath
        $list.Add([pscustomobject]@{
            PID = $p.ProcessId; PPID = $p.ParentProcessId; Name = $p.Name; Path = $p.ExecutablePath; CommandLine = $p.CommandLine
            Owner = $owner; Created = $p.CreationDate; SessionId = $p.SessionId; WorkingSetMB = [math]::Round($p.WorkingSetSize / 1MB, 1)
            SHA256 = $fi.SHA256; SigStatus = $fi.SigStatus; Signer = $fi.Signer; OriginalFilename = $fi.OriginalFilename; Company = $fi.CompanyName })
    }
    $Script:Procs = $list
    Save-Csv $list (Join-Path $Dirs.Volatile 'processes.csv')
    Save-Cmd 'tasklist /v /fo csv' (Join-Path $Dirs.Volatile 'tasklist_verbose.csv')
    Save-Cmd 'tasklist /svc /fo csv' (Join-Path $Dirs.Volatile 'tasklist_services.csv')
    # process tree
    $byParent = @{}; foreach ($p in $list) { $k = [string]$p.PPID; if (-not $byParent.ContainsKey($k)) { $byParent[$k] = @() }; $byParent[$k] += $p }
    $pids = @{}; foreach ($p in $list) { $pids[[string]$p.PID] = $true }
    $sb = New-Object System.Text.StringBuilder
    function Write-Tree($node, $depth) {
        [void]$sb.AppendLine(('  ' * $depth) + "[$($node.PID)] $($node.Name)  $($node.CommandLine)")
        if ($depth -lt 30 -and $byParent.ContainsKey([string]$node.PID)) { foreach ($c in $byParent[[string]$node.PID]) { if ($c.PID -ne $node.PID) { Write-Tree $c ($depth + 1) } } }
    }
    foreach ($p in $list) { if (-not $pids.ContainsKey([string]$p.PPID) -or $p.PPID -eq 0) { Write-Tree $p 0 } }
    $sb.ToString() | Out-File (Join-Path $Dirs.Volatile 'process_tree.txt') -Encoding UTF8
}

Invoke-Step 'Loaded modules outside Windows directory' {
    $mods = New-Object System.Collections.Generic.List[object]
    foreach ($gp in Get-Process -ErrorAction SilentlyContinue) {
        $ml = $null; try { $ml = $gp.Modules } catch { continue }
        foreach ($m in $ml) {
            if ($m.FileName -and $m.FileName -notmatch '(?i)^[A-Z]:\\Windows\\') {
                $fi = Get-FileInfoEx $m.FileName
                $mods.Add([pscustomobject]@{ PID = $gp.Id; Process = $gp.ProcessName; Module = $m.FileName; SHA256 = $fi.SHA256; SigStatus = $fi.SigStatus; Signer = $fi.Signer })
            }
        }
    }
    Save-Csv $mods (Join-Path $Dirs.Volatile 'modules_non_windows.csv')
}

$Script:Tcp = @(); $Script:Dns = @()
Invoke-Step 'Network state' {
    $pmap = @{}; foreach ($p in $Script:Procs) { $pmap[[int]$p.PID] = $p }
    $tcp = foreach ($c in Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $pp = $pmap[[int]$c.OwningProcess]
        [pscustomobject]@{ LocalAddress = $c.LocalAddress; LocalPort = $c.LocalPort; RemoteAddress = $c.RemoteAddress; RemotePort = $c.RemotePort
            State = [string]$c.State; PID = $c.OwningProcess; Process = $(if ($pp) { $pp.Name }); Path = $(if ($pp) { $pp.Path }); CreationTime = $c.CreationTime }
    }
    $Script:Tcp = @($tcp)
    Save-Csv $tcp (Join-Path $Dirs.Volatile 'tcp_connections.csv')
    $udp = foreach ($u in Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        $pp = $pmap[[int]$u.OwningProcess]
        [pscustomobject]@{ LocalAddress = $u.LocalAddress; LocalPort = $u.LocalPort; PID = $u.OwningProcess; Process = $(if ($pp) { $pp.Name }); Path = $(if ($pp) { $pp.Path }) }
    }
    Save-Csv $udp (Join-Path $Dirs.Volatile 'udp_endpoints.csv')
    Save-Cmd 'netstat -anob' (Join-Path $Dirs.Volatile 'netstat_anob.txt')
    $Script:Dns = @(Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, Name, Type, Status, TimeToLive, Data)
    Save-Csv $Script:Dns (Join-Path $Dirs.Volatile 'dns_cache.csv')
    Save-Csv (Get-NetNeighbor -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State) (Join-Path $Dirs.Volatile 'arp_neighbors.csv')
    Save-Csv (Get-NetRoute -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, DestinationPrefix, NextHop, RouteMetric) (Join-Path $Dirs.Volatile 'routes.csv')
    Save-Cmd 'ipconfig /all' (Join-Path $Dirs.Volatile 'ipconfig_all.txt')
    Save-Cmd 'netsh winhttp show proxy' (Join-Path $Dirs.Volatile 'winhttp_proxy.txt')
    Save-Cmd 'netsh advfirewall show allprofiles' (Join-Path $Dirs.Volatile 'firewall_profiles.txt')
    Save-Cmd 'netsh advfirewall firewall show rule name=all verbose' (Join-Path $Dirs.Volatile 'firewall_rules.txt')
    Save-Cmd 'net share' (Join-Path $Dirs.Volatile 'shares.txt')
    Save-Cmd 'net session' (Join-Path $Dirs.Volatile 'smb_sessions.txt')
    Save-Cmd 'net use' (Join-Path $Dirs.Volatile 'mapped_drives.txt')
    Save-Cmd 'query user' (Join-Path $Dirs.Volatile 'logged_on_users.txt')
    Save-Cmd 'qwinsta' (Join-Path $Dirs.Volatile 'sessions_qwinsta.txt')
    Save-Csv (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue | Select-Object ProxyEnable, ProxyServer, AutoConfigURL) (Join-Path $Dirs.Volatile 'user_proxy.csv')
    Copy-Evidence "$env:SystemRoot\System32\drivers\etc\hosts" $Dirs.Volatile 'hosts.txt' | Out-Null
}

# --------------------------------------------------------------------------------------------
#  3. System state
# --------------------------------------------------------------------------------------------
$Script:Services = @(); $Script:Software = @(); $Script:MpPref = $null; $Script:MpStatus = $null
Invoke-Step 'System information, users and software' {
    Save-Cmd 'systeminfo' (Join-Path $Dirs.System 'systeminfo.txt')
    Get-CimInstance Win32_OperatingSystem | Format-List * | Out-File (Join-Path $Dirs.System 'os.txt') -Encoding UTF8
    Get-CimInstance Win32_ComputerSystem | Format-List * | Out-File (Join-Path $Dirs.System 'computer_system.txt') -Encoding UTF8
    Get-CimInstance Win32_BIOS | Format-List * | Out-File (Join-Path $Dirs.System 'bios.txt') -Encoding UTF8
    Save-Csv (Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID, Description, InstalledOn, InstalledBy) (Join-Path $Dirs.System 'hotfixes.csv')
    Save-Csv (Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Select-Object Name, SID, Disabled, Lockout, PasswordRequired, PasswordChangeable, PasswordExpires, Description) (Join-Path $Dirs.System 'local_users.csv')
    try { Save-Csv (Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, PasswordExpires, UserMayChangePassword, SID, Description) (Join-Path $Dirs.System 'local_users_detail.csv') } catch { }
    Save-Cmd 'net localgroup administrators' (Join-Path $Dirs.System 'local_admins.txt')
    $grp = foreach ($g in Get-CimInstance Win32_Group -Filter 'LocalAccount=True') {
        $members = @(Get-CimAssociatedInstance -InputObject $g -ResultClassName Win32_Account -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Domain)\$($_.Name)" })
        [pscustomobject]@{ Group = $g.Name; SID = $g.SID; Members = ($members -join '; ') }
    }
    Save-Csv $grp (Join-Path $Dirs.System 'local_groups.csv')
    Save-Csv (Get-CimInstance Win32_UserProfile | Select-Object LocalPath, SID, Special, Loaded, LastUseTime) (Join-Path $Dirs.System 'user_profiles.csv')
    $sw = foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString, @{ n = 'Key'; e = { $_.PSPath -replace '^.*::', '' } }
    }
    $Script:Software = @($sw)
    Save-Csv $sw (Join-Path $Dirs.System 'installed_software.csv')
    Get-ChildItem Env: | Select-Object Name, Value | Export-Csv (Join-Path $Dirs.System 'environment.csv') -NoTypeInformation -Encoding UTF8
}

Invoke-Step 'Services and drivers' {
    $svc = foreach ($s in Get-CimInstance Win32_Service) {
        $exe = Get-ExeFromCommand $s.PathName
        $fi = Get-FileInfoEx $exe
        [pscustomobject]@{ Name = $s.Name; DisplayName = $s.DisplayName; State = $s.State; StartMode = $s.StartMode; StartName = $s.StartName
            PathName = $s.PathName; Exe = $exe; SHA256 = $fi.SHA256; SigStatus = $fi.SigStatus; Signer = $fi.Signer; Description = $s.Description }
    }
    $Script:Services = @($svc)
    Save-Csv $svc (Join-Path $Dirs.System 'services.csv')
    $drv = foreach ($d in Get-CimInstance Win32_SystemDriver) {
        $exe = Get-ExeFromCommand $d.PathName; $fi = Get-FileInfoEx $exe
        [pscustomobject]@{ Name = $d.Name; State = $d.State; StartMode = $d.StartMode; PathName = $d.PathName; SHA256 = $fi.SHA256; SigStatus = $fi.SigStatus; Signer = $fi.Signer }
    }
    Save-Csv $drv (Join-Path $Dirs.System 'drivers.csv')
    Save-Cmd 'driverquery /v /fo csv' (Join-Path $Dirs.System 'driverquery.csv')
}

Invoke-Step 'Security configuration (Defender, audit, logging, WinRE, BitLocker)' {
    try { $Script:MpStatus = Get-MpComputerStatus -ErrorAction Stop; $Script:MpStatus | Format-List * | Out-File (Join-Path $Dirs.System 'defender_status.txt') -Encoding UTF8 } catch { Write-Log "Get-MpComputerStatus: $($_.Exception.Message)" 'WARN' }
    try { $Script:MpPref = Get-MpPreference -ErrorAction Stop; $Script:MpPref | Format-List * | Out-File (Join-Path $Dirs.System 'defender_preferences.txt') -Encoding UTF8 } catch { Write-Log "Get-MpPreference: $($_.Exception.Message)" 'WARN' }
    try { Save-Csv (Get-MpThreatDetection -ErrorAction Stop | Select-Object ThreatID, InitialDetectionTime, LastThreatStatusChangeTime, ActionSuccess, ProcessName, DomainUser, @{ n = 'Resources'; e = { $_.Resources -join ' | ' } }) (Join-Path $Dirs.System 'defender_detections.csv') } catch { }
    try { Save-Csv (Get-MpThreat -ErrorAction Stop | Select-Object ThreatID, ThreatName, SeverityID, IsActive, DidThreatExecute, @{ n = 'Resources'; e = { $_.Resources -join ' | ' } }) (Join-Path $Dirs.System 'defender_threats.csv') } catch { }
    # Exclusions straight from the registry too (works even when Defender is passive/disabled)
    $exl = foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions') {
        foreach ($t in 'Paths', 'Extensions', 'Processes', 'IpAddresses', 'TemporaryPaths') {
            $k = Join-Path $base $t
            if (Test-Path $k) { $props = Get-ItemProperty $k; foreach ($pn in $props.PSObject.Properties) { if ($pn.Name -notlike 'PS*') { [pscustomobject]@{ Source = $base; Type = $t; Value = $pn.Name } } } }
        }
    }
    Save-Csv $exl (Join-Path $Dirs.System 'defender_exclusions_registry.csv')
    Save-Cmd 'auditpol /get /category:*' (Join-Path $Dirs.System 'audit_policy.txt')
    Save-Cmd 'reagentc /info' (Join-Path $Dirs.System 'reagentc_info.txt')
    Save-Cmd 'bcdedit /enum all' (Join-Path $Dirs.System 'bcdedit.txt')
    Save-Cmd 'manage-bde -status' (Join-Path $Dirs.System 'bitlocker_status.txt')
    Save-Cmd 'vssadmin list shadows' (Join-Path $Dirs.System 'shadow_copies.txt')
    try { "SecureBoot: $(Confirm-SecureBootUEFI -ErrorAction Stop)" | Out-File (Join-Path $Dirs.System 'secureboot.txt') } catch { "SecureBoot: unknown ($($_.Exception.Message))" | Out-File (Join-Path $Dirs.System 'secureboot.txt') }
    $logcfg = foreach ($k in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit') {
        if (Test-Path $k) { $p = Get-ItemProperty $k; foreach ($pn in $p.PSObject.Properties) { if ($pn.Name -notlike 'PS*') { [pscustomobject]@{ Key = $k; Name = $pn.Name; Value = $pn.Value } } } }
    }
    Save-Csv $logcfg (Join-Path $Dirs.System 'logging_policy.csv')
    try { Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop | Out-File (Join-Path $Dirs.System 'applocker_effective.xml') -Encoding UTF8 } catch { }
}

# --------------------------------------------------------------------------------------------
#  4. Persistence
# --------------------------------------------------------------------------------------------
$Script:Tasks = @(); $Script:Autoruns = @(); $Script:Wmi = @()
Invoke-Step 'Scheduled tasks (+ raw XML)' {
    $list = New-Object System.Collections.Generic.List[object]
    $xmlDir = Join-Path $Dirs.Persistence 'task_xml'; New-Item -ItemType Directory -Path $xmlDir -Force | Out-Null
    foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $info = $null; try { $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch { }
        $acts = @(); foreach ($a in $t.Actions) { if ($a.Execute) { $acts += ("{0} {1}" -f $a.Execute, $a.Arguments).Trim() } elseif ($a.ClassId) { $acts += "COM:$($a.ClassId)" } }
        $trig = @(); foreach ($tr in $t.Triggers) { $trig += ($tr.CimClass.CimClassName -replace '^MSFT_Task', '') }
        $xmlDate = $null
        try { $xml = Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
              ($xml | Out-String) | Out-File (Join-Path $xmlDir ((Get-SafeName ($t.TaskPath + $t.TaskName)) + '.xml')) -Encoding UTF8
              $m = [regex]::Match($xml, '<Date>([^<]+)</Date>'); if ($m.Success) { $xmlDate = $m.Groups[1].Value } } catch { }
        $list.Add([pscustomobject]@{ TaskPath = $t.TaskPath; TaskName = $t.TaskName; State = [string]$t.State; Author = $t.Author; RegistrationDate = $xmlDate
            RunAs = $t.Principal.UserId; RunLevel = [string]$t.Principal.RunLevel; Hidden = $t.Settings.Hidden; Actions = ($acts -join ' | '); Triggers = ($trig -join ',')
            LastRun = $(if ($info) { $info.LastRunTime }); LastResult = $(if ($info) { $info.LastTaskResult }); NextRun = $(if ($info) { $info.NextRunTime }) })
    }
    $Script:Tasks = $list
    Save-Csv $list (Join-Path $Dirs.Persistence 'scheduled_tasks.csv')
    Save-Cmd 'schtasks /query /fo csv /v' (Join-Path $Dirs.Persistence 'schtasks_verbose.csv')
}

Invoke-Step 'Registry autostart locations (all users)' {
    $keys = @(
        'Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
        'Software\Microsoft\Windows\CurrentVersion\RunServices', 'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
        'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce', 'Software\Microsoft\Windows NT\CurrentVersion\Windows',
        'Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
        'Software\Microsoft\Command Processor', 'Environment')
    $hives = @('HKLM:')
    foreach ($h in Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) { if ($h.PSChildName -match '^S-1-5-21-[\d-]+$') { $hives += "Registry::HKEY_USERS\$($h.PSChildName)" } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($h in $hives) {
        foreach ($k in $keys) {
            $full = "$h\$k"
            if (-not (Test-Path -LiteralPath $full)) { continue }
            $p = Get-ItemProperty -LiteralPath $full -ErrorAction SilentlyContinue
            foreach ($pn in $p.PSObject.Properties) {
                if ($pn.Name -like 'PS*') { continue }
                if ($k -match 'Winlogon$' -and $pn.Name -notin @('Shell', 'Userinit', 'Taskman', 'AppSetup', 'VMApplet', 'GinaDLL')) { continue }
                if ($k -match 'NT\\CurrentVersion\\Windows$' -and $pn.Name -notin @('Load', 'Run', 'AppInit_DLLs', 'LoadAppInit_DLLs')) { continue }
                if ($k -match 'Command Processor$' -and $pn.Name -ne 'AutoRun') { continue }
                if ($k -match 'Shell Folders$' -and $pn.Name -notmatch 'Startup') { continue }
                if ($k -eq 'Environment' -and $pn.Name -notin @('UserInitMprLogonScript', 'COR_PROFILER_PATH', 'COR_ENABLE_PROFILING')) { continue }
                $out.Add([pscustomobject]@{ Location = ($full -replace 'Registry::', ''); Name = $pn.Name; Value = [string]$pn.Value; Exe = (Get-ExeFromCommand ([string]$pn.Value)) })
            }
        }
    }
    # Machine-only ASEPs
    $special = @(
        @{ K = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; N = @('BootExecute', 'SetupExecute', 'Execute', 'S0InitialCommand') },
        @{ K = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = @('Authentication Packages', 'Notification Packages', 'Security Packages') },
        @{ K = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; N = @('AppInit_DLLs', 'LoadAppInit_DLLs') },
        @{ K = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'; N = @('AppInit_DLLs') },
        @{ K = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'; N = @('*') },
        @{ K = 'HKLM:\SOFTWARE\Microsoft\NetSh'; N = @('*') },
        @{ K = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'; N = @() })
    foreach ($s in $special) {
        if (-not (Test-Path $s.K)) { continue }
        $p = Get-ItemProperty $s.K -ErrorAction SilentlyContinue
        foreach ($pn in $p.PSObject.Properties) {
            if ($pn.Name -like 'PS*') { continue }
            if ($s.N -contains '*' -or $s.N -contains $pn.Name) { $out.Add([pscustomobject]@{ Location = $s.K; Name = $pn.Name; Value = (@($pn.Value) -join ' '); Exe = $null }) }
        }
    }
    foreach ($ifeo in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue) {
        $d = (Get-ItemProperty $ifeo.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($d) { $out.Add([pscustomobject]@{ Location = 'IFEO\' + $ifeo.PSChildName; Name = 'Debugger'; Value = $d; Exe = (Get-ExeFromCommand $d) }) }
    }
    foreach ($sp in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue) {
        $mp = (Get-ItemProperty $sp.PSPath -ErrorAction SilentlyContinue).MonitorProcess
        if ($mp) { $out.Add([pscustomobject]@{ Location = 'SilentProcessExit\' + $sp.PSChildName; Name = 'MonitorProcess'; Value = $mp; Exe = (Get-ExeFromCommand $mp) }) }
    }
    foreach ($as in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' -ErrorAction SilentlyContinue) {
        $sp = (Get-ItemProperty $as.PSPath -ErrorAction SilentlyContinue).StubPath
        if ($sp) { $out.Add([pscustomobject]@{ Location = 'ActiveSetup\' + $as.PSChildName; Name = 'StubPath'; Value = $sp; Exe = (Get-ExeFromCommand $sp) }) }
    }
    # Per-user COM hijacks (HKCU CLSID InprocServer32 / LocalServer32)
    foreach ($h in $hives) {
        if ($h -eq 'HKLM:') { continue }
        foreach ($c in Get-ChildItem "$h\Software\Classes\CLSID" -ErrorAction SilentlyContinue) {
            foreach ($sub in 'InprocServer32', 'LocalServer32') {
                $sk = Join-Path $c.PSPath $sub
                if (Test-Path -LiteralPath $sk) { $v = (Get-ItemProperty -LiteralPath $sk -ErrorAction SilentlyContinue).'(default)'; if ($v) { $out.Add([pscustomobject]@{ Location = ($h -replace 'Registry::', '') + '\CLSID\' + $c.PSChildName + '\' + $sub; Name = '(default)'; Value = $v; Exe = (Get-ExeFromCommand $v) }) } }
            }
        }
    }
    # IOC registry keys
    foreach ($rk in $IocDb.regkey) {
        if (Test-Path -LiteralPath $rk) {
            foreach ($i in Get-ChildItem -LiteralPath $rk -Recurse -ErrorAction SilentlyContinue) { $p = Get-ItemProperty -LiteralPath $i.PSPath; foreach ($pn in $p.PSObject.Properties) { if ($pn.Name -notlike 'PS*') { $out.Add([pscustomobject]@{ Location = $i.Name; Name = $pn.Name; Value = [string]$pn.Value; Exe = (Get-ExeFromCommand ([string]$pn.Value)) }) } } }
            $out.Add([pscustomobject]@{ Location = $rk; Name = '(IOC key present)'; Value = 'present'; Exe = $null })
        }
    }
    $Script:Autoruns = $out
    Save-Csv $out (Join-Path $Dirs.Persistence 'registry_autoruns.csv')
}

Invoke-Step 'Startup folders, WMI subscriptions, BITS jobs' {
    $su = New-Object System.Collections.Generic.List[object]
    $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    foreach ($pr in Get-CimInstance Win32_UserProfile -Filter 'Special=False') { $folders += Join-Path $pr.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
    foreach ($f in $folders) {
        foreach ($i in Get-ChildItem -LiteralPath $f -Force -File -ErrorAction SilentlyContinue) {
            $target = $null
            if ($i.Extension -eq '.lnk') { try { $sh = New-Object -ComObject WScript.Shell; $l = $sh.CreateShortcut($i.FullName); $target = "$($l.TargetPath) $($l.Arguments)" } catch { } }
            $su.Add([pscustomobject]@{ Folder = $f; File = $i.Name; Target = $target; Created = $i.CreationTime; Modified = $i.LastWriteTime })
            Copy-Evidence $i.FullName (Join-Path $Dirs.Persistence 'startup_items') | Out-Null
        }
    }
    Save-Csv $su (Join-Path $Dirs.Persistence 'startup_folders.csv')
    $w = New-Object System.Collections.Generic.List[object]
    foreach ($cls in '__EventFilter', '__EventConsumer', '__FilterToConsumerBinding') {
        foreach ($o in Get-CimInstance -Namespace root\subscription -ClassName $cls -ErrorAction SilentlyContinue) {
            $w.Add([pscustomobject]@{ Class = $o.CimClass.CimClassName; Name = $o.Name; Query = $o.Query; CommandLine = $o.CommandLineTemplate; Script = $o.ScriptText; Executable = $o.ExecutablePath; Filter = [string]$o.Filter; Consumer = [string]$o.Consumer })
        }
    }
    $Script:Wmi = $w
    Save-Csv $w (Join-Path $Dirs.Persistence 'wmi_subscriptions.csv')
    try { Save-Csv (Get-BitsTransfer -AllUsers -ErrorAction Stop | Select-Object DisplayName, JobState, OwnerAccount, CreationTime, TransferType, @{ n = 'Files'; e = { ($_.FileList | ForEach-Object { "$($_.RemoteName) -> $($_.LocalName)" }) -join ' | ' } }) (Join-Path $Dirs.Persistence 'bits_jobs.csv') } catch { }
}

# --------------------------------------------------------------------------------------------
#  5. Event logs
# --------------------------------------------------------------------------------------------
$Script:Ev = @{}
if (-not $SkipEventLogs) {
    Invoke-Step 'Event log export (.evtx)' {
        $raw = Join-Path $Dirs.EventLogs 'evtx'; New-Item -ItemType Directory -Path $raw -Force | Out-Null
        $logs = @('Security', 'System', 'Application', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Windows Defender/Operational',
                  'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
                  'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational', 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational',
                  'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Bits-Client/Operational', 'Microsoft-Windows-CodeIntegrity/Operational',
                  'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', 'Microsoft-Windows-DNS-Client/Operational',
                  'Microsoft-Windows-SMBServer/Security', 'Microsoft-Windows-WinRM/Operational', 'Microsoft-Windows-Winlogon/Operational', 'Microsoft-Windows-Shell-Core/Operational',
                  'Microsoft-Windows-NTLM/Operational', 'Microsoft-Windows-Kernel-PnP/Configuration', 'Setup')
        foreach ($l in $logs) {
            $f = Join-Path $raw ((Get-SafeName $l) + '.evtx')
            & wevtutil.exe epl "$l" "$f" 2>&1 | Out-Null
            if (-not (Test-Path -LiteralPath $f)) { Write-Log "Log not exported (absent or access denied): $l" 'WARN' }
        }
        Save-Cmd 'wevtutil el' (Join-Path $Dirs.EventLogs 'available_logs.txt')
        $meta = foreach ($l in Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 }) { [pscustomobject]@{ Log = $l.LogName; Records = $l.RecordCount; MaxSizeMB = [math]::Round($l.MaximumSizeInBytes / 1MB, 1); LastWrite = $l.LastWriteTime; Mode = $l.LogMode } }
        Save-Csv $meta (Join-Path $Dirs.EventLogs 'log_inventory.csv')
    }

    Invoke-Step 'Event log parsing (high-value IDs)' {
        $queries = @(
            @{ N = 'security_logons';        L = 'Security'; I = @(4624, 4625, 4634, 4647, 4648, 4672, 4776, 4768, 4769, 4771) },
            @{ N = 'security_accounts';      L = 'Security'; I = @(4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4738, 4740, 4756, 4798, 4799) },
            @{ N = 'security_process';       L = 'Security'; I = @(4688, 4689) },
            @{ N = 'security_persistence';   L = 'Security'; I = @(4697, 4698, 4699, 4700, 4702, 4657) },
            @{ N = 'security_audit_tamper';  L = 'Security'; I = @(1100, 1102, 4719, 4907) },
            @{ N = 'system_services';        L = 'System'; I = @(7034, 7035, 7036, 7040, 7045) },
            @{ N = 'system_logclear_boot';   L = 'System'; I = @(104, 6005, 6006, 6008, 6009, 1074, 12, 13, 41) },
            @{ N = 'powershell_classic';     L = 'Windows PowerShell'; I = @(400, 403, 600, 800) },
            @{ N = 'powershell_operational'; L = 'Microsoft-Windows-PowerShell/Operational'; I = @(4103, 4104, 40961, 40962, 53504) },
            @{ N = 'defender';               L = 'Microsoft-Windows-Windows Defender/Operational'; I = @(1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 1121, 5001, 5004, 5007, 5010, 5012, 5013) },
            @{ N = 'task_scheduler';         L = 'Microsoft-Windows-TaskScheduler/Operational'; I = @(106, 140, 141, 129, 200, 201) },
            @{ N = 'rdp';                    L = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; I = @(21, 22, 23, 24, 25, 39, 40) },
            @{ N = 'rdp_auth';               L = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; I = @(1149) },
            @{ N = 'wmi';                    L = 'Microsoft-Windows-WMI-Activity/Operational'; I = @(5857, 5858, 5859, 5860, 5861) },
            @{ N = 'bits';                   L = 'Microsoft-Windows-Bits-Client/Operational'; I = @(3, 59, 60, 61) },
            @{ N = 'sysmon';                 L = 'Microsoft-Windows-Sysmon/Operational'; I = @(1, 3, 6, 7, 8, 10, 11, 12, 13, 22, 25) },
            @{ N = 'application_crashes';    L = 'Application'; I = @(1000, 1001, 1002, 1026) })
        $pdir = Join-Path $Dirs.EventLogs 'parsed'; New-Item -ItemType Directory -Path $pdir -Force | Out-Null
        foreach ($q in $queries) {
            $evs = @()
            try { $evs = @(Get-WinEvent -FilterHashtable @{ LogName = $q.L; Id = $q.I; StartTime = $Since } -MaxEvents 50000 -ErrorAction Stop) } catch { continue }
            $rows = foreach ($e in $evs) {
                $data = ''
                try { $x = [xml]$e.ToXml(); $data = (@($x.Event.EventData.Data) | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_.Name) { "$($_.Name)=$($_.'#text')" } else { $_.'#text' } }) -join ' | ' } catch { }
                [pscustomobject]@{ TimeUtc = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'); TimeLocal = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    Log = $q.L; EventId = $e.Id; RecordId = $e.RecordId; Provider = $e.ProviderName; PID = $e.ProcessId
                    Message = ($(if ($e.Message) { $e.Message } else { '' }) -replace '\s+', ' '); EventData = $data }
            }
            $Script:Ev[$q.N] = @($rows)
            Save-Csv $rows (Join-Path $pdir ($q.N + '.csv'))
            Write-Log ("  {0}: {1} events" -f $q.N, $evs.Count)
        }
    }
}

# --------------------------------------------------------------------------------------------
#  6. Artefacts
# --------------------------------------------------------------------------------------------
$Profiles = @(Get-CimInstance Win32_UserProfile -Filter 'Special=False' -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) })
Invoke-Step 'Execution artefacts (Prefetch, Amcache, SRUM, ShimCache source, WER)' {
    $d = Join-Path $Dirs.Artifacts 'execution'; New-Item -ItemType Directory -Path $d -Force | Out-Null
    foreach ($f in Get-ChildItem "$env:SystemRoot\Prefetch" -Filter *.pf -Force -ErrorAction SilentlyContinue) { Copy-Evidence $f.FullName (Join-Path $d 'Prefetch') $f.Name | Out-Null }
    foreach ($f in 'Amcache.hve', 'Amcache.hve.LOG1', 'Amcache.hve.LOG2') { Copy-Evidence "$env:SystemRoot\appcompat\Programs\$f" (Join-Path $d 'Amcache') $f | Out-Null }
    Copy-Evidence "$env:SystemRoot\System32\sru\SRUDB.dat" (Join-Path $d 'SRUM') 'SRUDB.dat' | Out-Null
    $werRoot = "$env:ProgramData\Microsoft\Windows\WER"
    $werFiles = @(); if (Test-Path -LiteralPath $werRoot -PathType Container) { $werFiles = @(Get-ChildItem -LiteralPath $werRoot -Recurse -Filter 'Report.wer' -Force -ErrorAction SilentlyContinue) }
    foreach ($f in $werFiles | Where-Object { $_.LastWriteTime -gt $Since }) { Copy-Evidence $f.FullName (Join-Path $d 'WER') ((Split-Path $f.DirectoryName -Leaf) + '.wer') | Out-Null }
    foreach ($f in Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Support" -Filter 'MPLog*' -Force -ErrorAction SilentlyContinue) { Copy-Evidence $f.FullName (Join-Path $d 'DefenderMPLog') $f.Name | Out-Null }
    Copy-Evidence "$env:SystemRoot\INF\setupapi.dev.log" (Join-Path $d 'USB') 'setupapi.dev.log' | Out-Null
    $usb = foreach ($k in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue) { foreach ($s in Get-ChildItem $k.PSPath -ErrorAction SilentlyContinue) { $p = Get-ItemProperty $s.PSPath; [pscustomobject]@{ Device = $k.PSChildName; Serial = $s.PSChildName; FriendlyName = $p.FriendlyName } } }
    Save-Csv $usb (Join-Path $d 'usbstor.csv')
}

if (-not $SkipRegistryHives) {
    Invoke-Step 'Registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER, UsrClass)' {
        $d = Join-Path $Dirs.Artifacts 'registry'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        foreach ($h in 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY') { & reg.exe save "HKLM\$h" (Join-Path $d "$h.hiv") /y 2>&1 | Out-Null }
        Copy-Evidence "$env:SystemRoot\System32\config\DEFAULT" $d 'DEFAULT.hiv' | Out-Null
        foreach ($pr in $Profiles) {
            $u = Split-Path $pr.LocalPath -Leaf
            Copy-Evidence (Join-Path $pr.LocalPath 'NTUSER.DAT') $d "NTUSER_$u.DAT" | Out-Null
            Copy-Evidence (Join-Path $pr.LocalPath 'AppData\Local\Microsoft\Windows\UsrClass.dat') $d "UsrClass_$u.dat" | Out-Null
        }
    }
}

Invoke-Step 'User activity (PSReadLine, Recent/LNK, JumpLists, RMM traces, Recycle Bin)' {
    $d = Join-Path $Dirs.Artifacts 'user_activity'; New-Item -ItemType Directory -Path $d -Force | Out-Null
    foreach ($pr in $Profiles) {
        $u = Split-Path $pr.LocalPath -Leaf
        Copy-Evidence (Join-Path $pr.LocalPath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt') (Join-Path $d 'PSReadLine') "$u`_ConsoleHost_history.txt" | Out-Null
        foreach ($f in Get-ChildItem (Join-Path $pr.LocalPath 'AppData\Roaming\Microsoft\Windows\Recent') -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $Since }) { Copy-Evidence $f.FullName (Join-Path $d "Recent_$u") $f.Name | Out-Null }
        foreach ($sub in 'AutomaticDestinations', 'CustomDestinations') { foreach ($f in Get-ChildItem (Join-Path $pr.LocalPath "AppData\Roaming\Microsoft\Windows\Recent\$sub") -Force -File -ErrorAction SilentlyContinue) { Copy-Evidence $f.FullName (Join-Path $d "JumpLists_$u") $f.Name | Out-Null } }
        foreach ($f in Get-ChildItem (Join-Path $pr.LocalPath 'AppData\Roaming\AnyDesk') -Filter '*.trace' -Force -ErrorAction SilentlyContinue) { Copy-Evidence $f.FullName (Join-Path $d 'RemoteAccess') "$u`_$($f.Name)" | Out-Null }
        Copy-Evidence (Join-Path $pr.LocalPath 'AppData\Roaming\AnyDesk\connection_trace.txt') (Join-Path $d 'RemoteAccess') "$u`_anydesk_connection_trace.txt" | Out-Null
        foreach ($f in Get-ChildItem (Join-Path $pr.LocalPath 'AppData\Roaming\TeamViewer') -Filter '*.txt' -Force -ErrorAction SilentlyContinue) { Copy-Evidence $f.FullName (Join-Path $d 'RemoteAccess') "$u`_TV_$($f.Name)" | Out-Null }
    }
    foreach ($f in Get-ChildItem "$env:ProgramData\AnyDesk" -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.trace', '.txt', '.conf' }) { Copy-Evidence $f.FullName (Join-Path $d 'RemoteAccess') "ProgramData_AnyDesk_$($f.Name)" | Out-Null }
    foreach ($f in Get-ChildItem "${env:ProgramFiles(x86)}\TeamViewer", "$env:ProgramFiles\TeamViewer" -Filter '*.log' -Force -ErrorAction SilentlyContinue) { Copy-Evidence $f.FullName (Join-Path $d 'RemoteAccess') "TV_$($f.Name)" | Out-Null }
    $rbRoot = Join-Path "$env:SystemDrive\" '$Recycle.Bin'
    $rbFiles = @(); if ($env:SystemDrive -and (Test-Path -LiteralPath $rbRoot -PathType Container)) { $rbFiles = @(Get-ChildItem -LiteralPath $rbRoot -Recurse -Force -Filter '$I*' -ErrorAction SilentlyContinue) }
    $rb = foreach ($f in $rbFiles) {
        try { $b = [IO.File]::ReadAllBytes($f.FullName); $ver = [BitConverter]::ToInt64($b, 0); $size = [BitConverter]::ToInt64($b, 8); $del = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($b, 16))
              $name = if ($ver -eq 2) { [Text.Encoding]::Unicode.GetString($b, 28, $b.Length - 28).TrimEnd([char]0) } else { [Text.Encoding]::Unicode.GetString($b, 24, 520).TrimEnd([char]0) }
              [pscustomobject]@{ SID = (Split-Path $f.DirectoryName -Leaf); DeletedUtc = $del; Size = $size; OriginalPath = $name; IFile = $f.Name } } catch { }
    }
    Save-Csv $rb (Join-Path $d 'recycle_bin.csv')
}

if (-not $SkipBrowser) {
    Invoke-Step 'Browser history databases' {
        $d = Join-Path $Dirs.Artifacts 'browsers'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        foreach ($pr in $Profiles) {
            $u = Split-Path $pr.LocalPath -Leaf
            $chromium = @{ Chrome = 'AppData\Local\Google\Chrome\User Data'; Edge = 'AppData\Local\Microsoft\Edge\User Data'; Brave = 'AppData\Local\BraveSoftware\Brave-Browser\User Data'; Opera = 'AppData\Roaming\Opera Software\Opera Stable'; Vivaldi = 'AppData\Local\Vivaldi\User Data' }
            foreach ($b in $chromium.Keys) {
                $base = Join-Path $pr.LocalPath $chromium[$b]
                if (-not (Test-Path -LiteralPath $base)) { continue }
                foreach ($prof in @(Get-Item -LiteralPath $base) + @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Default|Profile \d+)$' })) {
                    foreach ($db in 'History', 'Downloads') { Copy-Evidence (Join-Path $prof.FullName $db) (Join-Path $d "$u\$b") ("{0}_{1}" -f ($prof.Name -replace ' ', ''), $db) | Out-Null }
                    foreach ($ext in Get-ChildItem (Join-Path $prof.FullName 'Extensions') -Directory -ErrorAction SilentlyContinue) { Add-Content -LiteralPath (Join-Path $d "$u`_${b}_extensions.txt") -Value ("{0}\{1}" -f $prof.Name, $ext.Name) -ErrorAction SilentlyContinue }
                }
            }
            foreach ($ff in Get-ChildItem (Join-Path $pr.LocalPath 'AppData\Roaming\Mozilla\Firefox\Profiles') -Directory -ErrorAction SilentlyContinue) {
                foreach ($db in 'places.sqlite', 'places.sqlite-wal', 'downloads.sqlite', 'extensions.json') { Copy-Evidence (Join-Path $ff.FullName $db) (Join-Path $d "$u\Firefox") ("{0}_{1}" -f $ff.Name, $db) | Out-Null }
            }
        }
    }
}

# --------------------------------------------------------------------------------------------
#  7. File inventory of user-writable / staging locations
# --------------------------------------------------------------------------------------------
$Script:FileInv = @()
Invoke-Step 'File inventory (executables & scripts in user-writable paths)' {
    $exts = @('.exe', '.dll', '.sys', '.scr', '.com', '.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.bat', '.cmd', '.lnk', '.msi', '.jar', '.py', '.cpl', '.ocx', '.au3', '.a3x')
    $roots = @("$env:ProgramData", "$env:SystemRoot\Temp", "$env:SystemRoot\SystemTemp", "$env:SystemDrive\Users\Public", "$env:SystemDrive\PerfLogs", "$env:SystemRoot\Tasks", "$env:SystemRoot\EdgeUpdate")
    foreach ($pr in $Profiles) { $roots += (Join-Path $pr.LocalPath 'AppData'); $roots += (Join-Path $pr.LocalPath 'Downloads'); $roots += (Join-Path $pr.LocalPath 'Desktop') }
    $list = New-Object System.Collections.Generic.List[object]
    $count = 0
    foreach ($r in $roots) {
        if ([string]::IsNullOrWhiteSpace($r) -or $r -match '^\\' -or -not (Test-Path -LiteralPath $r)) { continue }
        foreach ($f in Get-ChildItem -LiteralPath $r -Recurse -Force -File -ErrorAction SilentlyContinue) {
            if ($exts -notcontains $f.Extension.ToLower()) { continue }
            $recent = ($f.LastWriteTime -gt $Since -or $f.CreationTime -gt $Since)
            $isPe = $f.Extension -match '(?i)^\.(exe|dll|sys|scr|com|cpl|ocx)$'
            if (-not $recent -and -not $isPe) { continue }
            if (-not $recent -and $f.FullName -match '(?i)\\(Package Cache|Microsoft\\Windows Defender\\Definition Updates|Microsoft\\Windows Defender\\Platform|WindowsApps|Packages\\|assembly\\NativeImages)') { continue }
            $count++; if ($count -gt 40000) { if ($count -eq 40001) { Write-Log 'File inventory cap (40000) reached' 'WARN' }; break }
            $fi = Get-FileInfoEx $f.FullName
            $list.Add([pscustomobject]@{ Path = $f.FullName; Size = $f.Length; CreatedUtc = $f.CreationTimeUtc; ModifiedUtc = $f.LastWriteTimeUtc; Recent = $recent
                SHA256 = $fi.SHA256; SigStatus = $fi.SigStatus; Signer = $fi.Signer; OriginalFilename = $fi.OriginalFilename; Company = $fi.CompanyName; Description = $fi.FileDescription })
        }
    }
    # Recently created binaries in Windows / System32 (masquerading drops like Win-v42.exe)
    foreach ($r in "$env:SystemRoot", "$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot\System32\drivers") {
        if ([string]::IsNullOrWhiteSpace($env:SystemRoot) -or -not (Test-Path -LiteralPath $r)) { continue }
        foreach ($f in Get-ChildItem -LiteralPath $r -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt $Since -and $_.Extension -match '(?i)^\.(exe|dll|sys)$' }) {
            $fi = Get-FileInfoEx $f.FullName
            $list.Add([pscustomobject]@{ Path = $f.FullName; Size = $f.Length; CreatedUtc = $f.CreationTimeUtc; ModifiedUtc = $f.LastWriteTimeUtc; Recent = $true
                SHA256 = $fi.SHA256; SigStatus = $fi.SigStatus; Signer = $fi.Signer; OriginalFilename = $fi.OriginalFilename; Company = $fi.CompanyName; Description = $fi.FileDescription })
        }
    }
    $Script:FileInv = $list
    Save-Csv $list (Join-Path $Dirs.Files 'file_inventory.csv')
    Write-Log "  inventoried $($list.Count) files"
}

# --------------------------------------------------------------------------------------------
#  8. Analysis - rule engine
# --------------------------------------------------------------------------------------------
Invoke-Step 'Analysis: processes & network' {
    foreach ($p in $Script:Procs) {
        if (-not $p.Path) { continue }
        $r = Test-ExeSuspicious $p.Path
        if ($r -and $r[0] -ne 'Low') { Add-Finding $r[0] 'Process' "Suspicious running process: $($p.Name) (PID $($p.PID))" $r[1] "$($p.Path) | cmd: $($p.CommandLine) | SHA256 $($p.SHA256)" 'T1036 / T1204' }
        if ($p.CommandLine -and $p.CommandLine -match $SuspCmdRx) { Add-Finding 'High' 'Process' "Suspicious command line: $($p.Name) (PID $($p.PID))" 'Encoded/hidden/download/defence-tampering command line' $p.CommandLine 'T1059.001' }
        $ioc = Test-IocText $p.CommandLine; if ($ioc) { Add-Finding 'Critical' 'IOC' "Process command line matches IOC ($ioc)" "PID $($p.PID) $($p.Name)" $p.CommandLine 'IOC' }
        if ($p.Name -match $RmmRx) { Add-Finding 'Medium' 'Remote access' "Remote-access tool running: $($p.Name)" 'Confirm the tool is authorised; review its session logs' $p.Path 'T1219' }
    }
    $lolNet = '(?i)^(explorer|notepad|rundll32|regsvr32|mshta|wscript|cscript|dllhost|werfault|searchprotocolhost|calc|msbuild|installutil|regasm|regsvcs|cmstp|certutil|bitsadmin)\.exe$'
    foreach ($c in $Script:Tcp) {
        if ($c.State -notin 'Established', 'SynSent', 'Listen') { continue }
        $remote = [string]$c.RemoteAddress
        $isExternal = ($remote -and $remote -notmatch '^(0\.0\.0\.0|::|127\.|::1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fd|fc)')
        if ($IocIpSet.ContainsKey($remote)) { Add-Finding 'Critical' 'IOC' "Active connection to IOC IP $remote" "Process $($c.Process) PID $($c.PID) port $($c.RemotePort) state $($c.State)" "$($c.Path)" 'T1071' }
        if ($isExternal -and $c.Process -match $lolNet -and $c.State -ne 'Listen') { Add-Finding 'High' 'Network' "System/LOLBin process with external connection: $($c.Process) -> ${remote}:$($c.RemotePort)" 'Common sign of process injection/hollowing' "PID $($c.PID) $($c.Path)" 'T1055' }
        if ($isExternal -and $MiningPorts -contains [int]$c.RemotePort) { Add-Finding 'High' 'Network' "Connection to typical mining-pool port $($c.RemotePort): $($c.Process)" "Remote ${remote}" "PID $($c.PID) $($c.Path)" 'T1496' }
        if ($c.Path -and $c.Path -match $UserWritableRx -and ($isExternal -or $c.State -eq 'Listen')) { Add-Finding 'High' 'Network' "Network activity from user-writable binary: $($c.Process)" "$($c.State) $($c.LocalPort) -> ${remote}:$($c.RemotePort)" "PID $($c.PID) $($c.Path)" 'T1071' }
    }
    foreach ($d in $Script:Dns) { $ioc = Test-IocText "$($d.Entry) $($d.Data)"; if ($ioc) { Add-Finding 'Critical' 'IOC' "DNS cache contains IOC ($ioc)" "$($d.Entry) -> $($d.Data)" 'dns_cache.csv' 'T1071' } }
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    foreach ($l in Get-Content -LiteralPath $hostsFile -ErrorAction SilentlyContinue) { if ($l -match '^\s*[0-9a-fA-F:.]+\s+\S+' -and $l -notmatch '^\s*#' -and $l -notmatch '\blocalhost\b') { Add-Finding 'Medium' 'Network' 'Custom entry in hosts file' $l $hostsFile 'T1565.001' } }
}

Invoke-Step 'Analysis: persistence' {
    foreach ($s in $Script:Services) {
        if (-not $s.Exe) { continue }
        $r = Test-ExeSuspicious $s.Exe
        $pattern = ($s.Exe -match '(?i)\\ProgramData\\[a-z]{8,}\\[a-z]{8,}\.exe$' -and $s.Name -cmatch '^[A-Z]{6,10}$')
        if ($pattern) { Add-Finding 'Critical' 'Persistence' "Miner-pattern service: $($s.Name)" 'Random upper-case service name with random ProgramData folder/executable (XMRig dropper pattern)' "$($s.PathName) | $($s.StartName) | $($s.State)" 'T1543.003 / T1496' }
        elseif ($r -and $r[0] -ne 'Low') { Add-Finding $r[0] 'Persistence' "Suspicious service: $($s.Name) [$($s.State)]" $r[1] "$($s.PathName) | runs as $($s.StartName) | SHA256 $($s.SHA256)" 'T1543.003' }
        if ($s.PathName -match $SuspCmdRx -or ($s.PathName -match $ScriptHostRx -and $s.PathName -notmatch '(?i)svchost\.exe -k')) { Add-Finding 'High' 'Persistence' "Service launches script host/encoded command: $($s.Name)" '' $s.PathName 'T1543.003' }
    }
    foreach ($t in $Script:Tasks) {
        if (-not $t.Actions) { continue }
        $firstAct = ($t.Actions -split ' \| ')[0]
        $exe = Get-ExeFromCommand $firstAct
        $r = Test-ExeSuspicious $exe
        $ioc = Test-IocText $t.Actions
        $where = "$($t.TaskPath)$($t.TaskName)"
        if ($ioc) { Add-Finding 'Critical' 'Persistence' "Scheduled task matches IOC: $where" $ioc "$($t.Actions) | RunAs $($t.RunAs) | Registered $($t.RegistrationDate)" 'T1053.005' }
        elseif ($r -and $r[0] -ne 'Low') { Add-Finding $r[0] 'Persistence' "Suspicious scheduled task: $where" $r[1] "$($t.Actions) | RunAs $($t.RunAs) $($t.RunLevel) | Triggers $($t.Triggers) | Registered $($t.RegistrationDate)" 'T1053.005' }
        elseif ($t.Actions -match $SuspCmdRx -or ($t.Actions -match '(?i)\b(wscript|cscript|mshta)\b')) { Add-Finding 'High' 'Persistence' "Scheduled task runs script host / suspicious command: $where" '' $t.Actions 'T1053.005' }
        if ($t.TaskName -match '(?i)(Activation|KMS|AutoKMS|KMSpico|KMSAuto|HWID)' -or $t.Author -match '(?i)WindowsAddict') { Add-Finding 'Medium' 'Policy' "Unlicensed activation tool task: $where" 'Pirated activation tools are a common malware delivery vector' $t.Actions 'T1204' }
        if ($t.TaskPath -eq '\' -and $t.RunLevel -eq 'Highest' -and $t.Author -and $t.Author -notmatch '(?i)(Microsoft|SYSTEM|Google|Adobe|Mozilla|Brave|Intel|NVIDIA|Dell|HP|Lenovo)' -and (-not $r)) { Add-Finding 'Low' 'Persistence' "Root-folder task with highest privileges: $where" "Author $($t.Author)" $t.Actions 'T1053.005' }
    }
    foreach ($a in $Script:Autoruns) {
        $ioc = Test-IocText "$($a.Location) $($a.Value)"
        if ($a.Name -eq '(IOC key present)') { Add-Finding 'Critical' 'IOC' "IOC registry key present: $($a.Location)" '' $a.Location 'T1112'; continue }
        if ($ioc) { Add-Finding 'Critical' 'Persistence' "Autorun matches IOC: $($a.Name)" $ioc "$($a.Location) = $($a.Value)" 'T1547.001'; continue }
        if ($a.Value -match '(?i)\\Temp\\\d{5,}0101\\') { Add-Finding 'Critical' 'Persistence' "Loader staging autorun: $($a.Name)" 'Run value points to %TEMP%\<digits>0101\ (Amadey-style task payload)' "$($a.Location) = $($a.Value)" 'T1547.001'; continue }
        if ($a.Location -match 'Winlogon' -and (($a.Name -eq 'Shell' -and $a.Value -notmatch '^(?i)explorer\.exe,?$') -or ($a.Name -eq 'Userinit' -and $a.Value -notmatch '(?i)^C:\\Windows\\system32\\userinit\.exe,?$'))) { Add-Finding 'High' 'Persistence' "Modified Winlogon $($a.Name)" '' $a.Value 'T1547.004' }
        if ($a.Location -match '^IFEO|SilentProcessExit') { Add-Finding 'High' 'Persistence' "IFEO / SilentProcessExit hijack: $($a.Location)" '' $a.Value 'T1546.012' }
        if ($a.Name -in 'AppInit_DLLs' -and $a.Value) { Add-Finding 'High' 'Persistence' 'AppInit_DLLs configured' '' $a.Value 'T1546.010' }
        if ($a.Name -eq 'AutoRun' -and $a.Value) { Add-Finding 'High' 'Persistence' 'Command Processor AutoRun configured' '' $a.Value 'T1546' }
        if ($a.Location -match '\\CLSID\\' -and $a.Exe -and $a.Exe -match $UserWritableRx) { Add-Finding 'Medium' 'Persistence' "Per-user COM server in user-writable path: $($a.Location)" '' $a.Value 'T1546.015' }
        if ($a.Location -match '\\Run|RunOnce|Policies\\Explorer\\Run|StubPath|Load$') {
            if ($a.Value -match $SuspCmdRx -or $a.Value -match '(?i)\b(wscript|cscript|mshta)(\.exe)?\b.+\.(js|vbs|jse|vbe|hta|wsf)') { Add-Finding 'High' 'Persistence' "Autorun launches script/encoded command: $($a.Name)" '' "$($a.Location) = $($a.Value)" 'T1547.001' }
            elseif ($a.Exe) { $r = Test-ExeSuspicious $a.Exe; if ($r -and $r[0] -ne 'Low') { Add-Finding $r[0] 'Persistence' "Suspicious Run-key entry: $($a.Name)" $r[1] "$($a.Location) = $($a.Value)" 'T1547.001' } }
        }
    }
    foreach ($w in $Script:Wmi) { if ($w.Class -match 'Consumer' -and $w.Name -ne 'SCM Event Log Consumer') { Add-Finding 'High' 'Persistence' "WMI event consumer: $($w.Name)" $w.Class "$($w.CommandLine) $($w.Script) $($w.Executable)" 'T1546.003' } }
    foreach ($sw in $Script:Software) { if ($sw.DisplayName -match $RmmRx) { Add-Finding 'Medium' 'Remote access' "Remote-access software installed: $($sw.DisplayName) $($sw.DisplayVersion)" 'Confirm business justification' $sw.InstallLocation 'T1219' } }
}

Invoke-Step 'Analysis: defences & configuration' {
    $exl = @(Import-Csv (Join-Path $Dirs.System 'defender_exclusions_registry.csv') -ErrorAction SilentlyContinue)
    foreach ($e in $exl) {
        $v = $e.Value; $sev = 'Medium'
        if ($e.Type -eq 'Paths' -and ($v -match '^(?i)[A-Z]:\\?$' -or $v -match '(?i)^[A-Z]:\\Users(\\[^\\]+)?\\?$' -or $v -match '(?i)\\(ProgramData|Windows\\Temp|Windows\\System32|AppData(\\(Local|Roaming))?|Temp)\\?$')) { $sev = 'Critical' }
        if ($e.Type -eq 'Extensions' -and $v -match '(?i)^\.?(exe|dll|ps1|bat|cmd|vbs|js|scr|sys)$') { $sev = 'Critical' }
        if ($e.Type -eq 'Processes' -and $v -match '(?i)^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|explorer|svchost|conhost|msmpeng)(\.exe)?$') { $sev = 'Critical' }
        if ($e.Type -eq 'IpAddresses') { $sev = 'High' }
        Add-Finding $sev 'Defence evasion' "Defender exclusion ($($e.Type)): $v" "Configured under $($e.Source)" "Value: $v" 'T1562.001'
    }
    if ($Script:MpStatus) {
        $mode = [string]$Script:MpStatus.AMRunningMode
        if ($mode -eq 'Normal' -and -not $Script:MpStatus.RealTimeProtectionEnabled) { Add-Finding 'High' 'Defence evasion' 'Defender real-time protection is OFF' "AMRunningMode=$mode" 'Get-MpComputerStatus' 'T1562.001' }
        if ($Script:MpStatus.PSObject.Properties['IsTamperProtected'] -and -not $Script:MpStatus.IsTamperProtected -and $mode -eq 'Normal') { Add-Finding 'Medium' 'Defence evasion' 'Defender Tamper Protection is OFF' '' 'Get-MpComputerStatus' 'T1562.001' }
    }
    $re = Get-Content (Join-Path $Dirs.System 'reagentc_info.txt') -ErrorAction SilentlyContinue | Out-String
    if ($re -match '(?i)Access is denied|failed to run') { Add-Finding 'High' 'Impact' 'reagentc.exe cannot run (ACL tampering) - Windows RE likely disabled by malware' 'Seen with Sapphire miner (takeown/icacls deny on reagentc.exe)' $re.Trim() 'T1490' }
    elseif ($re -match '(?i)Windows RE status:\s+Disabled') { Add-Finding 'Medium' 'Impact' 'Windows Recovery Environment is disabled' '' 'reagentc_info.txt' 'T1490' }
    foreach ($s in $Script:Services) { if ($s.Name -in 'wuauserv', 'UsoSvc', 'BITS', 'WinDefend', 'WaaSMedicSvc' -and $s.StartMode -eq 'Disabled') { Add-Finding 'Medium' 'Defence evasion' "Security/update service disabled: $($s.Name)" '' "StartMode=$($s.StartMode)" 'T1562.001' } }
    $ap = Get-Content (Join-Path $Dirs.System 'audit_policy.txt') -ErrorAction SilentlyContinue | Out-String
    if ($ap -match '(?im)^\s*Process Creation\s+No Auditing') { Add-Finding 'Info' 'Logging gap' 'Process Creation auditing (4688) is disabled' 'Enable with command-line logging' 'audit_policy.txt' '' }
    $sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if ($sbl -ne 1) { Add-Finding 'Info' 'Logging gap' 'PowerShell Script Block Logging not enforced by policy' '' 'logging_policy.csv' '' }
    if (-not (Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)) { Add-Finding 'Info' 'Logging gap' 'Sysmon is not installed' '' '' '' }
    foreach ($u in Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction SilentlyContinue) { if (-not $u.Disabled -and -not $u.PasswordRequired) { Add-Finding 'Medium' 'Accounts' "Enabled local account does not require a password: $($u.Name)" '' $u.SID 'T1078' } }
    $admins = (Get-Content (Join-Path $Dirs.System 'local_admins.txt') -ErrorAction SilentlyContinue | Select-String -Pattern '^(?!Alias|Comment|Members|-+|The command|\s*$)' | ForEach-Object { $_.Line.Trim() })
    if ($admins) { Add-Finding 'Info' 'Accounts' 'Local Administrators group members' ($admins -join ', ') 'local_admins.txt' '' }
}

Invoke-Step 'Analysis: event logs' {
    if ($Script:Ev.Count -eq 0) { return }
    foreach ($e in @($Script:Ev['security_audit_tamper']) + @($Script:Ev['system_logclear_boot'])) {
        if ($null -eq $e) { continue }
        if (($e.Log -eq 'Security' -and [int]$e.EventId -eq 1102) -or ($e.Log -eq 'System' -and [int]$e.EventId -eq 104)) { Add-Finding 'High' 'Defence evasion' "Event log cleared ($($e.Log) $($e.EventId))" $e.TimeLocal "RecordId $($e.RecordId)" 'T1070.001' }
        if ([int]$e.EventId -eq 4719) { Add-Finding 'Medium' 'Defence evasion' 'Audit policy changed (4719)' $e.TimeLocal "RecordId $($e.RecordId)" 'T1562.002' }
    }
    foreach ($e in @($Script:Ev['system_services'])) {
        if ($null -eq $e -or [int]$e.EventId -ne 7045) { continue }
        $sev = 'Low'
        if ($e.EventData -match '(?i)WinRing0') { $sev = 'High' }
        if ($e.EventData -match $UserWritableRx -or $e.EventData -match '(?i)\\SystemTemp\\') { $sev = 'High' }
        $ioc = Test-IocText $e.EventData; if ($ioc) { $sev = 'Critical' }
        if ($sev -ne 'Low') { Add-Finding $sev 'Persistence' "Service installed $($e.TimeLocal)" 'System 7045 in look-back window' "RecordId $($e.RecordId): $($e.EventData)" 'T1543.003' }
    }
    foreach ($e in @($Script:Ev['system_services'])) { if ($e -and [int]$e.EventId -eq 7040 -and $e.Message -match '(?i)(Windows Update|Background Intelligent|Update Orchestrator|Defender).*to disabled') { Add-Finding 'Medium' 'Defence evasion' "Service set to disabled: $($e.TimeLocal)" $e.Message "RecordId $($e.RecordId)" 'T1562.001' } }
    $seen = @{}
    foreach ($e in @($Script:Ev['powershell_classic']) + @($Script:Ev['powershell_operational'])) {
        if ($null -eq $e) { continue }
        $txt = "$($e.Message) $($e.EventData)"
        if ($txt -match $SuspCmdRx) {
            $m = [regex]::Match($txt, '(?i)HostApplication=(.{0,400})'); $key = if ($m.Success) { $m.Groups[1].Value.Substring(0, [math]::Min(120, $m.Groups[1].Value.Length)) } else { $txt.Substring(0, [math]::Min(160, $txt.Length)) }
            if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
            $decoded = ''
            $em = [regex]::Match($txt, '(?i)-e(nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{20,})')
            if ($em.Success) { try { $decoded = ' | DECODED: ' + [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($em.Groups[2].Value)) } catch { } }
            $sev = 'High'; if (Test-IocText $txt) { $sev = 'Critical' }
            Add-Finding $sev 'Execution' "Suspicious PowerShell ($($e.Log) $($e.EventId)) at $($e.TimeLocal)" 'Download / encoded / defence-tampering / screen-capture keywords' ("RecordId $($e.RecordId): " + $txt.Substring(0, [math]::Min(900, $txt.Length)) + $decoded) 'T1059.001'
        }
    }
    $dseen = @{}
    foreach ($e in @($Script:Ev['defender'])) {
        if ($null -eq $e) { continue }
        if ([int]$e.EventId -in 1006, 1015, 1116) {
            $tn = ([regex]::Match($e.EventData, 'Threat Name=([^|]+)')).Groups[1].Value.Trim(); $pth = ([regex]::Match($e.EventData, 'Path=([^|]+)')).Groups[1].Value.Trim()
            $k = "$tn|$pth"; if ($dseen.ContainsKey($k)) { continue }; $dseen[$k] = $true
            Add-Finding 'High' 'Detection' "Defender detection: $tn" $e.TimeLocal "RecordId $($e.RecordId): $pth" ''
        }
        if ([int]$e.EventId -eq 5001) { Add-Finding 'High' 'Defence evasion' 'Defender real-time protection disabled (5001)' $e.TimeLocal "RecordId $($e.RecordId)" 'T1562.001' }
        if ([int]$e.EventId -eq 5007 -and $e.EventData -match '(?i)New Value=[^|]*(\\Exclusions\\|DisableRealtimeMonitoring = 0x1|DisableBehaviorMonitoring = 0x1|SpyNetReporting = 0x0)') { $k = 'cfg' + ([regex]::Match($e.EventData, 'New Value=([^|]+)')).Groups[1].Value; if (-not $dseen.ContainsKey($k)) { $dseen[$k] = $true; Add-Finding 'High' 'Defence evasion' "Defender configuration weakened at $($e.TimeLocal)" ([regex]::Match($e.EventData, 'New Value=([^|]+)')).Groups[1].Value "RecordId $($e.RecordId)" 'T1562.001' } }
    }
    $fail = @($Script:Ev['security_logons'] | Where-Object { $_ -and [int]$_.EventId -eq 4625 })
    if ($fail.Count -ge 20) {
        $byIp = $fail | Group-Object { ([regex]::Match($_.EventData, 'IpAddress=([^|]+)')).Groups[1].Value.Trim() } | Sort-Object Count -Descending | Select-Object -First 5
        Add-Finding 'Medium' 'Credential access' "$($fail.Count) failed logons in look-back window" (($byIp | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ') 'security_logons.csv' 'T1110'
    }
    foreach ($e in @($Script:Ev['security_logons'] | Where-Object { $_ -and [int]$_.EventId -eq 4624 -and $_.EventData -match 'LogonType=10' })) {
        $ip = ([regex]::Match($e.EventData, 'IpAddress=([^|]+)')).Groups[1].Value.Trim()
        if ($ip -and $ip -notmatch '^(-|127\.|::1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)') { Add-Finding 'Medium' 'Lateral movement' "RDP logon from external address $ip" $e.TimeLocal "RecordId $($e.RecordId)" 'T1021.001' }
    }
    foreach ($e in @($Script:Ev['security_accounts'] | Where-Object { $_ -and [int]$_.EventId -in 4720, 4732 })) { Add-Finding 'Medium' 'Accounts' "Account created / added to group ($($e.EventId)) at $($e.TimeLocal)" '' "RecordId $($e.RecordId): $($e.EventData)" 'T1136 / T1098' }
}

Invoke-Step 'Analysis: files & IOC hashes' {
    foreach ($f in $Script:FileInv) {
        if ($f.SHA256 -and $IocHashSet.ContainsKey($f.SHA256)) { Add-Finding 'Critical' 'IOC' "File hash matches IOC: $(Split-Path $f.Path -Leaf)" $f.SHA256 $f.Path 'IOC'; continue }
        $ioc = Test-IocText $f.Path; if ($ioc) { Add-Finding 'High' 'IOC' "File path matches IOC pattern" $ioc $f.Path 'IOC'; continue }
        if (-not $f.Recent) { continue }
        $ext = [IO.Path]::GetExtension($f.Path).ToLower()
        if ($ext -eq '.sys') { Add-Finding 'High' 'Files' 'Driver file in user-writable / temp location' "Sig $($f.SigStatus) $($f.Signer)" $f.Path 'T1068' ; continue }
        if ($ext -in '.exe', '.dll', '.scr', '.com', '.cpl') {
            if ($f.SigStatus -eq 'Valid' -and $f.OriginalFilename -and ([IO.Path]::GetFileNameWithoutExtension($f.OriginalFilename -replace '\.mui$', '')) -ne [IO.Path]::GetFileNameWithoutExtension($f.Path) -and $f.Path -match $UserWritableRx) {
                Add-Finding 'Medium' 'Files' "Renamed signed binary: $(Split-Path $f.Path -Leaf) (is $($f.OriginalFilename))" 'Possible DLL side-loading / LOLBin host' $f.Path 'T1036.003'
            } elseif ($f.SigStatus -ne 'Valid' -and $f.Path -match $UserWritableRx) {
                Add-Finding 'Low' 'Files' "New unsigned executable: $(Split-Path $f.Path -Leaf)" "Created $($f.CreatedUtc) UTC, $($f.Size) bytes" "$($f.Path) | $($f.SHA256)" 'T1105'
            }
        }
        if ($ext -in '.js', '.jse', '.vbs', '.vbe', '.hta', '.wsf', '.au3', '.a3x' -and $f.Path -match '(?i)\\ProgramData\\|\\AppData\\Roaming\\|\\Temp\\') { Add-Finding 'Medium' 'Files' "New script file in staging path: $(Split-Path $f.Path -Leaf)" '' $f.Path 'T1059' }
    }
}

# --------------------------------------------------------------------------------------------
#  9. Samples (inert copies of anything flagged High/Critical)
# --------------------------------------------------------------------------------------------
if (-not $SkipSamples) {
    Invoke-Step 'Sample preservation (inert .bin_ copies)' {
        $cand = @{}
        foreach ($f in $Script:Findings) {
            if ($f.Rank -lt 4) { continue }
            foreach ($m in [regex]::Matches("$($f.Evidence) $($f.Detail)", '(?i)[A-Z]:\\[^|"*?<>\r\n]+?\.(exe|dll|sys|scr|js|jse|vbs|vbe|hta|ps1|bat|cmd|wsf|au3|a3x)\b')) { $cand[$m.Value] = $f.Title }
        }
        $meta = foreach ($p in $cand.Keys) {
            if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
            $fi = Get-FileInfoEx $p
            if (-not $fi.Exists -or $fi.Size -gt ($MaxSampleMB * 1MB)) { continue }
            if ($fi.SigStatus -eq 'Valid' -and $fi.Signer -match '(?i)Microsoft Windows|Microsoft Corporation' -and $p -match '(?i)^[A-Z]:\\Windows\\') { continue }
            $dst = Copy-Evidence $p $Dirs.Samples ("{0}.bin_" -f $(if ($fi.SHA256) { $fi.SHA256 } else { (Get-SafeName $p) }))
            [pscustomobject]@{ OriginalPath = $p; StoredAs = $(if ($dst) { Split-Path $dst -Leaf }); SHA256 = $fi.SHA256; Size = $fi.Size; SigStatus = $fi.SigStatus; Signer = $fi.Signer; Reason = $cand[$p] }
        }
        Save-Csv $meta (Join-Path $Dirs.Samples 'samples_index.csv')
        "These files are LIVE MALWARE renamed to .bin_ to prevent accidental execution. Handle only in an isolated analysis environment." | Out-File (Join-Path $Dirs.Samples 'README_WARNING.txt') -Encoding UTF8
    }
}

# --------------------------------------------------------------------------------------------
# 10. Report
# --------------------------------------------------------------------------------------------
Invoke-Step 'Findings report' {
    $fs = @($Script:Findings | Sort-Object @{ e = 'Rank'; Descending = $true }, Category, Title)
    # de-duplicate identical title+evidence
    $u = @{}; $fs = @($fs | Where-Object { $k = "$($_.Title)|$($_.Evidence)"; if ($u.ContainsKey($k)) { $false } else { $u[$k] = $true; $true } })
    Save-Csv ($fs | Select-Object Severity, Category, Title, Detail, Evidence, MITRE) (Join-Path $Dirs.Analysis 'findings.csv')
    $fs | Select-Object Severity, Category, Title, Detail, Evidence, MITRE | ConvertTo-Json -Depth 3 | Out-File (Join-Path $Dirs.Analysis 'findings.json') -Encoding UTF8
    $cnt = @{}; foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') { $cnt[$s] = @($fs | Where-Object { $_.Severity -eq $s }).Count }
    $verdict = 'NO SIGNIFICANT FINDINGS - review Medium/Low items'
    if ($cnt.Critical -gt 0) { $verdict = 'COMPROMISE INDICATED - isolate host, preserve evidence, escalate to incident response' }
    elseif ($cnt.High -gt 0) { $verdict = 'SUSPICIOUS - analyst review required before returning host to service' }
    $Script:Verdict = $verdict; $Script:Counts = $cnt
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $os = Get-CimInstance Win32_OperatingSystem
    $rows = New-Object System.Text.StringBuilder
    foreach ($f in $fs) { [void]$rows.AppendFormat('<tr class="{0}"><td><span class="sev {0}">{0}</span></td><td>{1}</td><td><b>{2}</b><div class="d">{3}</div></td><td class="ev">{4}</td><td>{5}</td></tr>', $f.Severity, (& $enc $f.Category), (& $enc $f.Title), (& $enc $f.Detail), (& $enc $f.Evidence), (& $enc $f.MITRE)) }
    $steps = ($Script:StepResults | ForEach-Object { "<tr><td>$(& $enc $_.Step)</td><td>$($_.Status)</td><td>$($_.Seconds)</td></tr>" }) -join ''
    $html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>DFIR Triage - $HostName - $CaseId</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6fb;color:#1d2433}
header{background:#0A1F6B;color:#fff;padding:22px 32px;border-bottom:5px solid #C8102E}
header h1{margin:0;font-size:22px} header p{margin:4px 0 0;color:#c9d3f0;font-size:13px}
main{padding:24px 32px} .card{background:#fff;border:1px solid #dde2ee;border-radius:6px;padding:16px 20px;margin-bottom:18px}
.verdict{font-size:17px;font-weight:700;color:#C8102E} .kpi{display:inline-block;margin:8px 18px 0 0;font-size:13px}
.kpi b{font-size:22px;display:block}
table{border-collapse:collapse;width:100%;font-size:12.5px;background:#fff} th{background:#0A1F6B;color:#fff;text-align:left;padding:7px}
td{border-bottom:1px solid #e3e7f0;padding:6px 7px;vertical-align:top} td.ev{font-family:Consolas,monospace;font-size:11.5px;word-break:break-all;min-width:280px;max-width:520px}
.d{color:#5f6b7a;font-size:12px;margin-top:2px} .sev{padding:2px 7px;border-radius:3px;color:#fff;font-size:11px;font-weight:700}
.sev.Critical{background:#8b0000}.sev.High{background:#C8102E}.sev.Medium{background:#d9822b}.sev.Low{background:#5b6b9a}.sev.Info{background:#8a94a6}
input{padding:6px;width:300px;margin-bottom:8px} .meta td:first-child{font-weight:600;width:200px;color:#0A1F6B}
</style></head><body>
<header><h1>Digital Forensic Triage Report - $(& $enc $HostName)</h1><p>Case $(& $enc $CaseId) &middot; Examiner $(& $enc $Examiner) &middot; Collected $($StartTime.ToString('yyyy-MM-dd HH:mm:ss zzz')) &middot; 3tternp DFIR Toolkit v$ScriptVersion</p></header>
<main>
<div class="card"><div class="verdict">$verdict</div>
<span class="kpi"><b style="color:#8b0000">$($cnt.Critical)</b>Critical</span><span class="kpi"><b style="color:#C8102E">$($cnt.High)</b>High</span><span class="kpi"><b style="color:#d9822b">$($cnt.Medium)</b>Medium</span><span class="kpi"><b>$($cnt.Low)</b>Low</span><span class="kpi"><b>$($cnt.Info)</b>Info</span>
<p style="font-size:12.5px;color:#5f6b7a">Automated triage: findings are leads for an analyst, not final conclusions. Verify each item against the collected evidence before acting. The collector made no changes to the host.</p></div>
<div class="card"><table class="meta">
<tr><td>Host</td><td>$(& $enc $HostName) &middot; $(& $enc $os.Caption) $($os.Version) &middot; last boot $($os.LastBootUpTime)</td></tr>
<tr><td>Look-back window</td><td>$DaysBack days (since $($Since.ToString('yyyy-MM-dd HH:mm')))</td></tr>
<tr><td>Collected</td><td>$($Script:Procs.Count) processes &middot; $($Script:Tcp.Count) TCP endpoints &middot; $($Script:Services.Count) services &middot; $($Script:Tasks.Count) tasks &middot; $($Script:Autoruns.Count) autoruns &middot; $($Script:FileInv.Count) files inventoried &middot; $($Script:CopyLog.Count) artefacts copied</td></tr>
<tr><td>Run as</td><td>$(& $enc "$env:USERDOMAIN\$env:USERNAME") (administrator: $($Script:IsAdmin))</td></tr></table></div>
<div class="card"><h3 style="margin-top:0;color:#0A1F6B">Findings</h3><input id="q" placeholder="Filter findings..." onkeyup="var v=this.value.toLowerCase();document.querySelectorAll('#f tbody tr').forEach(function(r){r.style.display=r.innerText.toLowerCase().indexOf(v)>-1?'':'none'})">
<table id="f"><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Evidence</th><th>MITRE</th></tr></thead><tbody>$($rows.ToString())</tbody></table></div>
<div class="card"><h3 style="margin-top:0;color:#0A1F6B">Recommended next steps</h3><ol style="font-size:13px">
<li>If any Critical finding is confirmed: isolate the host (EDR network isolation), keep it powered on, and escalate to incident response.</li>
<li>Reset credentials used on the host from a clean device and revoke active sessions.</li>
<li>Submit samples in 07_samples_DO_NOT_EXECUTE to a sandbox from an isolated analysis workstation.</li>
<li>Block confirmed network indicators at the firewall/DNS and hunt for them across the estate.</li>
<li>Do not clean a compromised host in place - rebuild from trusted media after evidence is preserved.</li></ol></div>
<div class="card"><h3 style="margin-top:0;color:#0A1F6B">Collection steps</h3><table><tr><th>Step</th><th>Status</th><th>Seconds</th></tr>$steps</table></div>
</main></body></html>
"@
    $html | Out-File (Join-Path $Root 'REPORT.html') -Encoding UTF8
    $sum = @("DFIR TRIAGE SUMMARY - $HostName - case $CaseId", "Collected: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss zzz')) by $Examiner", "VERDICT : $verdict",
             ("Findings: Critical={0} High={1} Medium={2} Low={3} Info={4}" -f $cnt.Critical, $cnt.High, $cnt.Medium, $cnt.Low, $cnt.Info), '', 'TOP FINDINGS:')
    foreach ($f in ($fs | Where-Object { $_.Rank -ge 4 } | Select-Object -First 40)) { $sum += ("[{0}] {1} :: {2}" -f $f.Severity.ToUpper(), $f.Title, $f.Evidence) }
    $sum | Out-File (Join-Path $Root 'SUMMARY.txt') -Encoding UTF8
}

# --------------------------------------------------------------------------------------------
# 11. Integrity: copy log, manifest, chain of custody, zip
# --------------------------------------------------------------------------------------------
$EndTime = Get-Date
Save-Csv $Script:CopyLog (Join-Path $Dirs.Case 'copied_artifacts.csv')
Save-Csv $Script:StepResults (Join-Path $Dirs.Case 'step_results.csv')
try { Stop-Transcript | Out-Null } catch { }
Write-Log 'Hashing all collected files (manifest)' 'STEP'
$manifest = foreach ($f in Get-ChildItem -LiteralPath $Root -Recurse -File -Force) {
    if ($f.Name -eq 'MANIFEST_SHA256.csv') { continue }
    $h = $null; try { $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
    [pscustomobject]@{ SHA256 = $h; Bytes = $f.Length; File = $f.FullName.Replace($Root, '.') }
}
Save-Csv $manifest (Join-Path $Root 'MANIFEST_SHA256.csv')
$manifestHash = (Get-FileHash -LiteralPath (Join-Path $Root 'MANIFEST_SHA256.csv') -Algorithm SHA256).Hash
@(
    'CHAIN OF CUSTODY - EVIDENCE COLLECTION RECORD'
    '============================================='
    "Case ID              : $CaseId"
    "Evidence source      : $HostName ($((Get-CimInstance Win32_BIOS).SerialNumber))"
    "Collected by         : $Examiner (account $env:USERDOMAIN\$env:USERNAME)"
    "Collection start     : $($StartTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))Z"
    "Collection end       : $($EndTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))Z"
    "Tool                 : Invoke-DFIRCollection.ps1 v$ScriptVersion"
    "Files collected      : $(@($manifest).Count)"
    "Manifest SHA256      : $manifestHash"
    "Verdict (automated)  : $($Script:Verdict)"
    ''
    'Transfers (complete on each hand-over):'
    'Date/Time (UTC)      | Released by          | Received by          | Purpose / location'
    '---------------------+----------------------+----------------------+------------------------------'
    '                     |                      |                      |'
    '                     |                      |                      |'
) | Out-File (Join-Path $Root 'CHAIN_OF_CUSTODY.txt') -Encoding UTF8

if (-not $NoZip) {
    Write-Log 'Creating ZIP archive' 'STEP'
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = "$Root.zip"
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        [IO.Compression.ZipFile]::CreateFromDirectory($Root, $zip, [IO.Compression.CompressionLevel]::Optimal, $true)
        $zh = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
        "$zh  $(Split-Path $zip -Leaf)" | Out-File "$zip.sha256" -Encoding ASCII
        Write-Log "ZIP: $zip  SHA256 $zh"
    } catch { Write-Log "ZIP failed: $($_.Exception.Message)" 'ERROR' }
}

Write-Host ''
Write-Host '================================================================' -ForegroundColor Cyan
Write-Host (" VERDICT : {0}" -f $Script:Verdict) -ForegroundColor $(if ($Script:Counts.Critical -gt 0) { 'Red' } elseif ($Script:Counts.High -gt 0) { 'Yellow' } else { 'Green' })
Write-Host (" Findings: Critical={0} High={1} Medium={2} Low={3} Info={4}" -f $Script:Counts.Critical, $Script:Counts.High, $Script:Counts.Medium, $Script:Counts.Low, $Script:Counts.Info)
Write-Host " Report  : $(Join-Path $Root 'REPORT.html')"
Write-Host " Evidence: $Root"
if ($MemoryTool) { Write-Host " Memory  : $MemDir (kept outside the ZIP)" }
Write-Host (" Duration: {0:N0} s" -f ($EndTime - $StartTime).TotalSeconds)
Write-Host '================================================================' -ForegroundColor Cyan
