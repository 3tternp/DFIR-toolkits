# Vairav CSOC - DFIR Collection & Triage Toolkit

Two single-file collectors, one per platform, that perform the full live-response process
(collect -> analyse -> report -> hash -> package) used in case VAIRAV-DFIR-2026-002.
Both are **read-only** towards the host: they never kill, delete, quarantine or change anything.
They only write into the output folder.

| Platform | Script | Runtime |
|---|---|---|
| Windows 10/11, Server 2016+ | `Invoke-DFIRCollection.ps1` | Windows PowerShell 5.1 or PowerShell 7, **elevated** |
| Linux (Debian/Ubuntu, RHEL/CentOS/Rocky/Alma, SUSE, Amazon Linux) | `dfir_collect_linux.sh` | bash 4+, **root** |

## Quick start

### Windows
```powershell
# From an elevated PowerShell, ideally writing to an external/USB drive
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-DFIRCollection.ps1 `
    -CaseId VAIRAV-DFIR-2026-003 -Examiner "Prem Basnet" -OutputRoot E:\Evidence -DaysBack 30

# With memory capture (copy WinPmem to the USB first)
.\Invoke-DFIRCollection.ps1 -CaseId VAIRAV-DFIR-2026-003 -OutputRoot E:\Evidence -MemoryTool E:\tools\winpmem_mini_x64.exe

# Extra IOCs for a new case
.\Invoke-DFIRCollection.ps1 -CaseId X -IocFile .\iocs_example.csv
```
Useful switches: `-SkipEventLogs`, `-SkipRegistryHives`, `-SkipBrowser`, `-SkipSamples`, `-NoZip`, `-MaxSampleMB 50`.

### Linux
```bash
sudo bash dfir_collect_linux.sh -c VAIRAV-DFIR-2026-003 -e "Prem Basnet" -o /mnt/usb/evidence -d 30
# memory capture with AVML (token OUTFILE is replaced with the output path)
sudo bash dfir_collect_linux.sh -c X -o /mnt/usb/evidence -m "/mnt/usb/tools/avml OUTFILE"
# faster run without package verification, extra IOCs
sudo bash dfir_collect_linux.sh -c X -V -i iocs_example.csv
```
Options: `-s` skip samples, `-V` skip `dpkg --verify`/`rpm -Va`, `-n` no tar.gz.

## Output layout (both platforms)
```
<CASE>_<HOST>_<UTC>/
  REPORT.html                 <- open this first: verdict, prioritised findings (filterable), next steps
  SUMMARY.txt                 <- verdict + top Critical/High findings (paste into ticket)
  CHAIN_OF_CUSTODY.txt        <- collection record + hand-over table
  MANIFEST_SHA256.(csv|txt)   <- SHA-256 of every collected file
  00_case/                    case info, collection log, transcript, copied-artefact log (with source timestamps)
  01_volatile/                processes (+hash/signature/owner), process tree, modules, network, DNS, ARP, sessions
  02_system/                  OS, users/groups, software, services, drivers, Defender/audit/WinRE | packages, sudo, ssh
  03_persistence/             tasks(+XML), Run keys & ASEPs, WMI, BITS, startup | cron, systemd, rc, ld.so.preload, keys
  04_eventlogs | 04_logs/     raw .evtx + parsed CSVs | /var/log (look-back), journal, wtmp/btmp
  05_artifacts/               hives, Prefetch, Amcache, SRUM, PSReadLine, browser history, LNK, RMM traces | histories
  06_file_inventory/          executables/scripts in user-writable paths with SHA-256 + signature | SUID, caps, pkg verify
  07_samples_DO_NOT_EXECUTE/  suspicious binaries stored as <sha256>.bin_ (LIVE MALWARE - isolated lab only)
  08_analysis/                findings.csv / findings.json (.tsv on Linux)
<CASE>_<HOST>_<UTC>.zip|.tar.gz  + .sha256
<CASE>_<HOST>_<UTC>_memory/   memory image (kept outside the archive)
```

## What the analysis engine flags (examples)
**Windows** - services/tasks/Run keys executing from user-writable paths; Windows process names running
from AppData (masquerading); renamed signed binaries (e.g. Notepad as `NVDisplay.Container.exe`);
miner-pattern services (`<RANDOM>` -> `ProgramData\<12>\<12>.exe`), WinRing0 drivers; Amadey-style
`%TEMP%\<id>0101\` Run keys; DLL side-loading folders; Defender exclusions/tampering (registry + 5007
events); disabled Windows Update/WinRE (reagentc ACL lock); suspicious PowerShell (event 400/4104, with
Base64 decoding); Defender detections; log clearing; explorer/rundll32 with external connections; mining
ports; RMM tools; KMS activators; WMI consumers; IOC IP/domain/hash/string matches; logging gaps.

**Linux** - processes from deleted binaries or /tmp, /dev/shm, hidden dirs; fake kernel-thread names;
miner strings / mining ports / high CPU; LD_PRELOAD and `/etc/ld.so.preload`; malicious cron/systemd/rc
content (curl|sh, base64, /dev/tcp); UID-0 or empty-password accounts; passwordless sudo; recent
authorized_keys changes; root SSH from external IPs and brute force; `chattr +i` anti-removal; tainted
kernel; ELF files in temp/hidden dirs; SUID in user paths; package checksum mismatches (trojanised
binaries); history wiping; IOC matches.

Findings are **leads for an analyst**, ranked Critical/High/Medium/Low/Info with MITRE ATT&CK IDs.
Confirm against the collected evidence before acting.

## IOC file format
CSV or text, one indicator per line: `type,value`
(`ip`, `domain`, `sha256`, `string`, `path_regex`, Windows also `regkey`). Lines starting with `#` are ignored.
The built-in defaults are the indicators from VAIRAV-DFIR-2026-002.

## Handling guidance
- Run from trusted, read-only media where possible and write output to external storage.
- Collect **before** isolation actions that reboot or kill processes; memory first if it matters.
- The output contains sensitive data (registry hives with password hashes, browser history,
  shell history). Store and transfer it encrypted and record each hand-over in CHAIN_OF_CUSTODY.txt.
- Verify the archive hash on receipt (`Get-FileHash` / `sha256sum -c`).
- Expected runtime: 5-20 min on Windows (event-log parsing and file hashing dominate),
  2-10 min on Linux (package verification dominates; use `-V` to skip).
