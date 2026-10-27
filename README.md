<div align="center">

# 🛡️ Vairav DFIR Toolkit

### One script. One command. A complete forensic triage.

**Collect evidence ➜ Analyse it ➜ Get a verdict ➜ Hand over a hashed, court-ready package**

![Version](https://img.shields.io/badge/version-1.0.0-0A1F6B?style=for-the-badge)
![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server%202016%2B-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Debian%20%7C%20Ubuntu%20%7C%20RHEL%20%7C%20SUSE-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Read-only](https://img.shields.io/badge/host%20impact-read--only-2E8B57?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK%20mapped-C8102E?style=for-the-badge)

*Built by the Vairav Technology CSOC from real incident work (case VAIRAV-DFIR-2026-002).*

</div>

---

## 📑 Contents

- [✨ What it does](#-what-it-does)
- [📦 What's in the box](#-whats-in-the-box)
- [✅ Before you start](#-before-you-start)
- [🚀 Quick start (2 minutes)](#-quick-start-2-minutes)
- [⚙️ All options](#️-all-options)
- [📂 Understanding the output](#-understanding-the-output)
- [🚦 Reading the report](#-reading-the-report)
- [🔍 What it detects](#-what-it-detects)
- [🎯 Adding your own IOCs](#-adding-your-own-iocs)
- [🧑‍⚖️ Evidence handling & chain of custody](#️-evidence-handling--chain-of-custody)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [❓ FAQ](#-faq)

---

## ✨ What it does

When a machine looks compromised, you need answers **fast** and evidence that **holds up**.
This toolkit runs the full live-response process for you in one go:

| Step | | What happens |
|:---:|:---:|---|
| 1 | 🧠 | **Memory** (optional): captures RAM first, before it changes |
| 2 | ⚡ | **Volatile data**: processes, network connections, DNS, logged-on users |
| 3 | 🖥️ | **System state**: users, admins, software, services, drivers, security settings |
| 4 | 🔁 | **Persistence**: every common place malware hides to survive a reboot |
| 5 | 📜 | **Logs**: raw event logs plus parsed, analyst-friendly CSVs |
| 6 | 🗂️ | **Artefacts**: execution history, browser history, shell history, remote-access traces |
| 7 | 🧾 | **File inventory**: hashes and signatures of executables in risky folders |
| 8 | 🔬 | **Analysis**: ~60 detection rules plus IOC matching, ranked and MITRE-mapped |
| 9 | 🧪 | **Samples**: suspicious files saved safely as inert `.bin_` copies |
| 10 | 📊 | **Report**: an HTML report with a clear verdict and filterable findings |
| 11 | 🔐 | **Integrity**: a SHA-256 for every file, chain of custody, and a hashed archive |

> [!IMPORTANT]
> 🟢 **The toolkit never changes the system it examines.** It does not kill, delete, quarantine or "clean" anything. It only **reads** the system and **writes** into its own output folder.

---

## 📦 What's in the box

| File | Platform | Purpose |
|---|:---:|---|
| 🪟 `Invoke-DFIRCollection.ps1` | Windows | Collector and analyser (PowerShell 5.1 or 7) |
| 🐧 `dfir_collect_linux.sh` | Linux | Collector and analyser (bash 4+) |
| 🎯 `iocs_example.csv` | Both | Template for adding your own indicators |
| 🔏 `SHA256SUMS.txt` | Both | Checksums: verify the toolkit before use |
| 📘 `README.md` | | You are here |

---

## ✅ Before you start

- [ ] 🔑 You have **Administrator** (Windows) or **root** (Linux) rights
- [ ] 💾 You have an **external USB drive** or network share for the output (avoid writing to the suspect disk)
- [ ] 📏 There is **enough free space**: ~2–10 GB is typical, **plus the size of RAM** if you capture memory
- [ ] 🔏 You have **verified the toolkit checksums** (see below)
- [ ] 📝 You have a **Case ID** ready (e.g. `VAIRAV-DFIR-2026-003`)
- [ ] ⚠️ The host is **still powered on**. Collect **before** rebooting, isolating with a reboot, or running AV cleanup

<details>
<summary>🔏 <b>How to verify the toolkit checksums</b></summary>

**Windows**
```powershell
Get-FileHash .\Invoke-DFIRCollection.ps1 -Algorithm SHA256
# compare with the value in SHA256SUMS.txt
```

**Linux**
```bash
sha256sum -c SHA256SUMS.txt
```
</details>

---

## 🚀 Quick start (2 minutes)

### 🪟 Windows

1. Copy the toolkit folder to your **USB drive** (e.g. `E:\DFIR_Toolkit`).
2. Right-click **Start** ➜ **Terminal (Admin)** / **Windows PowerShell (Admin)**.
3. Run:

```powershell
cd E:\DFIR_Toolkit
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-DFIRCollection.ps1 `
    -CaseId VAIRAV-DFIR-2026-003 `
    -Examiner "Your Name" `
    -OutputRoot E:\Evidence
```

4. ☕ Wait **5–20 minutes**. Progress is shown in colour as each step runs.
5. 📊 Open **`REPORT.html`** in the output folder.

### 🐧 Linux

1. Mount your USB drive (e.g. `/mnt/usb`) and copy the toolkit there.
2. Run as root:

```bash
cd /mnt/usb/dfir_toolkit
sudo bash dfir_collect_linux.sh \
    -c VAIRAV-DFIR-2026-003 \
    -e "Your Name" \
    -o /mnt/usb/evidence
```

3. ☕ Wait **2–10 minutes**.
4. 📊 Open **`REPORT.html`** (copy it to your workstation or use `xdg-open`).

### 🏁 What you'll see when it finishes

```text
================================================================
 VERDICT : COMPROMISE INDICATED - isolate host, preserve evidence, escalate to incident response
 Findings: Critical=9 High=3 Medium=4 Low=1 Info=2
 Report  : E:\Evidence\VAIRAV-DFIR-2026-003_DESKTOP-OGN3FKJ_20261027T091134Z\REPORT.html
 Evidence: E:\Evidence\VAIRAV-DFIR-2026-003_DESKTOP-OGN3FKJ_20261027T091134Z
 Duration: 612 s
================================================================
```

---

## ⚙️ All options

### 🪟 Windows: `Invoke-DFIRCollection.ps1`

| Parameter | Default | Description |
|---|---|---|
| `-CaseId` | `CASE-<date-time>` | 📝 Case reference used in folder names and reports |
| `-Examiner` | current user | 🧑‍💼 Who ran the collection (chain of custody) |
| `-OutputRoot` | `C:\DFIR` | 💾 Where to write evidence. **Use external media** |
| `-DaysBack` | `30` | 📅 Look-back window for logs, new files and services |
| `-IocFile` | none | 🎯 Extra indicators (see [Adding your own IOCs](#-adding-your-own-iocs)) |
| `-MemoryTool` | none | 🧠 Full path to a RAM capture tool, e.g. `E:\tools\winpmem_mini_x64.exe` |
| `-SkipEventLogs` | off | ⏩ Skip event log export and parsing (faster, less evidence) |
| `-SkipRegistryHives` | off | ⏩ Skip SAM/SYSTEM/SOFTWARE/NTUSER hive copies |
| `-SkipBrowser` | off | 🔒 Skip browser history (privacy-sensitive cases) |
| `-SkipSamples` | off | 🧪 Don't copy suspicious binaries |
| `-MaxSampleMB` | `50` | 📏 Largest sample to preserve |
| `-NoZip` | off | 📁 Leave output as a folder only |

### 🐧 Linux: `dfir_collect_linux.sh`

| Flag | Default | Description |
|---|---|---|
| `-c` | `CASE-<date-time>` | 📝 Case ID |
| `-e` | current user | 🧑‍💼 Examiner name |
| `-o` | `/var/tmp/dfir` | 💾 Output root. **Use external media** |
| `-d` | `30` | 📅 Look-back days |
| `-i` | none | 🎯 IOC file |
| `-m` | none | 🧠 Memory capture command; `OUTFILE` is replaced with the output path, e.g. `-m "/mnt/usb/avml OUTFILE"` |
| `-s` | off | 🧪 Skip sample preservation |
| `-V` | off | ⏩ Skip package integrity verification (`dpkg --verify` / `rpm -Va`), which is much faster |
| `-n` | off | 📁 No `.tar.gz` archive |
| `-h` | | ❔ Show help |

<details>
<summary>💡 <b>Handy recipes</b></summary>

```powershell
# 🧠 Windows with memory capture
.\Invoke-DFIRCollection.ps1 -CaseId X -OutputRoot E:\Evidence -MemoryTool E:\tools\winpmem_mini_x64.exe

# ⚡ Windows quick triage (no hives, no browser, 7-day window)
.\Invoke-DFIRCollection.ps1 -CaseId X -OutputRoot E:\Evidence -DaysBack 7 -SkipRegistryHives -SkipBrowser

# 🎯 Windows with case-specific IOCs
.\Invoke-DFIRCollection.ps1 -CaseId X -OutputRoot E:\Evidence -IocFile .\iocs_example.csv
```

```bash
# 🧠 Linux with AVML memory capture
sudo bash dfir_collect_linux.sh -c X -o /mnt/usb/evidence -m "/mnt/usb/tools/avml OUTFILE"

# ⚡ Linux fast triage (skip package verification)
sudo bash dfir_collect_linux.sh -c X -o /mnt/usb/evidence -V -d 7
```
</details>

---

## 📂 Understanding the output

```text
📁 <CASE>_<HOST>_<UTC-TIME>/
├── 📊 REPORT.html                  ⬅️ START HERE: verdict + findings
├── 📝 SUMMARY.txt                  ⬅️ paste into your ticket
├── 🧑‍⚖️ CHAIN_OF_CUSTODY.txt         collection record + hand-over table
├── 🔐 MANIFEST_SHA256.(csv|txt)    hash of every collected file
├── 📁 00_case/                     case info, log, transcript, copy log
├── 📁 01_volatile/                 processes, process tree, network, DNS, sessions
├── 📁 02_system/                   users, admins, software, services, Defender, audit
├── 📁 03_persistence/              tasks, Run keys, WMI | cron, systemd, SSH keys
├── 📁 04_eventlogs/ (04_logs/)     raw .evtx + parsed CSVs | /var/log + journal
├── 📁 05_artifacts/                Prefetch, Amcache, SRUM, hives, browser | histories
├── 📁 06_file_inventory/           hashes + signatures of risky files
├── ☣️ 07_samples_DO_NOT_EXECUTE/   suspicious files as <sha256>.bin_
└── 📁 08_analysis/                 findings.csv / findings.json
📦 <CASE>_<HOST>_<UTC-TIME>.zip (.tar.gz)  + .sha256
🧠 <CASE>_<HOST>_<UTC-TIME>_memory/          RAM image (kept outside the archive)
```

---

## 🚦 Reading the report

### The verdict

| Verdict | Meaning | What to do |
|---|---|---|
| 🔴 **COMPROMISE INDICATED** | At least one **Critical** finding | 🚨 Isolate the host, keep it powered on, escalate to incident response |
| 🟠 **SUSPICIOUS** | **High** findings, no Critical | 🔎 Analyst review before the host goes back into service |
| 🟢 **NO SIGNIFICANT FINDINGS** | Only Medium/Low/Info | ✅ Review the remaining items and close or monitor |

### Severity levels

| Level | Icon | Typical examples |
|---|:---:|---|
| **Critical** | 🔴 | IOC match, miner service, masquerading system process, Defender excluding `C:\` |
| **High** | 🟠 | Unsigned binary running from AppData, suspicious PowerShell, explorer.exe talking to the internet |
| **Medium** | 🟡 | Remote-access tool installed, disabled Windows Update, passwordless account |
| **Low** | 🔵 | New unsigned file, custom hosts entry, root-folder task |
| **Info** | ⚪ | Logging gaps (e.g. no Sysmon, process auditing off) |

> [!TIP]
> 🔎 Use the **filter box** in `REPORT.html` to search across all findings, for example `powershell`, `T1543` or a file name.

> [!NOTE]
> 🧠 Findings are **leads for an analyst, not final conclusions**. Always confirm a finding against the collected evidence before acting on it.

---

## 🔍 What it detects

<details open>
<summary>🪟 <b>Windows</b></summary>

| | Detection |
|:---:|---|
| 🎭 | Windows process names running from AppData/ProgramData (masquerading) |
| ✍️ | Renamed signed binaries used as hosts, e.g. Notepad renamed to `NVDisplay.Container.exe` |
| ⛏️ | Miner services (`RANDOM` ➜ `ProgramData\<random>\<random>.exe`) and WinRing0 drivers |
| 📥 | Amadey-style loader Run keys (`%TEMP%\<id>0101\<hex>.exe`) |
| 🧬 | DLL side-loading folders (e.g. `kxetray.exe` + `kis.dll`) |
| 🛑 | Defender exclusions and tampering (registry **and** event 5007) |
| 🧯 | Disabled Windows Update / BITS and a locked Windows RE (`reagentc` ACL tamper) |
| 💻 | Suspicious PowerShell in events 400/4104, **with automatic Base64 decoding** |
| 🦠 | Defender detections, cleared event logs, audit policy changes |
| 🌐 | LOLBins (explorer, rundll32…) with internet connections, mining-pool ports |
| 🖧 | Remote-access tools (AnyDesk, TeamViewer, ScreenConnect…), pirated KMS activators |
| 🪝 | WMI event consumers, IFEO / Winlogon / AppInit / COM hijacks |
| 🎯 | IOC IP / domain / hash / string / path / registry matches |
</details>

<details open>
<summary>🐧 <b>Linux</b></summary>

| | Detection |
|:---:|---|
| 👻 | Processes running from **deleted** binaries (and recovers them from `/proc`) |
| 📍 | Executables running from `/tmp`, `/dev/shm`, `/var/tmp` or hidden directories |
| 🎭 | Userland processes disguised as kernel threads (`[kworker]`) |
| ⛏️ | Miner strings, mining-pool ports, sustained high CPU |
| 💉 | `LD_PRELOAD` and `/etc/ld.so.preload` (userland rootkits) |
| ⏰ | Malicious cron / systemd / rc content (`curl \| sh`, `base64 -d`, `/dev/tcp`) |
| 👤 | UID-0 backdoor accounts, empty passwords, passwordless sudo |
| 🔑 | Recently changed `authorized_keys`, root SSH from external IPs, brute force |
| 🔒 | `chattr +i` anti-removal tricks |
| 🧩 | Tainted kernel / unsigned modules |
| 🧬 | Packaged system binaries whose checksums no longer match (trojanised) |
| 🧹 | History wiping and emptied login records |
| 🎯 | IOC matches in processes, network, persistence, history and files |
</details>

---

## 🎯 Adding your own IOCs

Create a CSV/text file with **one indicator per line** in the form `type,value`:

```csv
# 💬 lines starting with # are ignored
ip,87.58.216.204
domain,golden-age.shop
sha256,5F7FD3A66470D95CC86EFAAF861A08BB6480050EE01F0E789E7F4E1E985D788D
string,mrebtkrF5v
path_regex,\\ProgramData\\Google\\Browser\\
regkey,HKLM:\SOFTWARE\$SHconfig
```

| Type | Matches against | Platforms |
|---|---|:---:|
| 🌐 `ip` | Live connections, DNS cache, logs, command lines | 🪟 🐧 |
| 🔗 `domain` | DNS cache, hosts file, command lines, persistence | 🪟 🐧 |
| #️⃣ `sha256` | Running processes, services, file inventory | 🪟 🐧 |
| 🔤 `string` | Command lines, tasks, Run keys, events, histories | 🪟 🐧 |
| 📁 `path_regex` | File, service, task and process paths (regex) | 🪟 🐧 |
| 🗝️ `regkey` | Registry key existence | 🪟 |

> [!NOTE]
> The **built-in defaults** already contain the indicators from case **VAIRAV-DFIR-2026-002** (Sapphire miner, MineFleet, the kis.dll loader and the initial-access server). Your file **adds to** them.

---

## 🧑‍⚖️ Evidence handling & chain of custody

| | Do ✅ | Don't ❌ |
|:---:|---|---|
| 💾 | Write output to **external media** | Write to the suspect disk if you can avoid it |
| ⏱️ | Collect **before** rebooting or cleaning | Run AV "clean up" first, which destroys evidence |
| 🔐 | **Verify** the archive hash on every transfer | Email evidence unencrypted |
| 🧑‍⚖️ | Fill in **`CHAIN_OF_CUSTODY.txt`** at each hand-over | Open `07_samples_DO_NOT_EXECUTE` on a normal PC |
| 🔒 | Store evidence **encrypted** with restricted access | Share browser history or hives beyond the case team |

```powershell
# 🪟 Verify on receipt
Get-FileHash .\CASE_HOST_TIME.zip -Algorithm SHA256   # compare with the .zip.sha256 file
```
```bash
# 🐧 Verify on receipt
sha256sum -c CASE_HOST_TIME.tar.gz.sha256
```

> [!WARNING]
> ☣️ **`07_samples_DO_NOT_EXECUTE` contains live malware**, renamed to `.bin_` to prevent accidental execution. Analyse it **only** in an isolated sandbox or lab.

> [!CAUTION]
> 🔏 The output contains **sensitive data**: registry hives (password hashes), browser and shell history, and system configuration. Treat it as confidential evidence.

---

## 🛠️ Troubleshooting

| Symptom | Fix |
|---|---|
| 🚫 *"running scripts is disabled on this system"* | Use `powershell.exe -ExecutionPolicy Bypass -File .\Invoke-DFIRCollection.ps1 …` |
| ⚠️ *"NOT running as Administrator"* | Re-open PowerShell with **Run as administrator** (or use `sudo` on Linux) |
| 🔒 *"Could not copy … / Access denied"* | Usually locked or AV-protected files. VSS copy is tried automatically; export the rest from your EDR (e.g. GravityZone quarantine) |
| 🐢 Windows run is slow | Event-log parsing and hashing dominate. Try `-DaysBack 7` or `-SkipEventLogs` for a first pass |
| 🐢 Linux run is slow | Package verification dominates. Use `-V` |
| 💽 Disk full | Point `-OutputRoot` / `-o` at a larger external drive; skip memory or hives |
| 🧾 A step shows **ERROR** | See `00_case/collection.log`. Each error includes the line number. Other steps still complete |
| 🛡️ EDR blocks the script | Expected on hardened hosts. Add a temporary, case-specific allow rule, or run it from the EDR console's live-response feature |

---

## ❓ FAQ

<details>
<summary>🤔 <b>Will it alert the attacker or change anything on the host?</b></summary>

It makes **no changes** to the host's configuration or files. It does run normal admin commands (`netstat`, `wevtutil`, `Get-FileHash`…), which an attacker with live access could in theory notice. If stealth matters, capture memory and image the disk instead.
</details>

<details>
<summary>⏱️ <b>How long does it take?</b></summary>

Typically **5–20 minutes on Windows** and **2–10 minutes on Linux**, depending on disk size, log volume and the look-back window. Memory capture adds roughly 1 minute per GB of RAM.
</details>

<details>
<summary>🧠 <b>Where do I get a memory capture tool?</b></summary>

Use **WinPmem** on Windows and **AVML** or **LiME** on Linux. Download them from their official GitHub releases on a clean machine, put them on your USB drive, and pass the path with `-MemoryTool` / `-m`.
</details>

<details>
<summary>🔁 <b>Can I run it on many machines?</b></summary>

Yes. Deploy it through your EDR's live-response feature, GPO/Intune (Windows), or Ansible/SSH (Linux), and point the output at a central evidence share. Each host gets its own uniquely named, hashed package.
</details>

<details>
<summary>🧹 <b>It says COMPROMISE INDICATED. Should I clean the machine?</b></summary>

**No.** Preserve the evidence first, then **rebuild from trusted media**. A compromised host cannot be trusted after an in-place clean-up. Reset any credentials used on it from a **clean** device.
</details>

---

<div align="center">

### 🛡️ Vairav Technology Security Pvt. Ltd. · Cyber Security Operations Centre

*Collect first. Analyse second. Act on evidence.*

</div>
