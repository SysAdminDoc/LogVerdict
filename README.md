# LogVerdict

![Version](https://img.shields.io/badge/version-0.3.0-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4) ![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-5391FE)

Scan a Windows PC's logs, collapse them into the handful of distinct things that actually happened, and rule on each one in plain English: **what it means, why it matters, and what to do about it.**

Event Viewer shows you 1,855 red icons. LogVerdict shows you 71 signatures, tells you that 1,017 of them are one warning Microsoft documents as harmless, and puts the disk error you actually needed to see at the top.

## Why

Log tooling splits into three camps, none of which help an admin sitting at one broken machine:

- **Collectors** (Microsoft TSS, `Get-WinEvent`) gather everything and interpret nothing.
- **Lookup databases** (EventID.Net, Event Log Explorer) explain one event at a time, by hand.
- **SIEMs** (ManageEngine EventLog Analyzer, Netdata) want a server, an agent, a fleet, and a budget.

LogVerdict is the missing middle: local, whole-machine, multi-source, deduplicated, prioritized triage.

## What it reads

| Source | Why it matters |
|---|---|
| System / Application event channels | The bulk of client troubleshooting signal |
| Any other populated channel (`-AllChannels`) | ~128 hold records on a typical machine |
| `CBS.log` | Component store damage - the reason updates fail and SFC cannot repair |
| `dism.log` | Image servicing failures |
| `setupapi.dev.log` | Every driver install and device enumeration |
| `NetSetup.LOG` | Domain join and rename - survives in-place upgrades that wipe the event channels |
| `Panther\setupact.log`, `MoSetup\BlueBox.log` | Setup, upgrade and compatibility blocks |
| `Minidump\`, WER `ReportArchive` | Crash evidence, inventoried (not decoded) |

## How it works

```
Collect  ->  Reduce  ->  Resolve  ->  Report
```

1. **Collect** - read-only. Nothing on the machine is modified beyond the report folder.
2. **Reduce** - event records group by `Provider + EventID`. Text-log lines group by a masked template (GUIDs, paths, hex, numbers and timestamps replaced), so the same failure recurring with different parameters collapses to one entry. On a typical machine this is a **26:1 reduction**, rising to **311:1** across every populated channel.
3. **Resolve** - each signature is matched against [`Data/verdicts.json`](Data/verdicts.json), a curated database of human-written rulings. Most-specific rule wins. Some rules escalate by rate: corrected hardware errors are noise at a trickle and a failing component at volume.
4. **Report** - console, plain text, JSON, and a self-contained dark HTML page that opens anywhere with no network access.

**No language model is involved.** Every explanation is a curated rule written by a human. A signature with no matching rule is reported as `unknown` with its raw evidence and **no guess at a cause** - because a confidently wrong fix is worse than no fix.

## Usage

### The executable

`LogVerdict.exe` is a single self-contained file with the verdict database compiled in. Copy it to the machine you are troubleshooting and run it - nothing is installed and there are no dependencies.

```
LogVerdict.exe                                  scan the last 30 days
LogVerdict.exe -DaysBack 7 -AllChannels         narrower window, every populated channel
LogVerdict.exe -IncludeBenign                   show the signatures ruled harmless too
LogVerdict.exe -NoReport                        console only, write nothing
LogVerdict.exe -OutputDir C:\Temp\lv             choose where reports land
```

It is **unsigned by design** - this project does not code-sign. SmartScreen will warn on first run: choose **More info** then **Run anyway**.

Drop a `verdicts.local.json` beside the .exe to add your own rules; they are merged automatically and win ties against the compiled-in ones. A full `Dataerdicts.json` beside the .exe replaces the compiled-in database entirely.

Build it yourself:

```powershell
Install-Module ps2exe -Scope CurrentUser
powershell -NoProfile -ExecutionPolicy Bypass -File .\Tools\Build-LogVerdictExe.ps1
# -> dist\LogVerdict.exe
```

### From source

```powershell
# Simplest: run it.
powershell -ExecutionPolicy Bypass -File .\Invoke-LogVerdict.ps1

# Narrower window, every populated channel
.\Invoke-LogVerdict.ps1 -DaysBack 7 -AllChannels

# Show the signatures ruled harmless too
.\Invoke-LogVerdict.ps1 -IncludeBenign

# Console only, no files written
.\Invoke-LogVerdict.ps1 -NoReport
```

Reports land in a timestamped folder on the Desktop by default (safe even for right-click-elevated runs that start in System32). Override with `-OutputDir`.

As a module:

```powershell
Import-Module .\LogVerdict.psd1
$r = Invoke-LogVerdictScan -DaysBack 30
$r.Findings | Where-Object Verdict -eq 'actionable'
$r | Export-LogVerdictReport -OutputDir C:\Temp\lv
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing above informational |
| 1 | Something to investigate, or an unrecognized signature |
| 2 | Actionable finding |
| 3 | Critical finding |
| 4 | The scan itself failed |

### Verdicts

`benign` - documented as harmless, suppressed by default. `informational` - real but not a problem. `unknown` - unrecognized, shown with raw evidence. `investigate` - a lead worth following. `actionable` - do something. `critical` - hardware or data integrity is at risk.

## Extending the verdict database

The rules are the product. Adding one is a JSON edit, no code:

```json
{
  "id": "LOCAL-0001",
  "match": { "source": "event", "provider": "Contoso-Agent", "eventId": 4242 },
  "verdict": "investigate",
  "title": "The Contoso agent lost its config",
  "plain": "What a non-specialist needs to understand.",
  "why": "Why this is or is not worth acting on.",
  "action": "The concrete next step.",
  "escalate": { "perDay": 10, "verdict": "actionable", "why": "At this rate it is failing, not glitching." },
  "confidence": "high"
}
```

`Data/verdicts.schema.json` describes the full rule format - point your editor at it for completion and inline validation. [CONTRIBUTING.md](CONTRIBUTING.md) walks through adding a rule end to end.

Put site-specific rules in `Data/verdicts.local.json` - it is merged automatically, wins ties against the shipped rules, and survives updates. Validate with:

```powershell
Test-LogVerdictDatabase
```

`match` accepts `source`, `channel`, `provider` (trailing `*` wildcard allowed), `eventId`, and `messagePattern` (regex). More match keys means higher specificity, and the most specific matching rule wins.

## Requirements

Windows 10/11. Windows PowerShell 5.1 (stock) or PowerShell 7.x. **No dependencies** - the whole point is that it runs on a broken machine with nothing installed.

Runs without admin; elevation unlocks the Security channel and some text logs.

Every scan probes each channel for readability before reading it, and reports what it could **not** see under "what this scan could not see": channels denied by ACL, channels whose metadata would not enumerate, channels truncated at the per-channel record cap, and requested channels that do not exist. This matters because `Get-WinEvent -FilterHashtable` reports a denied channel identically to an empty one - a scan that trusts that path would tell you a channel is clean when it was never allowed to open it.

Tests need [Pester](https://pester.dev/) 5+:

```powershell
Invoke-Pester -Path .\Tests
```

## Honest limitations

- **Coverage is the roadmap.** 65 rules ship. A first scan will report plenty of `unknown` signatures - that is the tool refusing to guess, and each one is a candidate rule.
- **Crash dumps are inventoried, not decoded.** Reading a minidump needs a debugger and symbols.
- **A clean result is not proof of health.** An in-place upgrade or a cleared log resets the event channels, so the report states each channel's oldest surviving record and warns when that horizon falls inside the requested window.
- Only the live machine is supported today. Offline analysis of a collected evidence bundle is planned.

## License

MIT
