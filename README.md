# LogVerdict

![Version](https://img.shields.io/badge/version-0.7.0-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4) ![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-5391FE)

Scan a Windows PC's logs, collapse them into the handful of distinct things that actually happened, and rule on each one in plain English: **what it means, why it matters, and what to do about it.**

Event Viewer shows you 1,855 red icons. LogVerdict shows you 71 signatures, tells you that 1,017 of them are one warning Microsoft documents as harmless, and puts the disk error you actually needed to see at the top.

![The LogVerdict window](docs/screenshot-gui.png)

There are two front ends over one engine: a window for reading, and a console tool for scripting. Neither can disagree with the other, because both call the same scan.

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
| `Minidump\`, WER `ReportArchive` | `Report.wer` app/module/exception metadata and kernel dump stop-code headers; artifacts that cannot be read remain inventoried |
| Reliability Monitor (`Win32_ReliabilityRecords`) | Microsoft's own curated view of what failed, plus the software install/removal history an error-only sweep never sees |

## How it works

```
Collect  ->  Reduce  ->  Resolve  ->  Correlate  ->  Report
```

1. **Collect** - read-only. Nothing on the machine is modified beyond the report folder.
2. **Reduce** - event records group by `Provider + EventID`. Text-log lines group by a masked template (GUIDs, paths, hex, numbers and timestamps replaced), so the same failure recurring with different parameters collapses to one entry. On a typical machine this is a **26:1 reduction**, rising to **311:1** across every populated channel.
3. **Resolve** - each signature is matched against [`Data/verdicts.json`](Data/verdicts.json), a curated database of human-written rulings. Most-specific rule wins. Some rules escalate by rate: corrected hardware errors are noise at a trickle and a failing component at volume.
4. **Correlate** - signatures that occurred within minutes of each other are reported together, above the flat list, with the window of time to look at. Corrected hardware errors and an unexpected restart are each easy to dismiss alone; together they name a cause. Correlations are curated, never inferred - on one machine the loudest signature co-occurs with everything, so a discovered correlation is mostly an artefact of volume.
5. **Report** - console, plain text, JSON, and a self-contained dark HTML page that opens anywhere with no network access.

**No language model is involved by default.** Every ruling and remediation is a curated rule written by a human. A signature with no matching rule is reported as `unknown` with its raw evidence and no guess at a cause. An explicit `-ExplainUnknown` opt-in can ask a local Ollama model for a separately labelled candidate explanation; it never changes the verdict and output containing remediation language is discarded.

## Usage

### The window

`LogVerdict-GUI.exe` is the whole tool in one double-clickable file. It scans, ranks the findings worst-first, and explains the selected one in plain English beside the raw evidence it was ruled on.

- **Overview** holds the scan controls, last-run state, reduction metrics, verdict distribution and the three highest-priority findings.
- **Findings** is the diagnostic workspace. Verdict chips and the search box filter the list; selecting a row opens its plain-English ruling, concrete action and raw evidence beside it.
- **Coverage** makes the trust boundary explicit. Readable channels, event horizons, denied sources, crash artifacts and curated correlations have one page rather than being buried in a sidebar.
- **Activity** shows the live collect, reduce, correlate, resolve and report stages, the full run transcript and a compact run summary.
- **Save report** writes the same text, JSON and HTML bundle the console tool produces.
- The scan runs on a background thread, so the window stays responsive and can be cancelled mid-run.
- Windows High Contrast changes the full interface to the active system colours, including verdict labels and keyboard focus, and switching it off restores the normal dark theme without restarting.

Elevation is optional and never forced. Without it the Security channel and some setup logs are unreadable; the window says so in a banner and offers to restart elevated.

```
LogVerdict-GUI.exe                    open the window
LogVerdict-GUI.exe -AutoScan          scan immediately on open
LogVerdict-GUI.exe -DaysBack 7        pre-fill a narrower window
```

### The executable

`LogVerdict.exe` is a single self-contained file with the verdict database compiled in. Copy it to the machine you are troubleshooting and run it - nothing is installed and there are no dependencies.

```
LogVerdict.exe                                  scan the last 30 days
LogVerdict.exe -DaysBack 7 -AllChannels         narrower window, every populated channel
LogVerdict.exe -IncludeBenign                   show the signatures ruled harmless too
LogVerdict.exe -NoReport                        console only, write nothing
LogVerdict.exe -OutputDir C:\Temp\lv             choose where reports land
LogVerdict.exe -Redact                          mask identifiers before writing
LogVerdict.exe -SkipReliability                 skip Reliability Monitor
LogVerdict.exe -IncludeEvidence                 also zip the evidence for a ticket
LogVerdict.exe -ExplainUnknown                  draft explanations for unknowns with local Ollama
LogVerdict.exe -PromoteToRule                   save safe candidates as inactive local rule drafts
```

`-IncludeEvidence` writes a zip beside the report holding the reports, the matching text-log lines and the scanned event channels as `.evtx`. The report says what LogVerdict concluded; the bundle carries what it concluded it *from*. Combined with `-Redact` the channel exports are deliberately left out - `.evtx` is binary and carries the identifiers redaction removes from the text, and the manifest says so, so a withheld channel is never mistaken for a clean one.

`-Redact` masks the account name, machine name, profile paths, SIDs and mail addresses out of the captured log messages before they are written. Use it when the report is going to a ticket or a vendor - the default report keeps everything, because locally that is the evidence. The reports say when they were redacted, and say that an identifier Windows wrote in a form this tool does not recognize may still be in there: read before sending.

Double-clicked, it holds the console window open until you press Enter. Run from a script or a scheduled task and it never pauses, so automation cannot hang; `-Pause` and `-NoPause` force the behaviour either way.

It is **unsigned by design** - this project does not code-sign. SmartScreen will warn on first run: choose **More info** then **Run anyway**.

Drop a `verdicts.local.json` beside either .exe to add your own rules; they are merged automatically and win ties against the compiled-in ones. A full `Data\verdicts.json` beside the .exe replaces the compiled-in database entirely.

Build them yourself:

```powershell
Install-Module ps2exe -Scope CurrentUser
powershell -NoProfile -ExecutionPolicy Bypass -File .\Tools\Build-LogVerdictExe.ps1
# -> dist\LogVerdict.exe  and  dist\LogVerdict-GUI.exe
# -Target Console or -Target Gui builds just one
```

### From source

```powershell
# The window
powershell -ExecutionPolicy Bypass -File .\LogVerdict-GUI.ps1

# Simplest: run it.
powershell -ExecutionPolicy Bypass -File .\Invoke-LogVerdict.ps1

# Narrower window, every populated channel
.\Invoke-LogVerdict.ps1 -DaysBack 7 -AllChannels

# Show the signatures ruled harmless too
.\Invoke-LogVerdict.ps1 -IncludeBenign

# Console only, no files written
.\Invoke-LogVerdict.ps1 -NoReport

# Re-evaluate a bundle collected on another PC with the current rule database
.\Invoke-LogVerdict.ps1 -EvidencePath .\LogVerdict-Evidence_HOST_20260801-120000.zip

# Opt in to non-remedial draft explanations for unknown signatures from local Ollama
.\Invoke-LogVerdict.ps1 -ExplainUnknown -OllamaModel llama3.2

# Accept safe candidates into verdicts.local.json for human review; implies ExplainUnknown
.\Invoke-LogVerdict.ps1 -PromoteToRule -OllamaModel llama3.2
```

Reports land in a timestamped folder on the Desktop by default (safe even for right-click-elevated runs that start in System32). Override with `-OutputDir`.

Offline analysis never reads the reviewing PC. It inherits the source report's look-back window unless `-DaysBack` is supplied, reopens exported `.evtx` members when present, and uses the captured report summaries for text logs and Reliability Monitor, whose full stores are deliberately not copied into a small evidence bundle. Redacted bundles contain no raw `.evtx`, so they are re-evaluated from report summaries and carry a coverage note saying so.

`-ExplainUnknown`, or the stronger `-PromoteToRule` switch that implies it, is the only path that contacts a model endpoint. LogVerdict accepts only plain HTTP on `localhost`, `127.0.0.1`, or `::1`, sends one reduced unknown signature at a time to Ollama's `/api/generate`, and requests structured output with no actions or fixes. Known signatures are never sent. The candidate appears in its own **MODEL-GENERATED CANDIDATE - NOT A CURATED RULING** block; a connection failure, malformed response, unexpected field, or remediation language leaves the deterministic scan intact and produces no candidate.

`-PromoteToRule` is a stronger opt-in and therefore implies `-ExplainUnknown`. Each safe candidate is written atomically to `Data\verdicts.local.json` from source, or `verdicts.local.json` beside the compiled executable. Generated rules are visibly marked, use `confidence: draft` and `status: unsupported`, and remain ineligible to match even if either gate is edited alone. Human review must supply a real verdict and remediation, check the evidence, then replace both fields. Re-running promotion updates the same hashed draft id instead of creating duplicates; a reviewed rule is never overwritten. `-LocalRulePath` selects a different local file when needed.

As a module:

```powershell
Import-Module .\LogVerdict.psd1
$r = Invoke-LogVerdictScan -DaysBack 30
$drafted = Invoke-LogVerdictScan -DaysBack 30 -ExplainUnknown -OllamaModel llama3.2
$r.Findings | Where-Object Verdict -eq 'actionable'
$r | Export-LogVerdictReport -OutputDir C:\Temp\lv

# Or open the window from the module
Show-LogVerdictGui -DaysBack 7 -AutoScan
```

To check whether a fix worked, save a JSON report before the change, scan again afterwards, and compare them. The output contains only signatures that are new, resolved, or worsening, as flat PowerShell objects that can be filtered or exported directly:

```powershell
Compare-LogVerdictScan `
  -Before .\before\LogVerdict-Report.json `
  -After  .\after\LogVerdict-Report.json
```

WPF needs a single-threaded apartment. Windows PowerShell is STA by default; `pwsh` is not, so `LogVerdict-GUI.ps1` relaunches itself under `powershell.exe -STA`. Calling `Show-LogVerdictGui` directly from `pwsh` throws and tells you why.

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

Put site-specific rules in `Data/verdicts.local.json` - it is merged automatically, wins ties against the shipped rules, and survives updates. Model-promoted entries in that file are review drafts, not site rules yet: `confidence: draft` is accepted only with `status: unsupported`, and the resolver independently excludes both. Change both fields only after replacing the placeholder action with reviewed guidance. Validate with:

```powershell
Test-LogVerdictDatabase
```

Every shipped rule also carries a regression fixture in [`Data/fixtures.json`](Data/fixtures.json): a minimal signature the rule must still claim, resolved through the real resolver. A rule that quietly stops matching is otherwise invisible - it produces no error, just an `unknown` signature that looks like a gap in coverage rather than a broken rule. The fixtures also catch the opposite mistake, a new rule that is broader than it looks and shadows an existing one, and the failure names which rule stole the match. Local databases need no fixtures; the checks are skipped when there is no fixture file.

The Microsoft support corpus has a guarded import path. `Tools\Import-MsDocsEvent.ps1` reads a local `MicrosoftDocs/SupportArticles-docs` checkout, verifies its CC-BY-4.0 licence, discovers event-ID articles, and turns only reviewed, paraphrased prose into attributed rule objects. It refuses copied prose and never edits the database on discovery alone.

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

- **Coverage is the roadmap.** 173 rules ship. A first scan will still report `unknown` signatures - that is the tool refusing to guess, and each one is a candidate rule.
- **Crash-stack analysis is bounded.** LogVerdict reads the bug-check code and four parameters from supported kernel dump headers, but naming the responsible driver still needs a debugger and symbols. Unsupported, truncated or access-controlled dumps remain inventoried with the reason they were not decoded.
- **A clean result is not proof of health.** An in-place upgrade or a cleared log resets the event channels, so the report states each channel's oldest surviving record and warns when that horizon falls inside the requested window.
- Offline review is bounded by what the bundle captured. Exported event channels are re-read in full, while text logs and Reliability Monitor are re-evaluated from the signature summaries in the source report rather than copied wholesale.

## License

MIT
