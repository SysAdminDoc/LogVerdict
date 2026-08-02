# LogVerdict

![Version](https://img.shields.io/badge/version-0.8.1-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4) ![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-5391FE)

Scan a Windows PC's logs, collapse them into the handful of distinct things that actually happened, and rule on each one in plain English: **what it means, why it matters, and what to do about it.**

Event Viewer shows you a wall of red icons. LogVerdict collapses repeats, explains what remains in plain English, and puts the highest-priority evidence first. Volatile scan totals are intentionally omitted here; the packaged GUI smoke test generates the current visual reference from the release artifact.

![The LogVerdict window](docs/screenshot-gui.png)

There are two front ends over one engine: a window for reading, and a console tool for scripting. Neither can disagree with the other, because both call the same scan.

## Why

Microsoft [SetupDiag](https://learn.microsoft.com/en-us/windows/deployment/upgrade/setupdiag) already explains
Windows upgrade failures from Panther logs, and [cmtraceopen](https://github.com/adamgell/cmtraceopen) reads
servicing and setup text logs with a findings-oriented interface. LogVerdict's narrower claim is deliberately
testable: it is an offline, local triage pass that rules both Windows event channels and servicing/diagnostic text
logs, deduplicates them into signatures, and returns a plain-English explanation plus a concrete remediation from a
curated non-LLM rule database. SetupDiag remains useful for upgrade-specific cases; cmtraceopen remains useful as a
viewer and text-log specialist.

## What it reads

| Source | Why it matters |
|---|---|
| System / Application event channels | The bulk of client troubleshooting signal |
| Focused operational channels (`-DiagnosticChannels`) | Storage, code integrity, device setup, packaged apps, memory pressure, and boot security without a full sweep |
| Any other populated channel (`-AllChannels`) | ~128 hold records on a typical machine |
| `CBS.log` | Component store damage - the reason updates fail and SFC cannot repair |
| `dism.log` | Image servicing failures |
| `setupapi.dev.log` | Every driver install and device enumeration |
| `NetSetup.LOG` | Domain join and rename - survives in-place upgrades that wipe the event channels |
| `Panther\setupact.log`, `MoSetup\BlueBox.log` | Setup, upgrade and compatibility blocks; when an existing `SetupDiag.exe` is available, its structured failure profile and remediation are merged too |
| `Minidump\`, WER `ReportArchive` | `Report.wer` app/module/exception metadata and kernel dump stop-code headers; artifacts that cannot be read remain inventoried |
| Reliability Monitor (`Win32_ReliabilityRecords`) | Microsoft's own curated view of what failed, plus the software install/removal history an error-only sweep never sees |

SetupDiag is never downloaded or trusted by filename alone. Normal discovery accepts only an existing executable with a valid Authenticode signature from Microsoft Corporation or Microsoft Windows. An unsigned, invalid, or differently signed candidate is reported as a coverage gap and the built-in Panther rules continue without executing it.

Every scan also emits normalized per-source coverage in JSON, HTML, CSV, and evidence manifests. Each event channel, text log, and offline EVTX source records whether it was readable, empty, not observed, unreadable, or truncated, along with its reason, cap, time window, parser error, record gap, timing, and source metadata. `empty` means the source was observed but had no matching event; a missing, denied, or failed source remains explicitly distinct.

Live scans additionally include advisory configuration-health profiles for provider manifests and EventID versions, channel retention and clock context, PowerShell logging, advanced audit policy, Defender state, Sysmon enabled/filtered IDs when a readable XML configuration is available, and WEF read-existing/heartbeat/bookmark state. These profiles explain visibility limits only; they never become malicious verdicts.

## How it works

```
Collect  ->  Reduce  ->  Resolve  ->  Correlate  ->  Report
```

1. **Collect** - diagnostic sources are read-only. The window stores only its small preferences file under `%LOCALAPPDATA%\LogVerdict`; report files are written only when requested.
2. **Reduce** - event records group by `Provider + EventID`. Text logs take two passes. First, typed slots mask timestamps, paths, SIDs, IPv4/IPv6 addresses, MAC addresses, URLs, FQDNs, UPNs, package identities, versions, GUIDs, hex and numbers. Then numeric, error-code and version slots with at most three distinct values in their template family are promoted back into the signature: two recurring HRESULTs remain two diagnoses, while a thousand transient operation ids remain one family. Identity and volatile slots are never promoted. Original token count participates in the hash, and reports show the reduction ratio before and after promotion.
3. **Resolve** - each signature is matched against [`Data/verdicts.json`](Data/verdicts.json), a curated database of human-written rulings. Most-specific rule wins. Some rules escalate by rate: corrected hardware errors are noise at a trickle and a failing component at volume. Event rules can additionally use the v6 bounded structured subset: named `EventData.<field>`/`UserData.<field>` predicates combined with `all`, `any`, and `not`, using `equals`, `contains`, `startswith`, `endswith`, or `regex`; rendered localized message text is not required for those matches.

Unknown signatures are also checked against the bundled [`Data/error-codes.json`](Data/error-codes.json) reference catalog. The catalog currently carries 3,157 typed entries: 2,745 Microsoft WinError.h statuses, 378 kernel bug-check codes, 13 common HRESULTs, nine NTSTATUS values, seven Setup/servicing codes, and five Windows Update codes. Each entry retains canonical numeric fields, applicability, retrieval date, and source metadata; one-time indexes keep repeated lookups bounded. A catalog match improves the explanation but stays `unknown` until provider-specific context justifies a reviewed verdict. Regenerate it from current Microsoft Learn tables with `Tools\Import-MicrosoftErrorCatalog.ps1`; the normal scan never makes a network call.

Windows Setup and Windows Update records also retain invariant result and extended codes, phase, operation, provider locale, and fallback text when localized provider prose is unavailable or not useful for matching. Reports and standard exports carry that structured context alongside the catalog's phase and operation, so a German, Japanese, or message-resource-missing capture can still be compared without translating its rendered message.
4. **Correlate** - signatures that occurred within minutes of each other are reported together, above the flat list, with the window of time to look at. Corrected hardware errors and an unexpected restart are each easy to dismiss alone; together they name a cause. Correlations are curated, never inferred - on one machine the loudest signature co-occurs with everything, so a discovered correlation is mostly an artefact of volume.
5. **Report** - console, plain text, JSON, and a self-contained dark HTML page that opens anywhere with no network access. The HTML report filters by verdict or text entirely offline, still shows every finding when scripting is disabled, and prints as a light document suitable for a ticket or PDF.

Presentation labels are loaded from the versioned [`Data/localization.json`](Data/localization.json) resource. The GUI and text, HTML, and CSV reports resolve the Windows UI culture, or an explicit `LOGVERDICT_LOCALE` such as `de-DE` or `ja-JP`, and fall back deterministically through the language, `en-US`, and the call-site English default. Localized provider prose is never used as a rule dependency: matching continues to use invariant event fields, codes, and structured data. Packaged executables embed the same resource and still allow a beside-the-executable `Data\localization.json` override.

JSON reports include the versioned `Contract` envelope (`LogVerdict.Report`, schema version 1) with live/offline mode, generation time, redaction state, and reader compatibility metadata. Readers should reject a newer schema rather than guessing at fields; unversioned legacy objects are explicitly marked when normalized.
Evidence bundles add `EVIDENCE-CONTRACT.json`, which records the report contract, source coverage, performance metadata, privacy/raw-evidence state, omissions, and SHA-256 hashes for the included files. A redacted bundle omits raw event channels and declares that state explicitly.

**No language model is involved by default.** Every ruling and remediation is a curated rule written by a human. A signature with no matching rule is reported as `unknown` with its raw evidence and no guess at a cause. An explicit `-ExplainUnknown` opt-in can ask a local Ollama model for a separately labelled candidate explanation; it never changes the verdict and output containing remediation language is discarded.

Unknowns and inactive candidates can be exchanged as one redacted review queue without changing the curated database. Export a JSON report first, then combine it with one or more Sigma/local candidate queues:

```powershell
Invoke-LogVerdictScan | Export-LogVerdictReport -OutputDir .\report -Format Json
.\Tools\Export-LogVerdictReviewArtifact.ps1 -ResultPath .\report\LogVerdict-Report.json `
  -CandidatePath .\Data\verdicts.local.json -OutputPath .\review.json
.\Tools\Import-LogVerdictReviewArtifact.ps1 -ArtifactPath .\review.json `
  -ExistingPath .\previous-review.json -OutputPath .\review-diff.json
```

The artifact carries stable unknown/candidate IDs, source/provider/event context, redacted samples and structured data, provenance, false-positive fields, and a fixture scaffold. Reviewers edit `review.status` and its fields; import reports added/changed/removed items and always leaves `Data\verdicts.json` untouched.

## Usage

### The window

`LogVerdict-GUI.exe` is the whole tool in one double-clickable file. It scans, ranks the findings worst-first, and explains the selected one in plain English beside the raw evidence it was ruled on.

- **Overview** holds the scan controls, last-run state, reduction metrics, verdict distribution and the three highest-priority findings.
- **Findings** is the diagnostic workspace. Verdict chips and the search box filter the list; selecting a row opens its plain-English ruling, concrete action and raw evidence beside it.
- Structured findings filters narrow the virtualized list by source, channel, provider, event ID, correlation, or rule status. Click `VERDICT`, `TIMES`, `PER DAY`, or `LAST SEEN` to sort on the underlying rank/count/rate/timestamp rather than display text; the selected finding remains resolved by index from the one stored result graph.
- **Coverage** makes the trust boundary explicit. Readable channels, event horizons, denied sources, crash artifacts and curated correlations have one page rather than being buried in a sidebar.
- **Activity** shows the live collect, reduce, correlate, resolve and report stages, the full run transcript and a compact run summary.
- **Save report** writes the same text, JSON and HTML bundle the console tool produces.
- The scan runs on a background thread, so the window stays responsive and can be cancelled mid-run.
- Look-back, source switches, harmless-finding visibility, and window size are remembered per user in `%LOCALAPPDATA%\LogVerdict\settings.json`. A missing, corrupt, future, or unreadable settings file falls back to safe defaults.
- Windows High Contrast changes the full interface to the active system colours, including verdict labels and keyboard focus, and switching it off restores the normal dark theme without restarting.

Elevation is optional and never forced. Without it the Security channel and some setup logs are unreadable; the window says so in a banner and offers to restart elevated.

```
LogVerdict-GUI.exe                    open the window
LogVerdict-GUI.exe -AutoScan          scan immediately on open
LogVerdict-GUI.exe -DaysBack 7        explicitly override the saved look-back
```

The Overview page exposes the deterministic live-scan and report choices rather than hiding them behind a second engine:

| Capability | Window control | Console / module equivalent |
|---|---|---|
| Look-back | Look back (1-3650 days) | `-DaysBack` |
| Default, focused, all, or named event channels | Focused/all switches or Named event channels | `-DiagnosticChannels`, `-AllChannels`, `-Channel` |
| Setup logs, Reliability Monitor, harmless findings | Source switches | `-SkipTextLogs`, `-SkipReliability`, `-IncludeBenign` |
| Alternate complete rule database | Rules path / picker | `-DatabasePath` |
| Report destination, identifier masking, evidence bundle | Report controls | `-OutputDir`, `-Redact`, `-IncludeEvidence`, `-AllowRawEvidence` |
| Offline evidence re-evaluation | Console-only batch/review workflow | `-EvidencePath` |
| Local-model draft and rule-authoring workflow | Deliberately console-only so model endpoint and local-rule writes remain explicit | `-ExplainUnknown`, `-OllamaModel`, `-OllamaEndpoint`, `-PromoteToRule`, `-LocalRulePath` |
| Local baseline/history and trend signals | Console/report and module opt-in; local state is bounded and advisory only | `-HistoryPath`, `-HistoryWindowDays` |
| Dependency/tool advisory cache | Offline cache/query path; displayed separately and never used to change event verdicts | `-AdvisoryPath`, `-AdvisoryPackage`, `-AdvisoryVersion`, `Get-LogVerdictAdvisory` |
| Case profile and responder handoff | Bounded collection metadata, redaction policy, source hashes, recipes, and attributed CSV/JSONL timelines | `New-LogVerdictCaseProfile`, `Export-LogVerdictHandoff` |
| Bounded live event tail and bookmark resume | Module-only, opt-in workflow with reconnect/drop/latency coverage and optional WEF health intake | `Watch-LogVerdict` |
| Large finding captures | Virtualized, recycling findings lists with indexed lazy detail resolution | GUI |
| Structured finding filters and sorting | UI Automation-labelled source/channel/provider/event ID/correlation/rule-state filters plus count/rate/latest sorting over lightweight row projections | GUI |
| GUI accessibility and scaling smoke | STA UI Automation names, keyboard targets, normal/high-contrast resources, long/error text, and 125% layout checks | `Tools/Test-LogVerdictGui.ps1` |
| Opt-in diagnostic performance telemetry | Content-free source status, bounded counts, caps, and elapsed timing in JSON, text, HTML, CSV, and standard exports | `-PerformanceTelemetry` |
| Content-free performance budgets | Temporary small, large, malformed-text, and malformed-EVTX fixtures; aggregate counts/status/timing only, checked on Windows PowerShell 5.1 and PowerShell 7.x | `Tools/Test-LogVerdictPerformance.ps1` |
| Shared collection safety budgets | One byte, normalized-record, and elapsed-time allowance across live/offline collectors; incomplete sources remain `truncated` or `timeout` | `-MaxCollectionBytes`, `-MaxCollectionRecords`, `-MaxCollectionSeconds` |
| Output format selection | The window always saves Text, JSON, CSV, and HTML together | `-Format` (`Text`, `Json`, `Csv`, `Html`, or `All`) |
| Console lifecycle | Not applicable to a persistent window | `-NoReport`, `-Pause`, `-NoPause` |

Named `-Channel` values take precedence over `-AllChannels` and `-DiagnosticChannels` when
wrappers pass a broad default alongside an explicit list. Supplying both broad switches is
rejected; choose one channel tier.

### The executable

`LogVerdict.exe` is a single self-contained file with the verdict database compiled in. Copy it to the machine you are troubleshooting and run it - nothing is installed and there are no dependencies.

```
LogVerdict.exe                                  scan the last 30 days
LogVerdict.exe -DiagnosticChannels              add six focused operational channels
LogVerdict.exe -DaysBack 7 -AllChannels         narrower window, every populated channel
LogVerdict.exe -IncludeBenign                   show the signatures ruled harmless too
LogVerdict.exe -NoReport                        console only, write nothing
LogVerdict.exe -OutputDir C:\Temp\lv             choose where reports land
LogVerdict.exe -Redact                          mask identifiers before writing
LogVerdict.exe -SkipReliability                 skip Reliability Monitor
LogVerdict.exe -IncludeEvidence -Redact          audit and zip a shareable evidence bundle
LogVerdict.exe -IncludeEvidence -AllowRawEvidence  explicitly authorize a forensic raw bundle
LogVerdict.exe -Format Csv                      write one flat row per finding for a pipeline
LogVerdict.exe -ExplainUnknown                  draft explanations for unknowns with local Ollama
LogVerdict.exe -PromoteToRule                   save safe candidates as inactive local rule drafts
LogVerdict.exe -HistoryPath C:\Temp\lv-history.json  save bounded local trend history
LogVerdict.exe -AdvisoryPackage PowerShell -AdvisoryVersion 7.4.0  match the shipped offline advisory cache
```

`-IncludeEvidence` writes a zip beside the report holding the reports, the matching text-log lines and, only with the explicit `-AllowRawEvidence` override, the scanned event channels as `.evtx`. Raw bundles are forensic artifacts and are never described as sanitized. `-Redact` runs a deterministic audit over the staged text, records hashed findings and substitution counts in `PRIVACY-AUDIT.json`, and refuses to create the zip if a known secret, SID, account/path identifier, or script-block marker remains. Combined with `-Redact` the channel exports are deliberately left out - `.evtx` is binary and carries the identifiers redaction removes from the text, and the manifest says so, so a withheld channel is never mistaken for a clean one.

`-Redact` masks the account name, machine name, profile paths, SIDs and mail addresses out of the captured log messages before they are written. Use it when the report is going to a ticket or a vendor - the default report keeps everything, because locally that is the evidence. The reports say when they were redacted, and say that an identifier Windows wrote in a form this tool does not recognize may still be in there: read before sending.

`-HistoryPath` opts into a local JSON history containing at most 30 recent scan summaries. It stores stable signature keys, counts, rates, verdict labels, and rule ids, not messages, paths, machine names, or account identifiers. `-HistoryWindowDays` bounds which prior scans are compared (default 30). Reports state the baseline method, comparison window, thresholds, missing-history state, and false-positive caveat. A trend signal is advisory only: it cannot raise a finding's verdict, `WorstVerdict`, or exit code.

The dependency/tool advisory cache is a separate, offline knowledge class. `-AdvisoryPackage` and `-AdvisoryVersion` match a package against `affectedRange`; the report carries fixed version, CVSS/vector, KEV state/date, publication and modification dates, source URL, and source hash under a distinct **DEPENDENCY ADVISORIES** section. These records never enter `Findings`, correlations, `WorstVerdict`, or the event exit code. `Get-LogVerdictAdvisory -Path .\Data\advisories.json -Package PowerShell -Version 7.4.0` queries the same cache without scanning logs. `Update-LogVerdictAdvisoryDatabase` is explicit and requires a SHA-256 digest, so an air-gapped cache can be staged with `-SourcePath` and used without a network.

Case profiles make a scan repeatable without copying raw event messages. `New-LogVerdictCaseProfile` records the selected sources, time bounds, redaction policy, operator choices, notes, and per-source SHA-256 values under a canonical profile id. `Invoke-LogVerdictScan -CaseProfilePath` attaches a validated profile for attribution; it does not override explicit scan parameters. `Export-LogVerdictHandoff` writes the profile, reviewable KAPE and Velociraptor collection recipes, deterministic attributed Timesketch and Hayabusa CSV timelines, and `LogVerdict-Timeline.jsonl`. The JSONL file is UTF-8 without a BOM, emits one versioned metadata/event/finding/correlation/coverage/provider object per line, normalizes timestamps to UTC, carries provider/channel/event/record IDs and rule provenance, and states whether the line is raw or redacted. It is written incrementally and atomically, so large handoffs do not create a second complete output graph. Timesketch rows include `message`, `datetime`, and `timestamp_desc`; source hashes and the profile id remain on every handoff row. The handoff contains normalized findings, not raw EVTX.
The cache declares a 60-day UTC freshness threshold and reports fresh, stale, or unavailable state in advisory scan context. A stale or unavailable cache never changes event findings, WorstVerdict, or the event exit code; the release gate rejects stale metadata until the cache is refreshed.
The shipped coverage manifest records Windows PowerShell 5.1 and PowerShell 7.x verification, plus the pinned Pester 5.9.0, PSScriptAnalyzer 1.25.0, and ps2exe 1.0.18 roles and runtimes.

`-Format Csv` writes `LogVerdict-Report.csv` with one scalar row per ordinary finding. Its stable columns include
the scan identity, source (`event`, `text`, or `reliability`), provider and event id, occurrence count and rate,
first and last timestamps, verdict, ruling prose, composite result/extend codes, phase, operation, provider locale,
fallback text, error-catalog fields, and the official reference. Correlations
remain in the text, JSON, and HTML reports. The row shape is deliberately suitable for `Import-Csv`,
`Export-Csv`, `Out-GridView`, or a ticketing-system import without knowing LogVerdict's nested JSON schema.

The module also has an explicit bounded live-tail path. `Watch-LogVerdict -Channel System -DurationSeconds 60 -BookmarkPath .\system-bookmark.json` reads only events newer than each channel's saved `RecordId`/timestamp,
writes the bookmark atomically, and returns normalized records with per-channel reconnect counts, possible dropped
record gaps, and event latency. `-MaxEvents`, `-MaxBytes`, `-IdleTimeoutSeconds`, and `-PollMilliseconds` keep the watch bounded;
it stops cleanly when a limit is reached or the caller interrupts it. `-IncludeWEFHealth` adds local `wecutil`
subscription configuration and runtime state, including read-existing, heartbeat, bookmark, reconnect/error, and
drop fields. These are collection-health facts, never malicious verdicts, and no fleet agent or remote connection is
required.

Double-clicked, it holds the console window open until you press Enter. Run from a script or a scheduled task and it never pauses, so automation cannot hang; `-Pause` and `-NoPause` force the behaviour either way.

It is **unsigned by design** - this project does not code-sign. SmartScreen will warn on first run: choose **More info** then **Run anyway**.

Release builds publish an SPDX 2.3 SBOM and a companion unsigned provenance record beside
each executable. The records include the asset SHA-256, source revision and source-tree
hash, build runtime, and content hashes for the pinned Pester, PSScriptAnalyzer, and
ps2exe modules. They can be checked without network access:

```powershell
.\Tools\Test-LogVerdictRelease.ps1 -ManifestDirectory .\Packaging -AssetDirectory .\dist -SupplyChainDirectory .\Packaging\supply-chain
```

The provenance is evidence about how an artifact was built, not a code signature; the
executables remain unsigned by design.

CI also runs `Tools\Test-LogVerdictPerformance.ps1` on both supported PowerShell
runtimes. It creates small, large, malformed-text, and malformed-EVTX inputs only in
the runner's temporary directory, deletes them after the run, and writes an aggregate
report containing statuses, bounded record counts, sizes, and timing. The checked-in
`Data\performance-budgets.json` makes a source-level timing regression fail the gate;
the report never contains fixture text or paths.
Drop a `verdicts.local.json` beside either .exe to add your own rules; they are merged automatically and win ties against the compiled-in ones. A full `Data\verdicts.json` beside the .exe replaces the compiled-in database entirely.

Rule updates are opt-in. `Update-LogVerdictDatabase` fetches `verdicts.json` from a
published GitHub release, verifies the release SHA-256 digest, validates the schema,
and installs it as the local override without changing the shipped database. The
previous override is retained as `verdicts.local.json.previous.json`; restore it with
`Update-LogVerdictDatabase -Rollback`. A normal scan, module import, or executable
launch never contacts the network.

```powershell
Import-Module .\LogVerdict.psd1
Update-LogVerdictDatabase                 # latest stable release
Update-LogVerdictDatabase -ReleaseTag v0.8.1
Update-LogVerdictDatabase -Rollback       # restore the previous local copy
```

Build them yourself:

```powershell
Install-Module ps2exe -RequiredVersion 1.0.18 -Scope CurrentUser
powershell -NoProfile -ExecutionPolicy Bypass -File .\Tools\Build-LogVerdictExe.ps1
# -> dist\LogVerdict.exe  and  dist\LogVerdict-GUI.exe
# -Target Console or -Target Gui builds just one
```

`VERSION` is the release source of truth. The build refuses a manifest-version mismatch, and
`Tools\Test-LogVerdictRelease.ps1` checks the module, README badge, typed catalog, verdict
provenance, package manifests, and (when supplied) executable hashes. Generate package metadata
from local assets without contacting GitHub with:

```powershell
.\Tools\New-PackageManifests.ps1 -AssetDirectory .\dist -ReleaseDate 2026-08-02
.\Tools\Test-LogVerdictRelease.ps1 -AssetDirectory .\dist
```

Release maintainers generate Scoop and winget manifests only after the matching GitHub release exists:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Tools\New-PackageManifests.ps1 -Version 0.8.1
```

The generator downloads the existing release assets, pins their SHA-256 hashes, and writes both manifests under `Packaging\`. It never creates or changes a release. Published assets must not be replaced in place: Scoop, winget, and SmartScreen all attach trust to the exact file hash.

### From source

```powershell
# The window
powershell -ExecutionPolicy Bypass -File .\LogVerdict-GUI.ps1

# Simplest: run it.
powershell -ExecutionPolicy Bypass -File .\Invoke-LogVerdict.ps1

# Narrower window, every populated channel
.\Invoke-LogVerdict.ps1 -DaysBack 7 -AllChannels

# Broader signal without sweeping every populated channel
.\Invoke-LogVerdict.ps1 -DiagnosticChannels

# Show the signatures ruled harmless too
.\Invoke-LogVerdict.ps1 -IncludeBenign

# Console only, no files written
.\Invoke-LogVerdict.ps1 -NoReport

# Re-evaluate a bundle collected on another PC with the current rule database
.\Invoke-LogVerdict.ps1 -EvidencePath .\LogVerdict-Evidence_HOST_20260801-120000.zip

# Re-evaluate one exported event log or every bounded .evtx file under a directory
.\Invoke-LogVerdict.ps1 -EvidencePath .\System.evtx
.\Invoke-LogVerdict.ps1 -EvidencePath .\Captured-Evtx\

# Opt in to non-remedial draft explanations for unknown signatures from local Ollama
.\Invoke-LogVerdict.ps1 -ExplainUnknown -OllamaModel llama3.2

# Accept safe candidates into verdicts.local.json for human review; implies ExplainUnknown
.\Invoke-LogVerdict.ps1 -PromoteToRule -OllamaModel llama3.2

# Opt in to bounded local trend history; change the comparison window if needed
.\Invoke-LogVerdict.ps1 -HistoryPath "$env:LOCALAPPDATA\LogVerdict\history.json" -HistoryWindowDays 30

# Match the shipped offline dependency advisory cache; this stays separate from event findings
.\Invoke-LogVerdict.ps1 -AdvisoryPackage PowerShell -AdvisoryVersion 7.4.0
```

Reports land in a timestamped folder on the Desktop by default (safe even for right-click-elevated runs that start in System32). Override with `-OutputDir`.

Offline analysis never reads the reviewing PC. It inherits the source report's look-back window unless `-DaysBack` is supplied, reopens exported `.evtx` members when present, and uses the captured report summaries for text logs and Reliability Monitor, whose full stores are deliberately not copied into a small evidence bundle. A direct `.evtx` path or directory is accepted as the offline source too. The source is bounded to 64 files, 512 MiB per file, 2 GiB total, and 20,000 events per file; parser time is measured against a 120-second per-file limit. Every admitted or skipped file carries size, status, parse time, reason, and a streaming SHA-256 in the coverage output and evidence manifest. Live and offline runs also have a shared default budget of 512 MiB, 100,000 normalized records, and 600 seconds; override it with the `MaxCollection*` parameters when a larger bounded capture is intentional. Redacted bundles contain no raw `.evtx`, so they are re-evaluated from report summaries and carry a coverage note saying so.

`-ExplainUnknown`, or the stronger `-PromoteToRule` switch that implies it, is the only path that contacts a model endpoint. LogVerdict accepts only plain HTTP on `localhost`, `127.0.0.1`, or `::1`, sends one reduced unknown signature at a time to Ollama's `/api/generate`, and requests structured output with no actions or fixes. Known signatures are never sent. The candidate appears in its own **MODEL-GENERATED CANDIDATE - NOT A CURATED RULING** block; a connection failure, malformed response, unexpected field, or remediation language leaves the deterministic scan intact and produces no candidate.

`-PromoteToRule` is a stronger opt-in and therefore implies `-ExplainUnknown`. Each safe candidate is written atomically to `Data\verdicts.local.json` from source, or `verdicts.local.json` beside the compiled executable. Generated rules are visibly marked, use `confidence: draft` and `status: unsupported`, and remain ineligible to match even if either gate is edited alone. Human review must supply a real verdict and remediation, check the evidence, then replace both fields. Re-running promotion updates the same hashed draft id instead of creating duplicates; a reviewed rule is never overwritten. `-LocalRulePath` selects a different local file when needed.

The executable is intentionally transparent. PS2EXE host code is licensed under the Microsoft Limited Public
License (MS-LPL), so the compiled file is a combined work even though the project source is MIT. The embedded
PowerShell is recoverable by design (for example, PS2EXE's `-extract` option); there are no secrets or proprietary
rules hidden in the binary. Use the PowerShell module for the cleanest source-licence boundary, or extract the
script when auditing the exact executable contents.

As a module:

```powershell
Import-Module .\LogVerdict.psd1
$r = Invoke-LogVerdictScan -DaysBack 30
$focused = Invoke-LogVerdictScan -DaysBack 30 -DiagnosticChannels
$drafted = Invoke-LogVerdictScan -DaysBack 30 -ExplainUnknown -OllamaModel llama3.2
$historical = Invoke-LogVerdictScan -DaysBack 30 -HistoryPath "$env:LOCALAPPDATA\LogVerdict\history.json"
$advisories = Get-LogVerdictAdvisory -Package PowerShell -Version 7.4.0
$r.Findings | Where-Object Verdict -eq 'actionable'
$r | Export-LogVerdictReport -OutputDir C:\Temp\lv

# Versioned machine-interchange JSON for ECS, OCSF, OpenTelemetry Logs, or STIX 2.1
Export-LogVerdictStandard -Result $r -Format Ocsf -Path C:\Temp\lv\finding.ocsf.json -Redact

# Bounded JSONL timeline: one compact record per line, streamed to an atomic file
Export-LogVerdictStandard -Result $r -Format Jsonl -Path C:\Temp\lv\timeline.jsonl -Redact

# Or open the window from the module
Show-LogVerdictGui -DaysBack 7 -AutoScan
```

`Export-LogVerdictStandard` uses one adapter contract across `Ecs`, `Ocsf`,
`OpenTelemetry`, and `Stix`. Each JSON document declares `schemaVersion: 1.0.0`,
preserves finding confidence, rule references, source/channel/provider/EventID fields,
timestamps, normalized coverage, configuration-health profiles, and explicit
`privacy.redacted`/`privacy.rawEvidenceIncluded` state. `-Redact` applies the same
identifier masking as the ordinary reports before projection; the adapters never copy
the internal result object wholesale or add raw EVTX bytes.

`-Format Jsonl` uses the same versioned privacy and provenance envelope but writes a
streaming timeline instead of an adapter document. It includes metadata, normalized event
and finding lines, curated correlations, per-source coverage, and provider provenance;
undated records keep `timestampUtc: null` rather than receiving an invented time. Omit
`-Path` to stream compact JSON objects to the PowerShell pipeline, or supply a path for
an atomic UTF-8 file.

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

Active rules and correlations must carry a reference, source record, or explicit
`provenance: "internal-observation"`. Database loading also rejects duplicate IDs, missing or
inactive correlation references, unsupported correlation fields, unreadable timespans, and
correlation types the resolver does not implement; malformed local additions fail before a scan
can produce a verdict.

Every shipped rule also carries a regression fixture in [`Data/fixtures.json`](Data/fixtures.json): a minimal signature the rule must still claim, resolved through the real resolver. A rule that quietly stops matching is otherwise invisible - it produces no error, just an `unknown` signature that looks like a gap in coverage rather than a broken rule. The fixtures also catch the opposite mistake, a new rule that is broader than it looks and shadows an existing one, and the failure names which rule stole the match. Local databases need no fixtures; the checks are skipped when there is no fixture file.

The Microsoft support corpus has a guarded import path. `Tools\Import-MsDocsEvent.ps1` reads a local `MicrosoftDocs/SupportArticles-docs` checkout, verifies its CC-BY-4.0 licence, discovers event-ID articles, and turns only reviewed, paraphrased prose into attributed rule objects. It refuses copied prose and never edits the database on discovery alone.

The [EvtxECmd Maps](https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps) are another guarded bootstrap
path. `Tools\Import-EvtxECmdMap.ps1 -MapsPath <checkout>\evtx\Maps` verifies the checkout's MIT licence and
emits attributed `experimental` drafts containing the channel, provider, event ID, and salient EventData fields.
Their title, explanation, why, action, and verdict are intentionally empty: the output is a human review queue,
not a publishable database and never edits `Data\verdicts.json`.

Sigma rules have the same guarded boundary. `Tools\Import-SigmaRule.ps1 -RulesPath <checkout> -LicensePolicy DRL-1.1`
reads a local Sigma YAML checkout, verifies a recognizable repository licence, maps only the common Windows logsource
and simple detection fields, and emits attributed `unsupported`/`draft` candidates. The queue retains Sigma IDs,
levels, tags, false positives, references, authors, conditions, mapping warnings, source hashes, and a `reviewStatus`
of `pending`; no imported rule can become active. Use `-ExistingPath` with `-DiffPath` to review added, changed, and
removed candidates between imports. The importer is offline and never edits `Data\verdicts.json`.

`Tools\Export-LogVerdictReviewArtifact.ps1` accepts the Sigma queue (or a local `rules` JSON file) through
`-CandidatePath`, so unknown findings, model candidates, and third-party candidates can be reviewed in one
redacted artifact. `Tools\Import-LogVerdictReviewArtifact.ps1` validates that contract and emits a diff only; it
does not promote accepted material automatically.

`match` accepts `source`, `channel`, `provider` (trailing `*` wildcard allowed), `eventId`, `messagePattern` (regex), and `eventData`. A structured condition looks like `{"all":[{"field":"EventData.Image","endswith":"\\\\powershell.exe"}]}`; unsupported Sigma modifiers remain inactive importer candidates. More match keys means higher specificity, and the most specific matching rule wins.

## Provider extensions

Local providers are explicit, versioned extension units for collectors that LogVerdict does not ship. A provider directory contains `manifest.json`, a relative PowerShell entrypoint, and optional hash-pinned fixtures. The manifest must declare schema version 1, a lowercase provider id, SemVer version, `read-only` permission, `collect`/`normalize`/`coverage`/`redaction` capabilities, and the SHA-256 of the entrypoint. Optional `reportProjection.fields` names the small set of redacted fields the provider may show in reports. Fixtures are validated by path and SHA-256 before execution.

Providers are never discovered or executed implicitly. Review the manifest and then opt in explicitly:

```powershell
$provider = Get-LogVerdictProvider -Path .\MyProvider
Test-LogVerdictProvider -Path .\MyProvider
Invoke-LogVerdictScan -ProviderPath .\MyProvider -AllowUntrustedProvider
```

The entrypoint receives a read-only context and must return one schema-versioned object with `records`, `coverage`, and optional `reportProjection`. Records are bounded by the scan's shared byte/record/time budget, normalized to the event contract, and redacted again at the host boundary. Their provider identity is prefixed as `extension:<id>`; they cannot provide curated `Verdict` or `RuleId` values, match the built-in Windows rules accidentally, or change the scan exit code. Invalid records are rejected and every provider contributes explicit coverage and untrusted provenance to JSON, text, HTML, and standard report data. Provider execution is live-only and cannot be combined with `-EvidencePath`.

## Requirements

Windows 10/11. Windows PowerShell 5.1 (stock) or PowerShell 7.x. **No dependencies** - the whole point is that it runs on a broken machine with nothing installed.

Runs without admin; elevation unlocks the Security channel and some text logs.

### Support matrix

| Area | Supported behavior | Recovery or verification |
|---|---|---|
| Windows | Windows 10 and Windows 11; event channels and diagnostic text logs are read locally | Start with `LogVerdict-GUI.exe` or `Invoke-LogVerdict.ps1 -DaysBack 30` |
| PowerShell | Windows PowerShell 5.1 (stock) and PowerShell 7.x; the GUI uses an STA thread for WPF | Run `Tools\Test-LogVerdictGui.ps1 -Theme Normal -ScalePercent 125` |
| Elevation | Optional; standard access reports unreadable Security/setup sources instead of calling the result clean | Use the GUI's **Restart as administrator** action, or rerun the console from an elevated PowerShell |
| SetupDiag | Optional; only an existing Microsoft-signed executable is used, otherwise built-in Panther rules remain active | Treat a rejected or missing candidate as a coverage gap, not an install failure |
| WEF | Optional, module-only health context; no fleet agent or remote connection is required | Use `Watch-LogVerdict -IncludeWEFHealth` when the Windows Event Collector service is in scope |
| Accessibility | Normal and Windows High Contrast themes are covered at 125% display scaling; navigation and reset controls expose UI Automation names | Run `Tools\Test-LogVerdictGui.ps1 -Theme HighContrast -ScalePercent 125` |
| GUI preferences | The Overview page's **Reset settings** button restores 30 days, focused defaults, a 1440x800 window, and clears transient source/report fields | If the GUI cannot open, remove `%LOCALAPPDATA%\LogVerdict\settings.json` and relaunch |
| Distribution | The module and unsigned packaged executables use the same engine and embedded data; no runtime package dependency is required | Run `Tools\Test-LogVerdictRelease.ps1` for offline version, catalog, manifest, and documentation checks |

Every scan probes each channel for readability before reading it, and reports what it could **not** see under "what this scan could not see": channels denied by ACL, channels whose metadata would not enumerate, channels truncated at the per-channel record cap, and requested channels that do not exist. This matters because `Get-WinEvent -FilterHashtable` reports a denied channel identically to an empty one - a scan that trusts that path would tell you a channel is clean when it was never allowed to open it.

Readable event channels also carry sequence coverage notes. A discontinuity in observed `RecordId` values or a
timestamp that runs backwards in record order is named with its channel and range. Retention, level filtering,
concurrent writers, and log clearing can all create a gap, so this is a coverage warning to inspect rather than a
claim that tampering occurred.

Unknown signatures also inspect the timestamps retained inside each signature. A compact cluster is labelled as a
burst with its onset and window in the console, text, HTML, JSON, and CSV outputs; the verdict remains `unknown`
because timing is evidence to triage, not proof of a cause. A regular trickle is left unlabelled.

Tests need the pinned [Pester](https://pester.dev/) 5.9.0 contract. Pester 6 is reported as an
advisory until the suite is migrated:

```powershell
Invoke-Pester -Path .\Tests
```

## Honest limitations

- **Coverage is the roadmap.** 180 rules ship, alongside a 3,157-entry typed Microsoft error and stop-code catalog. A first scan will still report `unknown` signatures - that is the tool refusing to guess, and each one is a candidate rule.
- **Crash-stack analysis is bounded.** LogVerdict reads the bug-check code and four parameters from supported kernel dump headers, but naming the responsible driver still needs a debugger and symbols. Unsupported, truncated or access-controlled dumps remain inventoried with the reason they were not decoded.
- **A clean result is not proof of health.** An in-place upgrade or a cleared log resets the event channels, so the report states each channel's oldest surviving record and warns when that horizon falls inside the requested window.
- Offline review is bounded by what the bundle captured. Exported event channels are re-read in full, while text logs and Reliability Monitor are re-evaluated from the signature summaries in the source report rather than copied wholesale.

## License

MIT
