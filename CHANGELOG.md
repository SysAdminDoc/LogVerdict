# Changelog

All notable changes to LogVerdict are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-08-01

### Added

- **Offline evidence analysis.** `Invoke-LogVerdictScan -EvidencePath` and the console entry point can re-evaluate a LogVerdict evidence zip, extracted bundle, or JSON report with the current rule database without querying the reviewing PC. Raw `.evtx` members are read when present; captured summaries preserve text-log and Reliability evidence. Safe extraction rejects traversal, duplicates, oversized members and zip bombs, while report-only or redacted bundles state their reduced coverage.
- **The curated database now contains 171 rules, up from 85.** New narrow rules cover 37 Windows failures observed on the development machine, all 30 documented Sysmon event types, and 19 Defender detection, remediation, health, configuration and tamper events. On the same 30-day live corpus this reduced unknown signatures from 43 of 76 (56.6%) to 6 of 76 (7.9%); the six left are product-specific providers and remain unknown rather than guessed.
- `Tools\Import-MsDocsEvent.ps1` turns a local `MicrosoftDocs/SupportArticles-docs` checkout into review candidates and imports only human-reviewed paraphrases. It re-verifies the checkout's CC-BY-4.0 licence on every run, rejects copied prose, and records Microsoft attribution, retrieval date and modification status on every imported rule.
- **`Export-LogVerdictReport -IncludeEvidence`** writes a zip beside the report holding the reports, the matching text-log lines and the scanned event channels as `.evtx` - the artifact to attach to a ticket. The report says what LogVerdict concluded; the bundle carries what it concluded it from, so somebody else can check the working.
- Combined with `-Redact` the channel exports are deliberately omitted. `.evtx` is a binary format carrying the same account names, hostnames and SIDs that redaction strips out of the text, and a bundle that claimed to be sanitized while shipping them would be worse than one that never claimed it. The manifest states the omission, so a reader months later cannot mistake a withheld channel for a clean one.
- The bundle carries the matching log lines rather than the log files. `CBS.log` alone routinely runs to hundreds of megabytes and almost none of it is evidence.
- **Signatures that happened together are now reported together.** An Application Error 1000 and a Service Control Manager 7031 thirty seconds apart are one incident described twice, not two findings - but sorted into a list by volume they land in different places and nothing connects them. Correlated findings render above the flat list in the console, text and HTML reports, with the concrete window of time to look at rather than the signature spans, and they count toward the exit code.
- Correlation rules live in a new `correlations` array in the verdict database and use the Sigma Correlation Rules Specification's vocabulary - `temporal`, `temporal_ordered`, `rules`, `timespan`, `group-by` - so anyone who can read a Sigma correlation can read one of these. Five ship.
- **The window slides rather than bucketing, which is where this departs from Sigma.** Sigma cuts time into fixed intervals: with a one-hour timespan a crash at 09:59 and the service death it caused at 10:01 fall in different buckets and never correlate, while two unrelated events at 09:01 and 09:56 do. Both behaviours are backwards for a single machine. Tests pin both directions.
- Correlation is deliberately curated and never inferred. Checked against this machine, the top discovered co-occurrences were all high-volume noise signatures pairing with everything - a constantly-firing signature is near everything by construction, so an inferred correlation is mostly an artefact of volume rather than a cause.

### Changed

- **The window is now a four-page diagnostics workspace.** Overview owns scan setup and the last-run summary; Findings combines filters, the signature table and full ruling detail; Coverage surfaces readable sources, evidence horizons, gaps, crash artifacts and correlations; Activity keeps the live pipeline and transcript visible. The scan and report engines are unchanged, so the console and GUI still cannot disagree about a verdict.
- The GUI now uses a purpose-built deep-navy observability palette, a persistent navigation rail, compact metric cards, a dark active caption and page-specific empty states. Keyboard focus, screen-reader names and the existing WCAG contrast checks remain part of the release gate.

### Fixed

- **Redaction missed any identifier sitting between underscores**, which included the one place the machine name most reliably appears: the report folder is named `LogVerdict_<MACHINE>_<timestamp>` and that path is all over the run transcript. The word-boundary lookaround treated `_` as a word character and refused to match there. Boundaries are now alphanumeric.
- The run transcript was written unredacted even under `-Redact`. It is built from log lines rather than from the result object, so redacting the result never touched it - and it names the machine on almost every line.
- The report writers crashed on a scan result that carried no `Correlations` property - an older result object, or one round-tripped through JSON. `@()` around a missing property yields a one-element array holding null, not an empty one.
- The roadmap's list of uncovered events named two events that do not exist as written. `Microsoft-Windows-WUDFRd/219` is really `Kernel-PnP/219`, covered since 0.2.0 - the "driver failed to load" message names WudfRd in its text, not in its provider. And `Perflib/108` is really Perflib **1008**. Both were corrected rather than covered, since a rule for a provider or id nothing logs is a rule that can never fire.

### Rules

- **Nine rules completing the community-verified list of high-traffic events**, closing the worklist begun in 0.6.0. `WHEA-Logger/19` (the processor's own corrected-error channel, escalating by rate), `TPM-WMI/1796` (a Secure Boot key update the firmware refused), `AppReadiness/214`, `Perflib/1008`, the `DeviceSetupManager/200/201/202` boot-order cluster, and two for `ESENT`. This brought the database to 85 rules before the later expansion to 171.
- ESENT is ruled as a family rather than per event id. Its events read as system database errors and are routinely mistaken for them; in fact each one belongs to whichever component the message names first. One rule covers the `-1032` access-denied file-operation family that `486` and `522` both report, and a provider-wide rule explains the rest without claiming a cause for an id nobody has documented. Together they cover 4 signatures here that previously reported as `unknown`.

## [0.6.0] - 2026-07-31

### Added

- **Every rule now carries a regression fixture.** `Data/fixtures.json` holds a minimal signature per rule, resolved through the real resolver by `Test-LogVerdictDatabase` and the test suite. A rule that quietly stops matching was previously invisible - it raises no error, it just produces an `unknown` signature that reads as a gap in coverage rather than as a broken rule. The fixtures also catch the inverse mistake, a newly added rule that is broader than it looks and shadows an existing one, and the failure names which rule stole the match rather than only reporting that the original missed.
- 47 of the fixtures were captured from a real machine; the rest are constructed from the rule's match keys, and each says which it is. Fixtures for rules with a rate threshold pin the escalated verdict, so an `escalate` block cannot silently stop firing.
- `Test-LogVerdictDatabase` gained `-FixturePath` and `-SkipFixture`. A missing fixture file is not an error - a site running a hand-written `verdicts.local.json` has none and must still be able to validate - but a rule in the shipped database without one is reported as a warning and fails the suite.
- **`Export-LogVerdictReport -Redact`** masks the account name, machine name, profile paths, SIDs and mail addresses out of the captured evidence before writing it. The JSON report previously embedded full log messages verbatim, which is the right thing locally and a liability the moment the report is attached to a ticket. Measured on a full scan of the authoring machine: 20 hostname, 234 account-name, 7 SID and 76 other-account profile-path occurrences, all reduced to zero. `Invoke-LogVerdict.ps1 -Redact` passes it through.
- Redaction copies before masking, so an operator who exports a redacted report for a ticket still holds the unmasked evidence for the machine in front of them. The reports state that redaction was applied - a masked report that does not say so reads as a complete one - and say plainly that identifiers Windows wrote in an unrecognizable form may remain.
- **Reliability Monitor is now a collection source.** It supplies two things no error-level channel sweep can: Microsoft's own curated view of what failed, and the software install, removal, reconfigure and update history - which are logged at Information level and therefore invisible to an error sweep. "What changed just before this started" is the first question in triage and the tool could not previously answer it. Six rules cover the sources it produces, including a catch-all, so the new source does not simply raise the unknown count.
- Records already collected from an event channel are dropped rather than counted twice. On the authoring machine 33 of 355 reliability records duplicated a channel record; counting both would have inflated the rate that rate escalation reads, so a signature could have crossed its threshold purely by being collected twice. A reliability signature is also keyed under its own prefix so it can never merge with the channel signature of the same provider and id.
- **The system stability index appears in the report header**, with the direction it moved over the window. Rate escalation answers "is this signature frequent"; this answers "is the machine getting worse", which a single scan otherwise cannot see. The authoring machine reads 5.33/10 and worsening, from 9.67.
- `-SkipReliability` turns the source off. Its absence is always reported as a source that was skipped, never as health: the provider is Group Policy gated and disabled by default on Windows Server, and silence from a source that was never read is not a clean result.
- **Five rules for high-traffic events**, each carrying its source: `disk/153` (an I/O retry, escalating by rate because the same event covers a dying drive and a merely busy one), `Service Control Manager/7011`, `VSS/8193`, `Windows Error Reporting/1001` and `DistributedCOM/10005`. Three of the five fire on the authoring machine, accounting for 19 records that previously reported as `unknown`. 76 rules ship.

### Changed

- **Verdict database schema is now v4.** The only addition is `reliability` as a `match.source`. It is a version bump rather than a silent extension because the database now describes a collection source an earlier build cannot read at all, and a rule that can never fire is worse than a database that refuses to load. Schema v1 to v3 databases continue to load unchanged.

## [0.5.0] - 2026-07-31

### Added

- **Verdict database schema v3: rules record where their ruling came from.** A `sources` list on each rule carries `uri`, and optionally `licence`, `author`, `retrieved` and `modified`. Attribution renders next to the finding in the console, text, HTML and JSON output, and in the window's detail pane - which is what makes deriving from a licensed corpus lawful, since CC-BY-4.0 requires attribution and an indication of changes and DRL-1.1 requires the author be shown wherever the rule matches.
- `Test-LogVerdictDatabase` now separates errors from warnings. A rule with no source is a warning: it does not make the database invalid, but `-IncludeWarnings` lists them and the summary line counts them. A `DRL-*` source with no author is an error, because the licence obliges us to display one.
- Schema v2 databases continue to load unchanged; a v4 database is still refused outright rather than partially read.

### Changed

- The window now shows crash evidence found on disk (minidumps and Windows Error Reporting archives). The console and HTML reports had always listed these; the window silently dropped them, so the same scan told you different things depending on how you ran it.
- The footer states when the verdict database was last updated, and warns when any finding was ruled on by guidance that has not been re-checked within the staleness ceiling. A curated ruling is only as good as the day it was verified, and that date was previously buried in the text report.

### Accessibility

- **The window was unusable with a screen reader.** Every findings row was announced as the underlying object graph - hex colour codes and the whole search haystack read aloud - because nothing supplied an accessible name. Rows now announce as a sentence: "ACTIONABLE. An update failed to install. Seen 12 time(s), 0.55 per day, last 2 days ago. Source Microsoft-Windows-WindowsUpdateClient 20."
- The look-back and filter boxes, the six verdict chips, the findings list, the evidence pane and the activity log all carry accessible names. The chips also state their count, so the summary is available without reading the sidebar.
- Verdict is now spoken as well as coloured, so the severity of a finding no longer depends on seeing it.
- **Muted text failed WCAG AA.** Two palette tones carried body text at 3.36:1 and 4.44:1 against the window background, below the 4.5:1 minimum. Text now uses a tone measuring 5.81:1 on the main surface, 6.22:1 on the sidebar and 6.64:1 on the log panel; the dimmer tones are kept for borders and dividers, where the 3:1 non-text threshold applies. Disabled controls keep the dim tone deliberately - they are exempt, and brightening them removed the cue that they were disabled.
- **Keyboard focus was invisible.** Replacing the stock control templates left only the framework's dotted adorner, which disappears on a dark surface. Buttons, verdict chips, checkboxes and text boxes now draw an accent focus ring. This is focus visibility, not a keyboard shortcut - the tool still has none.
- A test computes the contrast of every text colour against every surface it is painted on and fails below 4.5:1, so this cannot regress silently a third time.

### Fixed

- **The signature masker was destroying the diagnosis on CBS, DISM and Windows Update.** Error codes were masked away, so `0x800f081f` (no repair source), `0x80073712` (component store corrupt) and `0x800f0922` (system partition full) - three different problems with three different fixes - were reported as a single finding. Short error codes are now preserved inside the placeholder and normalized to lower case; long hex is still masked as an address.
- The same failure recurring across different updates produced one finding per update, because Windows package identity (`Package_for_KB...~token~arch~~version`) was left unmasked. It now collapses to `<PKG>`.
- Build numbers were reported as IP addresses: the address mask matched any four dotted integers. Octets are now range-checked, and dotted numbers that cannot be an address are masked as `<VER>`.

## [0.4.0] - 2026-07-31

### Added

- **A window.** `LogVerdict-GUI.exe` is the whole tool in one double-clickable file: it scans, ranks findings worst-first, and explains the selected one in plain English beside the raw evidence it was ruled on. Also available as `Show-LogVerdictGui` from the module and `LogVerdict-GUI.ps1` from a checkout.
- The window is a front end over `Invoke-LogVerdictScan`, not a second implementation of it, so the window and the console tool cannot disagree about a verdict.
- Verdict chips on the left double as filters, and a search box filters on title, provider, event id and message text at once. Column headers sort on a real key rather than on the displayed text, so "3 days ago" and "CRITICAL" order correctly instead of alphabetically.
- Coverage gaps are on screen next to the findings, not buried: denied channels, truncated logs, a horizon inside the requested window and a missing elevation all say so. The elevation banner offers to restart elevated rather than demanding it up front.
- The scan runs in a background runspace with progress streamed to an activity log panel, so the window stays responsive and a running scan can be cancelled. `Save report` writes the same text, JSON and HTML bundle the console tool produces, with a run log matching what the panel showed.
- `Tools\Build-LogVerdictExe.ps1` now builds both executables and takes `-Target Console|Gui|All`.

### Fixed

- `README.md` and `CHANGELOG.md` each contained a stray `0x0B` control byte where `Data\verdicts.json` was meant - a `\v` escape that had been interpreted rather than written literally.

### Notes

- The GUI is compiled `-noConsole -noOutput -noError`. `-noOutput` is not cosmetic: PS2EXE's `-noConsole` host renders every `Write-Host` as a modal dialog, and a scan logs constantly, so without it one run would fire a hundred message boxes.
- The default window is 760 units tall rather than 840. At the 125% scaling Windows picks for most 1080p displays, 840 becomes 1050 real pixels against a work area of about 1032, which pushed the status bar behind the taskbar.

## [0.3.1] - 2026-07-31

### Fixed

- **Double-clicking `LogVerdict.exe` looked like it never ran.** It did run - in about two seconds - but a console application loses its window the instant it exits, so the scan finished, wrote its reports to the Desktop, and vanished before any of it could be read. The executable now holds the window open with "Press Enter to close..." when it owns the console.
- The pause is deliberately conservative: it requires both that the parent process is Explorer and that output is not redirected, so a scheduled task, a script or a CI job can never be left waiting on a keypress. `-Pause` forces it on, `-NoPause` forces it off, and a regression test runs the entry script with redirected streams and fails on timeout.
- The report location is now printed as a labelled block at the end of the run rather than a single line, so it is readable at a glance before the window closes.

### Changed

- The build extracts the entry script's parameter block instead of carrying a hand-typed copy. The duplicate would have silently dropped `-Pause` from the compiled binary, which is the exact class of drift that produced this bug.

## [0.3.0] - 2026-07-31

### Added

- **`LogVerdict.exe` - a single, self-contained, unsigned console executable.** The verdict database is compiled in, so the one file is the whole product: copy it to a broken machine and run it. No install, no unpacking, no PowerShell module import, no dependencies.
- `Tools\Build-LogVerdictExe.ps1` flattens the module into one script and compiles it with PS2EXE, gating on pure-ASCII and a real PowerShell 5.1 parse before it will produce a binary.
- A `verdicts.local.json` placed beside the .exe is still merged and still wins ties, so a site can extend a compiled build without rebuilding it. A `Data\verdicts.json` beside the .exe overrides the compiled-in copy entirely.

### Fixed

- **Local rules did not reliably win ties against shipped rules**, despite the README promising they would. `Sort-Object` is not a stable sort in Windows PowerShell 5.1 and has no `-Stable` switch, so two rules of equal specificity resolved in arbitrary order. Rules now carry an explicit load ordinal used as the tie-break. Found while verifying the executable.

## [0.2.0] - 2026-07-31

### Fixed

- **Denied event channels are no longer reported as empty.** `Get-WinEvent -FilterHashtable` answers a permission denial with `NoMatchingEventsFound`, identical to a genuinely empty channel, so a scan that trusted it would report "nothing wrong" for channels it was never allowed to open. Every channel is now probed with `-LogName` first and classified `readable` / `denied` / `empty` / `missing`.
- **Channel classification no longer depends on the console language.** Control flow keyed on the English exception strings "No events were found" and "Access is denied", which are rendered from localized resources and therefore change on a non-English Windows. Classification now uses `FullyQualifiedErrorId`, which is locale-stable.
- `Get-WinEvent -ListLog` silently omits channels whose metadata it cannot read, which unelevated includes `Security`. Those omissions are now counted and reported, and the restricted channels are probed explicitly so they cannot vanish from a sweep.
- Event collection no longer truncates silently at the per-channel record cap; affected channels are named and flagged as lower bounds.
- `-Channel a,b,c` now works when the entry script is launched via `powershell.exe -File`, which hands the whole list over as a single string instead of binding it to the array parameter.
- Requested channels that do not exist on the machine are reported rather than silently skipped.
- The HTML report's small text (signature key, occurrence counts, date range, rule id, stat labels) failed WCAG AA contrast at 3.36-3.59:1 against a 4.5:1 requirement. Recoloured to 5.81:1 on the base surface and 6.22:1 on cards, with the measurements recorded in the stylesheet so a regression is visible in review.
- `Resolve-LVVerdict` no longer annotates the caller's signature objects in place, so resolving the same signatures against a second database no longer inherits the first pass's verdict.
- **Rules matching localized event text now declare the locale they assume.** Event `Message` strings are rendered from the provider's localized MUI resources, so an English `messagePattern` silently stops matching on a German or Japanese install. Such a rule is now skipped when the machine language differs, letting the signature fall through to `unknown` rather than quietly failing to fire, and the validator flags any localized-message rule that declares no locale. Text-log rules are exempt: CBS, DISM and SetupAPI are written in invariant English by the component that produces them.
- **Text-log lines carry their real timestamps.** Every line used to inherit the file's `LastWriteTime`, collapsing each log into a single instant: first/last seen were meaningless, the rate was wrong, rate escalation could never fire on a text rule, and `-DaysBack` filtered on the file rather than on the lines inside it, so a file touched today contributed lines from months ago. CBS, DISM, Panther and NetSetup lines are parsed from their own timestamps; SetupAPI error lines, which carry none, inherit the most recent `Section start` header above them. Timestamps parse under InvariantCulture because these formats are fixed by the writing component, not by the machine locale.
- Lines with no parseable timestamp are marked undated and rendered as `undated` rather than being given a fabricated time, and a single undated line no longer drags a whole signature's first-seen date to null.
- **Every channel that failed to read emitted one phantom record.** `continue` inside a `switch` continues the switch, not the enclosing loop, so an erroring channel fell through and produced a record with a null provider and id. On this machine that was a `/0` signature covering 81 records. Found by the new collector tests.
- The internal array-returning helper had an inconsistent contract - nothing for an empty result, a wrapped array otherwise - so `@(f).Count` answered 0 for empty and 1 for fifty records. It now streams uniformly.
- **Reports are written without a UTF-8 BOM.** `Set-Content -Encoding UTF8` emits one under Windows PowerShell 5.1 but not under PS 7, so the defect was invisible when testing on pwsh alone. The BOM made the JSON report - the tool's machine-readable contract - unreadable to strict parsers such as Python's `json.load`.

### Added

- **`Data/verdicts.schema.json`** - a JSON Schema for the rule format, so editors validate and autocomplete rules as they are written. A test keeps its verdict and status vocabularies in step with the code, so a rule cannot pass in an editor and be rejected at scan time.
- **CONTRIBUTING.md** - how to find an unrecognized signature, write a rule for it, and validate it, plus the project conventions that are easy to trip over (PS 5.1 compatibility, pure ASCII, the diagnostics stream, verifying under 5.1 rather than only pwsh 7).
- Collector test coverage: text-log parsing against fixture files, and mocked `Get-WinEvent` failures covering empty, denied, truncated and metadata-less channels. This layer previously had no tests and held every defect found in the last review.
- **29 new rules, taking the verdict database from 36 to 65.** Written against the signatures a real Windows 11 machine actually produces, and grounded in each event's own message text rather than recall. Covers Hyper-V/WSL virtual switch noise, the Store app state database, AppX deployment and packaging, CloudStore settings sync, WMI query failures, PowerShell script block logging, DPAPI decryption failures, Code Integrity blocks, exploit mitigations, BITS transfers, known-folder permissions, storage diagnostics and telemetry connectivity.
- Measured on the development machine, an `-AllChannels` scan went from 88.2% of signatures unrecognized to 62.7%; by record volume, unrecognized events fell to 3.1%, so 96.9% of what a reader actually sees is now explained.
- **Verdict database schema v2**, aligned with the Sigma specification's rule metadata model. Every rule now carries `status` (`stable` / `test` / `experimental` / `deprecated` / `unsupported`), a `verified` date, a `references` list replacing the single `reference`, and a `falsepositives` list naming the conditions under which the ruling is wrong. 24 of the 36 shipped rules document their false positives.
- Deprecated and unsupported rules stay in the database for traceability but are never applied to a signature. Schema v1 databases with no `status` continue to work, and their singular `reference` still surfaces through the v2 list.
- `Test-LogVerdictDatabase` enforces the status vocabulary and fails any rule whose `verified` date is more than 24 months old, because guidance ages across Windows releases.
- Loading a database whose `schemaVersion` this build does not understand now fails loudly instead of silently ruling on fields the code never read.
- Reports show each rule's verification date and its known false positives, so a reader can tell when a ruling does not apply to them.
- Per-channel progress during probing and reading, so an `-AllChannels` sweep (128 channels, ~38s) no longer sits silent long enough to look hung. Suppressed for small scans.
- Scan results carry `ChannelStatus`, `DeniedChannels`, `TruncatedChannels`, `MetadataUnreadableCount` and `CoverageNotes`.
- All three report writers render a "what this scan could not see" section, so findings always travel with the coverage behind them.

## [0.1.0] - 2026-07-31

Initial release. The deterministic core: collect, reduce, resolve, report. No language model involved.

### Added

- **Collection** from the System and Application event channels, any other populated channel via `-AllChannels`, and the plain-text logs Windows keeps outside Event Viewer (`CBS.log`, `dism.log`, `setupapi.dev.log`, `NetSetup.LOG`, `Panther\setupact.log`, `MoSetup\BlueBox.log`). Text logs are streamed, so a multi-hundred-megabyte `CBS.log` never lands in memory.
- **Reduction** to signatures: event records key on `Provider + EventID`; text-log lines key on a masked template with GUIDs, paths, IPs, hex, timestamps and numbers replaced. Measured 26:1 on a stock Windows 11 machine.
- **Verdict database** (`Data/verdicts.json`), 36 curated rules across DCOM, WHEA, storage, NTFS, services, application crashes, Kernel-Power, Windows Update, Group Policy, Kerberos, domain and servicing failures. Site-specific rules can be added in `Data/verdicts.local.json`, which is merged automatically and wins ties.
- **Rate-based escalation** so a rule can rule one way at a trickle and another at volume - corrected hardware errors being the canonical case.
- **Honest unknowns**: a signature matching no rule is reported as `unknown` with its raw evidence and no guessed cause.
- **Coverage warning** when a channel's oldest surviving record falls inside the requested window, so a clean result after an in-place upgrade or a cleared log is not mistaken for a healthy machine.
- **Crash artifact inventory** for kernel minidumps and WER report archives (located, not decoded).
- **Reports**: console, plain text, JSON, and a self-contained dark HTML page with no external requests.
- **Exit codes** 0-4 by worst verdict, for use in scripts and remediation pipelines.
- Pester 5 suite covering template masking, reduction, rule specificity, escalation, unknown handling and report rendering.

[0.7.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.7.0
[0.6.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.6.0
[0.5.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.5.0
[0.4.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.4.0
[0.3.1]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.3.1
[0.3.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.3.0
[0.2.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.2.0
[0.1.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.1.0
