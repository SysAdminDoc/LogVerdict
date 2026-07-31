# Changelog

All notable changes to LogVerdict are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.2.0
[0.1.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.1.0
