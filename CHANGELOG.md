# Changelog

All notable changes to LogVerdict are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Denied event channels are no longer reported as empty.** `Get-WinEvent -FilterHashtable` answers a permission denial with `NoMatchingEventsFound`, identical to a genuinely empty channel, so a scan that trusted it would report "nothing wrong" for channels it was never allowed to open. Every channel is now probed with `-LogName` first and classified `readable` / `denied` / `empty` / `missing`.
- **Channel classification no longer depends on the console language.** Control flow keyed on the English exception strings "No events were found" and "Access is denied", which are rendered from localized resources and therefore change on a non-English Windows. Classification now uses `FullyQualifiedErrorId`, which is locale-stable.
- `Get-WinEvent -ListLog` silently omits channels whose metadata it cannot read, which unelevated includes `Security`. Those omissions are now counted and reported, and the restricted channels are probed explicitly so they cannot vanish from a sweep.
- Event collection no longer truncates silently at the per-channel record cap; affected channels are named and flagged as lower bounds.
- `-Channel a,b,c` now works when the entry script is launched via `powershell.exe -File`, which hands the whole list over as a single string instead of binding it to the array parameter.
- Requested channels that do not exist on the machine are reported rather than silently skipped.
- **Reports are written without a UTF-8 BOM.** `Set-Content -Encoding UTF8` emits one under Windows PowerShell 5.1 but not under PS 7, so the defect was invisible when testing on pwsh alone. The BOM made the JSON report - the tool's machine-readable contract - unreadable to strict parsers such as Python's `json.load`.

### Added

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

[0.1.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.1.0
