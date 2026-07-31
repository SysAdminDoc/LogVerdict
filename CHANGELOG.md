# Changelog

All notable changes to LogVerdict are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
