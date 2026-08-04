# Changelog

All notable changes to LogVerdict are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.2] - 2026-08-02

- Redacted the prompt-specific finding copy sent to the local model when `-Redact` is combined with unknown-signature explanations, while retaining the raw finding for local report/export handling.
- Bounded evidence ZIP expansion by bytes actually copied, with separate per-member and total caps that reject understated archive headers before unbounded disk growth.
- Raised JSON report serialization to the safe projection depth and added a round-trip regression for structured EventData/UserData values.
- Accepted sign-extended Int32 Windows error codes, including HRESULT-wrapped Win32 lookup fallback, with regression coverage in both composite fields.
- Scoped OCSF export to a classless normalized-evidence envelope so diagnostic and benign records no longer claim the security-oriented Detection Finding class; verdicts, advisories, and correlations remain under the explicit `unmapped.logverdict` vendor extension.
- Added a dependency-free SARIF 2.1.0 export with active rule descriptors, verdict levels, signature partial fingerprints, event logical locations, and CBS/DISM line regions for GitHub code scanning and SARIF viewers.
- Re-sourced the 3,157-entry Windows error catalog from licence-verified CC-BY-4.0 MicrosoftDocs checkouts instead of Learn HTML, with per-entry repository paths, source revisions, file hashes, attribution, and an offline-only importer.
- Distinguished disabled event channels and unavailable Reliability Monitor sources (`policy-disabled` and `provider-absent`) from genuinely empty telemetry in coverage reports and the GUI Coverage page.
- Read Windows Setup's persisted SetupDiag XML and registry results before attempting the optional executable, preserving each profile GUID and provenance while marking coverage as `artifact-read` versus `executed`.
- Bound the ESENT access-denied, KMS-unreachable, and .NET missing-runtime rulings to structured EventData values instead of localized or over-broad event text, with validator-enforced positive and near-miss fixtures; completed source metadata for every active shipped rule.
- Declared Desktop/Core module compatibility, a complete FileList, PSEdition tags, and release notes; the Core quality gate now fails below PowerShell 7.6 LTS and the advisory coverage records the same floor.
- Routed GUI finding copies through the deterministic redaction helper, made the existing redaction toggle cover both saved reports and clipboard payloads, and made the status line identify redacted versus unredacted copies.
- Normalized report, JSONL, standard-export, CSV, case, evidence, and review timestamps to invariant RFC3339 UTC strings; durations now use ISO-8601 values instead of runtime-specific PowerShell objects. The offline release gate now validates generated report/evidence/case/review/provider documents against their shipped schemas and proves malformed variants are rejected.
- Added one shared scan-result resolver so JSON reports reloaded with `ConvertFrom-Json` restore `ScanTime` and `Duration` for case profiles, handoffs, comparisons, console/report presentation, and all standard export formats.
- Fixed RecordId sequence coverage so level-filtered scans validate candidate gaps against an unfiltered event range and do not report skipped Information events as missing records.
- Added one shared `http`/`https` URI allow-list for verdict database validation, HTML links, GUI references, and external navigation; unsafe `javascript:`, `file:`, UNC, and `ms-settings:` values are rejected or rendered as inert text.
- Fixed optional finding and correlation provenance arrays so missing `references`, `sources`, and `falsepositives` serialize as empty collections instead of `[null]`.
- Refreshed the offline PowerShell advisory cache with CVE-2026-26143 and CVE-2025-25004 coverage, added normalized cache-source integrity validation, and documented the explicit NVD-backed atomic refresh command. Release-gate tests now prove that an aged cache fails before a fresh run is trusted.
- Added an explicit, versioned provider extension contract with hash-pinned entrypoints and fixtures, mandatory redaction, shared collection budgets, provider coverage, report projections, and an `-AllowUntrustedProvider` execution gate.
- Added bounded JSONL timeline exports for standard and case handoffs, with UTC timestamps, event/finding/correlation/coverage/provider records, source record IDs, rule provenance, and explicit raw/redacted state.
- Added versioned GUI/report localization resources with de-DE and ja-JP coverage, deterministic English fallback, packaged-resource embedding, and locale-aware text, HTML, and CSV presentation labels.
- Extended content-free performance budgets with per-fixture parser-time ceilings, so EVTX parser regressions fail independently of end-to-end timing.
- Cut reduction overhead by reusing compiled template matchers, a module-scoped SHA-256 provider, hash-set error-context buckets, and the populated all-channel metadata during probes; the aggregate performance gate now includes a 2,359-record reduction budget on both supported runtimes.
- Added `LogVerdict-Ticket-Summary.md` and the Findings-page **Copy summary for ticket** action. Both share one bounded Markdown projection with worst verdict, suppression count, actionable findings, coverage caveats, version metadata, and the redaction toggle.
- Made GUI cancellation first-class: the Overview exposes a visible Cancel action, elapsed time updates while a scan runs, realistic look-back-specific timing guidance replaces the old vague promise, and cancelled runs report partial coverage without saving a misleading report.
- Closed CI quality gaps by running PSScriptAnalyzer on both PowerShell legs, pinning GitHub Actions to verified commits, directly verifying supply-chain metadata in the package job, and checking PowerShell script status without stale native exit codes.
- Fixed advisory-enabled GUI renders so dependency labels cannot shadow the mutable window state; the findings filter and count now refresh normally when advisory context is present.
- Added direct fixture coverage for the public console/advisory adapters, standard export contracts, evidence contracts, and review-artifact diff semantics.
- Replaced the standard-export dispatch table with a versioned data-only template registry; custom single-document and line-oriented projections now work without module code changes, with atomic writes and guarded append mode.
- Added UTC rule freshness policy and optional Windows build ranges, surfaced stale active rulings in reports and GUI Coverage, and made redacted unknown review artifacts carry a `status: test` contribution scaffold with mandatory `sources[].retrieved` metadata.
- Reworked correlation matching to keep sliding-window pointers and merge intervals without repeatedly copying the active occurrence slice; the 4,000-occurrence regression stays within its budget.
- Persisted every visible GUI Overview source and report choice, including diagnostic channels, named channels, alternate paths, Reliability Monitor, masking, and evidence; reset now clears the complete saved option set.

- Added a user-visible GUI settings reset that atomically restores safe scan defaults,
  resets the window size and transient source/report fields, and reports persistence failures;
  documented the Windows/runtime/elevation/optional-tool support matrix and recovery command.
- Replaced volatile README scan totals with stable product language and regenerated the GUI
  screenshot from the packaged WPF visual tree; release validation now checks the screenshot
  hash, version metadata, current rule/catalog examples, and runtime GUI version binding.
- Restored Windows PowerShell 5.1 compatibility for manifest validation and test hashing by
  using `Test-ModuleManifest` and a runtime-neutral SHA-256 helper.
- Added shared byte, normalized-record, and elapsed-time collection budgets across live and
  offline collectors, with partial findings retained and explicit `truncated`/`timeout`
  coverage for every source stopped by a limit.
- Extended deterministic redaction to generated credentials, bearer/JWT/cloud/GitHub tokens,
  IP and MAC addresses, and token-bearing URLs, with adversarial checks across text, JSON,
  CSV, HTML, evidence manifests, and privacy-audit output.
- Added versioned `LogVerdict.Report` and `LogVerdict.Evidence` JSON contracts and schemas with
  explicit redaction/raw state, live/offline mode, compatibility metadata, source coverage,
  included-file hashes, legacy migration markers, and future-schema rejection in report export.
- Added schema v6 structured EventData/UserData matching with bounded `all`/`any`/`not`
  conditions and locale-safe value modifiers; Sigma imports now map supported fields into
  inactive review candidates and warn on unsupported modifiers.
- Added a versioned redacted review artifact that deduplicates unknown findings and inactive
  candidates, carries stable IDs, provenance, false-positive fields and fixture scaffolds,
  and imports reviewed changes as a diff without mutating the curated database.
- Added packaged GUI launch smoke coverage for real UI Automation navigation, placement,
  error/empty/cancelled states, normal/high-contrast themes, and uploaded coverage evidence.
- Added per-asset SPDX 2.3 SBOMs and unsigned, offline-verifiable build provenance with
  source-tree, pinned-module, runtime, and artifact hashes; CI now validates and uploads
  the supply-chain records beside packaged GUI evidence.
- Added advisory-cache schema v2 freshness policy and supported-runtime coverage for
  PowerShell 5.1/7.x plus pinned Pester, PSScriptAnalyzer, and ps2exe versions. Stale or
  unavailable advisory context is explicit and cannot change event findings or exit codes;
  release gates reject stale cache metadata.
- Added content-free performance budgets for small, large, malformed-text, and malformed-EVTX
  fixtures. CI runs the aggregate-only benchmark on Windows PowerShell 5.1 and PowerShell 7.x
  and uploads timing reports without retaining fixture content.
- Added structured Findings filters for source, channel, provider, event ID, correlation,
  and rule status, with UI Automation names and empty-state guidance. Lightweight row
  projections retain only filter/sort metadata and resolve detail from the single stored
  finding graph; count, rate, and latest columns remain sortable by their raw values.

## [0.8.1] - 2026-08-02

- Bound all scan entry points to a 1-3650 day look-back window, and made named channels
  take precedence over broad channel switches while rejecting contradictory broad modes.
- Added fail-closed trust validation for active rule and correlation provenance, correlation
  references, supported fields, timespans, and implemented correlation types at database load.
- Expanded the error catalog to typed NTSTATUS, facility-aware HRESULT, Setup, and Windows
  Update families with canonical fields, provenance hashes, indexed lookup, and fail-closed
  family/ID validation.
- Added a committed `VERSION` source, offline release-integrity checks, pinned CI dependency
  versions, PowerShell 5.1/7 parsing and test jobs, and package hash validation.
- Constrained discovered SetupDiag execution to valid Microsoft Authenticode signatures;
  rejected candidates now remain an explicit coverage gap and the Panther fallback stays active.
- Offline analysis now accepts a direct EVTX file or directory with bounded file/byte/event
  limits, streaming source hashes, parser timing, malformed-file status, and a per-source
  evidence manifest.
- Added normalized per-source coverage to live and offline results and to JSON, HTML, CSV,
  and evidence-manifest output, distinguishing empty sources from missing, denied, unreadable,
  and truncated sources while retaining caps, windows, parser errors, record gaps, timing, and
  source metadata through redaction.
- Added advisory configuration-health profiles for provider manifests and EventID versions,
  channel retention and clock context, PowerShell logging, advanced audit policy, Defender,
  Sysmon filtering, and WEF subscription state. Health context is available in JSON, text,
  HTML, CSV, GUI coverage, and bundle manifests and is never promoted to a malicious verdict.
- Added opt-in, bounded local scan history with median-rate trend signals. Reports state the
  baseline, comparison window, thresholds, missing-history state, and false-positive caveat;
  history is advisory only and can never escalate a curated verdict or exit code.
- Added a hash-checked offline dependency/tool advisory cache with PowerShell range matching,
  CVSS/KEV/date/source metadata, explicit local/URL update and rollback commands, and a
  separate advisory report/export class that never changes event findings or exit codes.
- Added canonical case profiles with bounded source choices, redaction policy, analyst notes,
  source hashes, KAPE/Velociraptor collection recipes, and deterministic attributed Timesketch
  and Hayabusa handoff timelines; profiles remain metadata and never become verdicts.
- Preserved Windows Setup/Update composite result and extended codes, phase, operation, provider
  locale, and fallback text through localized matching, reduction, reports, GUI details, and
  standard exports; added German and Japanese non-English fixtures.
- Virtualized and recycled GUI findings lists and resolved selected detail by index so large
  captures do not retain a second full finding object graph for every row.
- Added an STA GUI smoke runner covering UI Automation names, keyboard targets, normal and
  high-contrast resources, long/error text, and 125% layout bounds without changing display
  or accessibility settings.
- Added opt-in, content-free performance telemetry for live and offline scans. Reports and
  standard exports carry source status, bounded counts, caps, elapsed timing, and slow-source
  markers without messages, paths, identifiers, or signature data.
- Added the versioned `Export-LogVerdictStandard` command with ECS, OCSF, OpenTelemetry Logs,
  and STIX 2.1 JSON adapters. All projections preserve normalized findings, source/provider/
  event fields, confidence, references, timestamps, coverage, health context, and explicit
  raw-versus-redacted state; round-trip fixtures cover each mapping.
- Added `Tools\Import-SigmaRule.ps1`, a local-only, licence-aware Sigma compatibility importer
  that emits attributed inactive review candidates, bounded field mappings, retained Sigma
  metadata, and stable-ID added/changed/removed diffs without modifying the curated database.
- Added the opt-in `Watch-LogVerdict` module command for bounded local event tails with atomic
  per-channel bookmark resume, reconnect/drop/latency coverage, clean stop limits, and optional
  advisory WEF `wecutil` configuration/runtime intake.
- Added committed cross-version and locale fixtures, explicit malformed-EVTX/elevation/theme
  coverage records, and Windows PowerShell 5.1/PowerShell 7 STA CI runs with uploaded reports.
- Added deterministic staged-artifact privacy audits for evidence bundles, hashed-only findings,
  substitution counts, redacted-bundle blocking, and an explicit `-AllowRawEvidence` forensic
  override for bundles that intentionally retain raw event channels.

## [0.8.0] - 2026-08-01

### Added

- Unknown signatures now expose compact occurrence bursts with an onset and duration across the console, text, HTML, JSON, and CSV reports; a regular trickle remains unlabelled and the verdict stays `unknown`.


## [0.7.0] - 2026-08-01

### Added

- **Opt-in verdict database updates.** `Update-LogVerdictDatabase` fetches a published GitHub release only when invoked, verifies its SHA-256 digest, validates before installation, and retains a rollback copy.
- **Documentation now states the executable's MS-LPL combined-work boundary and expected script extractability, and narrows the competitive claim around the offline multi-source rule engine.**
- Added `-Format Csv` report output with one stable scalar row per finding for pipelines, grid views, and ticket imports; the richer reports retain correlations and nested evidence.
- Added a licence-checked `Tools\Import-EvtxECmdMap.ps1` bootstrap that emits attributed, inactive drafts with salient fields but no machine-generated rulings.
- Event coverage now reports observed RecordId discontinuities and backwards timestamps by channel, while explicitly avoiding a tampering verdict.
- **Bundled Microsoft error knowledge.** The application now carries 2,745 WinError.h statuses, 378 kernel bug-check codes, and 13 common HRESULTs with official names, descriptions, explanations, and links. Unknown signatures are enriched locally while remaining unknown until provider-specific evidence supports a reviewed rule; `Tools\Import-MicrosoftErrorCatalog.ps1` refreshes the catalog from current Microsoft Learn tables.
- **Existing SetupDiag installations now deepen Panther analysis.** LogVerdict discovers an already-present Microsoft SetupDiag, runs it offline with `/NoTel` against the newest Panther log set, and merges its structured profile, failure details, and remediation as an attributed finding. Execution is bounded and temporary; no tool is downloaded, `/AddReg` is never used, and absence, stale logs, success, required elevation, launch failure, timeout, or invalid output all fall back explicitly to the built-in Panther collector.
- Reproducible Scoop and winget manifests for the immutable v0.7.0 release. `Tools\New-PackageManifests.ps1` downloads an existing release, hashes both unsigned executables, emits a Scoop package with the console shim and GUI shortcut, and emits an x64 winget portable package for the console tool. Offline asset mode keeps generation directly testable without network access.

- **The window now reaches every deterministic live-scan and report option.** It can scan the focused tier or named event channels, skip Reliability Monitor, load an alternate complete rule database, choose a report folder, redact written output, and include an evidence zip. All-channels and focused-channel choices are mutually exclusive, while a non-empty named list deliberately overrides both. Offline evidence review, local-model rule drafting, and output-format selection remain console-only and are documented as such.
- **The window remembers its last scan setup and size.** Look-back, all-channel mode, setup-log inclusion, harmless-finding visibility, width, and height are atomically stored under `%LOCALAPPDATA%\LogVerdict`. Missing, malformed, future-version, invalid, or unreadable settings are ignored; an explicit `-DaysBack` still wins over the saved value.
- **The self-contained HTML report is filterable offline.** Verdict toggles and a text search narrow the finding cards without any network request or external asset. Progressive enhancement keeps every finding visible and explains the limitation when scripting is disabled, while a live result count and keyboard-labelled controls keep the interaction accessible.
- **HTML reports now print as light documents.** The print stylesheet removes the dark page background and interactive controls, expands clipped evidence, and keeps finding, warning, and summary cards together across page boundaries for browser-to-PDF and paper handoffs.
- **A focused diagnostic-channel tier.** `-DiagnosticChannels` keeps System and Application, then adds the populated NTFS, Code Integrity, Kernel PnP configuration, AppModel Runtime, Resource Exhaustion, and Kernel Boot channels. Each added channel has a narrow curated rule. On the development machine's 30-day warning/error corpus the tier added 62 records across five signatures, all five ruled and none unknown.
- **Text-log reduction now promotes low-cardinality slots instead of relying on error-code exceptions.** A typed first pass masks the full variable vocabulary, including SID, IPv6, MAC, URL, FQDN, UPN, package identity and explicit version values. A corpus-wide second pass restores `NUM`, `HEX`, and `VER` values only when a template-family slot has at most three distinct values; volatile and identifying slots always stay masked. Token count participates in text-signature hashes, and console, text, JSON, HTML, and GUI activity output expose the signature count and reduction ratio before and after promotion.
- **Optional local-model drafts for unknown signatures.** `Invoke-LogVerdictScan` and the console entry point accept `-ExplainUnknown` to send only reduced, unruled signatures to an Ollama endpoint restricted to HTTP loopback. Structured responses are validated, remediation language is rejected, known verdicts are untouched, and accepted text renders in a separate `MODEL-GENERATED CANDIDATE - NOT A CURATED RULING` block rather than as rule prose.
- **Safe promotion closes the local-model loop.** `-PromoteToRule` implies the model opt-in and atomically writes accepted candidates to `verdicts.local.json` with a stable hashed id, `confidence: draft`, and `status: unsupported`. Draft confidence is independently ineligible during resolution, so changing either gate alone cannot activate model text; repeated promotion updates a draft but refuses to overwrite a reviewed rule.
- **`Compare-LogVerdictScan` answers whether a fix worked.** Give it before/after scan objects or JSON reports and it emits flat `new`, `resolved`, and `worsening` signature records. Worsening means a more severe verdict or, at the same verdict, a per-day rate increase of at least 25% and 0.10/day; unchanged and improving signatures stay out of the way.
- **Crash artifacts now contribute deterministic findings.** `Report.wer` is parsed by its named problem-signature fields and grouped by application plus faulting module. Supported `PAGEDU64` and `PAGEDUMP` kernel headers yield the bug-check code and four parameters with a bounded 96-byte read; malformed, truncated and access-controlled artifacts stay visible as inventory rather than being guessed at. Full stack/driver analysis still requires a debugger and symbols.
- **Offline evidence analysis.** `Invoke-LogVerdictScan -EvidencePath` and the console entry point can re-evaluate a LogVerdict evidence zip, extracted bundle, or JSON report with the current rule database without querying the reviewing PC. Raw `.evtx` members are read when present; captured summaries preserve text-log and Reliability evidence. Safe extraction rejects traversal, duplicates, oversized members and zip bombs, while report-only or redacted bundles state their reduced coverage.
- **The curated database now contains 179 rules, up from 85.** New narrow rules cover 43 Windows failures observed or defined by first-party provider metadata on the development machine, all 30 documented Sysmon event types, 19 Defender detection, remediation, health, configuration and tamper events, and the two decoded crash-artifact sources. The original default-source measurement reduced unknown signatures from 43 of 76 (56.6%) to 6 of 76 (7.9%); the focused tier is measured separately because it deliberately reads more sources.
- `Tools\Import-MsDocsEvent.ps1` turns a local `MicrosoftDocs/SupportArticles-docs` checkout into review candidates and imports only human-reviewed paraphrases. It re-verifies the checkout's CC-BY-4.0 licence on every run, rejects copied prose, and records Microsoft attribution, retrieval date and modification status on every imported rule.
- **`Export-LogVerdictReport -IncludeEvidence`** writes a zip beside the report holding the reports, the matching text-log lines and the scanned event channels as `.evtx` - the artifact to attach to a ticket. The report says what LogVerdict concluded; the bundle carries what it concluded it from, so somebody else can check the working.
- Combined with `-Redact` the channel exports are deliberately omitted. `.evtx` is a binary format carrying the same account names, hostnames and SIDs that redaction strips out of the text, and a bundle that claimed to be sanitized while shipping them would be worse than one that never claimed it. The manifest states the omission, so a reader months later cannot mistake a withheld channel for a clean one.
- The bundle carries the matching log lines rather than the log files. `CBS.log` alone routinely runs to hundreds of megabytes and almost none of it is evidence.
- **Signatures that happened together are now reported together.** An Application Error 1000 and a Service Control Manager 7031 thirty seconds apart are one incident described twice, not two findings - but sorted into a list by volume they land in different places and nothing connects them. Correlated findings render above the flat list in the console, text and HTML reports, with the concrete window of time to look at rather than the signature spans, and they count toward the exit code.
- Correlation rules live in a new `correlations` array in the verdict database and use the Sigma Correlation Rules Specification's vocabulary - `temporal`, `temporal_ordered`, `rules`, `timespan`, `group-by` - so anyone who can read a Sigma correlation can read one of these. Five ship.
- **The window slides rather than bucketing, which is where this departs from Sigma.** Sigma cuts time into fixed intervals: with a one-hour timespan a crash at 09:59 and the service death it caused at 10:01 fall in different buckets and never correlate, while two unrelated events at 09:01 and 09:56 do. Both behaviours are backwards for a single machine. Tests pin both directions.
- Correlation is deliberately curated and never inferred. Checked against this machine, the top discovered co-occurrences were all high-volume noise signatures pairing with everything - a constantly-firing signature is near everything by construction, so an inferred correlation is mostly an artefact of volume rather than a cause.

### Changed

- **The window's presentation decisions are now directly testable.** Literal finding filtering, six-way verdict counting, and detail-pane projection moved from nested WPF event closures into pure private functions. Direct tests cover disabled verdicts, case-insensitive literal searches (including wildcard characters), unexpected verdict values, event/text metadata, sample fallback, reference de-duplication, and source attribution.
- **The window is now a four-page diagnostics workspace.** Overview owns scan setup and the last-run summary; Findings combines filters, the signature table and full ruling detail; Coverage surfaces readable sources, evidence horizons, gaps, crash artifacts and correlations; Activity keeps the live pipeline and transcript visible. The scan and report engines are unchanged, so the console and GUI still cannot disagree about a verdict.
- The GUI now uses a purpose-built deep-navy observability palette, a persistent navigation rail, compact metric cards, a dark active caption and page-specific empty states. Keyboard focus, screen-reader names and the existing WCAG contrast checks remain part of the release gate.
- **The window now follows Windows High Contrast mode.** Semantic colours are dynamic resources that switch to the user's `SystemColors` palette at runtime, data-bound verdict pills use the system highlight colours, and WPF's framework focus visual replaces the custom dark-theme ring. Switching High Contrast off restores the original resource objects without restarting the app.

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
[0.8.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.8.0
[0.8.2]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.8.2
[0.8.1]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.8.1
[0.6.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.6.0
[0.5.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.5.0
[0.4.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.4.0
[0.3.1]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.3.1
[0.3.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.3.0
[0.2.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.2.0
[0.1.0]: https://github.com/SysAdminDoc/LogVerdict/releases/tag/v0.1.0
