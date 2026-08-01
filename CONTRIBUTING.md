# Contributing to LogVerdict

The rules are the product. Code changes are welcome, but a good rule is worth more than a good refactor here — coverage is what makes the tool useful, and it is the part that cannot be automated.

## The one principle

**Never guess.** A signature with no rule is reported as `unknown` with its raw evidence, and that is a perfectly good outcome. A confidently wrong explanation is worse than no explanation, because an admin who follows one bad remediation never trusts the tool again.

If you are not sure what an event means, do not write the rule. Or write it with `"status": "test"` and `"confidence": "medium"` and say plainly in `why` what you are unsure about.

## Adding a rule

1. Find something the tool does not recognize:

   ```powershell
   Import-Module .\LogVerdict.psd1
   $r = Invoke-LogVerdictScan -DaysBack 30 -AllChannels
   $r.Findings | Where-Object Verdict -eq 'unknown' | Sort-Object Count -Descending |
       Select-Object -First 20 Key, Count, SampleMessage
   ```

2. Read the actual event. `SampleMessage` is your primary source — most Windows events describe themselves, and translating that description into plain English is exactly the job. Reach for vendor documentation when the message is not self-explanatory, and put the URL in `references`.

3. Add the rule to `Data/verdicts.json`, or to `Data/verdicts.local.json` if it is specific to your environment. Local rules are gitignored, merged automatically, and win ties against shipped rules.

   ```json
   {
     "id": "LV-0200",
     "status": "test",
     "verified": "2026-07-31",
     "match": { "source": "event", "provider": "Contoso-Agent", "eventId": 4242 },
     "verdict": "investigate",
     "title": "The Contoso agent lost its configuration",
     "plain": "What actually happened, for someone who does not already know.",
     "why": "Why it does or does not matter. Judgement belongs here.",
     "action": "The concrete next step.",
     "confidence": "medium",
     "references": ["https://example.invalid/docs/4242"],
     "sources": [
       { "uri": "https://example.invalid/docs/4242", "retrieved": "2026-07-31" }
     ],
     "falsepositives": ["Expected during agent upgrade, when it re-reads config."]
   }
   ```

4. Add a regression fixture for it in `Data/fixtures.json`. Every shipped rule has one and the test suite fails if any rule does not:

   ```json
   {
     "ruleId": "LV-0200",
     "origin": "observed",
     "expect": "investigate",
     "signature": {
       "Source": "event",
       "Channel": "Application",
       "Provider": "Contoso-Agent",
       "Id": 4242,
       "SampleMessage": "The agent could not read its configuration file."
     }
   }
   ```

   The fixture is resolved through the real resolver and must come back as *your* rule with *your* verdict. This is what catches a later rule silently shadowing yours, and it is why the check cannot be skipped.

   - `origin` is `observed` if you captured the signature from a real machine, `constructed` if you built it from the match keys. Do not blur the two.
   - `expect` is the verdict the rule should produce. Add `"perDay"` above an `escalate.perDay` threshold to pin the escalated verdict instead.
   - **Redact before you commit.** A captured message carries the hostname, account name, SIDs and profile paths of the machine it came from. A test asserts none of those survive, but it only knows about the patterns it was taught, so read your own fixture before pushing it. If a message reproduces something private - PowerShell script block logging reproduces the source of whatever ran - replace it with a `constructed` one instead.

5. Validate:

   ```powershell
   Test-LogVerdictDatabase        # must report 0 problems
   Invoke-Pester -Path .\Tests    # must be green
   ```

`Data/verdicts.schema.json` describes the full format. Point your editor at it for completion and inline validation.

## Writing the four fields well

| Field | Ask yourself |
|---|---|
| `title` | Would a helpdesk tech understand this without the event ID? |
| `plain` | Does this explain what *happened*, not what the event is *called*? |
| `why` | Does this help someone decide whether to care? |
| `action` | Can someone actually do this? `Ignore.` is a complete answer and often the right one. |

Every rule should carry at least one `sources` entry or a `references` URL. The
validator reports an unsourced rule as a warning rather than an error, so it will not
block a build, but a ruling nobody can check is an assertion and this tool asks people to
act on it.

Use `sources` when the terms matter and `references` for plain further reading. A source
entry is `{ uri, licence, author, retrieved, modified }`; only `uri` is required. Fill
`licence` **only** when you derived the wording from a licensed corpus, and then say so:
CC-BY-4.0 requires attribution and that changes be indicated, so set `modified: true` when
you adapted the prose. A `DRL-*` licence additionally requires the original `author`, and
the validator rejects a DRL source without one because the licence obliges us to display it
on every match. Do not copy prose from a source whose terms you have not checked - most
event-ID encyclopaedias are proprietary.

Always fill `falsepositives` when the ruling is "ignore this". That field is what stops the tool from talking someone out of investigating a real problem.

Prefer `Provider + eventId` matching. It is locale-independent. `messagePattern` against event text is **not** — Windows renders event messages from localized resources, so an English pattern will not match on a German install. If you must use one, set `locale`. Text-log rules (CBS, DISM, SetupAPI) are exempt: those files are invariant English.

## Verdict levels

`benign` documented as harmless, suppressed by default · `informational` real but not a problem · `investigate` a lead worth following · `actionable` do something · `critical` hardware or data integrity at risk.

Be conservative. Most of what fills Event Viewer is genuinely `benign`, and correctly saying so is the tool's main job.

## Code changes

- Windows PowerShell **5.1** and PowerShell 7 both have to work. No `??`, no ternary, no `-AsHashtable`.
- **Pure ASCII** in `.ps1`, `.psm1` and `.psd1` files. PS 5.1 reads BOM-less UTF-8 as CP1252, and an em dash terminates a string mid-line with a parse error pointing somewhere innocent.
- A function's output stream is its return value. Diagnostics go through `Write-LVLog`, never `Write-Output`.
- Zero runtime dependencies. The tool has to run on a broken machine with nothing installed.

Before pushing:

```powershell
Invoke-Pester -Path .\Tests
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1   # expect 0
powershell -NoProfile -File .\Invoke-LogVerdict.ps1 -DaysBack 7 -NoReport          # exercise it for real
```

Verify under **Windows PowerShell 5.1**, not only pwsh 7. Several defects in this project's history were invisible under 7 — the UTF-8 BOM on report output being the clearest.

## Licence

MIT, same as the project. By contributing you agree your work ships under it.
