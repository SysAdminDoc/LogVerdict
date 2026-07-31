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
     "falsepositives": ["Expected during agent upgrade, when it re-reads config."]
   }
   ```

4. Validate:

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
