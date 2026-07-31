#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'LogVerdict.psd1'
    Import-Module $script:ModulePath -Force
}

Describe 'Module surface' {
    It 'exports exactly the documented public functions' {
        $exported = (Get-Module LogVerdict).ExportedFunctions.Keys | Sort-Object
        $exported | Should -Be @(
            'Export-LogVerdictReport',
            'Get-LogVerdictDatabase',
            'Invoke-LogVerdictScan',
            'Show-LogVerdictReport',
            'Test-LogVerdictDatabase'
        )
    }
}

Describe 'Verdict database' {
    It 'ships valid' {
        Test-LogVerdictDatabase -Quiet | Should -BeTrue
    }

    It 'reports no structural problems' {
        @(Test-LogVerdictDatabase).Count | Should -Be 0
    }

    It 'has unique rule ids' {
        $ids = (Get-LogVerdictDatabase).rules.id
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
    }

    It 'rejects a rule using an invalid verdict' {
        $bad = Join-Path $TestDrive 'bad.json'
        @'
{ "schemaVersion": 1, "name": "bad", "updated": "2026-07-31", "rules": [
  { "id": "X-1", "match": { "source": "event" }, "verdict": "catastrophic",
    "title": "t", "plain": "p", "why": "w", "action": "a", "confidence": "high" } ] }
'@ | Set-Content -LiteralPath $bad -Encoding UTF8
        Test-LogVerdictDatabase -Path $bad -Quiet | Should -BeFalse
    }
}

Describe 'Channel access classification' {
    # Declared in the Describe body, not BeforeAll: Pester expands -ForEach during
    # discovery, which runs before any BeforeAll block executes.
    # Real FullyQualifiedErrorId values observed from Get-WinEvent on Windows 11.
    # The Message beside each is localized; the FQEID is not, which is the whole
    # reason classification keys on the id.
    $fqidCases = @(
        @{ Fqid = 'System.UnauthorizedAccessException,Microsoft.PowerShell.Commands.GetWinEventCommand'; Expected = 'denied' }
        @{ Fqid = 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand';              Expected = 'empty' }
        @{ Fqid = 'NoMatchingLogsFound,Microsoft.PowerShell.Commands.GetWinEventCommand';                Expected = 'missing' }
        @{ Fqid = 'LogInfoUnavailable,Microsoft.PowerShell.Commands.GetWinEventCommand';                 Expected = 'denied' }
        @{ Fqid = 'SomethingElse,Microsoft.PowerShell.Commands.GetWinEventCommand';                      Expected = 'other' }
    )

    It 'classifies <Fqid> as <Expected>' -ForEach $fqidCases {
        InModuleScope LogVerdict -Parameters @{ fqid = $Fqid; expected = $Expected } {
            param($fqid, $expected)
            $err = [pscustomobject]@{ FullyQualifiedErrorId = $fqid }
            Get-LVErrorKind -ErrorRecord $err | Should -Be $expected
        }
    }

    It 'never branches on localized exception text' {
        # A German or Japanese Windows renders these strings from localized resources,
        # so any comparison against Message silently changes behaviour by locale.
        # Tokenized rather than regexed over the raw file so the prose in this file's
        # own comments explaining the trap does not trip the check.
        $path = Join-Path (Split-Path $PSScriptRoot -Parent) 'Private/10-LVCollectEvents.ps1'
        $parseErrors = $null
        $tokens = [System.Management.Automation.PSParser]::Tokenize((Get-Content $path -Raw), [ref]$parseErrors)
        @($parseErrors).Count | Should -Be 0

        $literals = @($tokens | Where-Object { $_.Type -eq 'String' } | ForEach-Object { $_.Content })
        foreach ($needle in @('No events were found', 'Access is denied', 'unauthorized operation')) {
            @($literals | Where-Object { $_ -like "*$needle*" }).Count |
                Should -Be 0 -Because "'$needle' is localized and must not appear in a string literal used for control flow"
        }
    }

    It 'reports a denied channel as denied rather than as empty' {
        InModuleScope LogVerdict {
            # Security is ACL-restricted; unelevated this must classify as denied.
            # Elevated it is readable. Either answer is correct - what must never
            # happen is it being reported as empty, which is what the
            # -FilterHashtable path would claim.
            $status = Get-LVChannelStatus -Channel @('Security')
            $status['Security'].Access | Should -BeIn @('readable', 'denied')
        }
    }

    It 'classifies a nonexistent channel as missing' {
        InModuleScope LogVerdict {
            $status = Get-LVChannelStatus -Channel @('LogVerdict-No-Such-Channel')
            $status['LogVerdict-No-Such-Channel'].Access | Should -Be 'missing'
        }
    }

    It 'always probes the restricted channels so they cannot vanish from a sweep' {
        InModuleScope LogVerdict {
            # Get-WinEvent -ListLog omits channels it cannot stat, so unelevated
            # Security disappears entirely. It must be unioned back in.
            Get-LVPopulatedChannel | Should -Contain 'Security'
        }
    }
}

Describe 'Template masking' {
    It 'masks the variable parts so repeats collapse' {
        InModuleScope LogVerdict {
            $a = ConvertTo-LVTemplate -Text 'Failed to open C:\Users\alice\thing.dat after 42 tries (0x80070005)'
            $b = ConvertTo-LVTemplate -Text 'Failed to open C:\Users\bob\other.dat after 7 tries (0x8007000E)'
            $a | Should -Be $b
        }
    }

    It 'masks GUIDs' {
        InModuleScope LogVerdict {
            $t = ConvertTo-LVTemplate -Text 'CLSID {D63B10C5-BB46-4990-A94F-E40B9D520160} denied'
            $t | Should -Be 'CLSID <GUID> denied'
        }
    }

    It 'keeps genuinely different messages apart' {
        InModuleScope LogVerdict {
            $a = ConvertTo-LVTemplate -Text 'Disk 3 was surprise removed'
            $b = ConvertTo-LVTemplate -Text 'Service Foo entered the stopped state'
            $a | Should -Not -Be $b
        }
    }
}

Describe 'Signature reduction' {
    BeforeAll {
        $script:MakeEvent = {
            param($provider, $id, $when, $message)
            [pscustomobject]@{
                Source = 'event'; Channel = 'System'; Provider = $provider; Id = $id
                Level = 2; LevelName = 'Error'; TimeCreated = $when
                MachineName = 'TESTPC'; RecordId = 1; Message = $message
            }
        }
    }

    It 'collapses repeats of one provider and event id into a single signature' {
        InModuleScope LogVerdict {
            $now = Get-Date
            $records = 1..50 | ForEach-Object {
                [pscustomobject]@{
                    Source = 'event'; Channel = 'System'; Provider = 'Microsoft-Windows-DistributedCOM'
                    Id = 10016; Level = 3; LevelName = 'Warning'
                    TimeCreated = $now.AddHours(-1 * $_); MachineName = 'TESTPC'; RecordId = $_
                    Message = "attempt $_"
                }
            }
            $sigs = Group-LVSignature -Record $records -WindowDays 30
            @($sigs).Count | Should -Be 1
            $sigs[0].Count | Should -Be 50
            $sigs[0].Key | Should -Be 'Microsoft-Windows-DistributedCOM/10016'
        }
    }

    It 'groups text-log lines that differ only in their variable parts' {
        InModuleScope LogVerdict {
            $now = Get-Date
            $records = 1..10 | ForEach-Object {
                [pscustomobject]@{
                    Source = 'textlog'; Channel = 'CBS'; Provider = 'CBS'; Id = 0
                    Level = 2; LevelName = 'Error'; TimeCreated = $now; MachineName = 'TESTPC'
                    RecordId = $_; Message = "Failed to stage package $_ with error 0x8007000$_"
                }
            }
            $sigs = Group-LVSignature -Record $records -WindowDays 30
            @($sigs).Count | Should -Be 1
            $sigs[0].Count | Should -Be 10
        }
    }

    It 'rates a single occurrence across the window, not as one per day' {
        InModuleScope LogVerdict {
            $records = @([pscustomobject]@{
                Source = 'event'; Channel = 'System'; Provider = 'Volsnap'; Id = 35
                Level = 2; LevelName = 'Error'; TimeCreated = (Get-Date)
                MachineName = 'TESTPC'; RecordId = 1; Message = 'one off'
            })
            $sigs = Group-LVSignature -Record $records -WindowDays 30
            # A lone event in a 30-day window is 0.03/day. Reporting 1/day would
            # read as a daily recurrence and inflate every singleton in the report.
            $sigs[0].PerDay | Should -BeLessThan 0.1
        }
    }

    It 'reports the reduction ratio' {
        InModuleScope LogVerdict {
            $now = Get-Date
            $records = @()
            $records += 1..90 | ForEach-Object {
                [pscustomobject]@{ Source='event'; Channel='System'; Provider='A'; Id=1; Level=2
                    LevelName='Error'; TimeCreated=$now; MachineName='T'; RecordId=$_; Message='x' }
            }
            $records += 1..10 | ForEach-Object {
                [pscustomobject]@{ Source='event'; Channel='System'; Provider='B'; Id=2; Level=2
                    LevelName='Error'; TimeCreated=$now; MachineName='T'; RecordId=$_; Message='y' }
            }
            $sigs = Group-LVSignature -Record $records -WindowDays 30
            $stat = Get-LVReductionStat -Record $records -Signature $sigs
            $stat.RecordCount | Should -Be 100
            $stat.SignatureCount | Should -Be 2
            $stat.Ratio | Should -Be 50
            $stat.LoudestShare | Should -Be 90
        }
    }
}

Describe 'Verdict resolution' {
    BeforeAll {
        $script:TestDb = [pscustomobject]@{
            schemaVersion = 1
            rules = @(
                [pscustomobject]@{
                    id = 'T-BROAD'
                    match = [pscustomobject]@{ source = 'event'; provider = 'Acme' }
                    verdict = 'informational'; title = 'broad'; plain = 'p'; why = 'w'
                    action = 'a'; confidence = 'high'
                },
                [pscustomobject]@{
                    id = 'T-NARROW'
                    match = [pscustomobject]@{ source = 'event'; provider = 'Acme'; eventId = 99 }
                    verdict = 'critical'; title = 'narrow'; plain = 'p'; why = 'w'
                    action = 'a'; confidence = 'high'
                },
                [pscustomobject]@{
                    id = 'T-RATE'
                    match = [pscustomobject]@{ source = 'event'; provider = 'Rate'; eventId = 1 }
                    verdict = 'investigate'; title = 'rate'; plain = 'p'; why = 'w'
                    action = 'a'; confidence = 'high'
                    escalate = [pscustomobject]@{ perDay = 10; verdict = 'actionable'; why = 'too often' }
                }
            )
        }
    }

    It 'prefers the more specific rule over a provider-wide catch-all' {
        InModuleScope LogVerdict -Parameters @{ db = $script:TestDb } {
            param($db)
            $sig = [pscustomobject]@{
                Key='Acme/99'; Source='event'; Channel='System'; Provider='Acme'; Id=99
                Count=1; PerDay=0.1; SampleMessage='m'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            $out = Resolve-LVVerdict -Signature @($sig) -Database $db
            $out[0].RuleId | Should -Be 'T-NARROW'
            $out[0].Verdict | Should -Be 'critical'
        }
    }

    It 'falls back to the catch-all when the specific rule does not apply' {
        InModuleScope LogVerdict -Parameters @{ db = $script:TestDb } {
            param($db)
            $sig = [pscustomobject]@{
                Key='Acme/1'; Source='event'; Channel='System'; Provider='Acme'; Id=1
                Count=1; PerDay=0.1; SampleMessage='m'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            $out = Resolve-LVVerdict -Signature @($sig) -Database $db
            $out[0].RuleId | Should -Be 'T-BROAD'
        }
    }

    It 'never guesses at an unmatched signature' {
        InModuleScope LogVerdict -Parameters @{ db = $script:TestDb } {
            param($db)
            $sig = [pscustomobject]@{
                Key='Nobody/7'; Source='event'; Channel='System'; Provider='Nobody'; Id=7
                Count=1; PerDay=0.1; SampleMessage='raw evidence here'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            $out = Resolve-LVVerdict -Signature @($sig) -Database $db
            $out[0].Verdict | Should -Be 'unknown'
            $out[0].RuleId | Should -BeNullOrEmpty
            $out[0].Confidence | Should -Be 'none'
        }
    }

    It 'escalates a signature that crosses its rate threshold' {
        InModuleScope LogVerdict -Parameters @{ db = $script:TestDb } {
            param($db)
            $quiet = [pscustomobject]@{
                Key='Rate/1'; Source='event'; Channel='System'; Provider='Rate'; Id=1
                Count=5; PerDay=1; SampleMessage='m'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            $loud = [pscustomobject]@{
                Key='Rate/1'; Source='event'; Channel='System'; Provider='Rate'; Id=1
                Count=500; PerDay=40; SampleMessage='m'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            (Resolve-LVVerdict -Signature @($quiet) -Database $db)[0].Verdict | Should -Be 'investigate'
            (Resolve-LVVerdict -Signature @($loud)  -Database $db)[0].Verdict | Should -Be 'actionable'
        }
    }

    It 'sorts an unknown above merely informational findings' {
        InModuleScope LogVerdict {
            (Get-LVVerdictRank -Verdict 'unknown') | Should -BeGreaterThan (Get-LVVerdictRank -Verdict 'informational')
            (Get-LVVerdictRank -Verdict 'critical') | Should -BeGreaterThan (Get-LVVerdictRank -Verdict 'actionable')
        }
    }
}

Describe 'Report rendering' {
    BeforeAll {
        $script:FakeResult = [pscustomobject]@{
            Tool = 'LogVerdict'; Version = '0.1.0'; MachineName = 'TESTPC'
            ScanTime = (Get-Date '2026-07-31 12:00:00'); Duration = [timespan]::FromSeconds(3)
            DaysBack = 30; Elevated = $false; Channels = @('System', 'Application')
            Reduction = [pscustomobject]@{
                RecordCount = 1855; SignatureCount = 71; Ratio = 26.1
                LoudestKey = 'A/1'; LoudestShare = 54.8
            }
            Findings = @([pscustomobject]@{
                Key = 'Acme/99'; Source = 'event'; Channel = 'System'; Provider = 'Acme'; Id = 99
                Count = 12; PerDay = 0.4; FirstSeen = (Get-Date '2026-07-01'); LastSeen = (Get-Date '2026-07-30')
                Verdict = 'actionable'; Title = 'Something broke'; Plain = 'plain text'
                Why = 'why text'; Action = 'do this'; RuleId = 'T-1'; Confidence = 'high'
                Reference = $null; SampleMessage = 'raw <script>alert(1)</script> & "quoted"'
            })
            CrashArtifacts = @(); Horizon = @{ 'System' = (Get-Date '2026-01-01') }
            HorizonWarning = $null; DatabaseName = 'test db'; DatabaseDate = '2026-07-31'
            RuleCount = 3; WorstVerdict = 'actionable'; ExitCode = 2
        }
    }

    It 'renders every multi-placeholder line in the text report' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            # Regression guard. Inside a METHOD call's parentheses a comma separates
            # arguments, so $sb.AppendLine('{0} {1}' -f $a, $b) silently starves the
            # format operator of its second argument and throws at render time.
            $text = ConvertTo-LVTextReport -Result $r
            $text | Should -Match 'Signatures    : 71 \(reduction 26\.1:1\)'
            $text | Should -Match 'Occurrences : 12 \(0\.4/day\)'
            $text | Should -Match 'Rule        : T-1 \(confidence: high\)'
        }
    }

    It 'escapes HTML so a log line cannot inject markup into the report' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $html = ConvertTo-LVHtmlReport -Result $r
            $html | Should -Match '&lt;script&gt;'
            $html | Should -Not -Match '<script>alert'
        }
    }

    It 'produces a self-contained page with no external requests' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $html = ConvertTo-LVHtmlReport -Result $r
            $html | Should -Not -Match '<link[^>]+href="http'
            $html | Should -Not -Match '<script[^>]+src='
        }
    }
}
