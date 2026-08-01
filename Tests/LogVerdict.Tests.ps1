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
            'Show-LogVerdictGui',
            'Show-LogVerdictReport',
            'Test-LogVerdictDatabase'
        )
    }

    It 'declares the same functions in the manifest as the module exports' {
        # These two lists are edited by hand in separate files. A function present in
        # one and not the other imports fine from a checkout and disappears from an
        # installed module, which is the sort of gap that only shows up on someone
        # else's machine.
        $root = Split-Path $PSScriptRoot -Parent
        $manifest = Import-PowerShellDataFile -Path (Join-Path $root 'LogVerdict.psd1')
        $exported = (Get-Module LogVerdict).ExportedFunctions.Keys | Sort-Object
        ($manifest.FunctionsToExport | Sort-Object) | Should -Be $exported
    }
}

Describe 'Entry script launch behaviour' {
    It 'never blocks for input when output is redirected' {
        # The interactive pause exists so a double-clicked .exe does not vanish before
        # its output can be read. Getting the condition wrong in the other direction is
        # far worse: a scheduled task or CI job would hang forever on a keypress that
        # never comes. This runs the real entry script with redirected streams and
        # fails on timeout rather than waiting.
        $entry = Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-LogVerdict.ps1'
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $stdout = Join-Path $TestDrive 'entry-out.txt'

        $proc = Start-Process -FilePath $psExe `
            -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $entry, '-DaysBack', '1', '-NoReport') `
            -PassThru -RedirectStandardOutput $stdout -NoNewWindow

        $exited = $proc.WaitForExit(120000)
        if (-not $exited) { $proc.Kill() }
        $exited | Should -BeTrue -Because 'a redirected run must never wait for a keypress'

        (Get-Content -LiteralPath $stdout -Raw) | Should -Not -Match 'Press Enter to close'
    }

    It 'exposes the pause switches on the entry script' {
        $entry = Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-LogVerdict.ps1'
        $text = Get-Content -LiteralPath $entry -Raw
        $text | Should -Match '\[switch\]\$Pause'
        $text | Should -Match '\[switch\]\$NoPause'
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

    It 'ships every rule with a status and a verification date' {
        foreach ($rule in (Get-LogVerdictDatabase).rules) {
            $rule.status | Should -Not -BeNullOrEmpty -Because "rule $($rule.id) must declare its lifecycle"
            $rule.verified | Should -Match '^\d{4}-\d{2}-\d{2}$' -Because "rule $($rule.id) must record when its guidance was last checked"
        }
    }

    It 'refuses a schema version this build does not understand' {
        $future = Join-Path $TestDrive 'future.json'
        '{ "schemaVersion": 99, "name": "future", "updated": "2026-07-31", "rules": [] }' |
            Set-Content -LiteralPath $future -Encoding UTF8
        { Get-LogVerdictDatabase -Path $future } | Should -Throw -ExpectedMessage '*schemaVersion 99*'
    }

    It 'refuses a database that declares no schema version' {
        $noVer = Join-Path $TestDrive 'nover.json'
        '{ "name": "old", "updated": "2026-07-31", "rules": [] }' |
            Set-Content -LiteralPath $noVer -Encoding UTF8
        { Get-LogVerdictDatabase -Path $noVer } | Should -Throw -ExpectedMessage '*no schemaVersion*'
    }

    It 'flags a rule whose verification has gone stale' {
        $stale = Join-Path $TestDrive 'stale.json'
        @'
{ "schemaVersion": 2, "name": "stale", "updated": "2026-07-31", "rules": [
  { "id": "S-1", "status": "stable", "verified": "2019-01-01",
    "match": { "source": "event" }, "verdict": "benign",
    "title": "t", "plain": "p", "why": "w", "action": "a", "confidence": "high" } ] }
'@ | Set-Content -LiteralPath $stale -Encoding UTF8
        $problems = Test-LogVerdictDatabase -Path $stale
        @($problems | Where-Object { $_.Problem -like '*older than*' }).Count | Should -Be 1
    }

    It 'rejects a rule using an unknown status' {
        $bad = Join-Path $TestDrive 'badstatus.json'
        @'
{ "schemaVersion": 2, "name": "bad", "updated": "2026-07-31", "rules": [
  { "id": "B-1", "status": "kinda-fine", "verified": "2026-07-31",
    "match": { "source": "event" }, "verdict": "benign",
    "title": "t", "plain": "p", "why": "w", "action": "a", "confidence": "high" } ] }
'@ | Set-Content -LiteralPath $bad -Encoding UTF8
        Test-LogVerdictDatabase -Path $bad -Quiet | Should -BeFalse
    }

    It 'keeps the published JSON Schema in step with the code' {
        # Contributors validate against the schema in their editor; the module validates
        # against $script:LVVerdictRank and $script:LVRuleStatus at runtime. If those
        # drift apart, a rule passes in the editor and is rejected at scan time.
        $schemaPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Data/verdicts.schema.json'
        Test-Path -LiteralPath $schemaPath | Should -BeTrue
        $schema = Get-Content -LiteralPath $schemaPath -Raw | ConvertFrom-Json

        $schemaVerdicts = @($schema.definitions.rule.properties.verdict.enum) | Sort-Object
        $schemaStatuses = @($schema.definitions.rule.properties.status.enum) | Sort-Object

        InModuleScope LogVerdict -Parameters @{ sv = $schemaVerdicts; ss = $schemaStatuses } {
            param($sv, $ss)
            ($sv -join ',') | Should -Be ((@($script:LVVerdictRank.Keys) | Sort-Object) -join ',')
            ($ss -join ',') | Should -Be ((@($script:LVRuleStatus) | Sort-Object) -join ',')
        }

        # Bound to the module's own ceiling rather than a literal, so the two cannot
        # drift apart the next time the schema gains a version.
        InModuleScope LogVerdict -Parameters @{ maxVer = $schema.properties.schemaVersion.maximum } {
            param($maxVer)
            $maxVer | Should -Be $script:LVSchemaVersionMax
        }
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
            $b = ConvertTo-LVTemplate -Text 'Failed to open C:\Users\bob\other.dat after 7 tries (0x80070005)'
            $a | Should -Be $b
        }
    }

    It 'never merges two different error codes' {
        # This test previously asserted the opposite. On CBS and DISM the HRESULT is
        # the diagnosis, so collapsing 0x800f081f (no source) with 0x80073712 (store
        # corrupt) reported two unrelated problems, with two unrelated fixes, as one
        # finding.
        InModuleScope LogVerdict {
            $codes = @('0x800f081f', '0x80073712', '0x800f0922')
            $templates = $codes | ForEach-Object {
                ConvertTo-LVTemplate -Text ('2026-07-31 10:00:00, Error CSI 00000123 Failed to stage package. Status = {0}' -f $_)
            }
            (@($templates | Sort-Object -Unique)).Count | Should -Be 3
        }
    }

    It 'normalizes error code casing so it is one signature, not two' {
        InModuleScope LogVerdict {
            $upper = ConvertTo-LVTemplate -Text 'Operation failed 0x800F081F'
            $lower = ConvertTo-LVTemplate -Text 'Operation failed 0x800f081f'
            $upper | Should -Be $lower
            $upper | Should -Match '<HEX:800f081f>'
        }
    }

    It 'keeps an all-digit error code intact instead of re-masking it' {
        # The preserved value sits between non-word characters, so a code with no
        # letters is exposed to the number mask unless the order is right.
        InModuleScope LogVerdict {
            ConvertTo-LVTemplate -Text 'Failed 0x12345678' | Should -BeExactly 'Failed <HEX:12345678>'
        }
    }

    It 'masks a long hex value as an address rather than preserving it' {
        InModuleScope LogVerdict {
            ConvertTo-LVTemplate -Text 'Faulting offset 0x00007ff8abcd1234' | Should -BeExactly 'Faulting offset <ADDR>'
        }
    }

    It 'collapses the same servicing failure across different updates' {
        # Package identity carries the KB, the arch and the version. Left unmasked, one
        # recurring failure became one finding per update installed.
        InModuleScope LogVerdict {
            $a = ConvertTo-LVTemplate -Text 'Package_for_KB5034441~31bf3856ad364e35~amd64~~10.0.1.3 failed'
            $b = ConvertTo-LVTemplate -Text 'Package_for_KB5055523~31bf3856ad364e35~amd64~~10.0.1.7 failed'
            $a | Should -Be $b
            $a | Should -BeExactly '<PKG> failed'
        }
    }

    It 'does not report a build number as an IP address' {
        InModuleScope LogVerdict {
            $t = ConvertTo-LVTemplate -Text 'Servicing stack 10.0.26100.1234 loaded'
            $t | Should -Match '<VER>'
            $t | Should -Not -Match '<IP>'
        }
    }

    It 'still recognises a real IPv4 address' {
        InModuleScope LogVerdict {
            ConvertTo-LVTemplate -Text 'Could not reach 192.168.1.20' | Should -BeExactly 'Could not reach <IP>'
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
                    # The error code is held constant on purpose. It is no longer a
                    # variable part: ten different codes are ten different problems.
                    RecordId = $_; Message = "Failed to stage package $_ from C:\pkg\p$_.cab with error 0x8007000e"
                }
            }
            $sigs = Group-LVSignature -Record $records -WindowDays 30
            @($sigs).Count | Should -Be 1
            $sigs[0].Count | Should -Be 10
        }
    }

    It 'splits a text-log signature when only the error code differs' {
        InModuleScope LogVerdict {
            $now = Get-Date
            $records = @('0x800f081f', '0x80073712') | ForEach-Object {
                [pscustomobject]@{
                    Source = 'textlog'; Channel = 'CBS'; Provider = 'CBS'; Id = 0
                    Level = 2; LevelName = 'Error'; TimeCreated = $now; MachineName = 'TESTPC'
                    RecordId = 1; Message = "Failed to stage package with error $_"
                }
            }
            @(Group-LVSignature -Record $records -WindowDays 30).Count | Should -Be 2
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

Describe 'Text-log timestamps' {
    # Real line shapes taken from C:\Windows\Logs\CBS\CBS.log, dism.log and
    # setupapi.dev.log on Windows 11.
    $timeCases = @(
        @{ Line = '2026-07-31 00:31:52, Error  CSI  00000123 Failed to stage'; Pattern = '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'; Format = 'yyyy-MM-dd HH:mm:ss'; Year = 2026; Hour = 0 }
        @{ Line = '2026-07-09 01:51:30, Info   DISM   API: PID=3';             Pattern = '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'; Format = 'yyyy-MM-dd HH:mm:ss'; Year = 2026; Hour = 1 }
        @{ Line = '>>>  Section start 2026/06/09 17:27:28.488';                Pattern = 'Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'; Format = 'yyyy/MM/dd HH:mm:ss'; Year = 2026; Hour = 17 }
        @{ Line = '07/31/2026 10:15:00:123 NetpDoDomainJoin: status 0x0';      Pattern = '^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})'; Format = 'MM/dd/yyyy HH:mm:ss'; Year = 2026; Hour = 10 }
    )

    It 'parses <Line>' -ForEach $timeCases {
        InModuleScope LogVerdict -Parameters @{ line = $Line; pattern = $Pattern; fmt = $Format; year = $Year; hour = $Hour } {
            param($line, $pattern, $fmt, $year, $hour)
            $t = ConvertFrom-LVLogTimestamp -Line $line -TimePattern $pattern -TimeFormat $fmt
            $t | Should -Not -BeNullOrEmpty
            $t.Year | Should -Be $year
            $t.Hour | Should -Be $hour
        }
    }

    It 'returns null rather than guessing when a line carries no timestamp' {
        InModuleScope LogVerdict {
            $t = ConvertFrom-LVLogTimestamp -Line '!!!  inf: Failed to open registry key' `
                    -TimePattern '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})' -TimeFormat 'yyyy-MM-dd HH:mm:ss'
            $t | Should -BeNullOrEmpty
        }
    }

    It 'parses with InvariantCulture so a non-English locale still reads the log' {
        InModuleScope LogVerdict {
            # These formats are fixed by the writing component, not by the machine
            # locale. Parsing under the current culture would fail on exactly the
            # machines that are hardest to troubleshoot.
            $original = [System.Threading.Thread]::CurrentThread.CurrentCulture
            try {
                [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::new('de-DE')
                $t = ConvertFrom-LVLogTimestamp -Line '2026-07-31 00:31:52, Error  CSI' `
                        -TimePattern '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})' -TimeFormat 'yyyy-MM-dd HH:mm:ss'
                $t.Year | Should -Be 2026
                $t.Month | Should -Be 7
            } finally {
                [System.Threading.Thread]::CurrentThread.CurrentCulture = $original
            }
        }
    }

    It 'does not let one undated record destroy the span of a whole signature' {
        InModuleScope LogVerdict {
            # $null compares as less than any date in PowerShell, so an unguarded
            # min/max drags FirstSeen to null and silently zeroes SpanDays.
            $base = Get-Date '2026-07-10 12:00:00'
            $records = @(
                [pscustomobject]@{ Source='textlog'; Channel='CBS'; Provider='CBS'; Id=0; Level=2
                    LevelName='Error'; TimeCreated=$base; MachineName='T'; RecordId=1; Message='Failed to stage package 1' }
                [pscustomobject]@{ Source='textlog'; Channel='CBS'; Provider='CBS'; Id=0; Level=2
                    LevelName='Error'; TimeCreated=$base.AddDays(10); MachineName='T'; RecordId=2; Message='Failed to stage package 2' }
                [pscustomobject]@{ Source='textlog'; Channel='CBS'; Provider='CBS'; Id=0; Level=2
                    LevelName='Error'; TimeCreated=$null; MachineName='T'; RecordId=3; Message='Failed to stage package 3' }
            )
            $sigs = Group-LVSignature -Record $records -WindowDays 30
            @($sigs).Count | Should -Be 1
            $sigs[0].Count | Should -Be 3
            $sigs[0].UndatedCount | Should -Be 1
            $sigs[0].FirstSeen | Should -Be $base
            $sigs[0].LastSeen | Should -Be $base.AddDays(10)
            $sigs[0].SpanDays | Should -Be 10
        }
    }

    It 'rates a wholly undated signature across the window instead of inventing a span' {
        InModuleScope LogVerdict {
            $records = 1..4 | ForEach-Object {
                [pscustomobject]@{ Source='textlog'; Channel='SetupAPI'; Provider='SetupAPI'; Id=0; Level=2
                    LevelName='Error'; TimeCreated=$null; MachineName='T'; RecordId=$_; Message='!!! inf: failed' }
            }
            $sigs = Group-LVSignature -Record $records -WindowDays 30
            $sigs[0].FirstSeen | Should -BeNullOrEmpty
            $sigs[0].SpanDays | Should -Be 0
            $sigs[0].UndatedCount | Should -Be 4
        }
    }

    It 'renders a null timestamp as undated rather than as an empty string' {
        InModuleScope LogVerdict {
            Format-LVWhen $null | Should -Be 'undated'
            Format-LVWhen (Get-Date '2026-07-31 08:05:00') | Should -Be '2026-07-31 08:05'
        }
    }
}

Describe 'Text-log collection against fixtures' {
    BeforeAll {
        $script:FixtureDir = Join-Path $TestDrive 'logs'
        New-Item -ItemType Directory -Path $script:FixtureDir -Force | Out-Null

        # A CBS-shaped log: two real errors on different days, one benign Info line
        # that must not match, and one error too old for a 30-day window.
        $script:CbsPath = Join-Path $script:FixtureDir 'CBS.log'
        $recent = (Get-Date).AddDays(-2)
        $older  = (Get-Date).AddDays(-9)
        $ancient = (Get-Date).AddDays(-400)
        @(
            ('{0:yyyy-MM-dd HH:mm:ss}, Info                  CBS    TI: --- Initializing' -f $recent)
            ('{0:yyyy-MM-dd HH:mm:ss}, Error                 CSI    00000001 Failed to stage package Foo' -f $recent)
            ('{0:yyyy-MM-dd HH:mm:ss}, Error                 CSI    00000002 Failed to stage package Bar' -f $older)
            ('{0:yyyy-MM-dd HH:mm:ss}, Error                 CSI    00000003 Failed long ago' -f $ancient)
        ) | Set-Content -LiteralPath $script:CbsPath -Encoding UTF8

        # A SetupAPI-shaped log: error lines carry no timestamp of their own and must
        # inherit the most recent section header above them.
        $script:SetupPath = Join-Path $script:FixtureDir 'setupapi.dev.log'
        @(
            ('>>>  [Device Install]')
            ('>>>  Section start {0:yyyy/MM/dd HH:mm:ss}.123' -f $recent)
            ('     inf: opened the driver store')
            ('!!!  inf: Failed to open registry key')
            ('<<<  Section end')
        ) | Set-Content -LiteralPath $script:SetupPath -Encoding UTF8

        $script:CbsTarget = @(@{
            Name = 'CBSFIX'; Path = $script:CbsPath; Pattern = ',\s*Error\s'
            TimePattern = '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'; TimeFormat = 'yyyy-MM-dd HH:mm:ss'
            Area = 'test'; Hint = 'test'
        })
        $script:SetupTarget = @(@{
            Name = 'SETUPFIX'; Path = $script:SetupPath; Pattern = '^\s*!!!'
            SectionTimePattern = 'Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
            TimeFormat = 'yyyy/MM/dd HH:mm:ss'; Area = 'test'; Hint = 'test'
        })
    }

    It 'matches only error-shaped lines and dates each from its own timestamp' {
        InModuleScope LogVerdict -Parameters @{ t = $script:CbsTarget } {
            param($t)
            $rec = @(Get-LVTextLogRecord -DaysBack 30 -Target $t)
            $rec.Count | Should -Be 2 -Because 'the Info line must not match and the 400-day-old error is outside the window'
            @($rec | Where-Object { $_.Message -like '*Initializing*' }).Count | Should -Be 0
            ($rec | Select-Object -ExpandProperty TimeCreated -Unique).Count | Should -Be 2 -Because 'each line keeps its own time rather than the file mtime'
            @($rec | Where-Object Undated).Count | Should -Be 0
        }
    }

    It 'filters by line date, not by file mtime' {
        InModuleScope LogVerdict -Parameters @{ t = $script:CbsTarget } {
            param($t)
            # The fixture was written moments ago, so an mtime-based filter would keep
            # everything. Only a line-level filter can drop the 9-day-old entry.
            $rec = @(Get-LVTextLogRecord -DaysBack 5 -Target $t)
            $rec.Count | Should -Be 1
        }
    }

    It 'carries a section-header timestamp forward onto undated error lines' {
        InModuleScope LogVerdict -Parameters @{ t = $script:SetupTarget } {
            param($t)
            $rec = @(Get-LVTextLogRecord -DaysBack 30 -Target $t)
            $rec.Count | Should -Be 1
            $rec[0].TimeCreated | Should -Not -BeNullOrEmpty
            $rec[0].Undated | Should -BeFalse
        }
    }

    It 'marks a line undated rather than inventing a time when nothing can be parsed' {
        InModuleScope LogVerdict -Parameters @{ dir = $script:FixtureDir } {
            param($dir)
            $p = Join-Path $dir 'nodates.log'
            @('!!!  inf: something failed', '!!!  inf: something else failed') |
                Set-Content -LiteralPath $p -Encoding UTF8
            $target = @(@{ Name='NODATE'; Path=$p; Pattern='^\s*!!!'; Area='t'; Hint='t' })
            $rec = @(Get-LVTextLogRecord -DaysBack 30 -Target $target)
            $rec.Count | Should -Be 2
            @($rec | Where-Object Undated).Count | Should -Be 2
            $rec[0].TimeCreated | Should -BeNullOrEmpty
        }
    }

    It 'caps matches per file and says so' {
        InModuleScope LogVerdict -Parameters @{ dir = $script:FixtureDir } {
            param($dir)
            $p = Join-Path $dir 'huge.log'
            1..50 | ForEach-Object { '!!!  inf: failure {0}' -f $_ } | Set-Content -LiteralPath $p -Encoding UTF8
            $target = @(@{ Name='HUGE'; Path=$p; Pattern='^\s*!!!'; Area='t'; Hint='t' })
            $rec = @(Get-LVTextLogRecord -DaysBack 30 -MaxMatchesPerFile 10 -Target $target)
            $rec.Count | Should -Be 10 -Because 'the cap must bound the result'
        }
    }

    It 'reports a missing file instead of failing the scan' {
        InModuleScope LogVerdict -Parameters @{ dir = $script:FixtureDir } {
            param($dir)
            $target = @(@{ Name='GONE'; Path=(Join-Path $dir 'does-not-exist.log'); Pattern='.'; Area='t'; Hint='t' })
            $rec = @(Get-LVTextLogRecord -DaysBack 30 -Target $target)
            $rec.Count | Should -Be 0
        }
    }
}

Describe 'Event collection failure handling' {
    It 'treats an empty channel as empty, not as an error' {
        InModuleScope LogVerdict {
            Mock Get-WinEvent {
                $e = [System.Management.Automation.ErrorRecord]::new(
                    [Exception]::new('localized: no events'), 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand',
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null)
                throw $e
            }
            $rec = @(Get-LVEventRecord -Channel @('Fake') -DaysBack 30)
            $rec.Count | Should -Be 0
            $script:LVDeniedChannel.Count | Should -Be 0
        }
    }

    It 'records a denied channel as denied' {
        InModuleScope LogVerdict {
            Mock Get-WinEvent {
                $e = [System.Management.Automation.ErrorRecord]::new(
                    [UnauthorizedAccessException]::new('localized: denied'),
                    'System.UnauthorizedAccessException,Microsoft.PowerShell.Commands.GetWinEventCommand',
                    [System.Management.Automation.ErrorCategory]::PermissionDenied, $null)
                throw $e
            }
            $rec = @(Get-LVEventRecord -Channel @('Fake') -DaysBack 30)
            $rec.Count | Should -Be 0
            $script:LVDeniedChannel | Should -Contain 'Fake'
        }
    }

    It 'flags a channel that hit the record cap instead of truncating silently' {
        InModuleScope LogVerdict {
            Mock Get-WinEvent {
                1..5 | ForEach-Object {
                    [pscustomobject]@{
                        ProviderName = 'Fake'; Id = 1; Level = 2; LevelDisplayName = 'Error'
                        TimeCreated = (Get-Date); MachineName = 'T'; RecordId = $_; Message = "m$_"
                    }
                }
            }
            $rec = @(Get-LVEventRecord -Channel @('Fake') -DaysBack 30 -MaxPerChannel 5)
            $rec.Count | Should -Be 5
            $script:LVTruncatedChannel | Should -Contain 'Fake'
        }
    }

    It 'substitutes a placeholder when a provider has no message template' {
        InModuleScope LogVerdict {
            Mock Get-WinEvent {
                [pscustomobject]@{
                    ProviderName = 'Orphaned'; Id = 7; Level = 2; LevelDisplayName = 'Error'
                    TimeCreated = (Get-Date); MachineName = 'T'; RecordId = 1; Message = $null
                }
            }
            $rec = @(Get-LVEventRecord -Channel @('Fake') -DaysBack 30 -MaxPerChannel 100)
            $rec[0].Message | Should -Match 'no message template'
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

    It 'lets a local rule beat a shipped rule of equal specificity' {
        InModuleScope LogVerdict {
            # Sort-Object is not stable in Windows PowerShell 5.1 and has no -Stable
            # switch, so equal-specificity rules resolved arbitrarily and the documented
            # "local rules win ties" behaviour held only by luck.
            $mk = {
                param($id, $verdict, $ordinal)
                [pscustomobject]@{
                    id = $id; status = 'stable'; verified = '2026-07-31'; lvOrdinal = $ordinal
                    match = [pscustomobject]@{ source = 'event'; provider = 'Acme'; eventId = 1 }
                    verdict = $verdict; title = $id; plain = 'p'; why = 'w'; action = 'a'; confidence = 'high'
                }
            }
            # Local rules are loaded first, so they carry the lower ordinal.
            $db = [pscustomobject]@{ schemaVersion = 2; rules = @(
                (& $mk 'SITE-1' 'critical' 0),
                (& $mk 'LV-0001' 'benign'  1)) }

            $sig = [pscustomobject]@{
                Key='Acme/1'; Source='event'; Channel='System'; Provider='Acme'; Id=1
                Count=1; PerDay=0.1; SampleMessage='m'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            $out = Resolve-LVVerdict -Signature @($sig) -Database $db
            $out[0].RuleId | Should -Be 'SITE-1'
            $out[0].Verdict | Should -Be 'critical'
        }
    }

    It 'assigns every loaded rule an ordinal for tie-breaking' {
        $rules = @((Get-LogVerdictDatabase).rules)
        $rules[0].lvOrdinal | Should -Be 0
        @($rules | Where-Object { $null -eq $_.lvOrdinal }).Count | Should -Be 0
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

    It 'never applies a deprecated or unsupported rule' -ForEach @(
        @{ Status = 'deprecated' }
        @{ Status = 'unsupported' }
    ) {
        InModuleScope LogVerdict -Parameters @{ status = $Status } {
            param($status)
            # Retired rules stay in the database so their ids remain resolvable and
            # their history survives, but they must never rule on a signature.
            $db = [pscustomobject]@{ schemaVersion = 2; rules = @(
                [pscustomobject]@{
                    id = 'RETIRED-1'; status = $status; verified = '2026-07-31'
                    match = [pscustomobject]@{ source = 'event'; provider = 'Acme'; eventId = 1 }
                    verdict = 'critical'; title = 't'; plain = 'p'; why = 'w'; action = 'a'; confidence = 'high'
                }) }
            $sig = [pscustomobject]@{
                Key='Acme/1'; Source='event'; Channel='System'; Provider='Acme'; Id=1
                Count=1; PerDay=0.1; SampleMessage='m'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            $out = Resolve-LVVerdict -Signature @($sig) -Database $db
            $out[0].Verdict | Should -Be 'unknown'
            $out[0].RuleId | Should -BeNullOrEmpty
        }
    }

    It 'still applies rules from a schema v1 database with no status field' {
        InModuleScope LogVerdict {
            $db = [pscustomobject]@{ schemaVersion = 1; rules = @(
                [pscustomobject]@{
                    id = 'OLD-1'
                    match = [pscustomobject]@{ source = 'event'; provider = 'Acme'; eventId = 1 }
                    verdict = 'investigate'; title = 't'; plain = 'p'; why = 'w'; action = 'a'
                    confidence = 'high'; reference = 'https://example.invalid/old'
                }) }
            $sig = [pscustomobject]@{
                Key='Acme/1'; Source='event'; Channel='System'; Provider='Acme'; Id=1
                Count=1; PerDay=0.1; SampleMessage='m'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            $out = Resolve-LVVerdict -Signature @($sig) -Database $db
            $out[0].RuleId | Should -Be 'OLD-1'
            # The v1 singular 'reference' must still surface through the v2 list.
            $out[0].References | Should -Contain 'https://example.invalid/old'
        }
    }

    It 'skips a localized-message rule when the machine language does not match' {
        InModuleScope LogVerdict {
            # Event Message text comes from the provider's localized MUI resources, so
            # an English pattern cannot match on a German install. Skipping makes the
            # signature fall through to unknown, which is honest; matching anyway would
            # be impossible and failing silently would be invisible.
            $db = [pscustomobject]@{ schemaVersion = 2; rules = @(
                [pscustomobject]@{
                    id = 'LOC-1'; status = 'stable'; verified = '2026-07-31'; locale = 'en-US'
                    match = [pscustomobject]@{ source = 'event'; provider = 'Acme'; messagePattern = 'disk is full' }
                    verdict = 'actionable'; title = 't'; plain = 'p'; why = 'w'; action = 'a'; confidence = 'high'
                }) }
            $sig = [pscustomobject]@{
                Key='Acme/1'; Source='event'; Channel='System'; Provider='Acme'; Id=1
                Count=1; PerDay=0.1; SampleMessage='the disk is full'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }

            $original = $script:LVUICulture
            try {
                $script:LVUICulture = 'en-GB'
                # Same language, different region: the provider strings are identical.
                (Resolve-LVVerdict -Signature @($sig) -Database $db)[0].RuleId | Should -Be 'LOC-1'

                $script:LVUICulture = 'de-DE'
                (Resolve-LVVerdict -Signature @($sig) -Database $db)[0].Verdict | Should -Be 'unknown'
            } finally {
                $script:LVUICulture = $original
            }
        }
    }

    It 'applies a text-log message rule regardless of machine language' {
        InModuleScope LogVerdict {
            # CBS, DISM and SetupAPI are written in invariant English by the component
            # that produces them, so they must not be gated on the UI culture.
            $db = [pscustomobject]@{ schemaVersion = 2; rules = @(
                [pscustomobject]@{
                    id = 'TXT-1'; status = 'stable'; verified = '2026-07-31'
                    match = [pscustomobject]@{ source = 'textlog'; channel = 'CBS'; messagePattern = 'corrupt' }
                    verdict = 'actionable'; title = 't'; plain = 'p'; why = 'w'; action = 'a'; confidence = 'high'
                }) }
            $sig = [pscustomobject]@{
                Key='CBS/abc'; Source='textlog'; Channel='CBS'; Provider='CBS'; Id=0
                Count=1; PerDay=0.1; SampleMessage='store is corrupt'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            $original = $script:LVUICulture
            try {
                $script:LVUICulture = 'ja-JP'
                (Resolve-LVVerdict -Signature @($sig) -Database $db)[0].RuleId | Should -Be 'TXT-1'
            } finally {
                $script:LVUICulture = $original
            }
        }
    }

    It 'does not annotate the caller signature objects' {
        InModuleScope LogVerdict {
            # Add-Member -Force on the input would leave a first pass's verdict on
            # objects the caller still holds, so a second resolve against a different
            # database silently inherits stale properties.
            $sig = [pscustomobject]@{
                Key='Acme/1'; Source='event'; Channel='System'; Provider='Acme'; Id=1
                Count=1; PerDay=0.1; SampleMessage='m'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            $db = [pscustomobject]@{ schemaVersion = 2; rules = @(
                [pscustomobject]@{
                    id='PURE-1'; status='stable'; verified='2026-07-31'
                    match=[pscustomobject]@{ source='event'; provider='Acme'; eventId=1 }
                    verdict='critical'; title='t'; plain='p'; why='w'; action='a'; confidence='high'
                }) }

            $out = Resolve-LVVerdict -Signature @($sig) -Database $db
            $out[0].Verdict | Should -Be 'critical'
            $sig.PSObject.Properties.Name | Should -Not -Contain 'Verdict'

            # An empty database must now yield unknown, not the previous run's verdict.
            $empty = [pscustomobject]@{ schemaVersion = 2; rules = @() }
            (Resolve-LVVerdict -Signature @($sig) -Database $empty)[0].Verdict | Should -Be 'unknown'
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
            Tool = 'LogVerdict'; Version = '0.5.0'; MachineName = 'TESTPC'
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

    It 'writes every report without a UTF-8 BOM' {
        # Set-Content -Encoding UTF8 emits a BOM on PS 5.1 but not on PS 7, so this
        # regresses invisibly if only pwsh is exercised. A BOM makes the JSON report
        # unreadable to strict parsers (Python json.load raises "Unexpected UTF-8 BOM"),
        # and that file is the machine-readable contract.
        $out = Join-Path $TestDrive 'reports'
        Export-LogVerdictReport -Result $script:FakeResult -OutputDir $out | Out-Null

        $files = Get-ChildItem -LiteralPath $out -File
        @($files).Count | Should -BeGreaterThan 0
        foreach ($f in $files) {
            $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
            $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
            $hasBom | Should -BeFalse -Because "$($f.Name) must start with its first content byte"
        }
    }

    It 'writes JSON that round-trips back to the same findings' {
        $out = Join-Path $TestDrive 'reports-json'
        Export-LogVerdictReport -Result $script:FakeResult -OutputDir $out -Format Json | Out-Null
        $json = Get-Content -LiteralPath (Join-Path $out 'LogVerdict-Report.json') -Raw
        $json.Substring(0, 1) | Should -Be '{'
        $parsed = $json | ConvertFrom-Json
        $parsed.Findings[0].Verdict | Should -Be 'actionable'
        $parsed.Reduction.SignatureCount | Should -Be 71
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

Describe 'GUI markup' {
    It 'is well-formed XML' {
        # XamlReader.Parse is stricter than it looks. XML forbids a double hyphen
        # inside a comment, so a decorative section divider drawn with dashes throws
        # at parse time and takes the whole window down with it.
        InModuleScope LogVerdict {
            { [xml](Get-LVGuiXaml) } | Should -Not -Throw
        }
    }

    It 'declares every element the window code resolves' {
        # Show-LogVerdictGui resolves this list through FindName and throws on the
        # first miss. Catching a rename here means catching it before a build rather
        # than when a user clicks something.
        InModuleScope LogVerdict {
            $xaml = Get-LVGuiXaml
            $missing = @($script:LVGuiElement | Where-Object { $xaml -notmatch ('x:Name="{0}"' -f [regex]::Escape($_)) })
            ($missing -join ', ') | Should -BeExactly ''
        }
    }

    It 'binds only to properties the row objects actually carry' {
        # A misspelled binding path fails silently in WPF - the cell simply renders
        # empty - so the columns are checked against the row shape instead.
        InModuleScope LogVerdict {
            $sig = [pscustomobject]@{
                Key = 'Contoso/7'; Source = 'event'; Channel = 'System'; Provider = 'Contoso'
                Id = 7; Count = 3; PerDay = 1.5; LastSeen = (Get-Date); UndatedCount = 0
                SampleMessage = 'x'; Verdict = 'actionable'; Title = 'T'; RuleId = 'LV-0001'
            }
            $row = @(ConvertTo-LVGuiRow -Finding @($sig))[0]
            $names = $row.PSObject.Properties.Name

            $xaml = Get-LVGuiXaml
            $bound = [regex]::Matches($xaml, '\{Binding (\w+)\}') |
                ForEach-Object { $_.Groups[1].Value } |
                Sort-Object -Unique

            @($bound).Count | Should -BeGreaterThan 0
            foreach ($b in $bound) { $names | Should -Contain $b }
        }
    }

    It 'gives every verdict a palette entry with dark ink on a light fill' {
        InModuleScope LogVerdict {
            foreach ($v in $script:LVVerdictRank.Keys) {
                $style = Get-LVVerdictStyle -Verdict $v
                $style.Label | Should -Not -BeNullOrEmpty
                $style.Fill  | Should -Match '^#[0-9a-f]{6}$'
                $style.Ink   | Should -Match '^#[0-9a-f]{6}$'
            }
        }
    }

    It 'sorts columns on a key rather than on the displayed text' {
        # "3 days ago" and "CRITICAL" both sort alphabetically into nonsense, so every
        # sortable header must map to a real, orderable row property.
        InModuleScope LogVerdict {
            $sig = [pscustomobject]@{
                Key = 'Contoso/7'; Source = 'event'; Channel = 'System'; Provider = 'Contoso'
                Id = 7; Count = 3; PerDay = 1.5; LastSeen = (Get-Date); UndatedCount = 0
                SampleMessage = 'x'; Verdict = 'critical'; Title = 'T'; RuleId = $null
            }
            $row = @(ConvertTo-LVGuiRow -Finding @($sig))[0]
            foreach ($key in $script:LVGuiSortKey.Values) {
                $row.PSObject.Properties.Name | Should -Contain $key
            }
            $row.VerdictRank  | Should -BeOfType [int]
            $row.LastSeenSort | Should -BeOfType [datetime]
        }
    }
}

Describe 'GUI row projection' {
    It 'dates an undated signature to DateTime.MinValue rather than to now' {
        # Undated text-log lines must sort to the bottom of a last-seen sort, not to
        # the top as if they had just happened.
        InModuleScope LogVerdict {
            $sig = [pscustomobject]@{
                Key = 'CBS/abc'; Source = 'text'; Channel = 'CBS'; Provider = $null
                Id = $null; Count = 1; PerDay = 0.03; LastSeen = $null; UndatedCount = 1
                SampleMessage = 'x'; Verdict = 'unknown'; Title = 'T'; RuleId = $null
            }
            $row = @(ConvertTo-LVGuiRow -Finding @($sig))[0]
            $row.LastSeenText | Should -BeExactly 'undated'
            $row.LastSeenSort | Should -Be ([datetime]::MinValue)
        }
    }

    It 'pads the per-day rate to two places so the column lines up' {
        InModuleScope LogVerdict {
            $make = {
                param($Rate)
                [pscustomobject]@{
                    Key = 'C/1'; Source = 'event'; Channel = 'System'; Provider = 'C'
                    Id = 1; Count = 2; PerDay = $Rate; LastSeen = (Get-Date); UndatedCount = 0
                    SampleMessage = 'x'; Verdict = 'unknown'; Title = 'T'; RuleId = $null
                }
            }
            (@(ConvertTo-LVGuiRow -Finding @((& $make 0.7)))[0]).PerDayText | Should -BeExactly '0.70'
            (@(ConvertTo-LVGuiRow -Finding @((& $make 10)))[0]).PerDayText  | Should -BeExactly '10.00'
        }
    }

    It 'returns an empty array for no findings rather than a phantom item' {
        InModuleScope LogVerdict {
            @(ConvertTo-LVGuiRow -Finding @()).Count | Should -Be 0
        }
    }

    It 'lower-cases the search haystack so filtering is case-insensitive' {
        InModuleScope LogVerdict {
            $sig = [pscustomobject]@{
                Key = 'Contoso/7'; Source = 'event'; Channel = 'System'; Provider = 'Contoso'
                Id = 7; Count = 1; PerDay = 1; LastSeen = (Get-Date); UndatedCount = 0
                SampleMessage = 'A LOUD Message'; Verdict = 'unknown'; Title = 'Title'; RuleId = $null
            }
            $row = @(ConvertTo-LVGuiRow -Finding @($sig))[0]
            $row.Haystack | Should -BeExactly $row.Haystack.ToLowerInvariant()
            $row.Haystack | Should -Match 'contoso'
        }
    }
}

Describe 'GUI list binding safety' {
    It 'never hands a bare string to an ItemsSource' {
        # A string is IEnumerable. Assigning one directly to ItemsSource binds to its
        # characters, and a rule caveat renders one letter per line - which is exactly
        # what happened until it was caught on screen. Every assignment must cast.
        $gui = Join-Path (Split-Path $PSScriptRoot -Parent) 'Public\Show-LogVerdictGui.ps1'
        $assignments = [regex]::Matches((Get-Content -LiteralPath $gui -Raw), '(?m)\.ItemsSource\s*=\s*(.+)$')
        @($assignments).Count | Should -BeGreaterThan 0
        foreach ($a in $assignments) {
            $rhs = $a.Groups[1].Value.Trim()
            # A CollectionView is already a real collection; anything else must be cast
            # to an array type so a one-element result cannot arrive as a scalar string.
            if ($rhs -ne '$view') {
                $rhs | Should -Match '^\[string\[\]\]|^\[object\[\]\]'
            }
        }
    }
}

Describe 'GUI entry script' {
    It 'relaunches itself STA rather than failing on a multi-threaded apartment' {
        $entry = Join-Path (Split-Path $PSScriptRoot -Parent) 'LogVerdict-GUI.ps1'
        $text = Get-Content -LiteralPath $entry -Raw
        $text | Should -Match "GetApartmentState\(\) -ne 'STA'"
        $text | Should -Match "'-STA'"
    }

    It 'writes a crash log when the window cannot start' {
        # A GUI that dies before painting has nowhere to show an error. Without this
        # the failure mode is a window that simply never appears.
        $entry = Join-Path (Split-Path $PSScriptRoot -Parent) 'LogVerdict-GUI.ps1'
        $text = Get-Content -LiteralPath $entry -Raw
        $text | Should -Match 'crash-'
        $text | Should -Match 'MessageBox'
    }

    It 'exposes the module-import marker the build cuts on' {
        # Tools\Build-LogVerdictExe.ps1 finds this exact line to split the entry script
        # in two. Rewording it fails the build loudly - which is the intent - but this
        # says why before anyone goes looking.
        $entry = Join-Path (Split-Path $PSScriptRoot -Parent) 'LogVerdict-GUI.ps1'
        (Get-Content -LiteralPath $entry -Raw) | Should -Match 'Import-Module \$modulePath -Force -ErrorAction Stop'
    }
}

Describe 'GUI background scan' {
    It 'streams log lines as level, timestamp and message' {
        # The GUI splits on the pipe with a cap of 3 so a message carrying its own
        # pipe characters survives intact.
        InModuleScope LogVerdict {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
            $script:LVLogSink = $queue
            try {
                Write-LVLog -Level warn -Message 'a | b | c'
            } finally {
                $script:LVLogSink = $null
            }

            $line = $null
            $queue.TryDequeue([ref]$line) | Should -BeTrue
            $parts = $line.Split(@('|'), 3, [System.StringSplitOptions]::None)
            $parts[0] | Should -BeExactly 'warn'
            $parts[1] | Should -Match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$'
            $parts[2] | Should -BeExactly 'a | b | c'
        }
    }

    It 'leaves no sink behind for an ordinary console run' {
        InModuleScope LogVerdict {
            $script:LVLogSink | Should -BeNullOrEmpty
        }
    }

    It 'runs a real scan in a worker runspace and returns the result' {
        # The window is only as good as this: if the runspace bootstrap cannot
        # reconstitute LogVerdict, the GUI shows a spinner forever.
        InModuleScope LogVerdict {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
            $job = Start-LVScanJob -ScanArgs @{ DaysBack = 1; SkipTextLogs = $true } -LogSink $queue
            $job.Mode | Should -BeExactly 'module'

            $deadline = (Get-Date).AddSeconds(120)
            while (-not $job.Async.IsCompleted -and (Get-Date) -lt $deadline) {
                Start-Sleep -Milliseconds 200
            }
            $job.Async.IsCompleted | Should -BeTrue -Because 'a one-day scan must not take two minutes'

            $result = Complete-LVScanJob -Job $job
            $result.Tool | Should -BeExactly 'LogVerdict'
            $result.PSObject.Properties['ExitCode'] | Should -Not -BeNullOrEmpty
            $queue.Count | Should -BeGreaterThan 0 -Because 'the worker must stream progress back'
        }
    }

    It 'tears a job down without throwing, twice' {
        InModuleScope LogVerdict {
            $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
            $job = Start-LVScanJob -ScanArgs @{ DaysBack = 1; SkipTextLogs = $true } -LogSink $queue
            { Stop-LVScanJob -Job $job -Confirm:$false } | Should -Not -Throw
            { Stop-LVScanJob -Job $job -Confirm:$false } | Should -Not -Throw
            { Stop-LVScanJob -Job $null -Confirm:$false } | Should -Not -Throw
        }
    }
}

Describe 'GUI accessibility' {
    It 'gives every input and the findings list an accessible name' {
        # Automation peers can be created without showing a window, so this asserts what
        # a screen reader would actually announce rather than that an attribute exists.
        # Requires STA; powershell.exe is STA by default, pwsh is not.
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
            Set-ItResult -Skipped -Because 'automation peers need a single-threaded apartment'
            return
        }
        InModuleScope LogVerdict {
            Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml, UIAutomationTypes
            $window = [Windows.Markup.XamlReader]::Parse((Get-LVGuiXaml))
            # LabeledBy is an ElementName binding, which stays unresolved until a layout
            # pass runs. A shown window gets one for free; an offscreen one needs asking.
            $window.Measure([System.Windows.Size]::new(1340, 760))
            $window.Arrange((New-Object System.Windows.Rect(0, 0, 1340, 760)))
            $window.UpdateLayout()

            foreach ($name in @('TxtDays', 'TxtSearch', 'LvFindings', 'TxtSample', 'TxtLog')) {
                $element = $window.FindName($name)
                $element | Should -Not -BeNullOrEmpty -Because "$name must exist"
                $peer = [System.Windows.Automation.Peers.UIElementAutomationPeer]::CreatePeerForElement($element)
                $peer | Should -Not -BeNullOrEmpty -Because "$name must expose an automation peer"
                $peer.GetName() | Should -Not -BeNullOrEmpty -Because "$name announces as an unlabelled control without a name"
            }
        }
    }

    It 'binds the findings row name to a spoken sentence, not the object graph' {
        InModuleScope LogVerdict {
            (Get-LVGuiXaml) | Should -Match 'AutomationProperties\.Name" Value="\{Binding AutomationName\}"'
        }
    }

    It 'builds a row name that reads as a sentence and leaks no styling' {
        InModuleScope LogVerdict {
            $sig = [pscustomobject]@{
                Key = 'Contoso/7'; Source = 'event'; Channel = 'System'; Provider = 'Contoso'
                Id = 7; Count = 12; PerDay = 0.55; LastSeen = (Get-Date).AddDays(-2); UndatedCount = 0
                SampleMessage = 'boom'; Verdict = 'actionable'; Title = 'An update failed to install'
                RuleId = 'LV-0001'
            }
            $row = @(ConvertTo-LVGuiRow -Finding @($sig))[0]
            $row.AutomationName | Should -Match '^ACTIONABLE\. An update failed to install\.'
            $row.AutomationName | Should -Match 'Seen 12 time'
            $row.AutomationName | Should -Match 'Contoso 7'
            # The defect this replaces: hex colours and the search haystack read aloud.
            $row.AutomationName | Should -Not -Match '#'
            $row.AutomationName | Should -Not -Match 'VerdictFill'
        }
    }
}

Describe 'Rule provenance' {
    It 'accepts a schema v3 database and still accepts v2' {
        InModuleScope LogVerdict {
            $script:LVSchemaVersionMax | Should -BeGreaterOrEqual 3
        }
        (Get-LogVerdictDatabase).schemaVersion | Should -Be 3
    }

    It 'still refuses a schema newer than this build understands' {
        $future = Join-Path $TestDrive 'v4.json'
        '{ "schemaVersion": 4, "name": "future", "updated": "2026-07-31", "rules": [] }' |
            Set-Content -LiteralPath $future -Encoding UTF8
        { Get-LogVerdictDatabase -Path $future } | Should -Throw -ExpectedMessage '*schemaVersion 4*'
    }

    It 'reports an unsourced rule as a warning, not as invalid' {
        # A documentation gap must not fail the same check as a broken regex, or the
        # shipped database refuses to load over missing citations.
        $bare = Join-Path $TestDrive 'bare.json'
        '{ "schemaVersion": 3, "name": "bare", "updated": "2026-07-31", "rules": [ { "id":"B-1","status":"stable","verified":"2026-07-31","match":{"source":"event"},"verdict":"benign","title":"t","plain":"p","why":"w","action":"a","confidence":"high" } ] }' |
            Set-Content -LiteralPath $bare -Encoding UTF8

        Test-LogVerdictDatabase -Path $bare -Quiet | Should -BeTrue
        @(Test-LogVerdictDatabase -Path $bare).Count | Should -Be 0
        $all = @(Test-LogVerdictDatabase -Path $bare -IncludeWarnings)
        @($all | Where-Object { $_.Severity -eq 'warning' }).Count | Should -Be 1
    }

    It 'does not invent a phantom source for a rule that has none' {
        # @($null) is a one-element array holding null, so an unfiltered wrap reported
        # every sourceless rule as having a source with no uri.
        $bare = Join-Path $TestDrive 'bare2.json'
        '{ "schemaVersion": 3, "name": "bare", "updated": "2026-07-31", "rules": [ { "id":"B-1","status":"stable","verified":"2026-07-31","match":{"source":"event"},"verdict":"benign","title":"t","plain":"p","why":"w","action":"a","confidence":"high" } ] }' |
            Set-Content -LiteralPath $bare -Encoding UTF8
        @(Test-LogVerdictDatabase -Path $bare -IncludeWarnings | Where-Object { $_.Problem -like '*without a uri*' }).Count | Should -Be 0
    }

    It 'rejects a DRL-licensed source that names no author' {
        # DRL-1.1 requires the author be shown on every match, so a rule that cannot
        # render one must not ship.
        $drl = Join-Path $TestDrive 'drl.json'
        '{ "schemaVersion": 3, "name": "drl", "updated": "2026-07-31", "rules": [ { "id":"D-1","status":"stable","verified":"2026-07-31","match":{"source":"event"},"verdict":"benign","title":"t","plain":"p","why":"w","action":"a","confidence":"high","sources":[{"uri":"https://example.invalid/r","licence":"DRL-1.1"}] } ] }' |
            Set-Content -LiteralPath $drl -Encoding UTF8
        Test-LogVerdictDatabase -Path $drl -Quiet | Should -BeFalse
    }

    It 'carries source attribution onto the finding, not just the rule' {
        InModuleScope LogVerdict {
            $db = [pscustomobject]@{
                schemaVersion = 3
                rules = @([pscustomobject]@{
                    id = 'S-1'; status = 'stable'; verdict = 'investigate'
                    title = 't'; plain = 'p'; why = 'w'; action = 'a'; confidence = 'high'
                    lvOrdinal = 0
                    match = [pscustomobject]@{ source = 'event'; provider = 'Contoso'; eventId = 7 }
                    sources = @([pscustomobject]@{ uri = 'https://example.invalid/a'; licence = 'CC-BY-4.0'; modified = $true })
                })
            }
            $sig = [pscustomobject]@{
                Key = 'Contoso/7'; Source = 'event'; Channel = 'System'; Provider = 'Contoso'
                Id = 7; Count = 1; PerDay = 1; SampleMessage = 'x'
            }
            $out = @(Resolve-LVVerdict -Signature @($sig) -Database $db)[0]
            @($out.Sources).Count | Should -Be 1
            $out.Sources[0].licence | Should -BeExactly 'CC-BY-4.0'
        }
    }
}

Describe 'GUI colour contrast' {
    It 'renders every text element at WCAG AA against every surface it sits on' {
        # Computed from the markup rather than eyeballed. Only the attribute form is
        # checked: a Foreground set through a Setter is almost always a disabled state,
        # and disabled controls are explicitly exempt from the contrast minimum.
        InModuleScope LogVerdict {
            $xaml = Get-LVGuiXaml

            $brush = @{}
            foreach ($m in [regex]::Matches($xaml, '<SolidColorBrush x:Key="(\w+)"\s+Color="(#[0-9a-fA-F]{6})"')) {
                $brush[$m.Groups[1].Value] = $m.Groups[2].Value
            }

            function Get-Channel([double]$v) {
                if ($v -le 0.03928) { return $v / 12.92 }
                return [Math]::Pow(($v + 0.055) / 1.055, 2.4)
            }
            function Get-Luminance([string]$hex) {
                $r = Get-Channel ([Convert]::ToInt32($hex.Substring(1, 2), 16) / 255)
                $g = Get-Channel ([Convert]::ToInt32($hex.Substring(3, 2), 16) / 255)
                $b = Get-Channel ([Convert]::ToInt32($hex.Substring(5, 2), 16) / 255)
                return (0.2126 * $r + 0.7152 * $g + 0.0722 * $b)
            }
            function Get-Ratio([string]$fg, [string]$bg) {
                $a = Get-Luminance $fg
                $b = Get-Luminance $bg
                $hi = [Math]::Max($a, $b); $lo = [Math]::Min($a, $b)
                return (($hi + 0.05) / ($lo + 0.05))
            }

            # Every background the window actually paints text on.
            $surfaces = @($brush['Base'], $brush['Mantle'], $brush['Crust'])

            $used = @([regex]::Matches($xaml, 'Foreground="\{StaticResource (\w+)\}"') |
                ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
            $used.Count | Should -BeGreaterThan 3

            foreach ($name in $used) {
                $hex = $brush[$name]
                $hex | Should -Not -BeNullOrEmpty -Because "brush '$name' must be defined"
                foreach ($bg in $surfaces) {
                    $ratio = Get-Ratio $hex $bg
                    $ratio | Should -BeGreaterThan 4.5 -Because "$name ($hex) on $bg is only $([Math]::Round($ratio,2)):1 and carries body text"
                }
            }
        }
    }

    It 'draws a visible focus ring on every interactive control' {
        InModuleScope LogVerdict {
            $xaml = Get-LVGuiXaml
            $xaml | Should -Match 'x:Key="LVFocusVisual"'
            # Button, accent button, chip toggle, checkbox, text box.
            ([regex]::Matches($xaml, 'FocusVisualStyle" Value="\{StaticResource LVFocusVisual\}"')).Count |
                Should -BeGreaterOrEqual 5
        }
    }
}

Describe 'GUI coverage surfacing' {
    It 'formats a crash artifact as one readable line' {
        InModuleScope LogVerdict {
            $a = [pscustomobject]@{ Kind = 'minidump'; When = [datetime]'2026-07-30 14:05'; Path = (Join-Path 'C:\Windows\Minidump' 'dump-1.dmp') }
            $line = @(Format-LVCrashArtifact -Artifact @($a))[0]
            $line | Should -Match '^minidump'
            $line | Should -Match '2026-07-30 14:05'
            $line | Should -Match 'dump-1\.dmp'
        }
    }

    It 'returns an empty array when there are no crash artifacts' {
        InModuleScope LogVerdict {
            @(Format-LVCrashArtifact -Artifact @()).Count | Should -Be 0
        }
    }

    It 'counts rulings whose guidance has gone stale' {
        InModuleScope LogVerdict {
            $fresh = [pscustomobject]@{ Verified = (Get-Date).ToString('yyyy-MM-dd') }
            $old   = [pscustomobject]@{ Verified = (Get-Date).AddMonths(-1 * ($script:LVVerificationMaxAgeMonths + 6)).ToString('yyyy-MM-dd') }
            $none  = [pscustomobject]@{ Verified = $null }
            Get-LVStaleRuleCount -Finding @($fresh, $old, $none) | Should -Be 1
        }
    }

    It 'ignores an unparseable verified date rather than counting it as stale' {
        InModuleScope LogVerdict {
            Get-LVStaleRuleCount -Finding @([pscustomobject]@{ Verified = 'last tuesday' }) | Should -Be 0
        }
    }
}

Describe 'Rule regression fixtures' {
    BeforeAll {
        $script:DataDir     = Join-Path (Split-Path $PSScriptRoot -Parent) 'Data'
        $script:FixtureJson = [IO.File]::ReadAllText((Join-Path $script:DataDir 'fixtures.json'))
        $script:VerdictJson = [IO.File]::ReadAllText((Join-Path $script:DataDir 'verdicts.json'))

        # Every negative case below writes a deliberately broken pair into a scratch
        # directory and validates THAT, so the shipped files are never touched.
        function Export-BrokenPair {
            param([scriptblock]$MutateFixtures, [scriptblock]$MutateDatabase)

            $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('n'))
            New-Item -ItemType Directory -Path $dir -Force | Out-Null

            $fx = $script:FixtureJson | ConvertFrom-Json
            $db = $script:VerdictJson | ConvertFrom-Json
            if ($MutateFixtures) { & $MutateFixtures $fx }
            if ($MutateDatabase) { & $MutateDatabase $db }

            $fx | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $dir 'fixtures.json') -Encoding UTF8
            $db | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $dir 'verdicts.json') -Encoding UTF8
            return (Join-Path $dir 'verdicts.json')
        }
    }

    It 'covers every shipped rule' {
        # The validator downgrades a missing fixture to a warning so a hand-written
        # local database still validates. The shipped database is held to all of them.
        $missing = @(Test-LogVerdictDatabase -IncludeWarnings | Where-Object { $_.Problem -like 'no regression fixture*' })
        $missing.Count | Should -Be 0 -Because ("these rules are unprotected: {0}" -f (($missing.RuleId) -join ', '))
    }

    It 'resolves every fixture to its own rule with the expected verdict' {
        @(Test-LogVerdictDatabase).Count | Should -Be 0
    }

    It 'drives the real resolver rather than a reimplementation of the matcher' {
        # A fixture check that reimplemented matching could agree with itself forever
        # while the shipped resolver drifted. This asserts the projected signature
        # carries the property names Group-LVSignature actually emits.
        InModuleScope LogVerdict {
            $fixture = [pscustomobject]@{
                ruleId = 'LV-0001'
                signature = [pscustomobject]@{
                    Source = 'event'; Channel = 'System'
                    Provider = 'Microsoft-Windows-DistributedCOM'; Id = 10016
                    SampleMessage = 'sample'
                }
            }
            $projected = ConvertTo-LVFixtureSignature -Fixture $fixture
            $reduced = @(Group-LVSignature -Record @([pscustomobject]@{
                Source = 'event'; Channel = 'System'; Provider = 'P'; Id = 1
                Level = 2; LevelName = 'Error'; TimeCreated = (Get-Date); Message = 'm'
            }))[0]

            foreach ($name in @('Key','Source','Channel','Provider','Id','SampleMessage','Count','PerDay','SpanDays')) {
                $projected.PSObject.Properties[$name] | Should -Not -BeNullOrEmpty -Because "the resolver reads $name"
                $reduced.PSObject.Properties[$name]   | Should -Not -BeNullOrEmpty -Because "$name must exist on a real signature too"
            }
        }
    }

    It 'catches a rule that has stopped claiming its own sample' {
        $path = Export-BrokenPair -MutateFixtures {
            param($fx)
            ($fx.fixtures | Where-Object ruleId -eq 'LV-0011')[0].signature.Provider = 'Totally-Different-Provider'
        }
        $problems = @(Test-LogVerdictDatabase -Path $path | Where-Object RuleId -eq 'LV-0011')
        $problems.Count | Should -BeGreaterThan 0
        $problems[0].Problem | Should -Match 'no longer claims its own sample'
    }

    It 'names the rule that shadowed another rather than merely reporting a miss' {
        # The failure mode this exists for: a new rule that looks specific but is
        # broader than an existing one, silently stealing its matches. Knowing WHICH
        # rule won is the whole diagnostic value.
        $path = Export-BrokenPair -MutateDatabase {
            param($db)
            $shadow = [pscustomobject]@{
                id = 'LV-9999'; status = 'stable'; verified = '2026-07-31'
                match = [pscustomobject]@{ source = 'event'; provider = 'Microsoft-Windows-WHEA-Logger'; eventId = 18 }
                verdict = 'benign'; title = 't'; plain = 'p'; why = 'w'; action = 'a'; confidence = 'low'
            }
            $db.rules = @($shadow) + @($db.rules)
        }
        $problems = @(Test-LogVerdictDatabase -Path $path | Where-Object RuleId -eq 'LV-0011')
        $problems[0].Problem | Should -Match 'resolved to LV-9999'
    }

    It 'catches a verdict edited without its fixture' {
        $path = Export-BrokenPair -MutateFixtures {
            param($fx)
            ($fx.fixtures | Where-Object ruleId -eq 'LV-0011')[0].expect = 'benign'
        }
        $problems = @(Test-LogVerdictDatabase -Path $path | Where-Object RuleId -eq 'LV-0011')
        $problems[0].Problem | Should -Match "expected verdict 'benign' but resolved to 'critical'"
    }

    It 'catches a fixture left behind by a deleted rule' {
        $path = Export-BrokenPair -MutateDatabase {
            param($db)
            $db.rules = @($db.rules | Where-Object { $_.id -ne 'LV-0011' })
        }
        $problems = @(Test-LogVerdictDatabase -Path $path | Where-Object RuleId -eq 'LV-0011')
        $problems[0].Problem | Should -Match 'not in the database'
    }

    It 'exercises rate escalation, not just the base verdict' {
        InModuleScope LogVerdict {
            $escalating = @((Get-LVFixtureSet).fixtures | Where-Object { $null -ne $_.perDay })
            $escalating.Count | Should -BeGreaterThan 0 -Because 'a threshold nothing crosses is a threshold nothing tests'
            foreach ($f in $escalating) {
                $rule = (Get-LogVerdictDatabase).rules | Where-Object id -eq $f.ruleId
                $f.expect | Should -Be $rule.escalate.verdict -Because "$($f.ruleId) is rated above its own threshold"
            }
        }
    }

    It 'skips the fixture checks rather than failing when a database has none' {
        # A site with a hand-written verdicts.local.json has no fixture file, and must
        # still be able to validate. Absence is not a defect.
        $dir = Join-Path $TestDrive 'no-fixtures'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $solo = @{
            schemaVersion = 3; name = 'solo'; updated = '2026-07-31'
            rules = @(@{
                id = 'X-1'; status = 'stable'; verified = '2026-07-31'
                match = @{ source = 'event'; provider = 'P'; eventId = 1 }
                verdict = 'benign'; title = 't'; plain = 'p'; why = 'w'; action = 'a'; confidence = 'low'
            })
        }
        $path = Join-Path $dir 'verdicts.json'
        $solo | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
        Test-LogVerdictDatabase -Path $path -Quiet | Should -BeTrue
    }

    It 'keeps every text-log fixture in a shape its collector would actually match' {
        # A fixture the collector would never produce cannot protect anything: the rule
        # would pass its test and still never see a real line.
        InModuleScope LogVerdict {
            $set = Get-LVFixtureSet
            foreach ($f in @($set.fixtures | Where-Object { $_.signature.Source -eq 'textlog' })) {
                $target = $script:LVTextLogTarget | Where-Object { $_.Name -eq $f.signature.Channel }
                $target | Should -Not -BeNullOrEmpty -Because "$($f.ruleId) names channel $($f.signature.Channel)"
                $f.signature.SampleMessage | Should -Match $target.Pattern -Because "$($f.ruleId)'s sample must be a line the collector picks up"
            }
        }
    }

    It 'publishes no hostname, account name or SID from the machine it was captured on' {
        # These are committed to a public repository and most were captured from a real
        # machine, so the redaction that made them publishable is asserted, not assumed.
        # Asserted against the decoded messages, not the raw JSON: in the file every
        # path separator is doubled, and a pattern written for the escaped form can
        # backtrack around its own lookahead and pass while the leak is still there.
        InModuleScope LogVerdict {
            foreach ($f in @((Get-LVFixtureSet).fixtures)) {
                $msg = [string]$f.signature.SampleMessage
                $msg | Should -Not -Match 'S-1-5-21-\d' -Because "$($f.ruleId) must not carry a real account SID"
                $msg | Should -Not -Match 'S-1-15-\d'   -Because "$($f.ruleId) must not carry a real package SID"
                $msg | Should -Not -Match ([regex]::Escape($env:COMPUTERNAME)) -Because "$($f.ruleId) must not name this machine"

                foreach ($m in [regex]::Matches($msg, '(?i)[A-Z]:\\Users\\([^\\/:*?"<>|\r\n]+)')) {
                    $m.Groups[1].Value | Should -BeIn @('user', 'Default', 'Public', 'All Users') `
                        -Because "$($f.ruleId) must not name a real account in a profile path"
                }
            }
        }
    }

    It 'says which fixtures were captured and which were constructed' {
        InModuleScope LogVerdict {
            $set = Get-LVFixtureSet
            foreach ($f in @($set.fixtures)) {
                $f.origin | Should -BeIn @('observed', 'constructed') -Because "$($f.ruleId) must not blur captured evidence with representative text"
            }
        }
    }
}
