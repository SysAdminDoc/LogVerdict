#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'LogVerdict.psd1'
    Import-Module $script:ModulePath -Force
}
Describe 'Case profiles and responder handoffs' {
    BeforeAll {
        $script:CaseResult = [pscustomobject]@{
            Tool = 'LogVerdict'; Version = '0.8.0'; MachineName = 'HOST-9'
            ScanTime = [datetime]'2026-08-02 12:00:00'; Duration = [timespan]::FromSeconds(2)
            DaysBack = 7; Channels = @('System'); Elevated = $true
            Reduction = [pscustomobject]@{ RecordCount=1; SignatureCount=1; Ratio=1 }
            WorstVerdict = 'investigate'; ExitCode = 1; RuleCount = 1; DatabaseName='test'; DatabaseDate='2026-08-02'
            ScanOptions = [ordered]@{ channelMode='named'; channels=@('System'); skipTextLogs=$false; skipReliability=$true; includeBenign=$false }
            Coverage = @([pscustomobject]@{
                Source='event'; Kind='channel'; Name='System'; Status='readable'
                SHA256=('A' * 64); SizeBytes=100
            })
            EvidenceManifest = @()
            CoverageNotes = @(); HealthProfiles = @(); SetupDiag = $null; Stability = $null
            Horizon = @{}; HorizonWarning = $null; CrashArtifacts = @()
            Findings = @([pscustomobject]@{
                FirstSeen=[datetime]'2026-08-02 11:00:00'; LastSeen=[datetime]'2026-08-02 11:00:01'
                Source='event'; Channel='System'; Provider='Test'; Id=100; Title='Test finding'
                RuleId='LV-TEST'; Verdict='investigate'; Count=1; PerDay=0.1
                Key='event|System|100'; SampleMessage='HOST-9 failed for C:\Users\bob'
            })
            Correlations = @()
        }
    }

    It 'creates a hash-addressed profile with bounds, choices, and source hashes' {
        $path = Join-Path $TestDrive 'case-profile.json'
        $profile = New-LogVerdictCaseProfile -Result $script:CaseResult -Name 'Upgrade review' -Purpose 'Review HOST-9' -Note 'Check C:\Users\bob' -Ticket 'INC-42' -Redact -Path $path

        Test-LogVerdictCaseProfile -Path $path -Quiet | Should -BeTrue
        $profile.profileId | Should -Match '^[0-9a-f]{64}$'
        $profile.bounds.daysBack | Should -Be 7
        $profile.choices.channelMode | Should -BeExactly 'named'
        $profile.hashes.sourceCount | Should -Be 1
        $profile.sources[0].sha256 | Should -BeExactly (('A' * 64).ToLowerInvariant())
        $profile.operator.name | Should -BeExactly '<USER>'
        $profile.notes[0] | Should -Not -Match 'HOST-9|bob'
    }

    It 'rejects a profile after its content changes' {
        $path = Join-Path $TestDrive 'case-profile-bad.json'
        New-LogVerdictCaseProfile -Result $script:CaseResult -Path $path | Out-Null
        $profile = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $profile.purpose = 'changed'
        $profile | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $path -Encoding UTF8

        Test-LogVerdictCaseProfile -Path $path -Quiet | Should -BeFalse
        { Test-LogVerdictCaseProfile -Path $path } | Should -Throw '*profileId*'
    }

    It 'emits deterministic attributed Timesketch and Hayabusa handoff files' {
        $profile = New-LogVerdictCaseProfile -Result $script:CaseResult -Name 'Handoff' -OperatorName 'analyst' -Ticket 'INC-42'
        $firstDir = Join-Path $TestDrive 'handoff-one'
        $secondDir = Join-Path $TestDrive 'handoff-two'
        $first = Export-LogVerdictHandoff -Result $script:CaseResult -Profile $profile -OutputDir $firstDir
        $second = Export-LogVerdictHandoff -Result $script:CaseResult -Profile $profile -OutputDir $secondDir

        @($first.Files).Count | Should -Be 6
        $timesketch = @(Import-Csv -LiteralPath (Join-Path $firstDir 'LogVerdict-Timesketch.csv'))
        $timesketch.Count | Should -Be 1
        $timesketch[0].message | Should -Match 'HOST-9'
        $timesketch[0].datetime | Should -Match '^2026-08-02T'
        $timesketch[0].timestamp_desc | Should -BeExactly 'LogVerdict first observed'
        $timesketch[0].logverdict_profile_id | Should -BeExactly $profile.profileId
        $hayabusa = @(Import-Csv -LiteralPath (Join-Path $firstDir 'LogVerdict-Hayabusa.csv'))
        $hayabusa[0].RuleTitle | Should -BeExactly 'Test finding'
        $hayabusa[0].Level | Should -BeExactly 'INVESTIGATE'
        (Get-Content -LiteralPath (Join-Path $firstDir 'LogVerdict-Collection.yaml') -Raw) | Should -Match 'type: CLIENT'
        (Get-Content -LiteralPath (Join-Path $firstDir 'LogVerdict-Collection.tkape') -Raw) | Should -Match 'Profile'
        (Get-Content -LiteralPath (Join-Path $firstDir 'LogVerdict-Timesketch.csv') -Raw) | Should -BeExactly (Get-Content -LiteralPath (Join-Path $secondDir 'LogVerdict-Timesketch.csv') -Raw)
    }

    It 'keeps the profile visible in reports and standard export context' {
        $result = $script:CaseResult | Select-Object *
        $profile = New-LogVerdictCaseProfile -Result $result -Name 'Report case' -Note 'operator note'
        $result | Add-Member -NotePropertyName CaseProfile -NotePropertyValue $profile -Force
        $out = Join-Path $TestDrive 'case-reports'
        Export-LogVerdictReport -Result $result -OutputDir $out -Format Text,Html | Out-Null
        $text = Get-Content -LiteralPath (Join-Path $out 'LogVerdict-Report.txt') -Raw
        $html = Get-Content -LiteralPath (Join-Path $out 'LogVerdict-Report.html') -Raw
        $text | Should -Match 'CASE PROFILE / HANDOFF'
        $html | Should -Match 'CASE PROFILE / HANDOFF'
        $standard = Export-LogVerdictStandard -Result $result -Format Ocsf
        $standard.Document.scan.caseProfile.profileId | Should -BeExactly $profile.profileId
    }

    It 'wires the profile path through console, scan, and GUI entry points' {
        $root = Split-Path $PSScriptRoot -Parent
        $scan = Get-Content -LiteralPath (Join-Path $root 'Public\Invoke-LogVerdictScan.ps1') -Raw
        $entry = Get-Content -LiteralPath (Join-Path $root 'Invoke-LogVerdict.ps1') -Raw
        $gui = Get-Content -LiteralPath (Join-Path $root 'Public\Show-LogVerdictGui.ps1') -Raw
        $guiEntry = Get-Content -LiteralPath (Join-Path $root 'LogVerdict-GUI.ps1') -Raw
        $scan | Should -Match 'CaseProfilePath'
        $entry | Should -Match 'CaseProfilePath'
        $gui | Should -Match 'CaseProfilePath'
        $guiEntry | Should -Match 'CaseProfilePath'
    }
}


Describe 'Module surface' {
    It 'exports exactly the documented public functions' {
        $exported = (Get-Module LogVerdict).ExportedFunctions.Keys | Sort-Object
        $exported | Should -Be @(
            'Compare-LogVerdictScan',
            'Export-LogVerdictHandoff',
            'Export-LogVerdictReport',
            'Export-LogVerdictStandard',
            'Get-LogVerdictAdvisory',
            'Get-LogVerdictDatabase',
            'Get-LogVerdictErrorCatalog',
            'Invoke-LogVerdictScan',
            'New-LogVerdictCaseProfile',
            'Show-LogVerdictGui',
            'Show-LogVerdictReport',
            'Test-LogVerdictAdvisoryDatabase',
            'Test-LogVerdictCaseProfile',
            'Test-LogVerdictDatabase',
            'Update-LogVerdictAdvisoryDatabase',
            'Update-LogVerdictDatabase',
            'Watch-LogVerdict'
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

    It 'keeps the module, badge, and package metadata on the version source' {
        $root = Split-Path $PSScriptRoot -Parent
        $version = (& (Join-Path $root 'Tools\Get-LogVerdictVersion.ps1')).Trim()
        $manifest = Import-PowerShellDataFile -Path (Join-Path $root 'LogVerdict.psd1')
        $manifest.ModuleVersion | Should -BeExactly $version
        (Get-Content -LiteralPath (Join-Path $root 'README.md') -Raw) | Should -Match ("shields\.io/badge/version-{0}-blue" -f [regex]::Escape($version))
    }
}

Describe 'Dependency advisory knowledge' {
    It 'ships a valid hash-checked offline cache with separate fields' {
        Test-LogVerdictAdvisoryDatabase -Quiet | Should -BeTrue
        $advisory = @(Get-LogVerdictAdvisory -Package PowerShell -Version '7.4.0')
        $advisory.Count | Should -Be 1
        $advisory[0].FindingType | Should -BeExactly 'dependency-advisory'
        $advisory[0].RecordType | Should -BeExactly 'advisory'
        $advisory[0].AffectedRange | Should -Match '7\.4\.14'
        $advisory[0].FixedVersion | Should -Match '7\.4\.14'
        $advisory[0].CVSS | Should -Be 7.8
        $advisory[0].SourceHash | Should -Match '^[0-9a-f]{64}$'
        $advisory[0].PSObject.Properties.Name | Should -Not -Contain 'Verdict'
    }

    It 'matches version ranges without treating fixed versions as affected' {
        @((Get-LogVerdictAdvisory -Package PowerShell -Version '7.4.13')).Count | Should -Be 1
        @((Get-LogVerdictAdvisory -Package PowerShell -Version '7.4.14')).Count | Should -Be 0
        @((Get-LogVerdictAdvisory -Package PowerShell -Version '7.5.4')).Count | Should -Be 1
        @((Get-LogVerdictAdvisory -Package PowerShell -Version '7.5.5')).Count | Should -Be 0
    }

    It 'refuses a cache whose normalized advisory hash was changed' {
        $path = Join-Path $TestDrive 'bad-advisories.json'
        $cache = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data\advisories.json') -Raw | ConvertFrom-Json
        $cache.advisories[0].fixedVersion = '7.4.99'
        $cache | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
        Test-LogVerdictAdvisoryDatabase -Path $path -Quiet | Should -BeFalse
        { Get-LogVerdictAdvisory -Path $path } | Should -Throw '*sourceHash*'
    }

    It 'installs a hash-verified offline cache and can roll it back' {
        $root = Split-Path $PSScriptRoot -Parent
        $source = Join-Path $root 'Data\advisories.json'
        $target = Join-Path $TestDrive 'advisories.local.json'
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $digest = ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($source)))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
        $updated = Update-LogVerdictAdvisoryDatabase -SourcePath $source -TargetPath $target -ExpectedSha256 $digest
        $updated.Action | Should -BeExactly 'update'
        (Test-LogVerdictAdvisoryDatabase -Path $target -Quiet) | Should -BeTrue
        Copy-Item -LiteralPath $target -Destination ($target + '.previous.json') -Force
        $rolled = Update-LogVerdictAdvisoryDatabase -TargetPath $target -Rollback
        $rolled.Action | Should -BeExactly 'rollback'
    }
}

Describe 'Scan comparison' {
    BeforeAll {
        $script:BeforeComparison = [pscustomobject]@{
            ScanTime = [datetime]'2026-07-31 10:00'
            Findings = @(
                [pscustomobject]@{ Key='Disk/7'; Title='Disk error'; Verdict='actionable'; Count=2; PerDay=0.5 }
                [pscustomobject]@{ Key='Old/1'; Title='Old failure'; Verdict='investigate'; Count=4; PerDay=1.0 }
                [pscustomobject]@{ Key='Rate/2'; Title='Rate climb'; Verdict='investigate'; Count=4; PerDay=1.0 }
                [pscustomobject]@{ Key='Severity/3'; Title='Severity climb'; Verdict='investigate'; Count=1; PerDay=0.1 }
                [pscustomobject]@{ Key='Noise/4'; Title='Rounding noise'; Verdict='informational'; Count=1; PerDay=0.03 }
            )
        }
        $script:AfterComparison = [pscustomobject]@{
            ScanTime = [datetime]'2026-08-01 10:00'
            Findings = @(
                [pscustomobject]@{ Key='Disk/7'; Title='Disk error'; Verdict='actionable'; Count=2; PerDay=0.5 }
                [pscustomobject]@{ Key='New/9'; Title='New failure'; Verdict='unknown'; Count=1; PerDay=0.1 }
                [pscustomobject]@{ Key='Rate/2'; Title='Rate climb'; Verdict='investigate'; Count=8; PerDay=1.5 }
                [pscustomobject]@{ Key='Severity/3'; Title='Severity climb'; Verdict='actionable'; Count=1; PerDay=0.1 }
                [pscustomobject]@{ Key='Noise/4'; Title='Rounding noise'; Verdict='informational'; Count=2; PerDay=0.05 }
            )
        }
    }

    It 'emits only new, resolved, and worsening signatures' {
        $changes = @(Compare-LogVerdictScan -Before $script:BeforeComparison -After $script:AfterComparison)
        $changes.Count | Should -Be 4
        @($changes.Change | Sort-Object) | Should -Be @('new', 'resolved', 'worsening', 'worsening')
        @($changes.Key) | Should -Not -Contain 'Disk/7'
        @($changes.Key) | Should -Not -Contain 'Noise/4'
    }

    It 'distinguishes a rate regression from a verdict regression' {
        $changes = @(Compare-LogVerdictScan $script:BeforeComparison $script:AfterComparison)
        ($changes | Where-Object Key -eq 'Rate/2').Reason | Should -Match 'Rate rose from 1\.00/day to 1\.50/day'
        ($changes | Where-Object Key -eq 'Severity/3').Reason | Should -Match 'investigate to actionable'
    }

    It 'accepts two JSON reports from disk' {
        $beforePath = Join-Path $TestDrive 'before.json'
        $afterPath = Join-Path $TestDrive 'after.json'
        $script:BeforeComparison | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $beforePath -Encoding UTF8
        $script:AfterComparison | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $afterPath -Encoding UTF8
        $changes = @(Compare-LogVerdictScan -Before $beforePath -After $afterPath)
        ($changes | Where-Object Change -eq 'resolved').Key | Should -BeExactly 'Old/1'
        ($changes | Where-Object Change -eq 'new').Key | Should -BeExactly 'New/9'
    }

    It 'refuses an object that is not a scan result' {
        { Compare-LogVerdictScan -Before ([pscustomobject]@{ Name='not a report' }) -After $script:AfterComparison } |
            Should -Throw '*no Findings collection*'
    }
}

Describe 'Local baseline history' {
    It 'creates bounded local state without raw event content' {
        $path = Join-Path $TestDrive 'history.json'
        $finding = [pscustomobject]@{
            Key='Acme/1'; Verdict='unknown'; Count=1; PerDay=0.5; RuleId=$null
            SampleMessage='password=super-secret'; MachineName='SECRET-PC'
        }
        $history = InModuleScope LogVerdict -Parameters @{ p = $path; f = $finding } {
            param($p, $f)
            Update-LVScanHistory -Path $p -Finding @($f) -ScanTime ([datetime]'2026-08-01 10:00:00') `
                -DaysBack 2 -RecordCount 12 -SignatureCount 1 -WindowDays 30
        }

        $history.Status | Should -BeExactly 'missing-history'
        $history.Persistence | Should -BeExactly 'created'
        $history.AdvisoryOnly | Should -BeTrue
        Test-Path -LiteralPath $path | Should -BeTrue
        $raw = Get-Content -LiteralPath $path -Raw
        $raw | Should -Not -Match 'super-secret|SECRET-PC|SampleMessage|MachineName'
        @((ConvertFrom-Json $raw).entries).Count | Should -Be 1
    }

    It 'signals a rate increase while preserving the finding verdict' {
        $path = Join-Path $TestDrive 'rate-history.json'
        $first = [pscustomobject]@{ Key='Acme/2'; Verdict='unknown'; Count=1; PerDay=0.5; RuleId=$null }
        $second = [pscustomobject]@{ Key='Acme/2'; Verdict='unknown'; Count=4; PerDay=2.0; RuleId=$null }
        InModuleScope LogVerdict -Parameters @{ p = $path; f = $first } {
            param($p, $f)
            Update-LVScanHistory -Path $p -Finding @($f) -ScanTime ([datetime]'2026-08-01 10:00:00') `
                -DaysBack 1 -RecordCount 1 -SignatureCount 1 -WindowDays 30 | Out-Null
        }
        $history = InModuleScope LogVerdict -Parameters @{ p = $path; f = $second } {
            param($p, $f)
            Update-LVScanHistory -Path $p -Finding @($f) -ScanTime ([datetime]'2026-08-02 10:00:00') `
                -DaysBack 1 -RecordCount 4 -SignatureCount 1 -WindowDays 30
        }

        $history.Status | Should -BeExactly 'signals'
        @($history.Signals | Where-Object Type -eq 'rate-increase').Count | Should -Be 1
        $history.Signals[0].Reason | Should -Match 'baseline|threshold'
        $history.FalsePositiveCaveat | Should -Match 'Advisory only|never changes'
        $second.Verdict | Should -BeExactly 'unknown'
        $history.AdvisoryOnly | Should -BeTrue
    }

    It 'keeps at most thirty entries' {
        $path = Join-Path $TestDrive 'bounded-history.json'
        InModuleScope LogVerdict -Parameters @{ p = $path } {
            param($p)
            for ($index = 0; $index -lt 40; $index++) {
                $finding = [pscustomobject]@{ Key=('Acme/{0}' -f $index); Verdict='unknown'; Count=1; PerDay=0.1; RuleId=$null }
                Update-LVScanHistory -Path $p -Finding @($finding) -ScanTime ([datetime]'2026-07-01 10:00:00').AddDays($index) `
                    -DaysBack 1 -RecordCount 1 -SignatureCount 1 -WindowDays 30 | Out-Null
            }
        }

        @((Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).entries).Count | Should -Be 30
    }

    It 'does not overwrite malformed history' {
        $path = Join-Path $TestDrive 'malformed-history.json'
        $original = '{ not-json'
        Set-Content -LiteralPath $path -Value $original -Encoding UTF8
        $history = InModuleScope LogVerdict -Parameters @{ p = $path } {
            param($p)
            $finding = [pscustomobject]@{ Key='Acme/3'; Verdict='unknown'; Count=1; PerDay=0.1; RuleId=$null }
            Update-LVScanHistory -Path $p -Finding @($finding) -ScanTime ([datetime]'2026-08-02 10:00:00') `
                -DaysBack 1 -RecordCount 1 -SignatureCount 1 -WindowDays 30
        }

        $history.Status | Should -BeExactly 'unreadable'
        $history.Persistence | Should -BeExactly 'not-written'
        (Get-Content -LiteralPath $path -Raw).Trim() | Should -BeExactly $original
    }

    It 'reports disabled state when no history path is supplied' {
        InModuleScope LogVerdict {
            $finding = [pscustomobject]@{ Key='Acme/4'; Verdict='unknown'; Count=1; PerDay=0.1; RuleId=$null }
            $history = Update-LVScanHistory -Path $null -Finding @($finding) -ScanTime (Get-Date) `
                -DaysBack 1 -RecordCount 1 -SignatureCount 1
            $history.Status | Should -BeExactly 'disabled'
            $history.Enabled | Should -BeFalse
            $history.AdvisoryOnly | Should -BeTrue
        }
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

    It 'exposes and forwards the explicit raw-evidence override' {
        $entry = Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-LogVerdict.ps1'
        $text = Get-Content -LiteralPath $entry -Raw
        $text | Should -Match '\[switch\]\$AllowRawEvidence'
        $text | Should -Match 'AllowRawEvidence\s*=\s*\$AllowRawEvidence'
    }

    It 'exposes the explicit local-model opt-in on the entry script' {
        $entry = Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-LogVerdict.ps1'
        $text = Get-Content -LiteralPath $entry -Raw
        $text | Should -Match '\[switch\]\$ExplainUnknown'
        $text | Should -Match 'ExplainUnknown\s*=\s*\$ExplainUnknown'
        $text | Should -Match '\[switch\]\$PromoteToRule'
        $text | Should -Match 'PromoteToRule\s*=\s*\$PromoteToRule'
        $scan = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Public\Invoke-LogVerdictScan.ps1') -Raw
        $scan | Should -Match '\$modelRequested\s*=\s*\[bool\]\(\$ExplainUnknown\s+-or\s+\$PromoteToRule\)'
    }

    It 'passes the focused diagnostic-channel tier through the entry script' {
        $entry = Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-LogVerdict.ps1'
        $text = Get-Content -LiteralPath $entry -Raw
        $text | Should -Match '\[switch\]\$DiagnosticChannels'
        $text | Should -Match 'DiagnosticChannels\s*=\s*\$DiagnosticChannels'
    }

    It 'exposes and forwards opt-in history settings' {
        $entry = Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-LogVerdict.ps1'
        $text = Get-Content -LiteralPath $entry -Raw
        $text | Should -Match '\[string\]\$HistoryPath'
        $text | Should -Match 'HistoryPath\s*=\s*\$HistoryPath'
        $text | Should -Match '\[ValidateRange\(1, 3650\)\]\[int\]\$HistoryWindowDays'
        $scan = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Public\Invoke-LogVerdictScan.ps1') -Raw
        $scan | Should -Match 'HistoryWindowDays\s*=\s*30'
        $scan | Should -Match 'Update-LVScanHistory'
    }

    It 'exposes optional offline advisory settings without coupling them to verdicts' {
        $root = Split-Path $PSScriptRoot -Parent
        $entry = Get-Content -LiteralPath (Join-Path $root 'Invoke-LogVerdict.ps1') -Raw
        $scan = Get-Content -LiteralPath (Join-Path $root 'Public\Invoke-LogVerdictScan.ps1') -Raw
        $entry | Should -Match '\[string\]\$AdvisoryPath'
        $entry | Should -Match 'AdvisoryPackage\s*=\s*\$AdvisoryPackage'
        $entry | Should -Match 'AdvisoryVersion\s*=\s*\$AdvisoryVersion'
        $scan | Should -Match 'Get-LVAdvisoryScanContext'
        $scan | Should -Match 'Advisories\s*=\s*@\(\$advisoryContext\.Records\)'
        $scan.IndexOf('Advisories     =') | Should -BeLessThan $scan.IndexOf('WorstVerdict')
    }

    It 'bounds the public scan window consistently' {
        $root = Split-Path $PSScriptRoot -Parent
        $entry = Get-Content -LiteralPath (Join-Path $root 'Invoke-LogVerdict.ps1') -Raw
        $scan = Get-Content -LiteralPath (Join-Path $root 'Public\Invoke-LogVerdictScan.ps1') -Raw
        $entry | Should -Match '\[ValidateRange\(1, 3650\)\]\[int\]\$DaysBack'
        $scan | Should -Match '\[ValidateRange\(1, 3650\)\]\[int\]\$DaysBack'
        { Invoke-LogVerdictScan -DaysBack 0 } | Should -Throw
        { Invoke-LogVerdictScan -DaysBack 3651 } | Should -Throw
    }

    It 'gives named channels precedence and rejects contradictory broad modes' {
        $scan = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Public\Invoke-LogVerdictScan.ps1') -Raw
        $scan.IndexOf('if ($Channel)') | Should -BeLessThan $scan.IndexOf('} elseif ($AllChannels)')
        $scan | Should -Match 'if \(\$AllChannels -and \$DiagnosticChannels\)'
        $scan | Should -Match 'Choose only one broad channel mode'
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

    It 'ships more than 150 curated rules' {
        @((Get-LogVerdictDatabase).rules).Count | Should -BeGreaterThan 150
    }

    It 'covers every documented Sysmon event type' {
        $rules = @((Get-LogVerdictDatabase).rules | Where-Object { $_.match.provider -eq 'Microsoft-Windows-Sysmon' })
        $expected = @(1..29) + @(255)
        @($rules.match.eventId | Sort-Object) | Should -Be @($expected | Sort-Object)
    }

    It 'covers Defender detection, remediation, health, and tamper events' {
        $ids = @((Get-LogVerdictDatabase).rules |
            Where-Object { $_.match.provider -eq 'Microsoft-Windows-Windows Defender' } |
            Select-Object -ExpandProperty match |
            Select-Object -ExpandProperty eventId)
        foreach ($eventId in @(1006, 1008, 1116, 1117, 1118, 1119, 1121, 1127, 5001, 5007, 5008, 5010, 5012, 5013)) {
            $ids | Should -Contain $eventId
        }
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
        $schemaConfidence = @($schema.definitions.rule.properties.confidence.enum) | Sort-Object

        InModuleScope LogVerdict -Parameters @{ sv = $schemaVerdicts; ss = $schemaStatuses; sc = $schemaConfidence } {
            param($sv, $ss, $sc)
            ($sv -join ',') | Should -Be ((@($script:LVVerdictRank.Keys) | Sort-Object) -join ',')
            ($ss -join ',') | Should -Be ((@($script:LVRuleStatus) | Sort-Object) -join ',')
            ($sc -join ',') | Should -Be ((@($script:LVRuleConfidence) | Sort-Object) -join ',')
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

Describe 'Bundled Microsoft error catalog' {
    It 'ships the current catalog families with provenance' {
        $catalog = Get-LogVerdictErrorCatalog
        @($catalog).Count | Should -BeGreaterThan 3000
          @($catalog | Where-Object kind -eq 'win32').Count | Should -BeGreaterOrEqual 2745
          @($catalog | Where-Object kind -eq 'bugcheck').Count | Should -BeGreaterOrEqual 378
          @($catalog | Where-Object kind -eq 'hresult').Count | Should -BeGreaterOrEqual 13
          @($catalog | Where-Object kind -eq 'ntstatus').Count | Should -BeGreaterOrEqual 9
          @($catalog | Where-Object kind -eq 'setup').Count | Should -BeGreaterOrEqual 7
          @($catalog | Where-Object kind -eq 'windowsupdate').Count | Should -BeGreaterOrEqual 5
          @($catalog.id | Select-Object -Unique).Count | Should -Be @($catalog).Count
          $catalog[0].sourceHash | Should -Match '^[0-9a-f]{64}$'
          foreach ($entry in @($catalog | Select-Object -First 20)) {
              $entry.reference | Should -Match '^https://learn\.microsoft\.com/'
              $entry.description | Should -Not -BeNullOrEmpty
              $entry.explanation | Should -Not -BeNullOrEmpty
              $entry.normalized.family | Should -BeExactly $entry.kind
              $entry.normalized.hex | Should -Match '^0x[0-9A-F]{8}$'
              $entry.sourceHash | Should -Match '^[0-9a-f]{64}$'
              $entry.applicability | Should -Not -BeNullOrEmpty
          }
    }

    It 'resolves common Win32 and HRESULT lookups locally' {
        $win32 = @(Get-LogVerdictErrorCatalog -Kind win32 -Hex '0x5')
        $win32.Count | Should -Be 1
        $win32[0].name | Should -BeExactly 'ERROR_ACCESS_DENIED'
        $hresult = @(Get-LogVerdictErrorCatalog -Kind hresult -Hex '0x80070005')
        $hresult.Count | Should -Be 1
        $hresult[0].name | Should -BeExactly 'E_ACCESSDENIED'
          $bugcheck = @(Get-LogVerdictErrorCatalog -Kind bugcheck -Hex '0x124')
          $bugcheck.Count | Should -Be 1
          $bugcheck[0].name | Should -BeExactly 'WHEA_UNCORRECTABLE_ERROR'
          $ntstatus = @(Get-LogVerdictErrorCatalog -Kind ntstatus -Hex '0xC0000022')
          $ntstatus.Count | Should -Be 1
          $ntstatus[0].name | Should -BeExactly 'STATUS_ACCESS_DENIED'
          $ntstatus[0].normalized.severity | Should -BeExactly 'error'
          $setup = @(Get-LogVerdictErrorCatalog -Kind setup -Hex '0xC1900101')
          $setup.Count | Should -Be 1
          $setup[0].operation | Should -BeExactly 'process'
          $update = @(Get-LogVerdictErrorCatalog -Kind windowsupdate -Hex '0x80240017')
          $update.Count | Should -Be 1
          $update[0].name | Should -BeExactly 'WU_E_NOT_APPLICABLE'
    }

    It 'enriches unknown signatures without changing their unknown verdict' {
        InModuleScope LogVerdict {
            $hresultSignature = [pscustomobject]@{
                Key='CBS/unknown'; Source='textlog'; Channel='CBS'; Provider='CBS'; Id=0
                SampleMessage='Error code: 0x80070005'; Count=1; PerDay=0.03
            }
            $resolved = @(Resolve-LVVerdict -Signature @($hresultSignature) -Database ([pscustomobject]@{ rules=@() }))
            $resolved[0].Verdict | Should -BeExactly 'unknown'
            $resolved[0].ErrorName | Should -BeExactly 'E_ACCESSDENIED'
              $resolved[0].ErrorCode | Should -BeExactly '0x80070005'
              $resolved[0].Plain | Should -Match 'General access denied error'
              $resolved[0].Action | Should -Match 'provider and operation'

              $fromWin32Signature = [pscustomobject]@{
                  Key='CBS/win32-fallback'; Source='textlog'; Channel='CBS'; Provider='CBS'; Id=0
                  SampleMessage='Error code: 0x8007000A'; Count=1; PerDay=0.03
              }
              $fromWin32 = @(Resolve-LVVerdict -Signature @($fromWin32Signature) -Database ([pscustomobject]@{ rules=@() }))
              $fromWin32[0].ErrorName | Should -BeExactly 'ERROR_BAD_ENVIRONMENT'
              $fromWin32[0].ErrorCatalogKind | Should -BeExactly 'win32'

            $bugcheckSignature = [pscustomobject]@{
                Key='Minidump/0x00000124'; Source='textlog'; Channel='Minidump'; Provider='Crash artifact'; Id=0
                SampleMessage='Kernel minidump bug check 0x00000124; parameters 0x0'; Count=1; PerDay=0.03
            }
            $bugcheck = @(Resolve-LVVerdict -Signature @($bugcheckSignature) -Database ([pscustomobject]@{ rules=@() }))
              $bugcheck[0].ErrorName | Should -BeExactly 'WHEA_UNCORRECTABLE_ERROR'
              $bugcheck[0].Action | Should -Match 'WinDbg'

              $ntstatusSignature = [pscustomobject]@{
                  Key='Native/unknown'; Source='textlog'; Channel='CBS'; Provider='Native'; Id=0
                  SampleMessage='Native status: 0xC0000022'; Count=1; PerDay=0.03
              }
              $ntstatus = @(Resolve-LVVerdict -Signature @($ntstatusSignature) -Database ([pscustomobject]@{ rules=@() }))
              $ntstatus[0].ErrorName | Should -BeExactly 'STATUS_ACCESS_DENIED'
              $ntstatus[0].ErrorCatalogKind | Should -BeExactly 'ntstatus'

              $setupSignature = [pscustomobject]@{
                  Key='Setup/unknown'; Source='textlog'; Channel='SetupDiag'; Provider='Setup'; Id=0
                  SampleMessage='Setup result 0xC1900101; extend code 0x00000000'; Count=1; PerDay=0.03
              }
              $setup = @(Resolve-LVVerdict -Signature @($setupSignature) -Database ([pscustomobject]@{ rules=@() }))
              $setup[0].ErrorName | Should -BeExactly 'MOSETUP_E_PROCESS_CRASH'

              $unknownSignature = [pscustomobject]@{
                  Key='Native/unknown-code'; Source='textlog'; Channel='CBS'; Provider='Native'; Id=0
                  SampleMessage='Native status: 0xC0DECAFE'; Count=1; PerDay=0.03
              }
              $unknown = @(Resolve-LVVerdict -Signature @($unknownSignature) -Database ([pscustomobject]@{ rules=@() }))
              $unknown[0].ErrorName | Should -BeNullOrEmpty
          }
      }

      It 'rejects a catalog entry whose family and id disagree' {
          $path = Join-Path $TestDrive 'bad-error-catalog.json'
          $catalog = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data/error-codes.json') -Raw | ConvertFrom-Json
          $catalog.entries[0].id = 'hresult:0x00000001'
          $catalog | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
          { Get-LogVerdictErrorCatalog -Path $path } | Should -Throw '*id/family mismatch*'
      }

    It 'keeps the default scan path free of network calls' {
        $module = Get-Module LogVerdict
        $loader = (& $module { (Get-Command Get-LVErrorCatalog).ScriptBlock.ToString() })
        $resolver = (& $module { (Get-Command Resolve-LVVerdict).ScriptBlock.ToString() })
        $loader + $resolver | Should -Not -Match 'Invoke-(WebRequest|RestMethod)'
        $catalogPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Data/error-codes.json'
        ([IO.File]::ReadAllBytes($catalogPath) | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }

    It 'retains composite setup and update context when prose is localized' {
        $coveragePath = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data') 'coverage-fixtures.json'
        $coverage = Get-Content -LiteralPath $coveragePath -Raw -Encoding UTF8 | ConvertFrom-Json
        $fixtures = @($coverage.fixtures | Where-Object kind -eq 'composite-code')
        $fixtures.Count | Should -Be 2
        InModuleScope LogVerdict -Parameters @{ Fixtures = $fixtures } {
            param($Fixtures)
            foreach ($fixture in $Fixtures) {
                $context = New-LVErrorContext -InputObject $fixture.record -Message $fixture.record.Message `
                    -FallbackMessage $fixture.record.FallbackMessage
                $context.ResultCode | Should -BeExactly $fixture.record.ResultCode
                $context.ExtendCode | Should -BeExactly $fixture.record.ExtendCode
                $context.Phase | Should -BeExactly $fixture.record.Phase
                $context.Operation | Should -BeExactly $fixture.record.Operation
                $context.ProviderLocale | Should -BeExactly $fixture.record.ProviderLocale
                $context.FallbackMessage | Should -BeExactly $fixture.record.FallbackMessage

                $signature = [pscustomobject]@{
                    Key = $fixture.id; Source = $fixture.record.Source; Channel = $fixture.record.Channel
                    Provider = $fixture.record.Provider; Id = [int]$fixture.record.Id
                    SampleMessage = $fixture.record.Message; Count = 1; PerDay = 0.1
                    ResultCode = $context.ResultCode; ExtendCode = $context.ExtendCode
                    Phase = $context.Phase; Operation = $context.Operation
                    ProviderLocale = $context.ProviderLocale; FallbackMessage = $context.FallbackMessage
                    ErrorContext = $context
                }
                $resolved = @(Resolve-LVVerdict -Signature @($signature) -Database ([pscustomobject]@{ rules=@() }))
                $resolved[0].ErrorName | Should -BeExactly $fixture.expected.errorName
                $resolved[0].ErrorPhase | Should -BeExactly $fixture.expected.phase
                $resolved[0].ErrorOperation | Should -BeExactly $fixture.expected.operation
            }

            $setup = $Fixtures | Where-Object id -eq 'setup-composite-code-german'
            $typedRule = [pscustomobject]@{
                id = 'FIXTURE-COMPOSITE'; lvOrdinal = 0
                match = [pscustomobject]@{
                    source = 'textlog'; channel = 'SetupDiag'; provider = 'Microsoft SetupDiag'
                    resultCode = '0xC1900101'; extendCode = '0x00000000'
                    phase = 'Downlevel'; operation = 'Process'; providerLocale = 'de-DE'
                }
                verdict = 'actionable'; title = 'Typed composite fixture'; plain = 'Typed fields matched.'
                why = 'The test does not depend on English message prose.'; action = 'Keep the structured fields.'
                confidence = 'high'
            }
            $typedSignature = [pscustomobject]@{
                Key = 'setup/composite'; Source = 'textlog'; Channel = 'SetupDiag'; Provider = 'Microsoft SetupDiag'; Id = 0
                SampleMessage = $setup.record.Message; Count = 1; PerDay = 0.1
                ResultCode = $setup.record.ResultCode; ExtendCode = $setup.record.ExtendCode
                Phase = $setup.record.Phase; Operation = $setup.record.Operation
                ProviderLocale = $setup.record.ProviderLocale; FallbackMessage = $setup.record.FallbackMessage
                ErrorContext = New-LVErrorContext -InputObject $setup.record -Message $setup.record.Message -FallbackMessage $setup.record.FallbackMessage
            }
            $typed = @(Resolve-LVVerdict -Signature @($typedSignature) -Database ([pscustomobject]@{ rules=@($typedRule) }))
            $typed[0].RuleId | Should -BeExactly 'FIXTURE-COMPOSITE'
            $typed[0].Verdict | Should -BeExactly 'actionable'
        }
    }
}

Describe 'Opt-in verdict database updates' {
    It 'hash-verifies and installs a staged database while retaining a rollback copy' {
        $source = Join-Path $TestDrive 'release-verdicts.json'
        $target = Join-Path $TestDrive 'Data/verdicts.local.json'
        $sourceDir = Split-Path -Parent $source
        New-Item -ItemType Directory -Path $sourceDir -Force | Out-Null
        $db = Get-LogVerdictDatabase
        $db.updated = '2026-08-02'
        ($db | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $source -Encoding UTF8
        $hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash

        $result = Update-LogVerdictDatabase -SourcePath $source -ExpectedSha256 $hash -TargetPath $target
        $result.Action | Should -BeExactly 'update'
        $result.RuleCount | Should -BeGreaterThan 150
        (Get-Content -LiteralPath $target -Raw | ConvertFrom-Json).updated | Should -BeExactly '2026-08-02'
        Test-Path -LiteralPath ($target + '.previous.json') | Should -BeFalse
    }

    It 'keeps the installed copy and restores the previous version on rollback' {
        $source = Join-Path $TestDrive 'release-verdicts-2.json'
        $target = Join-Path $TestDrive 'rollback/verdicts.local.json'
        New-Item -ItemType Directory -Path (Split-Path -Parent $source) -Force | Out-Null
        $db = Get-LogVerdictDatabase
        $db.updated = '2026-08-03'
        ($db | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $source -Encoding UTF8
        $hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        Update-LogVerdictDatabase -SourcePath $source -ExpectedSha256 $hash -TargetPath $target | Out-Null

        $db.updated = '2026-08-04'
        ($db | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $source -Encoding UTF8
        $hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        Update-LogVerdictDatabase -SourcePath $source -ExpectedSha256 $hash -TargetPath $target | Out-Null
        (Get-Content -LiteralPath ($target + '.previous.json') -Raw | ConvertFrom-Json).updated | Should -BeExactly '2026-08-03'

        $rollback = Update-LogVerdictDatabase -TargetPath $target -Rollback
        $rollback.Action | Should -BeExactly 'rollback'
        (Get-Content -LiteralPath $target -Raw | ConvertFrom-Json).updated | Should -BeExactly '2026-08-03'
    }

    It 'refuses an incorrect digest before touching the target' {
        $source = Join-Path $TestDrive 'bad-verdicts.json'
        $target = Join-Path $TestDrive 'bad-target/verdicts.local.json'
        $db = Get-LogVerdictDatabase
        ($db | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $source -Encoding UTF8
        { Update-LogVerdictDatabase -SourcePath $source -ExpectedSha256 ('0' * 64) -TargetPath $target } |
            Should -Throw -ExpectedMessage '*SHA-256 mismatch*'
        Test-Path -LiteralPath $target | Should -BeFalse
    }

    It 'does not contact the network during a normal module import or scan' {
        $source = Join-Path (Split-Path $PSScriptRoot -Parent) 'Public/Update-LogVerdictDatabase.ps1'
        (Get-Content -LiteralPath $source -Raw) | Should -Match 'Invoke-RestMethod'
        (Get-Content -LiteralPath $source -Raw) | Should -Match 'Invoke-WebRequest'
        (Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Private/30-LVResolve.ps1') -Raw) |
            Should -Not -Match 'Invoke-(RestMethod|WebRequest)'
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

    It 'defines the focused diagnostic tier explicitly and in stable order' {
        InModuleScope LogVerdict {
            @(Get-LVDiagnosticChannel) | Should -Be @(
                'System'
                'Application'
                'Microsoft-Windows-Ntfs/Operational'
                'Microsoft-Windows-CodeIntegrity/Operational'
                'Microsoft-Windows-Kernel-PnP/Configuration'
                'Microsoft-Windows-AppModel-Runtime/Admin'
                'Microsoft-Windows-Resource-Exhaustion-Detector/Operational'
                'Microsoft-Windows-Kernel-Boot/Operational'
            )
        }
    }

    It 'ships a channel-specific rule for every focused diagnostic channel beyond the defaults' {
        InModuleScope LogVerdict {
            $db = Get-LogVerdictDatabase
            foreach ($channel in @((Get-LVDiagnosticChannel) | Select-Object -Skip 2)) {
                @($db.rules | Where-Object {
                    (Test-LVRuleActive -Rule $_) -and
                    $_.match.source -eq 'event' -and
                    $_.match.channel -eq $channel
                }).Count | Should -BeGreaterThan 0 -Because "$channel must add signal, not only unknowns"
            }
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

    It 'fully masks error codes before the corpus-wide slot pass' {
        InModuleScope LogVerdict {
            $codes = @('0x800f081f', '0x80073712', '0x800f0922')
            $templates = $codes | ForEach-Object {
                ConvertTo-LVTemplate -Text ('2026-07-31 10:00:00, Error CSI 00000123 Failed to stage package. Status = {0}' -f $_)
            }
            (@($templates | Sort-Object -Unique)).Count | Should -Be 1
            $templates[0] | Should -Match '<HEX>'
        }
    }

    It 'normalizes error code casing so it is one signature, not two' {
        InModuleScope LogVerdict {
            $upper = ConvertTo-LVTemplate -Text 'Operation failed 0x800F081F'
            $lower = ConvertTo-LVTemplate -Text 'Operation failed 0x800f081f'
            $upper | Should -Be $lower
            $upper | Should -Match '<HEX>'
        }
    }

    It 'keeps an all-digit error code intact instead of re-masking it' {
        # The preserved value sits between non-word characters, so a code with no
        # letters is exposed to the number mask unless the order is right.
        InModuleScope LogVerdict {
            ConvertTo-LVTemplate -Text 'Failed 0x12345678' | Should -BeExactly 'Failed <HEX>'
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

    It 'masks the structured identities that generic number replacement misses' {
        InModuleScope LogVerdict {
            $text = 'User alice@example.com SID S-1-5-21-123-456-789-1001 reached host.example.com at https://host.example.com/a from fe80::1 using AA-BB-CC-DD-EE-FF version 1.2.3'
            $template = ConvertTo-LVTemplate -Text $text
            foreach ($placeholder in @('<UPN>', '<SID>', '<FQDN>', '<URL>', '<IPV6>', '<MAC>', '<VER>')) {
                $template | Should -Match ([regex]::Escape($placeholder))
            }
            $template | Should -Not -Match 'alice|123-456|host\.example|fe80|AA-BB|1\.2\.3'
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

    It 'reports the masked pass and the low-cardinality promotion pass separately' {
        InModuleScope LogVerdict {
            $now = Get-Date
            $records = @('0x800f081f', '0x80073712') | ForEach-Object {
                [pscustomobject]@{
                    Source='textlog'; Channel='CBS'; Provider='CBS'; Id=0; Level=2; LevelName='Error'
                    TimeCreated=$now; MachineName='TESTPC'; RecordId=1; Message="Failed to stage package with error $_"
                }
            }
            $grouped = Get-LVSignatureReduction -Record $records -WindowDays 30
            $stat = Get-LVReductionStat -Record $records -Signature @($grouped.Signatures) `
                -InitialSignatureCount $grouped.InitialSignatureCount -PromotedSlotCount $grouped.PromotedSlotCount
            $stat.InitialSignatureCount | Should -Be 1
            $stat.InitialRatio | Should -Be 2
            $stat.SignatureCount | Should -Be 2
            $stat.Ratio | Should -Be 1
            $stat.PromotedSlotCount | Should -Be 1
            @($grouped.Signatures.Template | Where-Object { $_ -match '<HEX:[0-9a-f]+>' }).Count | Should -Be 2
        }
    }

    It 'keeps a high-cardinality numeric slot masked' {
        InModuleScope LogVerdict {
            $now = Get-Date
            $records = 1..4 | ForEach-Object {
                [pscustomobject]@{
                    Source='textlog'; Channel='Setup'; Provider='Setup'; Id=0; Level=2; LevelName='Error'
                    TimeCreated=$now; MachineName='TESTPC'; RecordId=$_; Message="Transient operation $_ failed"
                }
            }
            $grouped = Get-LVSignatureReduction -Record $records -WindowDays 30
            @($grouped.Signatures).Count | Should -Be 1
            $grouped.Signatures[0].Template | Should -BeExactly 'Transient operation <NUM> failed'
            @($grouped.Signatures[0].PromotedSlots).Count | Should -Be 0
        }
    }

    It 'includes original token count in a text signature identity' {
        InModuleScope LogVerdict {
            $now = Get-Date
            $records = @(
                [pscustomobject]@{ Source='textlog'; Channel='Setup'; Provider='Setup'; Id=0; Level=2; LevelName='Error'; TimeCreated=$now; Message='Failed 2026-07-31T10:00:00Z' },
                [pscustomobject]@{ Source='textlog'; Channel='Setup'; Provider='Setup'; Id=0; Level=2; LevelName='Error'; TimeCreated=$now; Message='Failed 2026-07-31 10:00:00' }
            )
            $grouped = Get-LVSignatureReduction -Record $records -WindowDays 30
            @($grouped.Signatures).Count | Should -Be 2
            @($grouped.Signatures.Template | Sort-Object -Unique).Count | Should -Be 1
            @($grouped.Signatures.TemplateTokenCount | Sort-Object -Unique) | Should -Be @(2, 3)
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

    It 'detects a compact unknown burst and records its onset' {
        InModuleScope LogVerdict {
            $base = [datetime]'2026-08-01 10:00:00'
            $sig = [pscustomobject]@{
                Times = @($base, $base.AddMinutes(2), $base.AddMinutes(4), $base.AddDays(1))
            }
            $profile = Get-LVUnknownBurstProfile -Signature $sig
            $profile.IsBurst | Should -BeTrue
            $profile.Onset | Should -Be $base
            $profile.ClusterCount | Should -Be 3
            $profile.WindowMinutes | Should -Be 4
        }
    }

    It 'does not call a regular hourly trickle a burst' {
        InModuleScope LogVerdict {
            $base = [datetime]'2026-08-01 10:00:00'
            $sig = [pscustomobject]@{
                Times = 0..5 | ForEach-Object { $base.AddHours($_) }
            }
            Get-LVUnknownBurstProfile -Signature $sig | Should -BeNullOrEmpty
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
                    LevelName='Error'; TimeCreated=$base.AddDays(10); MachineName='T'; RecordId=2; Message='Failed to stage package 1' }
                [pscustomobject]@{ Source='textlog'; Channel='CBS'; Provider='CBS'; Id=0; Level=2
                    LevelName='Error'; TimeCreated=$null; MachineName='T'; RecordId=3; Message='Failed to stage package 1' }
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
            $script:LVTextLogCoverage[0].Status | Should -BeExactly 'truncated'
            $script:LVTextLogCoverage[0].Cap | Should -Be 10
        }
    }

    It 'reports a missing file instead of failing the scan' {
        InModuleScope LogVerdict -Parameters @{ dir = $script:FixtureDir } {
            param($dir)
            $target = @(@{ Name='GONE'; Path=(Join-Path $dir 'does-not-exist.log'); Pattern='.'; Area='t'; Hint='t' })
            $rec = @(Get-LVTextLogRecord -DaysBack 30 -Target $target)
            $rec.Count | Should -Be 0
            $script:LVTextLogCoverage[0].Status | Should -BeExactly 'not-observed'
        }
    }
}

Describe 'SetupDiag Panther integration' {
    BeforeAll {
        $script:SetupDiagFixtureRoot = Join-Path $TestDrive 'Panther'
        $null = New-Item -ItemType Directory -Path $script:SetupDiagFixtureRoot -Force
        $script:SetupDiagLog = Join-Path $script:SetupDiagFixtureRoot 'setupact.log'
        '2026-08-01 10:00:00, Error SP setup failed' | Set-Content -LiteralPath $script:SetupDiagLog -Encoding UTF8
        (Get-Item -LiteralPath $script:SetupDiagLog).LastWriteTime = Get-Date
        $script:SetupDiagExe = Join-Path $TestDrive 'SetupDiag.exe'
        [IO.File]::WriteAllBytes($script:SetupDiagExe, [byte[]](77, 90))
        $script:SetupDiagJson = @{
            Version = '1.7.0.0'
            ProfileName = 'FindSPFatalError'
            ProfileGuid = 'A4028172-1B09-48F8-AD3B-86CDD7D55852'
            SystemInfo = @{ UpgradeEndTime = (Get-Date).AddHours(-2).ToString('o') }
            LogErrorLine = 'SP failed with 0x80070057'
            FailureData = @('Error: SetupDiag reports Fatal Error.', 'Last Setup Phase = Downlevel')
            FailureDetails = 'Err = 0x80070057, LastOperation = Gather data, LastPhase = Downlevel'
            Remediation = @('Remove the incompatible component, reboot, and retry the upgrade.')
        } | ConvertTo-Json -Depth 5
    }

    It 'finds only existing executable candidates and the newest recent log set' {
        InModuleScope LogVerdict -Parameters @{ exe=$script:SetupDiagExe; root=$script:SetupDiagFixtureRoot } {
            param($exe, $root)
            Get-LVSetupDiagExecutable -CandidatePath @((Join-Path $root 'missing.exe'), $exe) | Should -BeExactly $exe
            $set = @(Get-LVSetupDiagLogSet -DaysBack 1 -CandidatePath @($root))
            $set.Count | Should -Be 1
            $set[0].Path | Should -BeExactly $root
            $set[0].Latest | Should -BeGreaterThan (Get-Date).AddHours(-1)
        }
    }

    It 'projects documented JSON fields into an attributed stable signature' {
        InModuleScope LogVerdict -Parameters @{ json=$script:SetupDiagJson } {
            param($json)
            $decoded = ConvertFrom-LVSetupDiagJson -Json $json -FallbackWhen (Get-Date).AddDays(-1)
            $decoded.Successful | Should -BeFalse
            $decoded.Profile | Should -BeExactly 'FindSPFatalError'
            $decoded.Remediation | Should -Be @('Remove the incompatible component, reboot, and retry the upgrade.')
            $decoded.Record.Provider | Should -BeExactly 'Microsoft SetupDiag'
            $decoded.Record.Channel | Should -BeExactly 'SetupDiag'
            $decoded.Record.SignatureKey | Should -BeExactly 'SetupDiag/findspfatalerror'
            $decoded.Record.ResultCode | Should -BeExactly '0x80070057'
            $decoded.Record.Phase | Should -BeExactly 'Downlevel'
            $decoded.Record.Operation | Should -BeExactly 'Gather data'
            $decoded.Record.FallbackMessage | Should -Match 'LastPhase = Downlevel'
            $decoded.Record.Message | Should -Match 'Failure:.*LastPhase = Downlevel'
            $decoded.Record.Message | Should -Match 'Remediation: Remove the incompatible component'

            $signature = @(Group-LVSignature -Record @($decoded.Record) -WindowDays 1)[0]
            $db = Get-LogVerdictDatabase
            $finding = @(Resolve-LVVerdict -Signature @($signature) -Database $db)[0]
            $finding.RuleId | Should -BeExactly 'LV-0327'
            $finding.Verdict | Should -BeExactly 'actionable'
            $finding.Sources[0].uri | Should -BeExactly 'https://learn.microsoft.com/en-us/windows/deployment/upgrade/setupdiag'
        }
    }

    It 'runs the available tool and returns its structured record' {
        InModuleScope LogVerdict -Parameters @{ exe=$script:SetupDiagExe; root=$script:SetupDiagFixtureRoot; json=$script:SetupDiagJson } {
            param($exe, $root, $json)
            Mock Invoke-LVSetupDiagProcess {
                param($ExecutablePath, $LogsPath, $OutputPath, $WorkingDirectory, $TimeoutSeconds)
                [IO.File]::WriteAllText($OutputPath, $json, (New-Object Text.UTF8Encoding($false)))
                [pscustomobject]@{ ExitCode=0; TimedOut=$false; StandardOutput=''; StandardError='' }
            }

            $status = Get-LVSetupDiagRecord -DaysBack 1 -ExecutableCandidate @($exe) -LogCandidate @($root)
            $status.Available | Should -BeTrue
            $status.Used | Should -BeTrue
            $status.Status | Should -BeExactly 'matched'
            $status.Profile | Should -BeExactly 'FindSPFatalError'
            @($status.Records).Count | Should -Be 1
            Assert-MockCalled Invoke-LVSetupDiagProcess -Times 1 -Exactly -Scope It -ParameterFilter {
                $ExecutablePath -eq $exe -and $LogsPath -eq $root -and $TimeoutSeconds -eq 120
            }
        }
    }

    It 'rejects an unsigned production candidate and never executes it' {
        InModuleScope LogVerdict -Parameters @{ exe=$script:SetupDiagExe; root=$script:SetupDiagFixtureRoot } {
            param($exe, $root)
            $exe | Should -Exist
            Mock Get-Command { [pscustomobject]@{ Path=$exe; Source=$exe } }
            Mock Test-LVSetupDiagExecutableTrust {
                [pscustomobject]@{ Trusted=$false; Reason='Authenticode status is NotSigned, not Valid.' }
            }
            Mock Invoke-LVSetupDiagProcess { throw 'must not run' }

            $status = Get-LVSetupDiagRecord -DaysBack 1 -LogCandidate @($root)
            $status.Available | Should -BeFalse
            $status.Used | Should -BeFalse
            $status.Status | Should -BeExactly 'untrusted'
            $status.Message | Should -Match 'Authenticode trust policy'
            $status.CoverageNote | Should -BeExactly $status.Message
            Assert-MockCalled Test-LVSetupDiagExecutableTrust -Times 1 -Exactly -Scope It
            Assert-MockCalled Invoke-LVSetupDiagProcess -Times 0 -Exactly -Scope It
        }
    }

    It 'accepts a valid Microsoft-signed production candidate' {
        InModuleScope LogVerdict -Parameters @{ exe=$script:SetupDiagExe; root=$script:SetupDiagFixtureRoot; json=$script:SetupDiagJson } {
            param($exe, $root, $json)
            $exe | Should -Exist
            $json | Should -Match 'FindSPFatalError'
            Mock Get-Command { [pscustomobject]@{ Path=$exe; Source=$exe } }
            Mock Test-LVSetupDiagExecutableTrust {
                [pscustomobject]@{ Trusted=$true; Reason='Valid Microsoft Authenticode signature.' }
            }
            Mock Invoke-LVSetupDiagProcess {
                param($OutputPath)
                [IO.File]::WriteAllText($OutputPath, $json, (New-Object Text.UTF8Encoding($false)))
                [pscustomobject]@{ ExitCode=0; TimedOut=$false; StandardOutput=''; StandardError='' }
            }

            $status = Get-LVSetupDiagRecord -DaysBack 1 -LogCandidate @($root)
            $status.Status | Should -BeExactly 'matched'
            Assert-MockCalled Test-LVSetupDiagExecutableTrust -Times 1 -Exactly -Scope It
            Assert-MockCalled Invoke-LVSetupDiagProcess -Times 1 -Exactly -Scope It
        }
    }

    It 'degrades explicitly when SetupDiag is absent' {
        InModuleScope LogVerdict -Parameters @{ root=$script:SetupDiagFixtureRoot } {
            param($root)
            Mock Invoke-LVSetupDiagProcess { throw 'must not run' }
            $status = Get-LVSetupDiagRecord -DaysBack 1 -ExecutableCandidate @((Join-Path $root 'missing.exe')) -LogCandidate @($root)
            $status.Available | Should -BeFalse
            $status.Used | Should -BeFalse
            $status.Status | Should -BeExactly 'absent'
            $status.Message | Should -Match 'built-in text rules'
            @($status.Records).Count | Should -Be 0
            Assert-MockCalled Invoke-LVSetupDiagProcess -Times 0 -Exactly -Scope It
        }
    }

    It 'keeps built-in rules active on timeout and invalid output' {
        InModuleScope LogVerdict -Parameters @{ exe=$script:SetupDiagExe; root=$script:SetupDiagFixtureRoot } {
            param($exe, $root)
            Mock Invoke-LVSetupDiagProcess {
                [pscustomobject]@{ ExitCode=$null; TimedOut=$true; StandardOutput=''; StandardError='' }
            }
            $timeout = Get-LVSetupDiagRecord -DaysBack 1 -ExecutableCandidate @($exe) -LogCandidate @($root) -TimeoutSeconds 1
            $timeout.Status | Should -BeExactly 'timeout'
            $timeout.Message | Should -Match 'built-in Panther rules remain active'

            Mock Invoke-LVSetupDiagProcess {
                param($ExecutablePath, $LogsPath, $OutputPath)
                [IO.File]::WriteAllText($OutputPath, '{not-json')
                [pscustomobject]@{ ExitCode=0; TimedOut=$false; StandardOutput=''; StandardError='' }
            }
            $invalid = Get-LVSetupDiagRecord -DaysBack 1 -ExecutableCandidate @($exe) -LogCandidate @($root)
            $invalid.Status | Should -BeExactly 'invalid-output'
            $invalid.Message | Should -Match 'built-in Panther rules remain active'
            @($invalid.Records).Count | Should -Be 0

            Mock Invoke-LVSetupDiagProcess { throw 'The requested operation requires elevation.' }
            $denied = Get-LVSetupDiagRecord -DaysBack 1 -ExecutableCandidate @($exe) -LogCandidate @($root)
            $denied.Status | Should -BeExactly 'requires-elevation'
            $denied.Used | Should -BeFalse
            $denied.Message | Should -Match 'built-in Panther rules remain active'
        }
    }

    It 'does not turn a successful upgrade profile into a failure' {
        InModuleScope LogVerdict {
            $json = @{
                Version='1.7.0.0'; ProfileName='FindSuccessfulUpgrade'
                SystemInfo=@{ UpgradeEndTime='2026-08-01T10:00:00' }
                FailureData=@(); Remediation=@()
            } | ConvertTo-Json -Depth 4
            $decoded = ConvertFrom-LVSetupDiagJson -Json $json -FallbackWhen (Get-Date)
            $decoded.Successful | Should -BeTrue
            $decoded.Record | Should -BeNullOrEmpty
        }
    }

    It 'invokes offline JSON mode with telemetry, zip, and registry writes disabled' {
        InModuleScope LogVerdict {
            $text = (Get-Command Invoke-LVSetupDiagProcess).ScriptBlock.ToString()
            $text | Should -Match '/LogsPath:'
            $text | Should -Match '/Format:json'
            $text | Should -Match '/ZipLogs:False'
            $text | Should -Match '/NoTel'
            $text | Should -Not -Match '/AddReg'
        }
    }

    It 'publishes status without duplicating raw SetupDiag records' {
        $path = Join-Path (Split-Path $PSScriptRoot -Parent) 'Public/Invoke-LogVerdictScan.ps1'
        $text = Get-Content -LiteralPath $path -Raw
        $text | Should -Match 'if \(\$property\.Name -ne ''Records''\)'
        $text | Should -Match 'SetupDiag\s+= \$setupDiagStatus'
        $text | Should -Match 'CoverageNote'
    }
}

Describe 'Crash artifact header decoding' {
    BeforeAll {
        $script:CrashFixtureDir = Join-Path $TestDrive 'crash-artifacts'
        $script:WerFixtureRoot = Join-Path $script:CrashFixtureDir 'ReportArchive'
        $script:WerFixtureDir = Join-Path $script:WerFixtureRoot 'AppCrash_widget.exe_test'
        New-Item -ItemType Directory -Path $script:WerFixtureDir -Force | Out-Null
        $script:WerFixturePath = Join-Path $script:WerFixtureDir 'Report.wer'
        @(
            'Version=1'
            'EventType=APPCRASH'
            'AppName=C:\Program Files\Widget\Widget.exe'
            'Sig[0].Name=Application Name'
            'Sig[0].Value=Widget.exe'
            'Sig[1].Name=Application Version'
            'Sig[1].Value=4.2.1.0'
            'Sig[2].Name=Exception Code'
            'Sig[2].Value=c0000005'
            # Deliberately not P3: selection must follow the label, because indexes
            # differ between WER event types.
            'Sig[7].Name=Fault Module Name'
            'Sig[7].Value=C:\Program Files\Widget\widget-core.dll'
        ) | Set-Content -LiteralPath $script:WerFixturePath -Encoding Unicode

        $script:DumpFixturePath = Join-Path $script:CrashFixtureDir 'kernel-x64.dmp'
        $bytes = New-Object byte[] 0x60
        [Text.Encoding]::ASCII.GetBytes('PAGEDU64').CopyTo($bytes, 0)
        [BitConverter]::GetBytes([uint32]0x0000007E).CopyTo($bytes, 0x38)
        [BitConverter]::GetBytes([uint64]1).CopyTo($bytes, 0x40)
        [BitConverter]::GetBytes([uint64]2).CopyTo($bytes, 0x48)
        [BitConverter]::GetBytes([uint64]3).CopyTo($bytes, 0x50)
        [BitConverter]::GetBytes([uint64]4).CopyTo($bytes, 0x58)
        [IO.File]::WriteAllBytes($script:DumpFixturePath, $bytes)

        $script:Dump32FixturePath = Join-Path $script:CrashFixtureDir 'kernel-x86.dmp'
        $bytes32 = New-Object byte[] 0x3c
        [Text.Encoding]::ASCII.GetBytes('PAGEDUMP').CopyTo($bytes32, 0)
        [BitConverter]::GetBytes([uint32]0x0000009F).CopyTo($bytes32, 0x28)
        [BitConverter]::GetBytes([uint32]10).CopyTo($bytes32, 0x2c)
        [BitConverter]::GetBytes([uint32]11).CopyTo($bytes32, 0x30)
        [BitConverter]::GetBytes([uint32]12).CopyTo($bytes32, 0x34)
        [BitConverter]::GetBytes([uint32]13).CopyTo($bytes32, 0x38)
        [IO.File]::WriteAllBytes($script:Dump32FixturePath, $bytes32)

        $script:BadDumpFixturePath = Join-Path $script:CrashFixtureDir 'not-a-kernel-dump.dmp'
        [IO.File]::WriteAllBytes($script:BadDumpFixturePath, [Text.Encoding]::ASCII.GetBytes('MDMPbad!'))
    }

    It 'reads WER parameters by label and keys a signature on app plus faulting module' {
        InModuleScope LogVerdict -Parameters @{ root = $script:WerFixtureRoot } {
            param($root)
            $artifacts = @(Get-LVCrashArtifact -DaysBack 1 -DumpPath @() -WerRoot $root)
            $artifacts.Count | Should -Be 1
            $artifact = $artifacts[0]
            $artifact.Decoded | Should -BeTrue
            $artifact.App | Should -BeExactly 'Widget.exe'
            $artifact.Module | Should -BeExactly 'widget-core.dll'
            $artifact.ExceptionCode | Should -BeExactly 'c0000005'

            $record = ConvertTo-LVCrashRecord -Artifact $artifact
            $signature = @(Group-LVSignature -Record @($record) -WindowDays 1)[0]
            $signature.Key | Should -BeExactly 'WER/widget.exe/widget-core.dll'
            $signature.SampleMessage | Should -Match 'application version=4\.2\.1\.0'
        }
    }

    It 'reads the x64 stop code and all four fixed-width parameters' {
        InModuleScope LogVerdict -Parameters @{ path = $script:DumpFixturePath } {
            param($path)
            $header = Get-LVKernelDumpHeader -Path $path
            $header.Decoded | Should -BeTrue
            $header.Architecture | Should -BeExactly 'x64'
            $header.BugCheckCode | Should -BeExactly '0x0000007E'
            $header.BugCheckParameters | Should -Be @(
                '0x0000000000000001', '0x0000000000000002',
                '0x0000000000000003', '0x0000000000000004'
            )

            $artifact = [pscustomobject]@{
                Kind = 'minidump'; Decoded = $true; When = (Get-Date)
                BugCheckCode = $header.BugCheckCode; BugCheckParameters = $header.BugCheckParameters
            }
            $record = ConvertTo-LVCrashRecord -Artifact $artifact
            $record.SignatureKey | Should -BeExactly 'Minidump/0x0000007e'
        }
    }

    It 'reads the x86 stop code and 32-bit parameters at their own offsets' {
        InModuleScope LogVerdict -Parameters @{ path = $script:Dump32FixturePath } {
            param($path)
            $header = Get-LVKernelDumpHeader -Path $path
            $header.Decoded | Should -BeTrue
            $header.Architecture | Should -BeExactly 'x86'
            $header.BugCheckCode | Should -BeExactly '0x0000009F'
            $header.BugCheckParameters | Should -Be @(
                '0x0000000A', '0x0000000B', '0x0000000C', '0x0000000D'
            )
        }
    }

    It 'leaves an unrecognized or truncated dump undecoded instead of guessing' {
        InModuleScope LogVerdict -Parameters @{ path = $script:BadDumpFixturePath } {
            param($path)
            $header = Get-LVKernelDumpHeader -Path $path
            $header.Decoded | Should -BeFalse
            $header.BugCheckCode | Should -BeNullOrEmpty
            $header.Reason | Should -Match 'Unrecognized dump signature'
            ConvertTo-LVCrashRecord -Artifact ([pscustomobject]@{ Kind='minidump'; Decoded=$false }) |
                Should -BeNullOrEmpty
        }
    }

    It 'reports an absent crash source as skipped rather than as health' {
        $scan = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'Public\Invoke-LogVerdictScan.ps1') -Raw
        $scan | Should -Match 'source was absent or empty, not a clean-health signal'
        $scan | Should -Match 'were not checked'
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
            $script:LVEventCoverage[0].Status | Should -BeExactly 'empty'
            $script:LVEventCoverage[0].Reason | Should -Match 'No matching'
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
            $script:LVEventCoverage[0].Status | Should -BeExactly 'not-observed'
            $script:LVEventCoverage[0].ParserError | Should -Match 'localized: denied'
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
            $script:LVEventCoverage[0].Status | Should -BeExactly 'truncated'
            $script:LVEventCoverage[0].Cap | Should -Be 5
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

Describe 'Cross-version, locale, and fixture coverage' {
    BeforeAll {
        $script:CoverageFixturePath = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data') 'coverage-fixtures.json'
        $script:CoverageFixtures = Get-Content -LiteralPath $script:CoverageFixturePath -Raw -Encoding UTF8 | ConvertFrom-Json
    }

    It 'ships a versioned manifest with every required coverage kind' {
        $script:CoverageFixtures.schemaVersion | Should -Be 1
        $fixtures = @($script:CoverageFixtures.fixtures)
        @($fixtures | Group-Object id | Where-Object Count -gt 1).Count | Should -Be 0
        foreach ($kind in @('event', 'textlog', 'offline-evtx', 'elevation', 'gui', 'display')) {
            @($fixtures | Where-Object kind -eq $kind).Count | Should -BeGreaterThan 0
        }
    }

    It 'normalizes old and new provider schemas without discarding structured metadata' {
        $eventFixtures = @($script:CoverageFixtures.fixtures | Where-Object kind -eq 'event')
        InModuleScope LogVerdict -Parameters @{ Fixtures = $eventFixtures } {
            param($Fixtures)
            $script:CoverageEventsByChannel = @{}
            foreach ($fixture in $Fixtures) { $script:CoverageEventsByChannel[[string]$fixture.channel] = $fixture.record }
            Mock Get-WinEvent {
                param($FilterHashtable)
                return $script:CoverageEventsByChannel[[string]$FilterHashtable.LogName]
            }

            try {
                $records = @(Get-LVEventRecord -Channel @($Fixtures | ForEach-Object channel) -DaysBack 1 -MaxPerChannel 10)
                $records.Count | Should -Be $Fixtures.Count
                $versions = @($records | ForEach-Object Version | Sort-Object -Unique)
                $versions | Should -Contain 0
                $versions | Should -Contain 2
                foreach ($record in $records) {
                    $record.ProviderId | Should -BeExactly '11111111-1111-1111-1111-111111111111'
                    $record.Task | Should -Not -BeNullOrEmpty
                    $record.Opcode | Should -Not -BeNullOrEmpty
                }
            } finally {
                Remove-Variable CoverageEventsByChannel -Scope Script -ErrorAction SilentlyContinue
            }
        }
    }

    It 'preserves a non-English provider message as evidence rather than matching rendered prose' {
        $fixture = $script:CoverageFixtures.fixtures | Where-Object id -eq 'event-provider-schema-modern'
        InModuleScope LogVerdict -Parameters @{ Fixture = $fixture } {
            param($Fixture)
            Mock Get-WinEvent { $Fixture.record }
            $record = @(Get-LVEventRecord -Channel $Fixture.channel -DaysBack 1 -MaxPerChannel 10)[0]
            $record.Message | Should -BeExactly ([string]$Fixture.record.Message)
            $record.Provider | Should -BeExactly 'LogVerdict-Fixture'
            $record.Version | Should -Be 2
            $record.Task | Should -Be 7
            $record.Opcode | Should -Be 2
        }
    }

    It 'exercises a text-log fixture through the real collector shape' {
        $fixture = $script:CoverageFixtures.fixtures | Where-Object kind -eq 'textlog' | Select-Object -First 1
        $path = Join-Path $TestDrive 'coverage-fixture.log'
        Set-Content -LiteralPath $path -Value $fixture.target.Line -Encoding UTF8
        InModuleScope LogVerdict -Parameters @{ Fixture = $fixture; Path = $path } {
            param($Fixture, $Path)
            $target = [pscustomobject]@{
                Name = $Fixture.target.Name
                Path = $Path
                Pattern = $Fixture.target.Pattern
                Area = $Fixture.target.Area
                Hint = $Fixture.target.Hint
            }
            $records = @(Get-LVTextLogRecord -DaysBack 1 -Target @($target))
            $records.Count | Should -Be 1
            $records[0].Message | Should -BeExactly $Fixture.target.Line
            $script:LVTextLogCoverage[0].Status | Should -BeExactly 'readable'
        }
    }

    It 'reports the current elevation state without requiring elevation' {
        if ($env:OS -ne 'Windows_NT') {
            Set-ItResult -Skipped -Because 'Windows token elevation is OS-dependent'
            return
        }
        InModuleScope LogVerdict {
            $elevated = Test-LVElevated
            $elevated | Should -BeOfType [bool]
        }
    }

    It 'exercises the high-contrast path through a non-global test override' {
        if ($env:OS -ne 'Windows_NT') {
            Set-ItResult -Skipped -Because 'WPF theme inspection is OS-dependent'
            return
        }
        InModuleScope LogVerdict {
            $previous = $env:LOGVERDICT_TEST_HIGH_CONTRAST
            try {
                $env:LOGVERDICT_TEST_HIGH_CONTRAST = '1'
                Test-LVGuiHighContrast | Should -BeTrue
            } finally {
                if ($null -eq $previous) { Remove-Item Env:LOGVERDICT_TEST_HIGH_CONTRAST -ErrorAction SilentlyContinue }
                else { $env:LOGVERDICT_TEST_HIGH_CONTRAST = $previous }
            }
        }
    }
}

Describe 'Provider and configuration health profiles' {
    It 'retains provider GUID, channel, EventID, and version metadata' {
        InModuleScope LogVerdict {
            Mock Get-WinEvent {
                param($ListProvider)
                if ($ListProvider) {
                    return [pscustomobject]@{
                        Name = $ListProvider
                        Events = @([pscustomobject]@{ Id = 7; Version = 3 })
                    }
                }
            }
            $status = @{ Fake = [pscustomobject]@{ Access='readable'; Oldest=(Get-Date).AddDays(-2) } }
            $records = @([pscustomobject]@{
                Source='event'; Channel='Fake'; Provider='FakeProvider'; ProviderId='11111111-1111-1111-1111-111111111111'
                Id=7; Version=3; TimeCreated=(Get-Date); Message='event'
            })
            $profiles = @(Get-LVProviderHealthProfile -EventRecord $records -ChannelStatus $status)
            $profiles.Count | Should -Be 1
            $profiles[0].Provider | Should -BeExactly 'FakeProvider'
            $profiles[0].ProviderId | Should -BeExactly '11111111-1111-1111-1111-111111111111'
            @($profiles[0].EventIds) | Should -Contain '7'
            @($profiles[0].EventVersions) | Should -Contain '7=3'
            $profiles[0].MetadataStatus | Should -BeExactly 'readable'
        }
    }

    It 'keeps missing policy and WEF state advisory rather than verdicts' {
        InModuleScope LogVerdict {
            $status = @{ Fake = [pscustomobject]@{ Access='readable'; Oldest=(Get-Date).AddDays(-2); RecordCount=3; LogMode='Circular'; MaximumSizeInBytes=4096 } }
            $profiles = @(Get-LVHealthProfile -EventRecord @() -ChannelStatus $status -WindowStart (Get-Date).AddDays(-1) -WindowEnd (Get-Date))
            @($profiles | Where-Object Profile -eq 'retention-and-clock').Count | Should -Be 1
            ($profiles | Where-Object Profile -eq 'retention-and-clock').Advice | Should -Match 'tamper verdict'
            ($profiles | Where-Object Profile -eq 'wef-subscriptions').Status | Should -BeIn @('not-observed', 'empty', 'unreadable')
            ($profiles | Where-Object Profile -eq 'defender-configuration').Advice | Should -Match 'not a malicious verdict'
        }
    }
}

Describe 'Live event watch and WEF intake' {
    It 'resumes from a bookmark and reports drops, reconnects, and latency' {
        InModuleScope LogVerdict {
            $bookmark = Join-Path $TestDrive 'watch-bookmark.json'
            @'
{
  "schemaVersion": 1,
  "channels": {
    "Fake": {
      "recordId": 1,
      "timeCreated": "2026-08-02T10:00:00.0000000Z"
    }
  }
}
'@ | Set-Content -LiteralPath $bookmark -Encoding UTF8
            $script:watchCalls = 0
            Mock Start-Sleep { }
            Mock Get-WinEvent {
                $script:watchCalls++
                if ($script:watchCalls -eq 1) { throw 'temporary subscription drop' }
                @(
                    [pscustomobject]@{ ProviderName='FakeProvider'; Id=7; Level=2; LevelDisplayName='Error'; TimeCreated=(Get-Date).AddMilliseconds(-25); MachineName='M'; RecordId=4; Message='first' }
                    [pscustomobject]@{ ProviderName='FakeProvider'; Id=7; Level=2; LevelDisplayName='Error'; TimeCreated=(Get-Date).AddMilliseconds(-15); MachineName='M'; RecordId=7; Message='second' }
                )
            }

            $result = Watch-LogVerdict -Channel Fake -BookmarkPath $bookmark -DurationSeconds 3 -MaxEvents 2 -PollMilliseconds 100 -PageSize 4
            $result.Mode | Should -BeExactly 'live-watch'
            $result.StopReason | Should -BeExactly 'max-events'
            $result.RecordCount | Should -Be 2
            $result.Records[0].Source | Should -BeExactly 'event'
            $result.Coverage[0].ReconnectCount | Should -Be 1
            $result.Coverage[0].SkippedRecords | Should -Be 4
            $result.Coverage[0].RecordGap | Should -Match 'RecordId gap'
            $result.Coverage[0].AverageLatencyMilliseconds | Should -BeGreaterThan 0
            $csvRow = ConvertTo-LVCoverageCsvRow -Result $result -Coverage $result.Coverage[0]
            $csvRow.CoverageReconnectCount | Should -Be 1
            $csvRow.CoverageAverageLatencyMilliseconds | Should -BeGreaterThan 0
            $saved = Get-Content -LiteralPath $bookmark -Raw | ConvertFrom-Json
            $saved.channels.Fake.recordId | Should -Be 7
        }
    }

    It 'parses WEF configuration and runtime state as advisory health' {
        InModuleScope LogVerdict {
            Mock Test-Path { $true }
            Mock Invoke-LVWecutil {
                param($Argument)
                if ($Argument[0] -eq 'gs') {
                    return '<Subscription><ReadExistingEvents>true</ReadExistingEvents><HeartbeatInterval>900</HeartbeatInterval><Bookmark>configured</Bookmark></Subscription>'
                }
                return "RuntimeStatus: active`nEventsDropped: 3`nBookmarkState: runtime"
            }
            $profiles = @(Get-LVWEFHealthProfile -Subscription @('DemoSubscription'))
            $profiles.Count | Should -Be 1
            $profiles[0].Status | Should -BeExactly 'readable'
            $profiles[0].ReadExistingEvents | Should -BeTrue
            $profiles[0].HeartbeatIntervalSeconds | Should -Be 900
            $profiles[0].BookmarkState | Should -BeExactly 'configured'
            $profiles[0].RuntimeStatus | Should -BeExactly 'active'
            $profiles[0].DroppedEvents | Should -Be 3
            $profiles[0].Advice | Should -Match 'not maliciousness signals'
        }
    }
}

Describe 'Event sequence coverage' {
    It 'reports missing record IDs with the channel and observed range' {
        InModuleScope LogVerdict {
            $script:LVTruncatedChannel = @()
            $base = [datetime]'2026-08-01 10:00:00'
            $records = @(
                [pscustomobject]@{ Source='event'; Channel='System'; RecordId=10; TimeCreated=$base }
                [pscustomobject]@{ Source='event'; Channel='System'; RecordId=11; TimeCreated=$base.AddSeconds(1) }
                [pscustomobject]@{ Source='event'; Channel='System'; RecordId=15; TimeCreated=$base.AddSeconds(2) }
            )
            $notes = @(Get-LVEventSequenceGap -Record $records)
            $notes.Count | Should -Be 1
            $notes[0] | Should -Match "Event channel 'System'"
            $notes[0] | Should -Match 'from 11 to 15'
            $notes[0] | Should -Match '3 observed IDs missing'
        }
    }

    It 'reports backwards timestamps and suppresses already-truncated channels' {
        InModuleScope LogVerdict {
            $script:LVTruncatedChannel = @()
            $base = [datetime]'2026-08-01 10:00:00'
            $records = 1..3 | ForEach-Object {
                [pscustomobject]@{ Source='event'; Channel='System'; RecordId=$_; TimeCreated=$base.AddMinutes((3 - $_)) }
            }
            @(Get-LVEventSequenceGap -Record $records) | Should -Match 'backwards timestamp'

            $script:LVTruncatedChannel = @('System')
            @(Get-LVEventSequenceGap -Record $records) | Should -BeNullOrEmpty
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

    It 'marks an unmatched compact cluster as a burst without changing unknown' {
        InModuleScope LogVerdict -Parameters @{ db = $script:TestDb } {
            param($db)
            $base = [datetime]'2026-08-01 10:00:00'
            $sig = [pscustomobject]@{
                Key='Nobody/8'; Source='event'; Channel='System'; Provider='Nobody'; Id=8
                Count=4; PerDay=0.2; SampleMessage='raw burst evidence'; FirstSeen=$base; LastSeen=$base.AddDays(1)
                Times=@($base, $base.AddMinutes(1), $base.AddMinutes(3), $base.AddDays(1))
            }
            $finding = (Resolve-LVVerdict -Signature @($sig) -Database $db)[0]
            $finding.Verdict | Should -BeExactly 'unknown'
            $finding.Burst | Should -BeTrue
            $finding.BurstOnset | Should -Be $base
            $finding.BurstCount | Should -Be 3
            $finding.Plain | Should -Match 'burst indicator'
            $finding.Action | Should -Match '2026-08-01 10:00:00'
        }
    }

    It 'adds stable non-burst fields to an unmatched trickle' {
        InModuleScope LogVerdict -Parameters @{ db = $script:TestDb } {
            param($db)
            $base = [datetime]'2026-08-01 10:00:00'
            $sig = [pscustomobject]@{
                Key='Nobody/9'; Source='event'; Channel='System'; Provider='Nobody'; Id=9
                Count=6; PerDay=0.2; SampleMessage='regular evidence'; FirstSeen=$base; LastSeen=$base.AddHours(5)
                Times=0..5 | ForEach-Object { $base.AddHours($_) }
            }
            $finding = (Resolve-LVVerdict -Signature @($sig) -Database $db)[0]
            $finding.Verdict | Should -BeExactly 'unknown'
            $finding.Burst | Should -BeFalse
            $finding.BurstOnset | Should -BeNullOrEmpty
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

Describe 'Local model explanations' {
    It 'requests structured output from loopback and keeps the candidate separate' {
        InModuleScope LogVerdict {
            $script:LVModelRequestBody = $null
            Mock Invoke-RestMethod {
                $script:LVModelRequestBody = $Body
                [pscustomobject]@{
                    response = '{"summary":"This may describe an Acme service failure.","evidence":["Provider Acme emitted event 99."],"uncertainty":"The message does not identify the underlying cause."}'
                }
            }
            $finding = [pscustomobject]@{
                Key='Acme/99'; Source='event'; Channel='System'; Provider='Acme'; Id=99
                Count=2; PerDay=0.2; SampleMessage='Acme stopped'; Verdict='unknown'; RuleId=$null
                Plain='deterministic fallback'; Why='deterministic reason'; Action='deterministic action'
            }

            $out = @(Add-LVModelExplanation -Finding @($finding) -Model 'test-model')
            Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Method -eq 'Post' -and $Uri -eq 'http://127.0.0.1:11434/api/generate'
            }
            $body = $script:LVModelRequestBody | ConvertFrom-Json
            $body.model | Should -BeExactly 'test-model'
            $body.stream | Should -BeFalse
            $body.format.additionalProperties | Should -BeFalse
            $out[0].ModelExplanation.Label | Should -BeExactly 'MODEL-GENERATED CANDIDATE - NOT A CURATED RULING'
            $out[0].ModelExplanation.PSObject.Properties.Name | Should -Not -Contain 'Action'
            $out[0].Plain | Should -BeExactly 'deterministic fallback'
            $out[0].Action | Should -BeExactly 'deterministic action'
        }
    }

    It 'never calls a model for a known finding' {
        InModuleScope LogVerdict {
            Mock Invoke-RestMethod { throw 'should not be called' }
            $known = [pscustomobject]@{ Key='Acme/1'; Verdict='actionable'; RuleId='LV-0001' }
            $out = @(Add-LVModelExplanation -Finding @($known))
            Assert-MockCalled Invoke-RestMethod -Times 0 -Exactly
            $out[0].PSObject.Properties.Name | Should -Not -Contain 'ModelExplanation'
        }
    }

    It 'refuses a non-loopback model endpoint' {
        InModuleScope LogVerdict {
            $unknown = [pscustomobject]@{ Key='Acme/2'; Verdict='unknown'; RuleId=$null }
            { Add-LVModelExplanation -Finding @($unknown) -Endpoint 'http://example.com:11434' } |
                Should -Throw '*must be HTTP on localhost*'
        }
    }

    It 'discards a response that contains remediation language' {
        InModuleScope LogVerdict {
            Mock Invoke-RestMethod {
                [pscustomobject]@{
                    response = '{"summary":"Run chkdsk to repair the volume.","evidence":["The message mentions a disk."],"uncertainty":"The disk state is unknown."}'
                }
            }
            $unknown = [pscustomobject]@{
                Key='Acme/3'; Source='event'; Channel='System'; Provider='Acme'; Id=3
                Count=1; PerDay=0.1; SampleMessage='disk message'; Verdict='unknown'; RuleId=$null
            }
            $out = @(Add-LVModelExplanation -Finding @($unknown))
            $out[0].PSObject.Properties.Name | Should -Not -Contain 'ModelExplanation'
            $out[0].ModelExplanationError | Should -Match 'remediation or instructional language'
        }
    }

    It 'writes a model candidate as an inactive, repeatable local rule draft' {
        InModuleScope LogVerdict {
            $path = Join-Path $TestDrive 'verdicts.local.json'
            $unknown = [pscustomobject]@{
                Key='Acme/4242'; Source='event'; Channel='System'; Provider='Acme'; Id=4242
                Count=3; PerDay=0.3; SampleMessage='Acme fault'; Verdict='unknown'; RuleId=$null
                ModelExplanation=[pscustomobject]@{
                    Label='MODEL-GENERATED CANDIDATE - NOT A CURATED RULING'
                    ModelGenerated=$true; Model='test-model'
                    Summary='This may describe an Acme component fault on TESTPC.'
                    Evidence=@('TESTPC emitted Acme event 4242 three times.')
                    Uncertainty='The component and cause are not identified.'
                }
            }

            $first = @(Write-LVModelDraftRule -Finding @($unknown) -Path $path -MachineName 'TESTPC')
            $first.Count | Should -Be 1
            $first[0].Replaced | Should -BeFalse
            $local = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            @($local.rules).Count | Should -Be 1
            $local.rules[0].confidence | Should -BeExactly 'draft'
            $local.rules[0].status | Should -BeExactly 'unsupported'
            $local.rules[0].plain | Should -Match '^\[MODEL-GENERATED - NOT CURATED\]'
            $local.rules[0].plain | Should -Not -Match 'TESTPC'
            $local.rules[0].why | Should -Match '<MACHINE>'
            $local.rules[0].action | Should -Match 'human reviewer'
            Test-LogVerdictDatabase -Path $path -SkipFixture -Quiet | Should -BeTrue

            $signature = [pscustomobject]@{
                Key='Acme/4242'; Source='event'; Channel='System'; Provider='Acme'; Id=4242
                Count=3; PerDay=0.3; SampleMessage='Acme fault'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            $resolved = @(Resolve-LVVerdict -Signature @($signature) -Database (Get-LogVerdictDatabase -Path $path))
            $resolved[0].Verdict | Should -BeExactly 'unknown'
            $resolved[0].RuleId | Should -BeNullOrEmpty

            $second = @(Write-LVModelDraftRule -Finding @($unknown) -Path $path -MachineName 'TESTPC')
            $second[0].Replaced | Should -BeTrue
            @(((Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).rules)).Count | Should -Be 1

            $reviewed = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $reviewed.rules[0].status = 'stable'
            $reviewed.rules[0].confidence = 'medium'
            $reviewed | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8
            { Write-LVModelDraftRule -Finding @($unknown) -Path $path -MachineName 'TESTPC' } |
                Should -Throw '*Refusing to overwrite reviewed local rule*'
            (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).rules[0].confidence | Should -BeExactly 'medium'
        }
    }

    It 'requires both inactive gates on a draft-confidence rule' {
        $bad = Join-Path $TestDrive 'active-draft.json'
        @'
{ "schemaVersion": 5, "name": "bad draft", "updated": "2026-08-01", "rules": [
  { "id": "LOCAL-DRAFT-BAD", "status": "experimental", "verified": "2026-08-01",
    "match": { "source": "event", "provider": "Acme", "eventId": 1 }, "verdict": "unknown",
    "title": "draft", "plain": "draft", "why": "draft", "action": "review", "confidence": "draft" } ] }
'@ | Set-Content -LiteralPath $bad -Encoding UTF8
        Test-LogVerdictDatabase -Path $bad -SkipFixture -Quiet | Should -BeFalse
    }
}

Describe 'Report rendering' {
    BeforeAll {
        $script:FakeResult = [pscustomobject]@{
            Tool = 'LogVerdict'; Version = '0.7.0'; MachineName = 'TESTPC'
            ScanTime = (Get-Date '2026-07-31 12:00:00'); Duration = [timespan]::FromSeconds(3)
            DaysBack = 30; Elevated = $false; Channels = @('System', 'Application')
            Reduction = [pscustomobject]@{
                RecordCount = 1855; SignatureCount = 71; Ratio = 26.1
                InitialSignatureCount = 68; InitialRatio = 27.3; PromotedSlotCount = 3
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
            $text | Should -Match 'Template pass : 68 masked \(27\.3:1\) -> 71 after low-cardinality promotion'
            $text | Should -Match 'Occurrences : 12 \(0\.4/day\)'
            $text | Should -Match 'Rule        : T-1 \(confidence: high\)'
        }
    }

    It 'renders the advisory baseline and caveat in text and HTML reports' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $result | Add-Member -NotePropertyName History -NotePropertyValue ([pscustomobject]@{
                Enabled=$true; Status='signals'; Persistence='saved'; EntriesStored=2; AdvisoryOnly=$true; WindowDays=30
                Baseline=[pscustomobject]@{ Method='Median per-day rate across prior bounded scans'; SampleCount=1; ScanTimes=@('2026-08-01T10:00:00Z') }
                Threshold=[pscustomobject]@{ RelativeIncrease=0.25; AbsolutePerDay=0.1; Description='Signal when the current rate is at least 25% above baseline and at least 0.10/day higher.' }
                Signals=@([pscustomobject]@{ Type='rate-increase'; Key='Acme/99'; Reason='Rate rose from a 0.50/day median baseline to 2.00/day in the current window.' })
                FalsePositiveCaveat='Advisory only; retention and missing history can create apparent changes.'
            })
            $text = ConvertTo-LVTextReport -Result $result
            $html = ConvertTo-LVHtmlReport -Result $result
            $text | Should -Match 'BASELINE \(ADVISORY ONLY\)'
            $text | Should -Match 'missing history can create apparent changes'
            $html | Should -Match 'BASELINE \(ADVISORY ONLY\)'
            $html | Should -Match 'curated verdicts'
        }
    }

    It 'keeps dependency advisories separate from event findings in reports' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $result | Add-Member -NotePropertyName AdvisoryStatus -NotePropertyValue 'affected'
            $result | Add-Member -NotePropertyName AdvisoryCache -NotePropertyValue ([pscustomobject]@{
                Name='offline cache'; EntryCount=1; Updated='2026-06-17'; Source='NVD'; SourceHash=('a' * 64)
            })
            $result | Add-Member -NotePropertyName Advisories -NotePropertyValue @([pscustomobject]@{
                RecordType='advisory'; FindingType='dependency-advisory'; Matched=$true; Id='CVE-TEST-1'
                Ecosystem='PowerShell'; Package='PowerShell'; Version='7.4.0'; AffectedRange='>=7.4.0 <7.4.14'
                FixedVersion='7.4.14'; CVSS=7.8; CVSSVector='CVSS:3.1/test'; KEV=$false; KEVDate=$null
                PublishedDate='2026-04-14'; ModifiedDate='2026-06-17'; Source='NVD'; SourceUri='https://example.test/CVE-TEST-1'
                SourceHash=('b' * 64); Title='test advisory'; Description='Dependency context only.'
            })
            $text = ConvertTo-LVTextReport -Result $result
            $html = ConvertTo-LVHtmlReport -Result $result
            $text | Should -Match 'DEPENDENCY ADVISORIES \(SEPARATE FROM EVENT FINDINGS\)'
            $text | Should -Match 'not Windows event verdicts'
            $html | Should -Match 'DEPENDENCY ADVISORIES \(SEPARATE FROM EVENT FINDINGS\)'
            $html | Should -Match 'CVE-TEST-1'
        }
    }

    It 'renders burst timing in text, HTML and CSV reports' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $finding = $r.Findings[0] | Select-Object *
            $finding | Add-Member -NotePropertyName Burst -NotePropertyValue $true
            $finding | Add-Member -NotePropertyName BurstOnset -NotePropertyValue ([datetime]'2026-08-01 10:00:00')
            $finding | Add-Member -NotePropertyName BurstCount -NotePropertyValue 3
            $finding | Add-Member -NotePropertyName BurstWindowMinutes -NotePropertyValue 4
            $result.Findings = @($finding)

            $text = ConvertTo-LVTextReport -Result $result
            $html = ConvertTo-LVHtmlReport -Result $result
            $csv = ConvertTo-LVCsvReport -Result $result
            $text | Should -Match 'Burst\s+: began 2026-08-01 10:00; 3 occurrence\(s\) in 4 minute\(s\)'
            $html | Should -Match 'Burst</div><div>2026-08-01 10:00'
            $csv | Should -Match '"True".*"2026-08-01T10:00:00.*".*"3".*"4"'
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

    It 'renders model text only in a clearly labelled candidate block' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $finding = $r.Findings[0] | Select-Object *
            $finding | Add-Member -NotePropertyName ModelExplanation -NotePropertyValue ([pscustomobject]@{
                Label='MODEL-GENERATED CANDIDATE - NOT A CURATED RULING'; Model='test-model'
                Summary='Possible <cause>'; Evidence=@('Evidence from TESTPC'); Uncertainty='Still uncertain'
            })
            $result.Findings = @($finding)

            $text = ConvertTo-LVTextReport -Result $result
            $html = ConvertTo-LVHtmlReport -Result $result
            $text | Should -Match 'MODEL-GENERATED CANDIDATE - NOT A CURATED RULING'
            $html | Should -Match 'MODEL-GENERATED CANDIDATE - NOT A CURATED RULING'
            $html | Should -Match 'Possible &lt;cause&gt;'
            $html | Should -Match 'Verdicts, actions and unlabelled explanations come only from the curated rule database'

            $redacted = ConvertTo-LVRedactedResult -Result $result
            $redacted.Findings[0].ModelExplanation.Evidence[0] | Should -BeExactly 'Evidence from <MACHINE>'
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

    It 'writes one stable scalar CSV row per finding' {
        $out = Join-Path $TestDrive 'reports-csv'
        Export-LogVerdictReport -Result $script:FakeResult -OutputDir $out -Format Csv | Out-Null
        $path = Join-Path $out 'LogVerdict-Report.csv'
        Test-Path -LiteralPath $path | Should -BeTrue
        $rows = @(Import-Csv -LiteralPath $path)
        $rows.Count | Should -Be 1
        $rows[0].Verdict | Should -BeExactly 'actionable'
        $rows[0].Provider | Should -BeExactly 'Acme'
        $rows[0].Count | Should -Be '12'
        $rows[0].Title | Should -BeExactly 'Something broke'
        $rows[0].PSObject.Properties.Name | Should -Contain 'ErrorCatalogKind'
        $rows[0].PSObject.Properties.Name | Should -Contain 'Reference'
        $rows[0].PSObject.Properties.Name | Should -Contain 'Burst'
    }

    It 'emits the CSV header even when no findings exist' {
        $out = Join-Path $TestDrive 'reports-csv-empty'
        $clean = $script:FakeResult | Select-Object *
        $clean.Findings = @()
        Export-LogVerdictReport -Result $clean -OutputDir $out -Format Csv | Out-Null
        $lines = @(Get-Content -LiteralPath (Join-Path $out 'LogVerdict-Report.csv'))
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match 'ScanTime'
        @(Import-Csv -LiteralPath (Join-Path $out 'LogVerdict-Report.csv')).Count | Should -Be 0
    }

    It 'renders normalized source coverage in text, HTML, CSV, and the bundle manifest' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $result | Add-Member -NotePropertyName Coverage -NotePropertyValue @([pscustomobject]@{
                Source='event'; Kind='channel'; Name='System'; Status='empty'
                Reason='No matching event was observed'; Path=$null
                WindowStart=(Get-Date).AddDays(-1); WindowEnd=(Get-Date); Cap=20000
                ObservedRecords=0; SkippedRecords=0; RecordGap=$null; ParserError=$null
                SizeBytes=$null; ParseMilliseconds=12; SHA256=$null; Origin='live'
            })
            $result | Add-Member -NotePropertyName HealthProfiles -NotePropertyValue @([pscustomobject]@{
                Profile='provider-metadata'; Source='event'; Name='FakeProvider'; Status='readable'
                RequiredConfiguration='Provider manifest required'; ObservedConfiguration='Observed EventID(s): 7; versions: 7=3'
                EnabledEventIds=@(); FilteredEventIds=@(); Provider='FakeProvider'; ProviderId='11111111-1111-1111-1111-111111111111'
                Channel='System'; EventIds=@('7'); EventVersions=@('7=3'); MetadataStatus='readable'
                ReadExistingEvents=$null; HeartbeatIntervalSeconds=$null; BookmarkState=$null
                RetentionMode=$null; RecordCount=$null; OldestRecord=$null; MaximumSizeBytes=$null; ClockOffsetMinutes=$null
                Reason=$null; Advice='Advisory only'; Path=$null; Origin='live'
            })
            $text = ConvertTo-LVTextReport -Result $result
            $html = ConvertTo-LVHtmlReport -Result $result
            $csv = ConvertTo-LVCsvReport -Result $result
            $manifest = Format-LVEvidenceManifest -Result $result -Content @()
            $text | Should -Match 'COVERAGE DETAIL.*per-source status'
            $html | Should -Match 'Coverage detail'
            @($csv | ConvertFrom-Csv | Where-Object RowType -eq 'coverage').Count | Should -Be 1
            @($csv | ConvertFrom-Csv | Where-Object RowType -eq 'health').Count | Should -Be 1
            $csv | Should -Match 'CoverageStatus'
            $csv | Should -Match 'HealthEventVersions'
            $manifest | Should -Match 'COVERAGE SOURCES'
            $manifest | Should -Match 'System: empty'
            $text | Should -Match 'CONFIGURATION HEALTH.*advisory profiles'
            $html | Should -Match 'Configuration health'
            $manifest | Should -Match 'CONFIGURATION HEALTH PROFILES'
        }
    }

    It 'renders opt-in content-free performance telemetry and distinguishes empty from slow' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $metric = New-LVPerformanceRecord -Source 'event' -Kind 'collector' -Name 'event channels' `
                -Status 'empty' -ObservedRecords 0 -SkippedRecords 2 -Cap 20000 -ElapsedMilliseconds 1200 -Origin 'live'
            $result | Add-Member -NotePropertyName PerformanceTelemetry -NotePropertyValue $true
            $result | Add-Member -NotePropertyName Performance -NotePropertyValue @($metric)

            $text = ConvertTo-LVTextReport -Result $result
            $html = ConvertTo-LVHtmlReport -Result $result
            $csv = ConvertTo-LVCsvReport -Result $result
            $text | Should -Match 'PERFORMANCE TELEMETRY \(OPT-IN; CONTENT-FREE\)'
            $text | Should -Match 'event/collector event channels - empty \(slow\); elapsed 1200 ms; 0 observed; 2 skipped; cap 20000'
            $html | Should -Match 'Performance telemetry \(opt-in; content-free\)'
            $html | Should -Match 'empty \(slow\); elapsed 1200 ms'
            $perfRows = @($csv | ConvertFrom-Csv | Where-Object RowType -eq 'performance')
            $perfRows.Count | Should -Be 1
            $perfRows[0].PerformanceStatus | Should -BeExactly 'empty'
            $perfRows[0].PerformanceSlow | Should -BeExactly 'True'

            $telemetryJson = $metric | ConvertTo-Json -Depth 5
            $telemetryJson | Should -Not -Match 'Message|Path|HOST|C:\\|secret'
            $ecs = (Export-LogVerdictStandard -Result $result -Format Ecs).Document
            $ecs.logverdict.scan.performanceTelemetry | Should -BeTrue
            $ecs.logverdict.scan.performance[0].status | Should -BeExactly 'empty'
            $ecs.logverdict.scan.performance[0].elapsedMilliseconds | Should -Be 1200
        }
    }

    It 'round-trips ECS, OCSF, OpenTelemetry, and STIX adapter JSON' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $finding = $r.Findings[0] | Select-Object *
            $finding | Add-Member -NotePropertyName Samples -NotePropertyValue @('raw HOST-9 C:\Users\bob\secret.txt')
            $result.Findings = @($finding)
            $result | Add-Member -NotePropertyName Coverage -NotePropertyValue @([pscustomobject]@{
                Source='event'; Kind='channel'; Name='System'; Status='empty'; Reason='No matching event'
                Path=$null; WindowStart=(Get-Date).AddDays(-1); WindowEnd=(Get-Date); Cap=20
                ObservedRecords=0; SkippedRecords=0; RecordGap=$null; ParserError=$null; SizeBytes=$null
                ParseMilliseconds=4; SHA256=$null; Origin='live'
            })
            $formats = @('Ecs', 'Ocsf', 'OpenTelemetry', 'Stix')
            foreach ($format in $formats) {
                $export = Export-LogVerdictStandard -Result $result -Format $format
                $json = $export.Document | ConvertTo-Json -Depth 30
                $roundTrip = $json | ConvertFrom-Json
                $roundTrip.schemaVersion | Should -BeExactly '1.0.0'
                $roundTrip.adapter | Should -Not -BeNullOrEmpty
                $json | Should -Match 'Acme'
                $json | Should -Match 'high'
                $json | Should -Match 'coverage'
            }
            $ecs = (Export-LogVerdictStandard -Result $result -Format Ecs).Document
            $ecs.findings[0].logverdict.event.provider | Should -BeExactly 'Acme'
            $ecs.findings[0].rule.confidence | Should -BeExactly 'high'
            $ecs.logverdict.coverage[0].status | Should -BeExactly 'empty'
            $ocsf = (Export-LogVerdictStandard -Result $result -Format Ocsf).Document
            $ocsf.findings[0].finding_info.uid | Should -BeExactly 'Acme/99'
            $otel = (Export-LogVerdictStandard -Result $result -Format OpenTelemetry).Document
            @($otel.resourceLogs[0].scopeLogs[0].logRecords[0].attributes.key) | Should -Contain 'logverdict.event.provider'
            $stix = (Export-LogVerdictStandard -Result $result -Format Stix).Document
            @($stix.objects | Where-Object type -eq 'observed-data').Count | Should -Be 1
            ($stix.objects | Where-Object type -eq 'report').x_logverdict.schemaVersion | Should -BeExactly '1.0.0'
            $path = Join-Path $TestDrive 'adapters\ecs.json'
            $written = Export-LogVerdictStandard -Result $result -Format Ecs -Path $path
            $written.Path | Should -BeExactly $path
            (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).adapter | Should -BeExactly 'ecs'
        }
    }

    It 'marks and enforces redaction in standard exports' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $finding = $r.Findings[0] | Select-Object *
            $finding | Add-Member -NotePropertyName Samples -NotePropertyValue @('raw HOST-9 C:\Users\bob\secret.txt')
            $result.Findings = @($finding)
            $result.MachineName = 'HOST-9'
            $result | Add-Member -NotePropertyName Redacted -NotePropertyValue $false
            $export = Export-LogVerdictStandard -Result $result -Format Ecs -Redact
            $json = $export.Document | ConvertTo-Json -Depth 30
            $export.Document.logverdict.privacy.redacted | Should -BeTrue
            $export.Document.logverdict.privacy.rawEvidenceIncluded | Should -BeFalse
            $json | Should -Not -Match 'HOST-9|bob'
            $json | Should -Match '<MACHINE>|identifiersMasked'
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

    It 'renders offline verdict toggles and text search without hiding findings when scripting is disabled' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $html = ConvertTo-LVHtmlReport -Result $r
            $html | Should -Match 'id="finding-filters"'
            $html | Should -Match 'data-filter-verdict="actionable"'
            $html | Should -Match 'id="finding-search"'
            $html | Should -Match '<article class="f finding" data-verdict="actionable"'
            $html | Should -Not -Match '<article class="f finding"[^>]+hidden'
            $html | Should -Match '<noscript>.*all findings are shown.*</noscript>'
            $html | Should -Match "card\.textContent\.toLowerCase\(\)"
        }
    }

    It 'prints as a light document and keeps finding cards together' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $html = ConvertTo-LVHtmlReport -Result $r
            $html | Should -Match '@media print'
            $html | Should -Match 'body\{background:#fff;color:#111'
            $html | Should -Match 'break-inside:avoid-page;page-break-inside:avoid'
            $html | Should -Match '\.filterbar,\.no-script\{display:none!important\}'
            $html | Should -Match 'pre\.ev\{max-height:none;overflow:visible'
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
            $row.FindingIndex | Should -Be 0
            $row.PSObject.Properties.Name | Should -Not -Contain 'Finding'
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
            $before = $env:LOGVERDICT_TEST_HIGH_CONTRAST
            try {
                $env:LOGVERDICT_TEST_HIGH_CONTRAST = '0'
                foreach ($v in $script:LVVerdictRank.Keys) {
                    $style = Get-LVVerdictStyle -Verdict $v
                    $style.Label | Should -Not -BeNullOrEmpty
                    $style.Fill  | Should -Match '^#[0-9a-f]{6}$'
                    $style.Ink   | Should -Match '^#[0-9a-f]{6}$'
                }
            } finally {
                $env:LOGVERDICT_TEST_HIGH_CONTRAST = $before
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

Describe 'GUI settings persistence' {
    It 'stores settings under the current user local app-data folder' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive } {
            param($Root)
            Get-LVGuiSettingsPath -LocalAppData $Root |
                Should -BeExactly (Join-Path (Join-Path $Root 'LogVerdict') 'settings.json')
        }
    }

    It 'round-trips scan options and window size without a UTF-8 BOM' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive } {
            param($Root)
            $path = Join-Path $Root 'prefs/settings.json'
            $value = [pscustomobject]@{
                DaysBack=14; AllChannels=$true; SkipTextLogs=$true; IncludeBenign=$true
                WindowWidth=1500.4; WindowHeight=820.4
            }
            Save-LVGuiSetting -Settings $value -Path $path | Should -BeTrue

            $read = Get-LVGuiSetting -Path $path
            $read.DaysBack | Should -Be 14
            $read.AllChannels | Should -BeTrue
            $read.SkipTextLogs | Should -BeTrue
            $read.IncludeBenign | Should -BeTrue
            $read.WindowWidth | Should -Be 1500
            $read.WindowHeight | Should -Be 820

            $bytes = [IO.File]::ReadAllBytes($path)
            ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) |
                Should -BeFalse
        }
    }

    It 'ignores malformed, future, and invalid settings instead of failing launch' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive } {
            param($Root)
            $path = Join-Path $Root 'bad-settings.json'
            foreach ($content in @(
                '{ definitely not json',
                '{"schemaVersion":2,"daysBack":30,"allChannels":false,"skipTextLogs":false,"includeBenign":false,"windowWidth":1440,"windowHeight":800}',
                '{"schemaVersion":1,"daysBack":0,"allChannels":"false","skipTextLogs":false,"includeBenign":false,"windowWidth":100,"windowHeight":100}'
            )) {
                Set-Content -LiteralPath $path -Value $content -Encoding UTF8
                { Get-LVGuiSetting -Path $path } | Should -Not -Throw
                $null -eq (Get-LVGuiSetting -Path $path) | Should -BeTrue
            }
        }
    }

    It 'keeps an unwritable settings destination non-fatal' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive } {
            param($Root)
            $value = [pscustomobject]@{
                DaysBack=30; AllChannels=$false; SkipTextLogs=$false; IncludeBenign=$false
                WindowWidth=1440; WindowHeight=800
            }
            Save-LVGuiSetting -Settings $value -Path $Root | Should -BeFalse
        }
    }

    It 'lets an explicit look-back override persisted state and saves restore bounds on close' {
        $path = Join-Path (Split-Path $PSScriptRoot -Parent) 'Public/Show-LogVerdictGui.ps1'
        $text = Get-Content -LiteralPath $path -Raw
        $text | Should -Match "PSBoundParameters\.ContainsKey\('DaysBack'\)"
        $text | Should -Match 'Get-LVGuiSetting'
        $text | Should -Match 'Save-LVGuiSetting'
        $text | Should -Match '\$window\.RestoreBounds'

        $entry = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'LogVerdict-GUI.ps1') -Raw
        $entry | Should -Match "PSBoundParameters\.ContainsKey\('DaysBack'\)"
        $entry | Should -Match '\$guiArgs\[''DaysBack''\]\s*=\s*\$DaysBack'
        $entry | Should -Not -Match 'Show-LogVerdictGui\s+-DaysBack\s+\$DaysBack'
    }
}

Describe 'GUI and console feature parity' {
    It 'normalizes comma, semicolon, and line-separated named channels' {
        InModuleScope LogVerdict {
            $channels = @(Get-LVGuiNamedChannel -Text "System, Application;System`r`nMicrosoft-Windows-Ntfs/Operational")
            $channels | Should -Be @('System', 'Application', 'Microsoft-Windows-Ntfs/Operational')
            @(Get-LVGuiNamedChannel -Text '  ').Count | Should -Be 0
        }
    }

    It 'wires every deterministic live scan choice into the engine arguments' {
        $path = Join-Path (Split-Path $PSScriptRoot -Parent) 'Public/Show-LogVerdictGui.ps1'
        $text = Get-Content -LiteralPath $path -Raw
        foreach ($argument in @('Channel', 'AllChannels', 'DiagnosticChannels', 'SkipTextLogs',
                'SkipReliability', 'IncludeBenign', 'DatabasePath')) {
            $text | Should -Match ("scanArgs\['{0}'\]|{0}\s*=" -f $argument) -Because "$argument must reach Invoke-LogVerdictScan"
        }
    }

    It 'wires report destination, redaction, and evidence choices into export' {
        $path = Join-Path (Split-Path $PSScriptRoot -Parent) 'Public/Show-LogVerdictGui.ps1'
        $text = Get-Content -LiteralPath $path -Raw
        $text | Should -Match "exportArgs\['OutputDir'\]"
        $text | Should -Match 'Redact\s*=\s*\[bool\]\$ui\.ChkOverviewRedact\.IsChecked'
        $text | Should -Match 'IncludeEvidence\s*=\s*\[bool\]\$ui\.ChkOverviewEvidence\.IsChecked'
        $text | Should -Match 'AllowRawEvidence\s*=\s*\[bool\]'
    }

    It 'keeps diagnostic performance telemetry opt-in and content-free on a live scan' {
        $result = Invoke-LogVerdictScan -DaysBack 1 -SkipTextLogs -SkipReliability -PerformanceTelemetry 6>$null
        $result.PerformanceTelemetry | Should -BeTrue
        @($result.Performance | Where-Object Source -eq 'event').Count | Should -Be 1
        @($result.Performance | Where-Object Name -eq 'scan total').Count | Should -Be 1
        ($result.Performance | ConvertTo-Json -Depth 5) | Should -Not -Match 'Message|Path|HOST|C:\\|secret'

        $default = Invoke-LogVerdictScan -DaysBack 1 -SkipTextLogs -SkipReliability 6>$null
        $default.PerformanceTelemetry | Should -BeFalse
        @($default.Performance).Count | Should -Be 0
    }

    It 'documents every intentionally console-only option' {
        $readme = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'README.md') -Raw
        foreach ($option in @('EvidencePath', 'ExplainUnknown', 'OllamaModel', 'OllamaEndpoint',
                'PromoteToRule', 'LocalRulePath', 'Format')) {
            $readme | Should -Match ([regex]::Escape($option)) -Because "$option must be reachable or deliberately documented"
        }
    }
}

Describe 'GUI pure presentation logic' {
    It 'filters by enabled verdict and literal case-insensitive text' {
        InModuleScope LogVerdict {
            $row = [pscustomobject]@{ Verdict='investigate'; Haystack='Disk [2] Failure' }
            $enabled = @{ investigate=$true }
            Test-LVGuiFindingVisible -Row $row -EnabledVerdict $enabled -Search '[2]' | Should -BeTrue
            Test-LVGuiFindingVisible -Row $row -EnabledVerdict $enabled -Search 'DISK' | Should -BeTrue
            Test-LVGuiFindingVisible -Row $row -EnabledVerdict $enabled -Search '[3]' | Should -BeFalse
            Test-LVGuiFindingVisible -Row $row -EnabledVerdict $enabled -Search '*' | Should -BeFalse
            $enabled.investigate = $false
            Test-LVGuiFindingVisible -Row $row -EnabledVerdict $enabled -Search '' | Should -BeFalse
        }
    }

    It 'counts every display verdict and maps unexpected values to unknown' {
        InModuleScope LogVerdict {
            $count = Get-LVGuiVerdictCount -Finding @(
                [pscustomobject]@{ Verdict='critical' },
                [pscustomobject]@{ Verdict='actionable' },
                [pscustomobject]@{ Verdict='actionable' },
                [pscustomobject]@{ Verdict='future-value' }
            )
            $count.critical | Should -Be 1
            $count.actionable | Should -Be 2
            $count.unknown | Should -Be 1
            $count.investigate | Should -Be 0
            @($count.Keys).Count | Should -Be 6
        }
    }

    It 'projects detail text, arrays, evidence, and attribution without WPF controls' {
        InModuleScope LogVerdict {
            $oldContrast = $env:LOGVERDICT_TEST_HIGH_CONTRAST
            $env:LOGVERDICT_TEST_HIGH_CONTRAST = '0'
            try {
                $finding = [pscustomobject]@{
                    Verdict='investigate'; Title='Disk delayed'; Count=2; PerDay=0.5
                    Source='event'; Provider='Disk'; Id=153; Channel='System'
                    LastSeen=[datetime]'2026-08-01T12:00:00'; UndatedCount=1
                    Plain='plain'; Why='why'; Action='act'; FalsePositives=@('snapshot')
                    References=@('https://example.test/rule')
                    Sources=@([pscustomobject]@{
                        uri='https://example.test/rule'; author='Example'; licence='CC-BY-4.0'; modified=$true
                    })
                    Samples=@('sample one', 'sample one'); SampleMessage='fallback'
                    RuleId='LV-TEST'; Status='stable'; Confidence='high'; Verified='2026-08-01'
                }

                $detail = ConvertTo-LVGuiDetail -Finding $finding
                $detail.VerdictLabel | Should -BeExactly 'INVESTIGATE'
                $detail.Meta | Should -Match 'Disk event 153.*System channel.*1 line\(s\) carried no timestamp'
                @($detail.FalsePositive) | Should -Be @('snapshot')
                @($detail.Reference) | Should -Be @('https://example.test/rule')
                $detail.SampleText | Should -BeExactly 'sample one'
                $detail.Provenance | Should -Match '^Rule LV-TEST - stable - high confidence - last verified 2026-08-01\.'
                $detail.Provenance | Should -Match 'Derived from Example, CC-BY-4\.0, adapted\.'
                $detail.PSObject.Properties.Name | Should -Not -Contain 'Control'
            } finally {
                $env:LOGVERDICT_TEST_HIGH_CONTRAST = $oldContrast
            }
        }
    }

    It 'projects an unknown finding with raw-message fallback and explicit provenance' {
        InModuleScope LogVerdict {
            $finding = [pscustomobject]@{
                Verdict='unknown'; Title='Unknown'; Count=1; PerDay=0.03
                Source='textlog'; Channel='CBS'; LastSeen=$null; UndatedCount=0
                Plain='plain'; Why='why'; Action='act'; SampleMessage='raw line'
            }
            $detail = ConvertTo-LVGuiDetail -Finding $finding
            $detail.Meta | Should -Match 'CBS log.*last seen undated'
            $detail.SampleText | Should -BeExactly 'raw line'
            $detail.Provenance | Should -Match '^No rule in the verdict database covers this signature'
            @($detail.FalsePositive).Count | Should -Be 0
            @($detail.Reference).Count | Should -Be 0
        }
    }

    It 'keeps the public window file as wiring over the pure helpers' {
        $path = Join-Path (Split-Path $PSScriptRoot -Parent) 'Public/Show-LogVerdictGui.ps1'
        $text = Get-Content -LiteralPath $path -Raw
        $text | Should -Match 'Test-LVGuiFindingVisible'
        $text | Should -Match 'Get-LVGuiVerdictCount'
        $text | Should -Match 'ConvertTo-LVGuiDetail'
        $text | Should -Not -Match '\$state\.Chips\[\$Item\.Verdict\]'
    }

    It 'passes optional advisory settings through the GUI wiring' {
        $root = Split-Path $PSScriptRoot -Parent
        $gui = Get-Content -LiteralPath (Join-Path $root 'Public/Show-LogVerdictGui.ps1') -Raw
        $entry = Get-Content -LiteralPath (Join-Path $root 'LogVerdict-GUI.ps1') -Raw
        $gui | Should -Match '\[string\]\$AdvisoryPath'
        $gui | Should -Match "scanArgs\['AdvisoryPackage'\]"
        $gui | Should -Match 'DEPENDENCY ADVISORIES \(SEPARATE FROM EVENT FINDINGS\)'
        $entry | Should -Match '\[string\]\$AdvisoryVersion'
        $entry | Should -Match "guiArgs\['AdvisoryVersion'\]"
    }
}

Describe 'Package-manager manifest generation' {
    BeforeAll {
        $script:PackageManifestTool = Join-Path (Split-Path $PSScriptRoot -Parent) 'Tools/New-PackageManifests.ps1'
    }

    It 'generates deterministic Scoop and winget manifests from local release assets' {
        $assetDirectory = Join-Path $TestDrive 'assets'
        $outputDirectory = Join-Path $TestDrive 'packaging'
        $null = New-Item -ItemType Directory -Path $assetDirectory
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict.exe'), [byte[]](1, 2, 3, 4))
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict-GUI.exe'), [byte[]](5, 6, 7))

        $result = & $script:PackageManifestTool -Version '9.8.7' -Repository 'Example/LogVerdict' `
            -AssetDirectory $assetDirectory -ReleaseDate '2026-08-01' -OutputDirectory $outputDirectory

        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $consoleHash = ([BitConverter]::ToString($sha256.ComputeHash([IO.File]::ReadAllBytes((Join-Path $assetDirectory 'LogVerdict.exe'))))).Replace('-', '')
            $sha256.Initialize()
            $guiHash = ([BitConverter]::ToString($sha256.ComputeHash([IO.File]::ReadAllBytes((Join-Path $assetDirectory 'LogVerdict-GUI.exe'))))).Replace('-', '')
        } finally {
            $sha256.Dispose()
        }
        $scoop = Get-Content -LiteralPath $result.ScoopManifest -Raw | ConvertFrom-Json
        $winget = Get-Content -LiteralPath $result.WingetManifest -Raw

        $result.Version | Should -BeExactly '9.8.7'
        $result.ReleaseDate | Should -BeExactly '2026-08-01'
        $result.ConsoleSha256 | Should -BeExactly $consoleHash
        $result.GuiSha256 | Should -BeExactly $guiHash
        $scoop.version | Should -BeExactly '9.8.7'
        $scoop.license | Should -BeExactly 'MIT, MS-LPL'
        @($scoop.architecture.'64bit'.url) | Should -Be @(
            'https://github.com/Example/LogVerdict/releases/download/v9.8.7/LogVerdict.exe',
            'https://github.com/Example/LogVerdict/releases/download/v9.8.7/LogVerdict-GUI.exe'
        )
        @($scoop.architecture.'64bit'.hash) | Should -Be @($consoleHash.ToLowerInvariant(), $guiHash.ToLowerInvariant())
        $scoop.bin | Should -BeExactly 'LogVerdict.exe'
        @($scoop.shortcuts[0]) | Should -Be @('LogVerdict-GUI.exe', 'LogVerdict')
        @($scoop.autoupdate.architecture.'64bit'.url)[0] | Should -Match '/v\$version/LogVerdict\.exe$'
        $winget | Should -Match '(?m)^PackageIdentifier: SysAdminDoc\.LogVerdict\r?$'
        $winget | Should -Match '(?m)^PackageVersion: 9\.8\.7\r?$'
        $winget | Should -Match '(?m)^InstallerType: portable\r?$'
        $winget | Should -Match '(?m)^  - Architecture: x64\r?$'
        $winget | Should -Match ('(?m)^    InstallerSha256: {0}\r?$' -f [regex]::Escape($consoleHash))
        $winget | Should -Match '(?m)^ManifestVersion: 1\.12\.0\r?$'
        $winget | Should -Not -Match [regex]::Escape($guiHash)
    }

    It 'requires a release date with offline assets and writes nothing on failure' {
        $assetDirectory = Join-Path $TestDrive 'offline-assets'
        $outputDirectory = Join-Path $TestDrive 'failed-output'
        $null = New-Item -ItemType Directory -Path $assetDirectory
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict.exe'), [byte[]](1))
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict-GUI.exe'), [byte[]](2))

        { & $script:PackageManifestTool -Version '1.2.3' -AssetDirectory $assetDirectory `
                -OutputDirectory $outputDirectory } | Should -Throw '*ReleaseDate is required*'
        Test-Path -LiteralPath $outputDirectory | Should -BeFalse
    }

    It 'tracks the current version and immutable hashes in the checked-in manifests' {
        $repo = Split-Path $PSScriptRoot -Parent
        $version = (& (Join-Path $repo 'Tools\Get-LogVerdictVersion.ps1')).Trim()
        $scoopPath = Join-Path $repo 'Packaging/scoop/logverdict.json'
        $wingetPath = Join-Path $repo 'Packaging/winget/SysAdminDoc.LogVerdict.yaml'
        Test-Path -LiteralPath $scoopPath | Should -BeTrue
        Test-Path -LiteralPath $wingetPath | Should -BeTrue

        $scoop = Get-Content -LiteralPath $scoopPath -Raw | ConvertFrom-Json
        $winget = Get-Content -LiteralPath $wingetPath -Raw
        $scoop.version | Should -BeExactly $version
        @($scoop.architecture.'64bit'.hash).Count | Should -Be 2
        @($scoop.architecture.'64bit'.hash | Where-Object { $_ -notmatch '^(?i:[0-9a-f]{64})$' }).Count | Should -Be 0
        $winget | Should -Match ("(?m)^PackageVersion: {0}\r?$" -f [regex]::Escape($version))
        $winget | Should -Match '(?m)^    InstallerSha256: [0-9A-Fa-f]{64}\r?$'
        $winget | Should -Not -Match '/releases/latest/'
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
    It 'keeps the findings list virtualized and resolves detail by index' {
        InModuleScope LogVerdict {
            $xaml = Get-LVGuiXaml
            $xaml | Should -Match 'VirtualizingPanel\.IsVirtualizing="True"'
            $xaml | Should -Match 'VirtualizingPanel\.VirtualizationMode="Recycling"'
            $gui = Join-Path (Split-Path $PSScriptRoot -Parent) 'Public\Show-LogVerdictGui.ps1'
            $text = Get-Content -LiteralPath $gui -Raw
            $text | Should -Match 'FindingStore'
            $text | Should -Match 'FindingIndex'
            $text | Should -Not -Match '\$Row\.Finding\b'
        }
    }

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

    It 'keeps keyboard targets and long error states usable at the requested scale' {
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
            Set-ItResult -Skipped -Because 'WPF layout and keyboard navigation need a single-threaded apartment'
            return
        }
        InModuleScope LogVerdict {
            Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml, UIAutomationTypes
            $xaml = Get-LVGuiXaml
            $xml = [xml]$xaml
            $scale = 1.25
            if ($env:LOGVERDICT_TEST_DPI_SCALE) {
                $parsedScale = 0.0
                if ([double]::TryParse($env:LOGVERDICT_TEST_DPI_SCALE,
                        [Globalization.NumberStyles]::Float,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [ref]$parsedScale) -and $parsedScale -gt 0) {
                    $scale = $parsedScale
                }
            }

            # The default window is deliberately sized in device-independent units.
            # Check its real footprint before layout so 125% scaling stays inside a
            # 1920x1080 work area instead of hiding the status bar behind the taskbar.
            ([double]$xml.Window.Width * $scale) | Should -BeLessOrEqual 1920
            ([double]$xml.Window.Height * $scale) | Should -BeLessOrEqual 1080

            $window = [Windows.Markup.XamlReader]::Parse($xaml)
            $snapshot = Get-LVGuiThemeSnapshot -Window $window
            Sync-LVGuiTheme -Window $window -Snapshot $snapshot -HighContrast (Test-LVGuiHighContrast) | Out-Null
            $window.Measure([System.Windows.Size]::new(1340, 760))
            $window.Arrange((New-Object System.Windows.Rect(0, 0, 1340, 760)))
            $window.UpdateLayout()

            foreach ($name in @('TxtOverviewDays', 'TxtOverviewChannels', 'TxtSearch', 'BtnOverviewScan', 'LvFindings')) {
                $element = $window.FindName($name)
                $element | Should -Not -BeNullOrEmpty -Because "$name must remain present at the scaled layout"
                $element.Focusable | Should -BeTrue -Because "$name must be reachable by keyboard focus"
                [System.Windows.Input.KeyboardNavigation]::GetTabIndex($element) | Should -BeGreaterOrEqual 0
            }

            $long = 'The scan did not finish. ' + ('diagnostic detail ' * 400)
            $window.FindName('TxtEmptyTitle').Text = 'The scan did not finish'
            $window.FindName('TxtEmptyBody').Text = $long
            $window.FindName('TxtSample').Text = $long
            $window.FindName('PnlEmpty').Visibility = 'Visible'
            $window.UpdateLayout()
            $window.FindName('TxtEmptyBody').TextWrapping | Should -Be ([System.Windows.TextWrapping]::Wrap)
            $window.FindName('TxtSample').TextWrapping | Should -Be ([System.Windows.TextWrapping]::Wrap)
            $window.FindName('TxtEmptyBody').Text.Length | Should -Be $long.Length
            $window.FindName('TxtSample').Text.Length | Should -Be $long.Length
            $window.Close()
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
    It 'ships at the newest schema this build understands, and still accepts the older ones' {
        # Bound to the constant, not to a literal. Pinning the number here meant that
        # every schema bump broke this test for a reason unrelated to what it checks.
        InModuleScope LogVerdict {
            $script:LVSchemaVersionMax | Should -BeGreaterOrEqual 3
            (Get-LogVerdictDatabase).schemaVersion | Should -Be $script:LVSchemaVersionMax
        }
    }

    It 'still refuses a schema newer than this build understands' {
        InModuleScope LogVerdict {
            $next = $script:LVSchemaVersionMax + 1
            $future = Join-Path $TestDrive 'future.json'
            ('{{ "schemaVersion": {0}, "name": "future", "updated": "2026-07-31", "rules": [] }}' -f $next) |
                Set-Content -LiteralPath $future -Encoding UTF8
            { Get-LogVerdictDatabase -Path $future } | Should -Throw -ExpectedMessage ('*schemaVersion {0}*' -f $next)
        }
    }

    It 'rejects an active rule without provenance' {
        # A live ruling must be checkable by a reader. Internal observations are valid
        # when they are declared explicitly; an omitted citation is not.
        $bare = Join-Path $TestDrive 'bare.json'
        '{ "schemaVersion": 3, "name": "bare", "updated": "2026-07-31", "rules": [ { "id":"B-1","status":"stable","verified":"2026-07-31","match":{"source":"event"},"verdict":"benign","title":"t","plain":"p","why":"w","action":"a","confidence":"high" } ] }' |
            Set-Content -LiteralPath $bare -Encoding UTF8

        Test-LogVerdictDatabase -Path $bare -Quiet | Should -BeFalse
        @(Test-LogVerdictDatabase -Path $bare).Count | Should -Be 1
        $all = @(Test-LogVerdictDatabase -Path $bare -IncludeWarnings)
        @($all | Where-Object { $_.Problem -like '*active rule requires*' }).Count | Should -Be 1

        $observed = [pscustomobject]@{
            schemaVersion = 5; name = 'observed'; updated = '2026-07-31'
            rules = @([pscustomobject]@{
                id='B-1'; status='stable'; verified='2026-07-31'; provenance='internal-observation'
                match=[pscustomobject]@{ source='event' }; verdict='benign'; title='t'; plain='p'; why='w'; action='a'; confidence='high'
            })
        }
        $observedPath = Join-Path $TestDrive 'observed.json'
        $observed | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $observedPath -Encoding UTF8
        Test-LogVerdictDatabase -Path $observedPath -Quiet | Should -BeTrue
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

            # AccentInk is intentionally dark because it is used only on light accent
            # fills. These four brushes are the ones that carry body text on the dark
            # page surfaces measured below.
            $bodyBrush = @('Text', 'TextMuted', 'Subtext0', 'Subtext1')
            $used = @([regex]::Matches($xaml, 'Foreground="\{DynamicResource (\w+)\}"') |
                ForEach-Object { $_.Groups[1].Value } |
                Where-Object { $_ -in $bodyBrush } |
                Sort-Object -Unique)
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
            ([regex]::Matches($xaml, 'FocusVisualStyle" Value="\{DynamicResource LVFocusVisual\}"')).Count |
                Should -BeGreaterOrEqual 5
        }
    }

    It 'uses dynamic resources for every semantic colour reference' {
        InModuleScope LogVerdict {
            $xaml = Get-LVGuiXaml
            $xaml | Should -Not -Match '(Background|Foreground|BorderBrush|Stroke|Tag)="\{StaticResource (Base|Mantle|Crust|Surface\d|Overlay\d|Text|TextMuted|Subtext\d|Blue|Lavender|Mauve|Red|Peach|Yellow|Green|Sky|Accent\w*|Row\w*|Nav\w*|SoftPanel|BluePanel|Success\w*|ElevationPanel|StatusIcon|Warning\w*|InfoPanel|CoveragePanel|LogBackground)\}"'
            ([regex]::Matches($xaml, '\{DynamicResource \w+\}')).Count | Should -BeGreaterThan 100
        }
    }

    It 'maps High Contrast to SystemColors and restores the original resource objects' {
        InModuleScope LogVerdict {
            Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
            $window = [Windows.Markup.XamlReader]::Parse((Get-LVGuiXaml))
            $snapshot = Get-LVGuiThemeSnapshot -Window $window
            $base = $snapshot['Base']
            $focus = $snapshot['LVFocusVisual']
            $frameworkFocus = $window.TryFindResource([System.Windows.SystemParameters]::FocusVisualStyleKey)

            Sync-LVGuiTheme -Window $window -Snapshot $snapshot -HighContrast $true | Should -BeTrue
            [object]::ReferenceEquals($window.Resources['Base'], [System.Windows.SystemColors]::WindowBrush) | Should -BeTrue
            [object]::ReferenceEquals($window.Resources['Blue'], [System.Windows.SystemColors]::HighlightBrush) | Should -BeTrue
            [object]::ReferenceEquals($window.Resources['AccentInk'], [System.Windows.SystemColors]::HighlightTextBrush) | Should -BeTrue
            [object]::ReferenceEquals($window.Resources['LVFocusVisual'], $frameworkFocus) | Should -BeTrue

            Sync-LVGuiTheme -Window $window -Snapshot $snapshot -HighContrast $false | Should -BeFalse
            [object]::ReferenceEquals($window.Resources['Base'], $base) | Should -BeTrue
            [object]::ReferenceEquals($window.Resources['LVFocusVisual'], $focus) | Should -BeTrue
            $window.Close()
        }
    }

    It 'uses system highlight colours for data-bound verdict pills in High Contrast' {
        InModuleScope LogVerdict {
            $before = $env:LOGVERDICT_TEST_HIGH_CONTRAST
            try {
                $env:LOGVERDICT_TEST_HIGH_CONTRAST = '1'
                $style = Get-LVVerdictStyle -Verdict 'critical'
                [object]::ReferenceEquals($style.Fill, [System.Windows.SystemColors]::HighlightBrush) | Should -BeTrue
                [object]::ReferenceEquals($style.Ink, [System.Windows.SystemColors]::HighlightTextBrush) | Should -BeTrue
            } finally {
                $env:LOGVERDICT_TEST_HIGH_CONTRAST = $before
            }
        }
    }

    It 'subscribes to High Contrast changes and unsubscribes when the window closes' {
        $gui = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'Public\Show-LogVerdictGui.ps1') -Raw
        $gui | Should -Match 'SystemParameters\]::add_StaticPropertyChanged'
        $gui | Should -Match 'SystemParameters\]::remove_StaticPropertyChanged'
        $gui | Should -Match "PropertyName -ne 'HighContrast'"
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

    It 'formats a correlated finding as a sentence, leading with the verdict' {
        InModuleScope LogVerdict {
            $c = [pscustomobject]@{
                Verdict = 'critical'; Title = 'Hardware died'; Timespan = '10m'
                Windows = @(
                    [pscustomobject]@{ Start = [datetime]'2026-06-20 09:09:02' }
                    [pscustomobject]@{ Start = [datetime]'2026-06-24 05:40:26' }
                )
            }
            $line = @(Format-LVCorrelation -Correlation @($c))[0]
            $line | Should -Match '^CRITICAL\. Hardware died\. 2 time\(s\), within 10m'
            $line | Should -Match '2026-06-20 09:09'
        }
    }

    It 'returns an empty array when nothing correlated' {
        InModuleScope LogVerdict {
            @(Format-LVCorrelation -Correlation @()).Count | Should -Be 0
        }
    }

    It 'surfaces correlations in the window, not only in the console report' {
        # The window silently dropping something the console shows is how the same scan
        # ends up telling you different things depending on how you ran it.
        $gui = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'Public\Show-LogVerdictGui.ps1') -Raw
        $gui | Should -Match 'Format-LVCorrelation'
        $gui | Should -Match 'PnlCorrelation'
        $xaml = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'Private\50-LVGuiXaml.ps1') -Raw
        $xaml | Should -Match 'x:Name="LstCorrelation"'
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

Describe 'Evidence bundle' {
    BeforeAll {
        $script:Scan = Invoke-LogVerdictScan -DaysBack 2 -SkipReliability 6>$null
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        function Get-ZipEntry {
            param([string]$Path)
            $zip = [IO.Compression.ZipFile]::OpenRead($Path)
            try { return @($zip.Entries | ForEach-Object { $_.Name }) } finally { $zip.Dispose() }
        }
        function Get-ZipText {
            param([string]$Path, [string]$Entry)
            $zip = [IO.Compression.ZipFile]::OpenRead($Path)
            try {
                $e = $zip.Entries | Where-Object { $_.Name -eq $Entry } | Select-Object -First 1
                if (-not $e) { return $null }
                $r = New-Object IO.StreamReader($e.Open())
                try { return $r.ReadToEnd() } finally { $r.Close() }
            } finally { $zip.Dispose() }
        }
    }

    It 'writes a zip carrying the reports and a manifest' {
        $dir = Join-Path $TestDrive 'bundle-plain'
        $out = Export-LogVerdictReport -Result $script:Scan -OutputDir $dir -IncludeEvidence -AllowRawEvidence 6>$null
        $out.EvidenceBundle | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $out.EvidenceBundle | Should -BeTrue

        $names = Get-ZipEntry -Path $out.EvidenceBundle
        $names | Should -Contain 'MANIFEST.txt'
        $names | Should -Contain 'LogVerdict-Report.json'
        $names | Should -Contain 'PRIVACY-AUDIT.json'
    }

    It 'requires an explicit override before packaging raw evidence' {
        $dir = Join-Path $TestDrive 'bundle-raw-confirmation'
        { Export-LogVerdictReport -Result $script:Scan -OutputDir $dir -IncludeEvidence } |
            Should -Throw '*AllowRawEvidence*'
    }

    It 'omits the channel exports when the bundle is redacted' {
        # .evtx is binary and carries the account names, hostnames and SIDs that
        # redaction strips out of the text. A bundle that claimed to be sanitized while
        # shipping them would be worse than one that never claimed it.
        $dir = Join-Path $TestDrive 'bundle-redacted'
        $out = Export-LogVerdictReport -Result $script:Scan -OutputDir $dir -IncludeEvidence -Redact 6>$null

        $names = Get-ZipEntry -Path $out.EvidenceBundle
        @($names | Where-Object { $_ -like '*.evtx' }).Count | Should -Be 0
    }

    It 'says in the manifest why the channel exports are missing' {
        # An omission nobody is told about reads as an absence of evidence. Somebody
        # opening this months later must not conclude those channels were clean.
        $dir = Join-Path $TestDrive 'bundle-manifest'
        $out = Export-LogVerdictReport -Result $script:Scan -OutputDir $dir -IncludeEvidence -Redact 6>$null

        $manifest = Get-ZipText -Path $out.EvidenceBundle -Entry 'MANIFEST.txt'
        $manifest | Should -Match 'Redacted  : yes'
        $manifest | Should -Match 'Sanitized : yes'
        $manifest | Should -Match 'Privacy audit: passed; 0 finding'
        $manifest | Should -Match 'WHAT IS DELIBERATELY NOT HERE'
        $manifest | Should -Match '(?s)Event channel exports.*sanitized'
    }

    It 'blocks a redacted bundle when a staged report retains a secret' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive } {
            param($Root)
            $dir = Join-Path $Root 'bundle-blocked'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $report = Join-Path $dir 'dirty-report.txt'
            Set-Content -LiteralPath $report -Value 'access_token=not-safe-to-share' -Encoding UTF8
            $result = [pscustomobject]@{
                Version='0.8.0'; MachineName='HOST-9'; ScanTime=(Get-Date); DaysBack=1; Elevated=$false
                Channels=@(); Reduction=[pscustomobject]@{ RecordCount=0; SignatureCount=0; Ratio=0 }
                DatabaseName='fixture'; RuleCount=0; DatabaseDate='2026-08-02'; WorstVerdict='benign'
                Findings=@(); Correlations=@(); Coverage=@(); HealthProfiles=@(); CoverageNotes=@()
            }
            $audit = $null
            $zip = New-LVEvidenceBundle -Result $result -OutputDir $dir -ReportFile @($report) -Redact `
                -OriginalMachineName 'HOST-9' -OriginalUserName 'jsmith' -Audit ([ref]$audit)
            $zip | Should -BeNullOrEmpty
            $audit.Status | Should -BeExactly 'blocked'
            $audit.FindingCount | Should -BeGreaterThan 0
            Test-Path -LiteralPath (Join-Path $dir 'evidence') | Should -BeTrue
            (Get-Content -LiteralPath (Join-Path $dir 'evidence\PRIVACY-AUDIT.json') -Raw) | Should -Not -Match 'not-safe-to-share'
        }
    }

    It 'leaks no hostname into any text member of a redacted bundle' {
        $dir = Join-Path $TestDrive 'bundle-leak'
        $out = Export-LogVerdictReport -Result $script:Scan -OutputDir $dir -IncludeEvidence -Redact 6>$null

        $zip = [IO.Compression.ZipFile]::OpenRead($out.EvidenceBundle)
        try {
            foreach ($e in $zip.Entries) {
                $r = New-Object IO.StreamReader($e.Open())
                try { $text = $r.ReadToEnd() } finally { $r.Close() }
                $text | Should -Not -Match ([regex]::Escape($env:COMPUTERNAME)) -Because "$($e.Name) must not name the machine"
            }
        } finally { $zip.Dispose() }
    }

    It 'writes no bundle unless asked' {
        $dir = Join-Path $TestDrive 'bundle-none'
        $out = Export-LogVerdictReport -Result $script:Scan -OutputDir $dir 6>$null
        $out.EvidenceBundle | Should -BeNullOrEmpty
        @(Get-ChildItem -LiteralPath $dir -Filter '*.zip').Count | Should -Be 0
    }

    It 'removes the staging directory once the zip exists' {
        $dir = Join-Path $TestDrive 'bundle-staging'
        Export-LogVerdictReport -Result $script:Scan -OutputDir $dir -IncludeEvidence -AllowRawEvidence 6>$null | Out-Null
        Test-Path -LiteralPath (Join-Path $dir 'evidence') | Should -BeFalse
    }

    It 'carries the matching text-log lines rather than the whole log' {
        # CBS.log alone routinely runs to hundreds of megabytes and almost none of it is
        # evidence. An excerpt file must never approach the size of its source.
        InModuleScope LogVerdict -Parameters @{ Scan = $script:Scan; Drive = $TestDrive } {
            param($Scan, $Drive)
            $dest = Join-Path $Drive 'excerpt'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            $written = @(Export-LVTextLogEvidence -Result $Scan -Destination $dest)
            foreach ($w in $written) {
                (Get-Item -LiteralPath $w).Length | Should -BeLessThan 2MB
            }
        }
    }

    It 'redacts the text-log excerpts too, not only the reports' {
        InModuleScope LogVerdict -Parameters @{ Drive = $TestDrive } {
            param($Drive)
            $dest = Join-Path $Drive 'excerpt-redacted'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            $result = [pscustomobject]@{
                MachineName = 'HOST-9'
                Findings = @([pscustomobject]@{
                    Source = 'textlog'; Channel = 'CBS'; Key = 'CBS/abc'; Count = 1
                    FirstSeen = (Get-Date); LastSeen = (Get-Date)
                    Samples = @('HOST-9 failed to stage a package')
                })
            }
            $written = @(Export-LVTextLogEvidence -Result $result -Destination $dest -Redact)
            (Get-Content -LiteralPath $written[0] -Raw) | Should -Not -Match 'HOST-9'
        }
    }
}

Describe 'Offline evidence analysis' {
    BeforeAll {
        Add-Type -AssemblyName System.IO.Compression.FileSystem

        function Export-OfflineReportBundle {
            param([string]$Root)

            $source = Join-Path $Root 'source'
            New-Item -ItemType Directory -Path $source -Force | Out-Null
            $report = [ordered]@{
                Tool = 'LogVerdict'; Version = '0.7.0'; MachineName = 'ARCHIVE-HOST'
                ScanTime = '2026-08-01T10:00:00-04:00'; DaysBack = 9; Elevated = $true
                Channels = @('System'); ChannelStatus = @{}; DeniedChannels = @()
                TruncatedChannels = @(); MetadataUnreadableCount = 0; CoverageNotes = @()
                Reduction = [ordered]@{ RecordCount=1; SignatureCount=1; Ratio=1; LoudestKey='CBS/test'; LoudestShare=100 }
                Findings = @([ordered]@{
                    Key='CBS/test'; Source='textlog'; Channel='CBS'; Provider='CBS'; Id=0
                    Template='failure'; Count=1; UndatedCount=0
                    FirstSeen='2026-08-01T09:00:00-04:00'; LastSeen='2026-08-01T09:00:00-04:00'
                    WorstLevel=2; LevelName='Error'; SampleMessage='2026-08-01 09:00:00, Error CSI test failure'
                    Samples=@('2026-08-01 09:00:00, Error CSI test failure')
                    Times=@('2026-08-01T09:00:00-04:00'); Area='Component servicing'; PerDay=0.03; SpanDays=0
                })
                Correlations=@(); CrashArtifacts=@(); Horizon=@{}; HorizonWarning=$null
                Stability=$null; ReliabilityAvailable=$false; DatabaseName='old'; DatabaseDate='2026-07-31'
                RuleCount=85; WorstVerdict='investigate'; ExitCode=1
            }
            [IO.File]::WriteAllText((Join-Path $source 'LogVerdict-Report.json'),
                ($report | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
            $zip = Join-Path $Root 'evidence.zip'
            [IO.Compression.ZipFile]::CreateFromDirectory($source, $zip)
            return $zip
        }
    }

    It 're-evaluates a report-only bundle without querying live sources' {
        $bundle = Export-OfflineReportBundle -Root (Join-Path $TestDrive 'offline')
        InModuleScope LogVerdict -Parameters @{ Bundle = $bundle } {
            param($Bundle)
            Mock Get-LVChannelStatus { throw 'live channel probe must not run' }
            Mock Get-LVTextLogRecord { throw 'live text collection must not run' }
            Mock Get-LVReliabilityRecord { throw 'live Reliability collection must not run' }
            Mock Get-LVCrashArtifact { throw 'live crash inventory must not run' }

            $result = Invoke-LogVerdictScan -EvidencePath $Bundle -SkipReliability

            $result.Offline | Should -BeTrue
            $result.MachineName | Should -Be 'ARCHIVE-HOST'
            $result.DaysBack | Should -Be 9
            $result.Findings[0].RuleId | Should -Be 'LV-0091'
            $result.CoverageNotes | Should -Contain 'The package contains no raw event channel export. Findings were re-evaluated from the captured report summaries only.'
            Assert-MockCalled Get-LVChannelStatus -Times 0
            Assert-MockCalled Get-LVTextLogRecord -Times 0
            Assert-MockCalled Get-LVReliabilityRecord -Times 0
            Assert-MockCalled Get-LVCrashArtifact -Times 0
        }
    }

    It 'normalizes records from an exported event file' {
        InModuleScope LogVerdict {
            Mock Get-WinEvent {
                if ($Path) {
                    return [pscustomobject]@{ LogName='System'; TimeCreated=[datetime]'2026-08-01T08:00:00'; }
                }
                return [pscustomobject]@{
                    LogName='System'; ProviderName='Disk'; Id=7; Level=2; LevelDisplayName='Error'
                    TimeCreated=[datetime]'2026-08-01T09:00:00'; MachineName='ARCHIVE-HOST'; RecordId=42; Message='bad block'
                }
            }

            $data = Read-LVArchivedEventFile -Path 'fixture.evtx' -DaysBack 30

            $data.Error | Should -BeNullOrEmpty
            $data.Channel | Should -Be 'System'
            $data.Records.Count | Should -Be 1
            $data.Records[0].Provider | Should -Be 'Disk'
            $data.Records[0].RecordId | Should -Be 42
        }
    }

    It 'scans one direct EVTX file with a source hash and parser metadata' {
        $evtx = Join-Path $TestDrive 'single.evtx'
        [IO.File]::WriteAllBytes($evtx, [byte[]](0x45, 0x56, 0x54, 0x58, 0x01))
            InModuleScope LogVerdict -Parameters @{ EvtxPath=$evtx } {
            param($EvtxPath)
            Mock Get-WinEvent {
                param($Oldest)
                if ($Oldest) {
                    return [pscustomobject]@{ LogName='System'; TimeCreated=(Get-Date).AddHours(-1) }
                }
                return [pscustomobject]@{
                    LogName='System'; ProviderName='Disk'; Id=7; Level=2; LevelDisplayName='Error'
                    TimeCreated=(Get-Date).AddHours(-1); MachineName='ARCHIVE-HOST'; RecordId=42; Message='bad block'
                }
            }

            $result = Invoke-LVOfflineScan -EvidencePath $EvtxPath -DaysBack 1 -SkipTextLogs -SkipReliability -PerformanceTelemetry
            $result.Offline | Should -BeTrue
            @($result.EvidenceManifest).Count | Should -Be 1
            $result.EvidenceManifest[0].Status | Should -BeExactly 'parsed'
            $result.EvidenceManifest[0].SHA256 | Should -Match '^[0-9A-F]{64}$'
            $result.EvidenceManifest[0].RecordCount | Should -Be 1
            $result.EvidenceManifest[0].ParseMilliseconds | Should -Not -BeNullOrEmpty
            $result.PerformanceTelemetry | Should -BeTrue
            @($result.Performance | Where-Object Source -eq 'offline-evtx').Count | Should -Be 1
            @($result.Performance | Where-Object Name -eq 'scan total').Count | Should -Be 1
            ($result.Performance | ConvertTo-Json -Depth 5) | Should -Not -Match 'bad block|ARCHIVE-HOST|single\.evtx'
            @($result.CoverageNotes | Where-Object { $_ -match 'SHA-256 [0-9A-F]{64}' }).Count | Should -Be 1
            $manifest = Format-LVEvidenceManifest -Result $result -Content @()
            $manifest | Should -Match ('SHA-256 ' + $result.EvidenceManifest[0].SHA256)
        }
    }

    It 'bounds an EVTX directory by file count and size before parsing' {
        $root = Join-Path $TestDrive 'evtx-bounded'
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        foreach ($name in @('01.evtx', '02.evtx', '03.evtx')) {
            [IO.File]::WriteAllBytes((Join-Path $root $name), [byte[]](0x45, 0x56, 0x54, 0x58))
        }
        InModuleScope LogVerdict -Parameters @{ Root=$root } {
            param($Root)
            Mock Get-WinEvent {
                param($Oldest)
                if ($Oldest) { return [pscustomobject]@{ LogName='System'; TimeCreated=(Get-Date).AddHours(-1) } }
                return [pscustomobject]@{
                    LogName='System'; ProviderName='Disk'; Id=7; Level=2; LevelDisplayName='Error'
                    TimeCreated=(Get-Date).AddHours(-1); MachineName='ARCHIVE-HOST'; RecordId=42; Message='bad block'
                }
            }

            $result = Invoke-LVOfflineScan -EvidencePath $Root -DaysBack 1 -MaxEvtxFiles 1 -SkipTextLogs -SkipReliability
            @($result.EvidenceManifest).Count | Should -Be 2 -Because 'one extra file proves the count cap was reached'
            @($result.EvidenceManifest | Where-Object Status -eq 'parsed').Count | Should -Be 1
            @($result.EvidenceManifest | Where-Object Status -eq 'skipped').Count | Should -Be 1
            $result.CoverageNotes | Should -Contain 'The offline EVTX file-count cap of 1 was reached; additional files were not enumerated.'
            @($result.CoverageNotes | Where-Object { $_ -match 'file-count cap of 1 reached' }).Count | Should -Be 1
        }

        $large = Join-Path $TestDrive 'too-large.evtx'
        [IO.File]::WriteAllBytes($large, [byte[]](0..15))
        InModuleScope LogVerdict -Parameters @{ EvtxPath=$large } {
            param($EvtxPath)
            Mock Get-WinEvent { throw 'must not parse an oversized source' }
            $result = Invoke-LVOfflineScan -EvidencePath $EvtxPath -DaysBack 1 -MaxEvtxFileBytes 4 -SkipTextLogs -SkipReliability
            $result.EvidenceManifest[0].Status | Should -BeExactly 'skipped'
            $result.EvidenceManifest[0].Reason | Should -Match 'per-file cap'
        }
    }

    It 'reports malformed EVTX content as a source failure with parse timing' {
        $evtx = Join-Path $TestDrive 'malformed.evtx'
        [IO.File]::WriteAllBytes($evtx, [byte[]](0x00, 0x01, 0x02))
        InModuleScope LogVerdict -Parameters @{ EvtxPath=$evtx } {
            param($EvtxPath)
            Mock Get-WinEvent { throw 'malformed event log fixture' }
            $result = Invoke-LVOfflineScan -EvidencePath $EvtxPath -DaysBack 1 -SkipTextLogs -SkipReliability
            $result.EvidenceManifest[0].Status | Should -BeExactly 'unreadable'
            $result.EvidenceManifest[0].Reason | Should -Match 'malformed event log fixture'
            $result.EvidenceManifest[0].ParseMilliseconds | Should -Not -BeNullOrEmpty
            @($result.CoverageNotes | Where-Object { $_ -match 'EVTX malformed\.evtx: unreadable' }).Count | Should -Be 1
        }
    }

    It 'rejects an archive member that escapes the extraction directory' {
        $zipPath = Join-Path $TestDrive 'traversal.zip'
        $stream = [IO.File]::Open($zipPath, [IO.FileMode]::CreateNew)
        $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create)
        try {
            $entry = $zip.CreateEntry('../escape.evtx')
            $writer = New-Object IO.StreamWriter($entry.Open())
            try { $writer.Write('not an event log') } finally { $writer.Dispose() }
        } finally {
            $zip.Dispose()
            $stream.Dispose()
        }

        InModuleScope LogVerdict -Parameters @{ ZipPath = $zipPath } {
            param($ZipPath)
            $archivePath = $ZipPath
            { Expand-LVEvidencePackage -Path $archivePath } | Should -Throw '*escapes the extraction directory*'
        }
    }
}

Describe 'Correlation' {
    BeforeAll {
        # The test data is built here, in the test's own scope, and handed to the module
        # through -Parameters. Helper functions cannot simply be declared for
        # InModuleScope to use: every InModuleScope call is its own scope, so a function
        # defined in one is gone by the next.
        function Build-Sig {
            param($RuleId, $Key, [datetime[]]$Times, $Verdict = 'investigate')
            [pscustomobject]@{
                Key = $Key; RuleId = $RuleId; Verdict = $Verdict; Title = "t $RuleId"
                Times = @($Times); Count = @($Times).Count
            }
        }
        function Build-CorrDb {
            param($Type = 'temporal', $Rules = @('R-1', 'R-2'), $Timespan = '5m', $Verdict = 'actionable')
            [pscustomobject]@{
                schemaVersion = 5; name = 'test'; updated = '2026-08-01'; rules = @()
                correlations = @([pscustomobject]@{
                    id = 'C-1'; status = 'stable'; verified = '2026-08-01'
                    correlation = [pscustomobject]@{ type = $Type; rules = $Rules; timespan = $Timespan }
                    verdict = $Verdict; title = 'together'; plain = 'p'; why = 'w'; action = 'a'; confidence = 'medium'
                })
            }
        }
        function Invoke-Correlate {
            param($Finding, $Database)
            InModuleScope LogVerdict -Parameters @{ F = @($Finding); D = $Database } {
                param($F, $D)
                @(Resolve-LVCorrelation -Finding $F -Database $D)
            }
        }
    }

    Context 'duration parsing' {
        It 'parses <Text> as <Seconds> seconds' -ForEach @(
            @{ Text = '30s'; Seconds = 30 }
            @{ Text = '5m';  Seconds = 300 }
            @{ Text = '2h';  Seconds = 7200 }
            @{ Text = '1d';  Seconds = 86400 }
        ) {
            InModuleScope LogVerdict -Parameters @{ Text = $Text; Seconds = $Seconds } {
                param($Text, $Seconds)
                (ConvertFrom-LVTimespan -Text $Text).TotalSeconds | Should -Be $Seconds
            }
        }

        It 'returns null for <Text> rather than guessing a default' -ForEach @(
            @{ Text = '' }, @{ Text = '5' }, @{ Text = 'soon' }, @{ Text = '0m' }, @{ Text = '-5m' }, @{ Text = '5 minutes' }
        ) {
            # A window that silently became a default would make the rule fire on the
            # wrong span; a window that silently became zero would make it never fire,
            # which looks exactly like a healthy machine.
            InModuleScope LogVerdict -Parameters @{ Text = $Text } {
                param($Text)
                ConvertFrom-LVTimespan -Text $Text | Should -BeNullOrEmpty
            }
        }
    }

    It 'matches a pair that straddles an hour boundary' {
        # The reason this slides rather than bucketing. Sigma's fixed intervals put
        # 09:59 and 10:01 in different buckets and never correlate them, which is
        # precisely the pair a human would call obviously related.
        $findings = @(
            Build-Sig -RuleId 'R-1' -Key 'a' -Times @([datetime]'2026-06-20 09:59:30')
            Build-Sig -RuleId 'R-2' -Key 'b' -Times @([datetime]'2026-06-20 10:01:00')
        )
        $got = Invoke-Correlate -Finding $findings -Database (Build-CorrDb)
        @($got).Count | Should -Be 1
        @($got[0].Windows).Count | Should -Be 1
    }

    It 'does not match a pair at opposite ends of one bucket' {
        # The inverse of the boundary case, and the other half of why bucketing is wrong:
        # 09:01 and 09:56 share a bucket but are 55 minutes apart.
        $findings = @(
            Build-Sig -RuleId 'R-1' -Key 'a' -Times @([datetime]'2026-06-20 09:01:00')
            Build-Sig -RuleId 'R-2' -Key 'b' -Times @([datetime]'2026-06-20 09:56:00')
        )
        @(Invoke-Correlate -Finding $findings -Database (Build-CorrDb)).Count | Should -Be 0
    }

    It 'does not fire when only one of the referenced rules is present' {
        $findings = @(Build-Sig -RuleId 'R-1' -Key 'a' -Times @([datetime]'2026-06-20 09:00:00'))
        @(Invoke-Correlate -Finding $findings -Database (Build-CorrDb)).Count | Should -Be 0
    }

    It 'collapses a burst into one incident rather than one match per occurrence' {
        # Twenty crashes beside twenty service deaths is one episode. Emitting a match
        # per sliding-window position would replace the two findings this feature
        # merges with several hundred, which is worse than not correlating at all.
        $base = [datetime]'2026-06-20 09:00:00'
        $a = 0..19 | ForEach-Object { $base.AddSeconds($_ * 2) }
        $b = 0..19 | ForEach-Object { $base.AddSeconds(1 + $_ * 2) }
        $findings = @(
            Build-Sig -RuleId 'R-1' -Key 'a' -Times $a
            Build-Sig -RuleId 'R-2' -Key 'b' -Times $b
        )
        $got = Invoke-Correlate -Finding $findings -Database (Build-CorrDb)
        @($got[0].Windows).Count | Should -Be 1
    }

    It 'separates two genuinely distinct incidents' {
        $findings = @(
            Build-Sig -RuleId 'R-1' -Key 'a' -Times @([datetime]'2026-06-20 09:00:00', [datetime]'2026-06-24 05:00:00')
            Build-Sig -RuleId 'R-2' -Key 'b' -Times @([datetime]'2026-06-20 09:00:30', [datetime]'2026-06-24 05:00:30')
        )
        $got = Invoke-Correlate -Finding $findings -Database (Build-CorrDb)
        @($got[0].Windows).Count | Should -Be 2
    }

    It 'enforces order for temporal_ordered and ignores it for temporal' {
        # R-2 occurs BEFORE R-1, so the declared order R-1 then R-2 is violated.
        $findings = @(
            Build-Sig -RuleId 'R-1' -Key 'a' -Times @([datetime]'2026-06-20 09:00:30')
            Build-Sig -RuleId 'R-2' -Key 'b' -Times @([datetime]'2026-06-20 09:00:00')
        )
        @(Invoke-Correlate -Finding $findings -Database (Build-CorrDb -Type 'temporal_ordered')).Count | Should -Be 0
        @(Invoke-Correlate -Finding $findings -Database (Build-CorrDb -Type 'temporal')).Count | Should -Be 1
    }

    It 'skips a correlation whose window is unreadable instead of defaulting it' {
        $findings = @(
            Build-Sig -RuleId 'R-1' -Key 'a' -Times @([datetime]'2026-06-20 09:00:00')
            Build-Sig -RuleId 'R-2' -Key 'b' -Times @([datetime]'2026-06-20 09:00:10')
        )
        @(Invoke-Correlate -Finding $findings -Database (Build-CorrDb -Timespan 'whenever') 3>$null).Count | Should -Be 0
    }

    It 'reports the window bounds, not the signature spans' {
        # The reader needs the moment to look at. A signature span can be weeks wide
        # while the incident inside it lasted twelve seconds.
        $findings = @(
            Build-Sig -RuleId 'R-1' -Key 'a' -Times @([datetime]'2026-05-01 00:00:00', [datetime]'2026-06-20 09:00:00')
            Build-Sig -RuleId 'R-2' -Key 'b' -Times @([datetime]'2026-06-20 09:00:12')
        )
        $w = @(Invoke-Correlate -Finding $findings -Database (Build-CorrDb))[0].Windows[0]
        $w.Start | Should -Be ([datetime]'2026-06-20 09:00:00')
        $w.End   | Should -Be ([datetime]'2026-06-20 09:00:12')
    }

    It 'keeps every occurrence time on a signature so correlation has something to read' {
        InModuleScope LogVerdict {
            $now = [datetime]'2026-06-20 09:00:00'
            $records = 0..4 | ForEach-Object {
                [pscustomobject]@{
                    Source = 'event'; Channel = 'System'; Provider = 'P'; Id = 1
                    Level = 2; LevelName = 'Error'; TimeCreated = $now.AddMinutes($_); Message = 'm'
                }
            }
            $sig = @(Group-LVSignature -Record @($records) -WindowDays 30)[0]
            @($sig.Times).Count | Should -Be 5
            # Sorted here so the sliding window is correct; records arrive channel by
            # channel, each sorted within itself but not across channels.
            @($sig.Times)[0] | Should -BeLessThan @($sig.Times)[-1]
        }
    }

    It 'never lets one runaway signature retain unbounded timestamps' {
        InModuleScope LogVerdict {
            $now = [datetime]'2026-06-20 09:00:00'
            $n = $script:LVMaxSignatureTimes + 50
            $records = 0..($n - 1) | ForEach-Object {
                [pscustomobject]@{
                    Source = 'event'; Channel = 'System'; Provider = 'P'; Id = 1
                    Level = 2; LevelName = 'Error'; TimeCreated = $now.AddSeconds($_); Message = 'm'
                }
            }
            $sig = @(Group-LVSignature -Record @($records) -WindowDays 30)[0]
            $sig.Count | Should -Be $n
            @($sig.Times).Count | Should -Be $script:LVMaxSignatureTimes
        }
    }

    It 'ships correlations that reference rules which actually exist' {
        # A correlation naming a deleted or renamed rule can never fire, and nothing
        # else in the suite would notice.
        $db = Get-LogVerdictDatabase
        $ids = @($db.rules.id)
        @($db.correlations).Count | Should -BeGreaterThan 0
        foreach ($c in @($db.correlations)) {
            foreach ($ref in @($c.correlation.rules)) {
                $ids | Should -Contain $ref -Because "$($c.id) references $ref"
            }
        }
    }

    It 'ships correlations whose windows all parse' {
        InModuleScope LogVerdict {
            foreach ($c in @((Get-LogVerdictDatabase).correlations)) {
                ConvertFrom-LVTimespan -Text $c.correlation.timespan |
                    Should -Not -BeNullOrEmpty -Because "$($c.id) declares timespan '$($c.correlation.timespan)'"
                $script:LVCorrelationType | Should -Contain $c.correlation.type -Because "$($c.id) declares type $($c.correlation.type)"
            }
        }
    }

    It 'rejects correlation fields and references the resolver cannot honor' {
        $path = Join-Path $TestDrive 'bad-correlation.json'
        $db = [pscustomobject]@{
            schemaVersion = 5; name = 'bad correlation'; updated = '2026-08-01'
            rules = @(
                [pscustomobject]@{ id='R-1'; status='stable'; verified='2026-08-01'; provenance='internal-observation'; match=[pscustomobject]@{ source='event' }; verdict='investigate'; title='r1'; plain='p'; why='w'; action='a'; confidence='high' }
                [pscustomobject]@{ id='R-2'; status='stable'; verified='2026-08-01'; provenance='internal-observation'; match=[pscustomobject]@{ source='event' }; verdict='investigate'; title='r2'; plain='p'; why='w'; action='a'; confidence='high' }
            )
            correlations = @([pscustomobject]@{
                id='C-BAD'; status='stable'; verified='2026-08-01'
                correlation=[pscustomobject]@{ type='temporal'; rules=@('R-1','MISSING'); timespan='5m'; 'group-by'=@('ProcessGuid') }
                verdict='actionable'; title='bad'; plain='p'; why='w'; action='a'; confidence='medium'
            })
        }
        $db | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
        Test-LogVerdictDatabase -Path $path -SkipFixture -Quiet | Should -BeFalse
        { Get-LogVerdictDatabase -Path $path } | Should -Throw '*failed trust validation*'
        $problems = @(Test-LogVerdictDatabase -Path $path -SkipFixture)
        @($problems | Where-Object Problem -like '*active correlation requires*').Count | Should -Be 1
        @($problems | Where-Object Problem -like '*missing rule*').Count | Should -Be 1
        @($problems | Where-Object Problem -like '*group-by*').Count | Should -Be 1
    }

    It 'rejects event-count correlations until their semantics are implemented' {
        $path = Join-Path $TestDrive 'event-count.json'
        $db = [pscustomobject]@{
            schemaVersion = 5; name = 'event count'; updated = '2026-08-01'
            rules = @(
                [pscustomobject]@{ id='R-1'; status='stable'; verified='2026-08-01'; provenance='internal-observation'; match=[pscustomobject]@{ source='event' }; verdict='investigate'; title='r1'; plain='p'; why='w'; action='a'; confidence='high' }
                [pscustomobject]@{ id='R-2'; status='stable'; verified='2026-08-01'; provenance='internal-observation'; match=[pscustomobject]@{ source='event' }; verdict='investigate'; title='r2'; plain='p'; why='w'; action='a'; confidence='high' }
            )
            correlations = @([pscustomobject]@{
                id='C-COUNT'; status='stable'; verified='2026-08-01'; provenance='internal-observation'
                correlation=[pscustomobject]@{ type='event_count'; rules=@('R-1','R-2'); timespan='5m' }
                verdict='actionable'; title='count'; plain='p'; why='w'; action='a'; confidence='medium'
            })
        }
        $db | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
        { Get-LogVerdictDatabase -Path $path } | Should -Throw '*event_count*not implemented*'
    }

    It 'correlates before benign suppression, so a benign signature still counts as evidence' {
        # A benign signature is perfectly good evidence of WHEN something happened.
        # Dropping it first would silently stop any pairing involving one from firing,
        # for a reason nothing in the output could explain.
        $findings = @(
            Build-Sig -RuleId 'R-1' -Key 'a' -Verdict 'benign' -Times @([datetime]'2026-06-20 09:00:00')
            Build-Sig -RuleId 'R-2' -Key 'b' -Times @([datetime]'2026-06-20 09:00:10')
        )
        @(Invoke-Correlate -Finding $findings -Database (Build-CorrDb)).Count | Should -Be 1
    }

    It 'renders correlations above the flat findings list in the text report' {
        InModuleScope LogVerdict {
            $result = [pscustomobject]@{
                Version = '0.7.0'; MachineName = 'M'; ScanTime = (Get-Date); DaysBack = 30
                Elevated = $false; Channels = @('System'); Reduction = [pscustomobject]@{ RecordCount = 1; SignatureCount = 1; Ratio = 1 }
                DatabaseName = 'db'; RuleCount = 1; DatabaseDate = '2026-08-01'; WorstVerdict = 'critical'
                CoverageNotes = @(); Horizon = @{}; HorizonWarning = $null; Stability = $null
                Findings = @([pscustomobject]@{
                    Verdict = 'investigate'; Title = 'lone signature'; Key = 'K'; Count = 1; PerDay = 1
                    FirstSeen = (Get-Date); LastSeen = (Get-Date); RuleId = 'R-1'; Confidence = 'high'
                    Plain = 'p'; Why = 'w'; Action = 'a'; SampleMessage = 'm'; Samples = @('m')
                    References = @(); Sources = @(); FalsePositives = @(); Status = 'stable'; Verified = '2026-08-01'
                })
                Correlations = @([pscustomobject]@{
                    Id = 'C-1'; Type = 'temporal'; Timespan = '5m'; RuleIds = @('R-1', 'R-2')
                    Verdict = 'critical'; Title = 'the paired finding'; Plain = 'p'; Why = 'w'; Action = 'a'
                    Confidence = 'medium'; References = @(); Sources = @(); FalsePositives = @()
                    InvolvedKeys = @('K'); InvolvedTitles = @('lone signature'); OccurrenceCount = 2
                    Windows = @([pscustomobject]@{ Start = (Get-Date); End = (Get-Date); Occurrences = @() })
                })
            }
            $text = ConvertTo-LVTextReport -Result $result
            $text | Should -Match 'THINGS THAT HAPPENED TOGETHER'
            $text.IndexOf('the paired finding') | Should -BeLessThan $text.IndexOf('lone signature')
        }
    }
}

Describe 'Report redaction' {
    BeforeAll {
        $script:Dirty = 'User MACHINE-01\jsmith SID S-1-5-21-1691094572-189533642-593899815-1000 opened C:\Users\jsmith\AppData\Local\app.log as jsmith@contoso.com'
    }

    It 'masks account, machine, SID, profile path and mail address' {
        InModuleScope LogVerdict -Parameters @{ Dirty = $script:Dirty } {
            param($Dirty)
            $clean = ConvertTo-LVRedactedText -Text $Dirty -UserName 'jsmith' -MachineName 'MACHINE-01'
            $clean | Should -Not -Match 'jsmith'
            $clean | Should -Not -Match 'MACHINE-01'
            $clean | Should -Not -Match 'S-1-5-21-\d'
            $clean | Should -Match '<USER>'
            $clean | Should -Match '<MACHINE>'
            $clean | Should -Match '<UPN>'
        }
    }

    It 'masks a name sitting between underscores' {
        # The report folder is named LogVerdict_<MACHINE>_<timestamp>, and that path is
        # all over the run transcript. A \w boundary treats the underscore as a word
        # character and refuses to match there - so the machine name survived redaction
        # in the one place it most reliably appears.
        InModuleScope LogVerdict {
            $clean = ConvertTo-LVRedactedText -Text 'wrote C:\out\LogVerdict_HOST-9_20260801-113216\report.txt' -UserName 'u' -MachineName 'HOST-9'
            $clean | Should -Not -Match 'HOST-9'
            $clean | Should -Match 'LogVerdict_<MACHINE>_20260801'
        }
    }

    It 'masks another account name in a profile path it was never told about' {
        # The account running the scan is not the only account on the machine, and a
        # report that masks only the current user leaks every other one.
        InModuleScope LogVerdict {
            $clean = ConvertTo-LVRedactedText -Text 'Failed to read C:\Users\adiaz\ntuser.dat' -UserName 'someone-else' -MachineName 'HOST'
            $clean | Should -Be 'Failed to read C:\Users\<USER>\ntuser.dat'
        }
    }

    It 'leaves Windows own profile names alone, since they identify nobody' {
        InModuleScope LogVerdict {
            $clean = ConvertTo-LVRedactedText -Text 'copy to C:\Users\Default\AppData and C:\Users\Public\Desktop' -UserName 'u' -MachineName 'm'
            $clean | Should -Match 'C:\\Users\\Default\\AppData'
            $clean | Should -Match 'C:\\Users\\Public\\Desktop'
        }
    }

    It 'keeps the diagnostic remainder of a path' {
        InModuleScope LogVerdict {
            $clean = ConvertTo-LVRedactedText -Text 'C:\Users\bob\AppData\Local\Programs\Python\Python312\python.exe crashed' -UserName 'bob' -MachineName 'm'
            $clean | Should -Match 'Python312\\python\.exe'
        }
    }

    It 'passes the privacy audit when known identifiers were substituted' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive } {
            param($Root)
            $path = Join-Path $Root 'masked.txt'
            Set-Content -LiteralPath $path -Value 'report <MACHINE> <USER> S-1-5-21-<SID> <UPN>' -Encoding UTF8
            $audit = New-LVPrivacyAudit -Path @($path) -MachineName 'HOST-9' -UserName 'jsmith' -Redacted
            $audit.Status | Should -BeExactly 'passed'
            $audit.Sanitized | Should -BeTrue
            $audit.FindingCount | Should -Be 0
            $audit.SubstitutionCount | Should -BeGreaterThan 0
        }
    }

    It 'reports credential, profile, token, SID, and script-block findings without retaining values' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive } {
            param($Root)
            $path = Join-Path $Root 'dirty.txt'
            Set-Content -LiteralPath $path -Value 'password=super-secret SID S-1-5-21-1-2-3-1000 C:\Users\bob\x.log bearer Bearer abcdefghijklmnop ScriptBlockText=Get-Process' -Encoding UTF8
            $audit = New-LVPrivacyAudit -Path @($path) -MachineName 'HOST-9' -UserName 'jsmith' -AllowRawEvidence
            $audit.Status | Should -BeExactly 'raw-override-approved'
            $audit.Sanitized | Should -BeFalse
            @($audit.Findings | Where-Object Category -eq 'credential-or-secret').Count | Should -BeGreaterThan 0
            @($audit.Findings | Where-Object Category -eq 'profile-path').Count | Should -BeGreaterThan 0
            @($audit.Findings | Where-Object Category -eq 'SID').Count | Should -BeGreaterThan 0
            @($audit.Findings | Where-Object Category -eq 'bearer-token').Count | Should -BeGreaterThan 0
            @($audit.Findings | Where-Object Category -eq 'PowerShell-script-block').Count | Should -BeGreaterThan 0
            foreach ($finding in @($audit.Findings)) {
                $finding.PSObject.Properties.Name | Should -Not -Contain 'Value'
            }
        }
    }

    It 'does not mutate the result the caller still holds' {
        # An operator who exports a redacted copy for a ticket is still troubleshooting
        # the machine in front of them and needs the unmasked evidence afterwards.
        InModuleScope LogVerdict {
            $result = [pscustomobject]@{
                MachineName = 'HOST-9'
                Findings = @([pscustomobject]@{ SampleMessage = 'HOST-9 failed'; Samples = @('HOST-9 failed') })
                CrashArtifacts = @()
                CoverageNotes = @()
            }
            $redacted = ConvertTo-LVRedactedResult -Result $result

            $redacted.Findings[0].SampleMessage | Should -Be '<MACHINE> failed'
            $redacted.MachineName | Should -Be '<MACHINE>'
            $result.Findings[0].SampleMessage   | Should -Be 'HOST-9 failed'
            $result.MachineName | Should -Be 'HOST-9'
        }
    }

    It 'redacts the sample list, not only the single sample message' {
        InModuleScope LogVerdict {
            $result = [pscustomobject]@{
                MachineName = 'HOST-9'
                Findings = @([pscustomobject]@{ SampleMessage = 'a'; Samples = @('HOST-9 one', 'HOST-9 two') })
                CrashArtifacts = @(); CoverageNotes = @()
            }
            $redacted = ConvertTo-LVRedactedResult -Result $result
            foreach ($s in $redacted.Findings[0].Samples) { $s | Should -Not -Match 'HOST-9' }
        }
    }

    It 'redacts the crash artifact paths, which sit under a profile directory' {
        InModuleScope LogVerdict {
            $result = [pscustomobject]@{
                MachineName = 'HOST-9'; Findings = @(); CoverageNotes = @()
                CrashArtifacts = @([pscustomobject]@{
                    Kind = 'wer'; Path = 'C:\Users\bob\AppData\Local\CrashDumps'
                    ReportPath = 'C:\Users\bob\AppData\Local\CrashDumps\Report.wer'
                    App = 'HOST-9-tool.exe'; Module = 'HOST-9-helper.dll'
                    DecodeStatus = 'Access denied at C:\Users\bob\AppData\Local\CrashDumps\Report.wer'
                })
            }
            $redacted = ConvertTo-LVRedactedResult -Result $result
            foreach ($name in @('Path', 'ReportPath', 'App', 'Module', 'DecodeStatus')) {
                $redacted.CrashArtifacts[0].$name | Should -Not -Match 'bob|HOST-9'
            }
        }
    }

    It 'redacts SetupDiag status paths and messages without duplicating its raw records' {
        InModuleScope LogVerdict {
            $result = [pscustomobject]@{
                MachineName = 'HOST-9'; Findings = @(); CrashArtifacts = @(); CoverageNotes = @()
                SetupDiag = [pscustomobject]@{
                    Status='execution-failed'; Message='HOST-9 failed under C:\Users\bob\Panther'
                    ExecutablePath='C:\Users\bob\SetupDiag.exe'; LogsPath='C:\Users\bob\Panther'
                }
            }
            $redacted = ConvertTo-LVRedactedResult -Result $result
            foreach ($name in @('Message', 'ExecutablePath', 'LogsPath')) {
                $redacted.SetupDiag.$name | Should -Not -Match 'bob|HOST-9'
            }
            $redacted.SetupDiag.PSObject.Properties.Name | Should -Not -Contain 'Records'
            $result.SetupDiag.Message | Should -Match 'HOST-9.*bob'
        }
    }

    It 'redacts offline source paths while retaining source hashes' {
        InModuleScope LogVerdict {
            $result = [pscustomobject]@{
                MachineName = 'HOST-9'
                EvidencePath = 'C:\Users\bob\captures\System.evtx'
                EvidenceManifest = @([pscustomobject]@{
                    Path='C:\Users\bob\captures\System.evtx'; Name='System.evtx'; SizeBytes=5
                    SHA256='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
                    Status='parsed'; Reason=$null; ParseMilliseconds=12; RecordCount=1
                })
                Coverage = @([pscustomobject]@{
                    Source='offline-evtx'; Kind='file'; Name='System.evtx'
                    Status='readable'; Path='C:\Users\bob\captures\System.evtx'
                    Reason='captured from HOST-9 workstation'; RecordGap=$null; ParserError=$null
                    SHA256='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
                })
                HealthProfiles = @([pscustomobject]@{
                    Profile='provider-metadata'; Source='event'; Name='HOST-9 provider'; Status='readable'
                    ObservedConfiguration='captured from HOST-9 at C:\Users\bob\captures'; Reason='HOST-9 metadata'
                    Advice='advisory'; Path='C:\Users\bob\captures\provider.xml'; EventIds=@('7'); EventVersions=@('7=3')
                })
                Findings = @(); CrashArtifacts = @(); CoverageNotes = @()
            }
            $redacted = ConvertTo-LVRedactedResult -Result $result
            $redacted.EvidencePath | Should -Not -Match 'bob|HOST-9'
            $redacted.EvidenceManifest[0].Path | Should -Not -Match 'bob|HOST-9'
            $redacted.EvidenceManifest[0].SHA256 | Should -BeExactly $result.EvidenceManifest[0].SHA256
            $redacted.Coverage[0].Path | Should -Not -Match 'bob|HOST-9'
            $redacted.Coverage[0].Reason | Should -Not -Match 'bob|HOST-9'
            $redacted.Coverage[0].Status | Should -BeExactly 'readable'
            $redacted.Coverage[0].SHA256 | Should -BeExactly $result.Coverage[0].SHA256
            $redacted.HealthProfiles[0].Name | Should -Not -Match 'HOST-9'
            $redacted.HealthProfiles[0].ObservedConfiguration | Should -Not -Match 'bob|HOST-9'
            $redacted.HealthProfiles[0].Path | Should -Not -Match 'bob|HOST-9'
            @($redacted.HealthProfiles[0].EventVersions) | Should -Contain '7=3'
        }
    }

    It 'writes reports that state redaction was applied' {
        # A masked report that does not say it is masked reads as a complete one, and
        # the reader draws conclusions from evidence that was removed.
        $result = Invoke-LogVerdictScan -DaysBack 1 -SkipTextLogs -SkipReliability 6>$null
        $dir = Join-Path $TestDrive 'redacted'
        Export-LogVerdictReport -Result $result -OutputDir $dir -Redact 6>$null | Out-Null

        (Get-Content (Join-Path $dir 'LogVerdict-Report.txt') -Raw)  | Should -Match 'Redacted\s+: yes'
        (Get-Content (Join-Path $dir 'LogVerdict-Report.html') -Raw) | Should -Match '<strong>Redacted\.</strong>'
    }

    It 'keeps the machine name out of the written reports but not out of the folder name' {
        $result = Invoke-LogVerdictScan -DaysBack 1 -SkipTextLogs -SkipReliability 6>$null
        $dir = Join-Path $TestDrive 'redacted2'
        Export-LogVerdictReport -Result $result -OutputDir $dir -Redact 6>$null | Out-Null

        foreach ($file in @('LogVerdict-Report.txt', 'LogVerdict-Report.json', 'LogVerdict-Report.html')) {
            (Get-Content (Join-Path $dir $file) -Raw) | Should -Not -Match ([regex]::Escape($env:COMPUTERNAME)) -Because "$file must not name the machine"
        }
    }

    It 'writes the machine name normally when redaction is not asked for' {
        # Redaction must be opt-in. The default report is evidence for the operator.
        $result = Invoke-LogVerdictScan -DaysBack 1 -SkipTextLogs -SkipReliability 6>$null
        $dir = Join-Path $TestDrive 'plain'
        Export-LogVerdictReport -Result $result -OutputDir $dir 6>$null | Out-Null
        (Get-Content (Join-Path $dir 'LogVerdict-Report.txt') -Raw) | Should -Match ([regex]::Escape($env:COMPUTERNAME))
    }
}

Describe 'Reliability Monitor collection' {
    It 'drops a record already collected from an event channel' {
        # Reliability Monitor overlaps the channels heavily. Counting both views of one
        # incident would inflate the count and the rate that rate escalation reads, so a
        # signature could cross its threshold purely because it was collected twice.
        InModuleScope LogVerdict {
            Mock Get-CimInstance {
                @(
                    [pscustomobject]@{ SourceName = 'Application Error'; EventIdentifier = 1000; TimeGenerated = (Get-Date); Message = 'dup'; RecordNumber = 1 }
                    [pscustomobject]@{ SourceName = 'MsiInstaller';      EventIdentifier = 1033; TimeGenerated = (Get-Date); Message = 'new'; RecordNumber = 2 }
                ) } -ParameterFilter { $ClassName -eq 'Win32_ReliabilityRecords' }

            $existing = @([pscustomobject]@{ Source = 'event'; Provider = 'Application Error'; Id = 1000 })
            $got = @(Get-LVReliabilityRecord -DaysBack 30 -ExistingRecord $existing)

            $got.Count | Should -Be 1
            $got[0].Provider | Should -Be 'MsiInstaller'
        }
    }

    It 'reports an unavailable provider as a skipped source rather than as health' {
        # The provider is Group Policy gated and off by default on Server. Silence from
        # a source that was never read must never be reported as a clean result.
        InModuleScope LogVerdict {
            Mock Get-CimInstance { throw 'Invalid class' } -ParameterFilter { $ClassName -eq 'Win32_ReliabilityRecords' }

            $script:LVReliabilityAvailable = $true
            @(Get-LVReliabilityRecord -DaysBack 30).Count | Should -Be 0
            $script:LVReliabilityAvailable | Should -BeFalse
            $script:LVReliabilitySkipReason | Should -Not -BeNullOrEmpty
        }
    }

    It 'keeps a reliability signature separate from the channel signature of the same id' {
        InModuleScope LogVerdict {
            $now = Get-Date
            $records = @(
                [pscustomobject]@{ Source = 'event';       Channel = 'Application'; Provider = 'Application Error'; Id = 1000; Level = 2; LevelName = 'Error'; TimeCreated = $now; Message = 'from the channel' }
                [pscustomobject]@{ Source = 'reliability'; Channel = 'Reliability'; Provider = 'Application Error'; Id = 1000; Level = 4; LevelName = 'Information'; TimeCreated = $now; Message = 'from reliability' }
            )
            $sigs = @(Group-LVSignature -Record $records -WindowDays 30)
            $sigs.Count | Should -Be 2
            ($sigs.Key | Sort-Object) | Should -Be @('Application Error/1000', 'Reliability/Application Error/1000')
        }
    }

    It 'reads the stability index and says which way it is moving' {
        InModuleScope LogVerdict {
            Mock Get-CimInstance {
                @(
                    [pscustomobject]@{ SystemStabilityIndex = 9.5; TimeGenerated = (Get-Date).AddDays(-20) }
                    [pscustomobject]@{ SystemStabilityIndex = 2.1; TimeGenerated = (Get-Date).AddDays(-10) }
                    [pscustomobject]@{ SystemStabilityIndex = 4.0; TimeGenerated = (Get-Date).AddDays(-1) }
                ) } -ParameterFilter { $ClassName -eq 'Win32_ReliabilityStabilityMetrics' }

            $t = Get-LVStabilityTrend -DaysBack 30
            $t.Current   | Should -Be 4.0
            $t.Starting  | Should -Be 9.5
            $t.Lowest    | Should -Be 2.1
            $t.Direction | Should -Be 'worsening'
        }
    }

    It 'returns null rather than a flat trend when the provider is missing' {
        # "No data" and "no change" are different answers and the report renders them
        # differently, so they must not collapse into one value here.
        InModuleScope LogVerdict {
            Mock Get-CimInstance { throw 'Invalid class' } -ParameterFilter { $ClassName -eq 'Win32_ReliabilityStabilityMetrics' }
            Get-LVStabilityTrend -DaysBack 30 | Should -BeNullOrEmpty
        }
    }

    It 'treats a tenth of a point as noise rather than as a trend' {
        InModuleScope LogVerdict {
            Mock Get-CimInstance {
                @(
                    [pscustomobject]@{ SystemStabilityIndex = 5.00; TimeGenerated = (Get-Date).AddDays(-5) }
                    [pscustomobject]@{ SystemStabilityIndex = 5.05; TimeGenerated = (Get-Date).AddDays(-1) }
                ) } -ParameterFilter { $ClassName -eq 'Win32_ReliabilityStabilityMetrics' }
            (Get-LVStabilityTrend -DaysBack 30).Direction | Should -Be 'steady'
        }
    }

    It 'rules every reliability source it collects so the new source does not just raise the unknown count' {
        # Adding a collector that produces nothing but unrecognized signatures would make
        # every scan noisier and every exit code worse, for no diagnostic gain.
        InModuleScope LogVerdict {
            $db = Get-LogVerdictDatabase
            $sigs = @('MsiInstaller/1033', 'MsiInstaller/1034', 'MsiInstaller/1035', 'MsiInstaller/1036', 'Anything/9999') |
                ForEach-Object {
                    $parts = $_ -split '/'
                    [pscustomobject]@{
                        Key = ('Reliability/{0}' -f $_); Source = 'reliability'; Channel = 'Reliability'
                        Provider = $parts[0]; Id = [int]$parts[1]; SampleMessage = 'sample'
                        Count = 1; PerDay = 0; SpanDays = 0
                    }
                }
            foreach ($f in (Resolve-LVVerdict -Signature @($sigs) -Database $db)) {
                $f.Verdict | Should -Not -Be 'unknown' -Because "$($f.Key) must be ruled, even if only by the catch-all"
            }
        }
    }
}

Describe 'Microsoft Docs event importer' {
    BeforeAll {
        $script:MsDocsImporter = Join-Path (Split-Path $PSScriptRoot -Parent) 'Tools\Import-MsDocsEvent.ps1'

        function Export-MsDocsFixtureCorpus {
            param([string]$Root)

            New-Item -ItemType Directory -Path (Join-Path $Root 'support\windows-server\backup-and-storage') -Force | Out-Null
            @'
Attribution 4.0 International
https://creativecommons.org/licenses/by/4.0/
'@ | Set-Content -LiteralPath (Join-Path $Root 'LICENSE') -Encoding UTF8
            @'
---
title: Event ID 513 when running VSS in Windows Server
---

Event ID 513 is logged when Cryptographic Services cannot process the System Writer identity.
The article explains the affected writer and the permissions that should be checked before another backup.
'@ | Set-Content -LiteralPath (Join-Path $Root 'support\windows-server\backup-and-storage\event-id-513-vss-windows-server.md') -Encoding UTF8
        }

        function Export-MsDocsReviewFile {
            param([string]$Path, [string]$Plain)

            @([ordered]@{
                id = 'LV-TEST1'
                sourcePath = 'support/windows-server/backup-and-storage/event-id-513-vss-windows-server.md'
                match = [ordered]@{ source = 'event'; provider = 'Microsoft-Windows-CAPI2'; eventId = 513 }
                verdict = 'investigate'
                title = 'A backup writer could not inventory a service'
                plain = $Plain
                why = 'The snapshot can omit service files when the System Writer cannot enumerate them.'
                action = 'Read the named service and repair only its access or registration problem before retrying the backup.'
                confidence = 'high'
                falsepositives = @()
            }) | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
        }
    }

    It 'discovers event IDs only after verifying the corpus licence' {
        $corpus = Join-Path $TestDrive 'discover'
        Export-MsDocsFixtureCorpus -Root $corpus

        $candidate = @(& $script:MsDocsImporter -CorpusPath $corpus)

        $candidate.Count | Should -Be 1
        $candidate[0].EventId | Should -Be 513
        $candidate[0].SourceUri | Should -Be 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/event-id-513-vss-windows-server'
    }

    It 'turns reviewed paraphrases into attributed CC-BY rules' {
        $corpus = Join-Path $TestDrive 'reviewed'
        Export-MsDocsFixtureCorpus -Root $corpus
        $review = Join-Path $TestDrive 'review.json'
        Export-MsDocsReviewFile -Path $review -Plain 'The snapshot service could not list one service binary while assembling the System Writer metadata.'

        $rule = @(& $script:MsDocsImporter -CorpusPath $corpus -ReviewPath $review -Retrieved '2026-08-01')

        $rule.Count | Should -Be 1
        $rule[0].id | Should -Be 'LV-TEST1'
        $rule[0].sources[0].licence | Should -Be 'CC-BY-4.0'
        $rule[0].sources[0].author | Should -Be 'Microsoft'
        $rule[0].sources[0].modified | Should -BeTrue
        $rule[0].verified | Should -Be '2026-08-01'
    }

    It 'rejects reviewed prose copied from the article' {
        $corpus = Join-Path $TestDrive 'copied'
        Export-MsDocsFixtureCorpus -Root $corpus
        $review = Join-Path $TestDrive 'copied.json'
        Export-MsDocsReviewFile -Path $review -Plain 'The article explains the affected writer and the permissions that should be checked before another backup.'

        { & $script:MsDocsImporter -CorpusPath $corpus -ReviewPath $review } |
            Should -Throw '*reproduces source prose verbatim*'
    }

    It 'fails closed when the checkout does not carry the expected licence' {
        $corpus = Join-Path $TestDrive 'unlicensed'
        New-Item -ItemType Directory -Path $corpus -Force | Out-Null
        'Not a licence' | Set-Content -LiteralPath (Join-Path $corpus 'LICENSE') -Encoding UTF8

        { & $script:MsDocsImporter -CorpusPath $corpus } | Should -Throw '*not recognizably CC-BY-4.0*'
    }
}

Describe 'EvtxECmd map importer' {
    BeforeAll {
        $script:EvtxImporter = Join-Path (Split-Path $PSScriptRoot -Parent) 'Tools\Import-EvtxECmdMap.ps1'

        function Export-EvtxMapFixtureCorpus {
            param([string]$Root)
            $maps = Join-Path $Root 'evtx\Maps'
            New-Item -ItemType Directory -Path $maps -Force | Out-Null
            @'
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy.
'@ | Set-Content -LiteralPath (Join-Path $Root 'evtx\LICENSE') -Encoding UTF8
            @'
Author: Eric Zimmerman
Description: Application Error
EventId: 1000
Channel: Application
Provider: "Application Error"
Maps:
  -
    Property: ExecutableInfo
    PropertyValue: "%ExecutableInfo%"
'@ | Set-Content -LiteralPath (Join-Path $maps 'Application_Application-Error_1000.map') -Encoding UTF8
        }
    }

    It 'emits attributed experimental drafts with empty human prose and salient fields' {
        $root = Join-Path $TestDrive 'evtx-maps'
        Export-EvtxMapFixtureCorpus -Root $root
        $outputPath = Join-Path $TestDrive 'evtx-drafts.json'
        $drafts = @(& $script:EvtxImporter -MapsPath (Join-Path $root 'evtx\Maps') -OutputPath $outputPath -Retrieved '2026-08-01')

        $drafts.Count | Should -Be 1
        $drafts[0].status | Should -BeExactly 'experimental'
        $drafts[0].verdict | Should -BeExactly 'unknown'
        $drafts[0].title | Should -BeExactly ''
        $drafts[0].plain | Should -BeExactly ''
        $drafts[0].why | Should -BeExactly ''
        $drafts[0].action | Should -BeExactly ''
        $drafts[0].match.channel | Should -BeExactly 'Application'
        $drafts[0].match.provider | Should -BeExactly 'Application Error'
        $drafts[0].match.eventId | Should -Be 1000
        $drafts[0].candidateFields | Should -Contain 'ExecutableInfo'
        $drafts[0].sources[0].licence | Should -BeExactly 'MIT'
        $drafts[0].sources[0].author | Should -BeExactly 'Eric Zimmerman'
        (Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json).status | Should -BeExactly 'experimental'
    }

    It 'fails closed when the checkout does not carry the expected MIT licence' {
        $root = Join-Path $TestDrive 'unlicensed-maps'
        $maps = Join-Path $root 'evtx\Maps'
        New-Item -ItemType Directory -Path $maps -Force | Out-Null
        'Not a licence' | Set-Content -LiteralPath (Join-Path $root 'evtx\LICENSE') -Encoding UTF8
        { & $script:EvtxImporter -MapsPath $maps } | Should -Throw '*not recognizably MIT*'
    }
}

Describe 'Sigma rule importer' {
    BeforeAll {
        $script:SigmaImporter = Join-Path (Split-Path $PSScriptRoot -Parent) 'Tools\Import-SigmaRule.ps1'

        function Export-SigmaFixtureCorpus {
            param([string]$Root, [string]$Title = 'PowerShell process creation')
            $rules = Join-Path $Root 'rules\windows'
            New-Item -ItemType Directory -Path $rules -Force | Out-Null
            @'
Detection Rule License (DRL) 1.1
'@ | Set-Content -LiteralPath (Join-Path $Root 'LICENSE') -Encoding UTF8
            @"
title: $Title
id: 11111111-1111-1111-1111-111111111111
status: experimental
description: A review-only process rule
author: Sigma Fixture Author
date: 2026-08-01
references:
  - https://example.test/sigma/process
tags:
  - attack.execution
  - attack.t1059
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith:
      - '\\powershell.exe'
  condition: selection
falsepositives:
  - Administrative scripts
level: high
"@ | Set-Content -LiteralPath (Join-Path $rules 'process.yml') -Encoding UTF8
        }
    }

    It 'emits inactive attributed candidates with mappings and a review diff' {
        $root = Join-Path $TestDrive 'sigma'
        Export-SigmaFixtureCorpus -Root $root
        $queuePath = Join-Path $TestDrive 'sigma-queue.json'
        $diffPath = Join-Path $TestDrive 'sigma-diff.json'
        $candidates = @(& $script:SigmaImporter -RulesPath (Join-Path $root 'rules') -OutputPath $queuePath -DiffPath $diffPath -Retrieved '2026-08-02')

        $candidates.Count | Should -Be 1
        $candidates[0].status | Should -BeExactly 'unsupported'
        $candidates[0].confidence | Should -BeExactly 'draft'
        $candidates[0].match.channel | Should -BeExactly 'Microsoft-Windows-Sysmon/Operational'
        $candidates[0].match.provider | Should -BeExactly 'Microsoft-Windows-Sysmon'
        $candidates[0].match.eventId | Should -Be 1
        $candidates[0].sigma.tags | Should -Contain 'attack.execution'
        $candidates[0].falsepositives | Should -Contain 'Administrative scripts'
        $candidates[0].sources[0].licence | Should -BeExactly 'DRL-1.1'
        $candidates[0].sources[0].author | Should -BeExactly 'Sigma Fixture Author'
        (Get-Content -LiteralPath $queuePath -Raw | ConvertFrom-Json).diff.counts.added | Should -Be 1
        (Get-Content -LiteralPath $diffPath -Raw | ConvertFrom-Json).schemaVersion | Should -Be 1
    }

    It 'reports changed rules by stable Sigma id' {
        $root = Join-Path $TestDrive 'sigma-changed'
        Export-SigmaFixtureCorpus -Root $root
        $firstPath = Join-Path $TestDrive 'sigma-first.json'
        & $script:SigmaImporter -RulesPath (Join-Path $root 'rules') -OutputPath $firstPath -Retrieved '2026-08-02' | Out-Null
        Export-SigmaFixtureCorpus -Root $root -Title 'Changed PowerShell process creation'
        $diffPath = Join-Path $TestDrive 'sigma-changed-diff.json'
        & $script:SigmaImporter -RulesPath (Join-Path $root 'rules') -ExistingPath $firstPath -DiffPath $diffPath -Retrieved '2026-08-02' | Out-Null
        $diff = Get-Content -LiteralPath $diffPath -Raw | ConvertFrom-Json
        @($diff.changed).Count | Should -Be 1
        @($diff.added).Count | Should -Be 0
        @($diff.removed).Count | Should -Be 0
    }

    It 'fails closed for missing or disallowed licenses' {
        $root = Join-Path $TestDrive 'sigma-unlicensed'
        $rules = Join-Path $root 'rules'
        New-Item -ItemType Directory -Path $rules -Force | Out-Null
        @'
title: Unlicensed
id: 22222222-2222-2222-2222-222222222222
logsource:
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
'@ | Set-Content -LiteralPath (Join-Path $rules 'rule.yml') -Encoding UTF8
        { & $script:SigmaImporter -RulesPath $rules } | Should -Throw '*no root LICENSE*'
        "MIT License`nPermission is hereby granted" | Set-Content -LiteralPath (Join-Path $root 'LICENSE') -Encoding UTF8
        { & $script:SigmaImporter -RulesPath $rules -LicensePolicy 'DRL-1.1' } | Should -Throw '*does not satisfy*'
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
                provenance = 'internal-observation'
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
                if ($f.signature.Channel -eq 'WER') {
                    $f.signature.SampleMessage | Should -Match '^Report\.wer application crash:' -Because "$($f.ruleId)'s sample must be a line the crash collector produces"
                    continue
                }
                if ($f.signature.Channel -eq 'Minidump') {
                    $f.signature.SampleMessage | Should -Match '^Kernel minidump bug check 0x[0-9A-Fa-f]{8}; parameters ' -Because "$($f.ruleId)'s sample must be a line the crash collector produces"
                    continue
                }
                if ($f.signature.Channel -eq 'SetupDiag') {
                    $f.signature.Provider | Should -BeExactly 'Microsoft SetupDiag' -Because "$($f.ruleId)'s sample must retain SetupDiag attribution"
                    $f.signature.SampleMessage | Should -Match '^Microsoft SetupDiag .* matched profile ' -Because "$($f.ruleId)'s sample must be a record the SetupDiag projection produces"
                    continue
                }
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
