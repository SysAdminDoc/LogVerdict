#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.1' }

BeforeAll {
    $script:ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'LogVerdict.psd1'
    Import-Module $script:ModulePath -Force

    function Get-LVTestSha256 {
        param([Parameter(Mandatory = $true)][string]$Path)

        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant()
        } finally {
            $sha.Dispose()
        }
    }

    function Get-LVGuiSourceText {
        $root = Split-Path $PSScriptRoot -Parent
        return @(
            Get-Content -LiteralPath (Join-Path $root 'Public\Show-LogVerdictGui.ps1') -Raw
            Get-Content -LiteralPath (Join-Path $root 'Private\51-LVGuiHost.ps1') -Raw
            Get-Content -LiteralPath (Join-Path $root 'Private\51-LVGuiSession.ps1') -Raw
            Get-Content -LiteralPath (Join-Path $root 'Private\52-LVGuiRender.ps1') -Raw
            Get-Content -LiteralPath (Join-Path $root 'Private\53-LVGuiActions.ps1') -Raw
            Get-Content -LiteralPath (Join-Path $root 'Private\54-LVGuiEvents.ps1') -Raw
        ) -join [Environment]::NewLine
    }

    function Get-LVScanSourceText {
        $root = Split-Path $PSScriptRoot -Parent
        return @(
            Get-Content -LiteralPath (Join-Path $root 'Public\Invoke-LogVerdictScan.ps1') -Raw
            Get-Content -LiteralPath (Join-Path $root 'Private\12-LVScanPipeline.ps1') -Raw
            Get-Content -LiteralPath (Join-Path $root 'Private\13-LVCollectOffline.ps1') -Raw
        ) -join [Environment]::NewLine
    }
}
Describe 'Case profiles and responder handoffs' {
    BeforeAll {
        $script:CaseResult = [pscustomobject]@{
            Tool = 'LogVerdict'; Version = '0.8.1'; MachineName = 'HOST-9'
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

        @($first.Files).Count | Should -Be 10
        $timelinePath = Join-Path $firstDir 'LogVerdict-Timeline.jsonl'
        $timeline = @(Get-Content -LiteralPath $timelinePath | ForEach-Object { $_ | ConvertFrom-Json })
        $timeline.Count | Should -BeGreaterThan 0
        $timeline[0].recordType | Should -BeExactly 'metadata'
        $timeline[0].schemaVersion | Should -BeExactly '1.0.0'
        @($timeline | Where-Object recordType -eq 'finding').Count | Should -Be 1
        ($timeline | Where-Object recordType -eq 'finding' | Select-Object -First 1).privacy.state | Should -BeExactly 'raw'
        ($timeline | Where-Object recordType -eq 'finding' | Select-Object -First 1).provider | Should -BeExactly 'Test'
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
        (Get-Content -LiteralPath (Join-Path $firstDir 'LogVerdict-Ticket-Summary.txt') -Raw) | Should -Match 'Scanned \(UTC\): 2026-08-02T'
        (Get-Content -LiteralPath (Join-Path $firstDir 'LogVerdict-Ticket-Summary.html') -Raw) | Should -Not -Match '@media|<style'
        (Get-Content -LiteralPath (Join-Path $firstDir 'LogVerdict-Timesketch.csv') -Raw) | Should -BeExactly (Get-Content -LiteralPath (Join-Path $secondDir 'LogVerdict-Timesketch.csv') -Raw)
    }

    It 'neutralises formula cells in every handoff CSV writer' {
        InModuleScope LogVerdict -Parameters @{ sourceResult = $script:CaseResult } {
            param($sourceResult)
            $result = $sourceResult | Select-Object *
            $finding = $sourceResult.Findings[0] | Select-Object *
            foreach ($property in @(
                [pscustomobject]@{ Name = 'Title'; Value = 'title' }
                [pscustomobject]@{ Name = 'Plain'; Value = 'plain' }
                [pscustomobject]@{ Name = 'Why'; Value = 'why' }
                [pscustomobject]@{ Name = 'Action'; Value = 'action' }
            )) {
                $finding | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value -Force
            }
            $finding.SampleMessage = '=cmd|/C calc'
            $finding.Title = '+title'
            $finding.Plain = '-plain'
            $finding.Why = '@why'
            $finding.Action = "`tcmd"
            $result.Findings = @($finding)

            $reportRow = @(ConvertTo-LVCsvReport -Result $result | ConvertFrom-Csv)[0]
            $reportRow.SampleMessage | Should -BeExactly "'=cmd|/C calc"
            $reportRow.Title | Should -BeExactly "'+title"
            $reportRow.Plain | Should -BeExactly "'-plain"
            $reportRow.Why | Should -BeExactly "'@why"
            $reportRow.Action | Should -BeExactly "'`tcmd"

            $profile = New-LVCaseProfileObject -Result $result -Name 'CSV handoff'
            $output = Join-Path $TestDrive 'formula-handoff'
            Export-LogVerdictHandoff -Result $result -Profile $profile -OutputDir $output | Out-Null
            $timesketch = @(Import-Csv -LiteralPath (Join-Path $output 'LogVerdict-Timesketch.csv'))[0]
            $hayabusa = @(Import-Csv -LiteralPath (Join-Path $output 'LogVerdict-Hayabusa.csv'))[0]
            $timesketch.message | Should -BeExactly "'=cmd|/C calc"
            $hayabusa.Details | Should -BeExactly "'=cmd|/C calc"
        }
    }

    It 'rejects unsafe case-profile prose before profile-id validation' {
        InModuleScope LogVerdict -Parameters @{ sourceResult = $script:CaseResult } {
            param($sourceResult)
            $profile = New-LVCaseProfileObject -Result $sourceResult -Name 'Safe name'
            foreach ($field in @('name', 'purpose')) {
                $profile.$field = "bad: <value>"
                @(Get-LVCaseProfileProblems -Profile $profile) -join ' ' | Should -Match $field
                $profile.$field = "bad`nvalue"
                @(Get-LVCaseProfileProblems -Profile $profile) -join ' ' | Should -Match $field
            }
            $profile.name = 'Safe name'
            $profile.purpose = 'Safe purpose'
            $profile | Add-Member -NotePropertyName notes -NotePropertyValue @('bad: note') -Force
            @(Get-LVCaseProfileProblems -Profile $profile) -join ' ' | Should -Match 'notes'
            $profile | Add-Member -NotePropertyName notes -NotePropertyValue @("bad`nnote") -Force
            @(Get-LVCaseProfileProblems -Profile $profile) -join ' ' | Should -Match 'notes'
        }
    }

    It 'quotes recipe values and strips line breaks from text-source comments' {
        InModuleScope LogVerdict -Parameters @{ sourceResult = $script:CaseResult } {
            param($sourceResult)
            $profile = New-LVCaseProfileObject -Result $sourceResult -Name 'Recipe profile'
            $profile.sources = @($profile.sources + [pscustomobject]@{
                source = 'textlog'; kind = 'textlog'; name = "evil`nname\file"; status = 'readable'; sha256 = $null; sizeBytes = $null
            })
            $kape = Get-LVCaseKapeRecipe -Profile $profile
            $kape | Should -Not -Match "evil`nname"
            $kape | Should -Match ([regex]::Escape('"evil name\\file"'))
            $velociraptor = Get-LVCaseVelociraptorRecipe -Profile $profile
            $velociraptor | Should -Match ('(?m)^name: "Custom\.LogVerdict\.' + $profile.profileId.Substring(0, 16))
            $velociraptor | Should -Match ('LET profile_id = "' + $profile.profileId + '"')
        }
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

    It 'writes a bounded Markdown ticket summary with the same projection used by the GUI' {
        $dir = Join-Path $TestDrive 'ticket-summary'
        $export = Export-LogVerdictReport -Result $script:CaseResult -OutputDir $dir -Format Markdown 6>$null
        $path = Join-Path $dir 'LogVerdict-Ticket-Summary.md'
        $export.Files | Should -Contain $path
        $summary = Get-Content -LiteralPath $path -Raw
        $summary | Should -Match '# LogVerdict ticket summary'
        $summary | Should -Match '\*\*Worst verdict:\*\* \*\*INVESTIGATE\*\*'
        $summary | Should -Match 'Suppressed repeats.*0 record\(s\) reduced to 1 signature'
        $summary | Should -Match '\*\*Action:\*\*\s+Review the full finding details\.'
        $export.Files | Should -Contain (Join-Path $dir 'LogVerdict-Ticket-Summary.txt')
        $export.Files | Should -Contain (Join-Path $dir 'LogVerdict-Ticket-Summary.html')
        (Get-Content -LiteralPath (Join-Path $dir 'LogVerdict-Ticket-Summary.txt') -Raw) | Should -Match 'Scanned \(UTC\): 2026-08-02T'
        $ticketHtml = Get-Content -LiteralPath (Join-Path $dir 'LogVerdict-Ticket-Summary.html') -Raw
        $ticketHtml | Should -Not -Match '@media|<style|<link'
        ([Text.Encoding]::UTF8.GetByteCount($summary)) | Should -BeLessThan 16000

        InModuleScope LogVerdict -Parameters @{ InputResult = $script:CaseResult } {
            param($InputResult)
            $guiText = ConvertTo-LVTicketSummary -Result $InputResult
            $fileText = Get-Content -LiteralPath (Join-Path $TestDrive 'ticket-summary\LogVerdict-Ticket-Summary.md') -Raw
            $guiText | Should -BeExactly $fileText.TrimEnd()
        }
    }

    It 'emits an under-2048-character Intune digest with a binary exit contract' {
        $findingDigest = Get-LogVerdictIntuneDigest -Result $script:CaseResult
        $findingDigest.Text | Should -Not -BeNullOrEmpty
        $findingDigest.CharacterCount | Should -BeLessThan 2048
        $findingDigest.ExitCode | Should -Be 1
        $findingDigest.Encoding | Should -BeExactly 'UTF-8 without BOM'

        $benign = $script:CaseResult | Select-Object *
        $benignFindings = foreach ($finding in @($script:CaseResult.Findings)) {
            $copy = $finding | Select-Object *
            $copy.Verdict = 'benign'
            $copy
        }
        $benign.Findings = @($benignFindings)
        $benign | Add-Member -NotePropertyName Incidents -NotePropertyValue @() -Force
        $benign | Add-Member -NotePropertyName Correlations -NotePropertyValue @() -Force
        $benign.WorstVerdict = 'benign'
        $benign.ExitCode = 0
        $cleanDigest = Get-LogVerdictIntuneDigest -Result $benign
        $cleanDigest.Text | Should -Not -BeNullOrEmpty
        $cleanDigest.CharacterCount | Should -BeLessThan 2048
        $cleanDigest.ExitCode | Should -Be 0
    }

    It 'round-trips a written JSON report through every result consumer and standard format' {
        $writtenDir = Join-Path $TestDrive 'roundtrip-written'
        Export-LogVerdictReport -Result $script:CaseResult -OutputDir $writtenDir -Format Json 6>$null | Out-Null
        $reloaded = Get-Content -LiteralPath (Join-Path $writtenDir 'LogVerdict-Report.json') -Raw | ConvertFrom-Json

        $roundtripProfile = New-LogVerdictCaseProfile -Result $reloaded -Name 'Reloaded case'
        $roundtripProfile.bounds.windowStart | Should -Match '^2026-07-26T'
        $handoffDir = Join-Path $TestDrive 'roundtrip-handoff'
        $handoff = Export-LogVerdictHandoff -Result $reloaded -Profile $roundtripProfile -OutputDir $handoffDir
        @($handoff.Files).Count | Should -Be 10

        $reportDir = Join-Path $TestDrive 'roundtrip-report'
        Export-LogVerdictReport -Result $reloaded -OutputDir $reportDir -Format Text 6>$null | Out-Null
        Show-LogVerdictReport -Result $reloaded 6>$null
        @(Compare-LogVerdictScan -Before $reloaded -After $reloaded) | Should -BeNullOrEmpty

        foreach ($format in @('Ecs', 'Ocsf', 'Sarif', 'OpenTelemetry', 'Stix', 'Jsonl')) {
            $standard = @(Export-LogVerdictStandard -Result $reloaded -Format $format)
            $standard.Count | Should -BeGreaterThan 0 -Because "$format must accept a reloaded report"
        }
    }

    It 'wires the profile path through console, scan, and GUI entry points' {
        $root = Split-Path $PSScriptRoot -Parent
        $scan = Get-LVScanSourceText
        $entry = Get-Content -LiteralPath (Join-Path $root 'Invoke-LogVerdict.ps1') -Raw
        $gui = Get-LVGuiSourceText
        $guiEntry = Get-Content -LiteralPath (Join-Path $root 'LogVerdict-GUI.ps1') -Raw
        $scan | Should -Match 'CaseProfilePath'
        $entry | Should -Match 'CaseProfilePath'
        $gui | Should -Match 'CaseProfilePath'
        $guiEntry | Should -Match 'CaseProfilePath'
    }
}

Describe 'Export adapters and contract builders' {
    BeforeAll {
        $script:AdapterResult = [pscustomobject]@{
            Tool = 'LogVerdict'; Version = '0.7.0'; MachineName = 'TESTPC'
            ScanTime = [datetime]'2026-07-31T12:00:00Z'; Duration = [timespan]::FromSeconds(3)
            DaysBack = 30; Elevated = $false; Channels = @('System')
            Reduction = [pscustomobject]@{ RecordCount = 10; SignatureCount = 1; Ratio = 10 }
            Findings = @([pscustomobject]@{
                Key = 'Acme/99'; Source = 'event'; Channel = 'System'; Provider = 'Acme'; Id = 99
                Count = 2; PerDay = 0.1; FirstSeen = [datetime]'2026-07-30T10:00:00Z'; LastSeen = [datetime]'2026-07-30T10:01:00Z'
                Verdict = 'actionable'; Title = 'Something broke'; Plain = 'plain text'
                Why = 'why text'; Action = 'do this'; RuleId = 'T-1'; Confidence = 'high'
                Reference = $null; References = @(); SampleMessage = 'raw message'
            })
            CoverageNotes = @(); Coverage = @(); HealthProfiles = @(); Correlations = @()
            Advisories = @(); AdvisoryStatus = 'not-requested'; AdvisoryCache = $null
            CaseProfile = $null; ProviderExtensions = @(); ProviderProjections = @()
            CrashArtifacts = @(); Horizon = @{}; HorizonWarning = $null; Stability = $null; SetupDiag = $null
            DatabaseName = 'test db'; DatabaseDate = '2026-07-31'; RuleCount = 1
            WorstVerdict = 'actionable'; ExitCode = 2
        }
    }

    It 'invokes the console report and advisory-status public adapters directly' {
        $output = @(& { Show-LogVerdictReport -Result $script:AdapterResult } 6>&1 | ForEach-Object { [string]$_ })
        ($output -join "`n") | Should -Match 'LogVerdict \d+\.\d+\.\d+ - TESTPC'
        ($output -join "`n") | Should -Match '\[ACTIONABLE\] Something broke'
        ($output -join "`n") | Should -Match 'Do this\s+: do this'

        $root = Split-Path $PSScriptRoot -Parent
        $cache = Get-LogVerdictAdvisoryStatus -Path (Join-Path $root 'Data\advisories.json')
        $cache.Status | Should -BeIn @('fresh', 'stale')
        $cache.EntryCount | Should -BeGreaterThan 0
        $cache.SourceHash | Should -Match '^[0-9a-f]{64}$'

        $missing = Get-LogVerdictAdvisoryStatus -Path (Join-Path $TestDrive 'missing-advisories.json')
        $missing.Status | Should -BeExactly 'unavailable'
        $missing.EntryCount | Should -Be 0
        $missing.Reason | Should -Not -BeNullOrEmpty
    }

    It 'builds and validates report and evidence contracts without a report export' {
        InModuleScope LogVerdict -Parameters @{ InputResult = $script:AdapterResult; Drive = $TestDrive } {
            param($InputResult, $Drive)
            $result = $InputResult | Select-Object *
            $result | Add-Member -NotePropertyName Coverage -NotePropertyValue @() -Force
            $result | Add-Member -NotePropertyName Performance -NotePropertyValue @() -Force

            $reportContract = New-LVReportContract -Result $result -Redacted
            $reportContract.schemaVersion | Should -Be 1
            $reportContract.name | Should -BeExactly 'LogVerdict.Report'
            $reportContract.privacy.redacted | Should -BeTrue

            $report = ConvertTo-LVReportContract -Result $result -Redacted
            Test-LVReportContract -InputObject $report -Quiet | Should -BeTrue

            $evidencePath = Join-Path $Drive 'contract-evidence.txt'
            'fixture evidence' | Set-Content -LiteralPath $evidencePath -Encoding UTF8
            $evidence = New-LVEvidenceContract -Result $result -Content @($evidencePath) `
                -Omission @('event channels omitted') -Redacted
            $evidence.Contract.name | Should -BeExactly 'LogVerdict.Evidence'
            $evidence.Privacy.rawEvidence | Should -BeFalse
            $evidence.Files[0].name | Should -BeExactly 'contract-evidence.txt'
            $evidence.Files[0].sha256 | Should -Match '^[0-9a-f]{64}$'
            @($evidence.Omissions) | Should -Contain 'event channels omitted'
            Test-LVEvidenceContract -InputObject $evidence -Quiet | Should -BeTrue
            (ConvertFrom-LVEvidenceContract -InputObject $evidence).Contract.schemaVersion | Should -Be 1
        }
    }

    It 'rejects offline lifecycle states from the reader-facing coverage contract' {
        InModuleScope LogVerdict -Parameters @{ InputResult = $script:AdapterResult } {
            param($InputResult)
            $legacy = $InputResult | Select-Object *
            $legacy | Add-Member -NotePropertyName Coverage -NotePropertyValue @([pscustomobject]@{
                Source = 'offline-evtx'; Kind = 'file'; Name = 'System.evtx'; Status = 'parsed'
                ObservedRecords = 1; SkippedRecords = 0
            }) -Force
            $report = ConvertTo-LVReportContract -Result $legacy
            Test-LVReportContract -InputObject $report -Quiet | Should -BeFalse
            { New-LVCoverageRecord -Source 'event' -Kind 'channel' -Name 'System' -Status 'parsed' } |
                Should -Throw '*ValidateSet*'
        }
    }

    It 'diffs review artifacts by stable id and validates their exchange envelope' {
        InModuleScope LogVerdict {
            $previous = [pscustomobject]@{
                items = @(
                    [pscustomobject]@{ id = 'UNKNOWN-OLD'; kind = 'unknown'; review = [pscustomobject]@{ status = 'pending' } }
                    [pscustomobject]@{ id = 'CANDIDATE-REMOVED'; kind = 'candidate'; review = [pscustomobject]@{ status = 'pending' } }
                )
            }
            $current = [pscustomobject]@{
                items = @(
                    [pscustomobject]@{ id = 'UNKNOWN-OLD'; kind = 'unknown'; review = [pscustomobject]@{ status = 'accepted' } }
                    [pscustomobject]@{ id = 'UNKNOWN-ADDED'; kind = 'unknown'; review = [pscustomobject]@{ status = 'pending' } }
                )
            }
            $diff = Get-LVReviewArtifactDiff -Previous $previous -Current $current
            @($diff.added) | Should -Be @('UNKNOWN-ADDED')
            @($diff.changed) | Should -Be @('UNKNOWN-OLD')
            @($diff.removed) | Should -Be @('CANDIDATE-REMOVED')
            $diff.counts.current | Should -Be 2
            $diff.counts.reviewed | Should -Be 1

            $artifact = [pscustomobject]@{
                schemaVersion = 1; name = 'LogVerdict.ReviewArtifact'
                privacy = [pscustomobject]@{ redacted = $true; rawEvidence = $false }
                items = @([pscustomobject]@{
                    id = 'UNKNOWN-OLD'; kind = 'unknown'
                    review = [pscustomobject]@{ status = 'accepted' }
                })
            }
            Test-LVReviewArtifactObject -Artifact $artifact | Should -BeTrue
            $artifact.items[0].review.status = 'invalid'
            { Test-LVReviewArtifactObject -Artifact $artifact } | Should -Throw '*unsupported review status*'
        }
    }
}

Describe 'CI gate wiring' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:CiWorkflow = Get-Content -LiteralPath (Join-Path $root '.github\workflows\ci.yml') -Raw
    }

    It 'pins actions, runs analyzer on both quality legs, and verifies supply-chain metadata directly' {
        $script:CiWorkflow | Should -Not -Match 'actions/(checkout|upload-artifact)@v\d'
        ([regex]::Matches($script:CiWorkflow, 'actions/checkout@[0-9a-f]{40}')).Count | Should -Be 2
        ([regex]::Matches($script:CiWorkflow, 'actions/upload-artifact@[0-9a-f]{40}')).Count | Should -Be 3
        $script:CiWorkflow | Should -Match 'name: Run analyzer\r?\n\s+shell: \$\{\{ matrix\.shell \}\}'
        $script:CiWorkflow | Should -Not -Match 'name: Run analyzer\r?\n\s+if:'
        $script:CiWorkflow | Should -Match 'name: Audit constrained-language compatibility'
        $script:CiWorkflow | Should -Match 'PSUseConstrainedLanguageMode'
        $script:CiWorkflow | Should -Match 'name: Verify supply-chain metadata directly'
        $script:CiWorkflow | Should -Match 'Tools\\Test-LogVerdictSupplyChain\.ps1'
        $script:CiWorkflow | Should -Match 'name: Run runtime-agnostic release gates'
        $script:CiWorkflow | Should -Match 'Tools\\Test-LogVerdictReleaseStatic\.ps1'
        $script:CiWorkflow | Should -Match 'name: Run Core schema release gates'
        $script:CiWorkflow | Should -Match 'Test-LogVerdictRelease\.ps1[^\r\n]+-ReleaseValidation'
        $script:CiWorkflow | Should -Match 'if \(-not \$\?\) \{ exit 1 \}'
        $script:CiWorkflow | Should -Match 'probeExit = if \(\$LASTEXITCODE\)'
        $script:CiWorkflow | Should -Match 'reportExit = \[int\]\$LASTEXITCODE'
    }
}

Describe 'Constrained Language Mode compatibility' {
    BeforeAll {
        $script:ClmRoot = Split-Path $PSScriptRoot -Parent
    }

    It 'probes the runtime, documents the degraded matrix, and configures the analyzer audit' {
        $common = Get-Content -LiteralPath (Join-Path $script:ClmRoot 'Private\00-LVCommon.ps1') -Raw
        $gui = Get-Content -LiteralPath (Join-Path $script:ClmRoot 'Public\Show-LogVerdictGui.ps1') -Raw
        $wrapper = Get-Content -LiteralPath (Join-Path $script:ClmRoot 'LogVerdict-GUI.ps1') -Raw
        $readme = Get-Content -LiteralPath (Join-Path $script:ClmRoot 'README.md') -Raw
        $settings = Import-PowerShellDataFile -LiteralPath (Join-Path $script:ClmRoot 'PSScriptAnalyzerSettings.psd1')

        $common | Should -Match '\$ExecutionContext\.SessionState\.LanguageMode'
        $gui | Should -Match 'LVGuiConstrainedLanguageErrorId'
        $wrapper | Should -Match 'exit 5'
        $readme | Should -Match 'Offline ZIP re-evaluation'
        $settings.Rules.PSUseConstrainedLanguageMode.Enable | Should -BeTrue
        @($settings.ExcludeRules) | Should -Contain 'PSUseConstrainedLanguageMode'
    }

    It 'refuses the GUI before any WPF or apartment work when the mode is constrained' {
        InModuleScope LogVerdict {
            $oldMode = $script:LVConstrainedLanguage
            try {
                $script:LVConstrainedLanguage = $true
                Mock Write-LVLog {}

                { Show-LogVerdictGui -DaysBack 1 } | Should -Throw '*LogVerdict.GuiConstrainedLanguage*'
                Should -Invoke Write-LVLog -Times 1 -Exactly -ParameterFilter {
                    $Message -match 'exit code 5'
                }
            } finally {
                $script:LVConstrainedLanguage = $oldMode
            }
        }
    }

    It 'uses Compress-Archive for evidence creation in constrained mode' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive } {
            param($Root)
            $oldMode = $script:LVConstrainedLanguage
            $staging = Join-Path $Root 'evidence-staging'
            $zip = Join-Path $Root 'evidence.zip'
            try {
                New-Item -ItemType Directory -Path $staging -Force | Out-Null
                Set-Content -LiteralPath (Join-Path $staging 'evidence.txt') -Value 'bounded evidence' -Encoding UTF8
                $script:LVConstrainedLanguage = $true

                New-LVEvidenceArchive -Staging $staging -Destination $zip

                Test-Path -LiteralPath $zip | Should -BeTrue
                $archive = [IO.Compression.ZipFile]::OpenRead($zip)
                try {
                    @($archive.Entries | Select-Object -ExpandProperty FullName) | Should -Contain 'evidence.txt'
                } finally {
                    $archive.Dispose()
                }
            } finally {
                $script:LVConstrainedLanguage = $oldMode
            }
        }
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
            'Get-LogVerdictAdvisoryStatus',
            'Get-LogVerdictDatabase',
            'Get-LogVerdictErrorCatalog',
            'Get-LogVerdictIntuneDigest',
            'Get-LogVerdictProvider',
            'Get-LogVerdictSuppression',
            'Invoke-LogVerdictProvider',
            'Invoke-LogVerdictScan',
            'New-LogVerdictCaseProfile',
            'Show-LogVerdictGui',
            'Show-LogVerdictReport',
            'Test-LogVerdictAdvisoryDatabase',
            'Test-LogVerdictCaseProfile',
            'Test-LogVerdictDatabase',
            'Test-LogVerdictProvider',
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
        $manifest = Test-ModuleManifest -Path (Join-Path $root 'LogVerdict.psd1')
        $exported = (Get-Module LogVerdict).ExportedFunctions.Keys | Sort-Object
        ($manifest.ExportedFunctions.Keys | Sort-Object) | Should -Be $exported
    }

    It 'keeps the module, badge, and package metadata on the version source' {
        $root = Split-Path $PSScriptRoot -Parent
        $version = (& (Join-Path $root 'Tools\Get-LogVerdictVersion.ps1')).Trim()
        $manifest = Test-ModuleManifest -Path (Join-Path $root 'LogVerdict.psd1')
        $manifest.Version.ToString() | Should -BeExactly $version
        (Get-Content -LiteralPath (Join-Path $root 'README.md') -Raw) | Should -Match ("shields\.io/badge/version-{0}-blue" -f [regex]::Escape($version))
    }

    It 'declares both PSEditions, a complete module file list, and release notes' {
        $root = Split-Path $PSScriptRoot -Parent
        $manifest = Test-ModuleManifest -Path (Join-Path $root 'LogVerdict.psd1')
        @($manifest.CompatiblePSEditions) | Should -Be @('Desktop', 'Core')
        @($manifest.PrivateData.PSData.Tags) | Should -Contain 'PSEdition_Desktop'
        @($manifest.PrivateData.PSData.Tags) | Should -Contain 'PSEdition_Core'
        [string]::IsNullOrWhiteSpace([string]$manifest.PrivateData.PSData.ReleaseNotes) | Should -BeFalse
        @($manifest.FileList).Count | Should -BeGreaterThan 60
        foreach ($file in @($manifest.FileList)) {
            Test-Path -LiteralPath $file -PathType Leaf | Should -BeTrue -Because "manifest FileList entry '$file' must exist"
        }
        $advisories = Get-Content -LiteralPath (Join-Path $root 'Data\advisories.json') -Raw | ConvertFrom-Json
        @($advisories.coverage.runtime.verifiedRuntimes) | Should -Contain 'PowerShell 7.6 LTS'
    }
}

Describe 'Versioned provider extension contract' {
    BeforeAll {
        $script:ProviderRoot = Join-Path $TestDrive 'provider-contract'
        New-Item -ItemType Directory -Path $script:ProviderRoot -Force | Out-Null
        $script:ProviderEntrypoint = Join-Path $script:ProviderRoot 'provider.ps1'
        @'
param([hashtable]$Context)
[pscustomobject][ordered]@{
    schemaVersion = 1
    records = @(
        [pscustomobject][ordered]@{
            id = 4242
            channel = 'vendor-channel'
            provider = 'vendor-provider'
            message = 'secret=TOPSECRET token=abcdefghijklmnopqrstuvwxyz123456 user@example.com C:\Users\alice'
            timeCreated = '2026-08-02T12:00:00Z'
            level = 2
            levelName = 'Error'
            recordId = 7
            structuredData = [pscustomobject]@{
                EventData = [pscustomobject]@{ Secret = 'TOPSECRET'; Machine = $env:COMPUTERNAME }
            }
        }
        [pscustomobject]@{ id = 'not-an-event-id'; message = 'rejected' }
    )
    coverage = @([pscustomobject]@{ name = 'vendor source'; status = 'readable'; observedRecords = 2; reason = 'C:\Users\alice' })
    reportProjection = [pscustomobject]@{ Summary = 'secret=TOPSECRET'; Ignored = 'not declared' }
}
'@ | Set-Content -LiteralPath $script:ProviderEntrypoint -Encoding UTF8
        $fixturePath = Join-Path $script:ProviderRoot 'fixture.json'
        '{"fixture":"provider contract"}' | Set-Content -LiteralPath $fixturePath -Encoding UTF8
        $manifest = [ordered]@{
            schemaVersion = 1
            id = 'test.provider'
            name = 'Provider contract fixture'
            version = '1.2.3'
            entrypoint = 'provider.ps1'
            entrypointSha256 = Get-LVTestSha256 -Path $script:ProviderEntrypoint
            capabilities = @('collect', 'normalize', 'coverage', 'redaction', 'fixtures', 'reportProjection')
            permissions = @('read-only')
            fixtures = @([ordered]@{ id = 'sample'; path = 'fixture.json'; sha256 = (Get-LVTestSha256 -Path $fixturePath) })
            reportProjection = [ordered]@{ fields = @('Summary') }
        }
        $manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $script:ProviderRoot 'manifest.json') -Encoding UTF8
    }

    It 'validates the manifest, entrypoint pin, and fixture pin without execution' {
        $plan = Get-LogVerdictProvider -Path $script:ProviderRoot
        $plan.Id | Should -BeExactly 'test.provider'
        $plan.Trust | Should -BeExactly 'untrusted'
        @($plan.Fixtures).Count | Should -Be 1
        $plan.Fixtures[0].SHA256 | Should -Match '^[0-9a-f]{64}$'
        Test-LogVerdictProvider -Path $script:ProviderRoot -Quiet | Should -BeTrue
    }

    It 'keeps an explicitly UTC provider record in the local basis used by event correlation' {
        InModuleScope LogVerdict {
            $localWallClock = [datetime]::SpecifyKind([datetime]'2026-08-02T12:00:00', [DateTimeKind]::Unspecified)
            $localOffset = [TimeZoneInfo]::Local.GetUtcOffset($localWallClock)
            $providerInstant = ([datetimeoffset]::new($localWallClock, $localOffset)).ToUniversalTime().ToString(
                'yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture)
            $provider = [pscustomobject]@{ Id = 'time.provider'; Version = '1.0.0'; Trust = 'untrusted'; ProjectionFields = @() }
            $payload = [pscustomobject]@{
                records = @([pscustomobject]@{
                    id = 900; channel = 'vendor'; message = 'provider event'; timeCreated = $providerInstant; level = 2
                })
            }
            $normalized = ConvertTo-LVProviderResult -Provider $provider -Payload $payload `
                -CollectionBudget (New-LVCollectionBudget -MaxBytes 1MB -MaxRecords 10 -MaxSeconds 60)
            $normalized.Records[0].TimeCreated | Should -Be $localWallClock

            $eventRecord = [pscustomobject]@{
                Source = 'event'; Channel = 'System'; Provider = 'fixture-event'; Id = 901
                Level = 2; LevelName = 'Error'; TimeCreated = $localWallClock; MachineName = 'FIXTURE'; RecordId = 1
                Message = 'event at the same instant'
            }
            $reduction = Get-LVSignatureReduction -Record @($eventRecord, $normalized.Records[0]) -WindowDays 1
            $eventSignature = @($reduction.Signatures | Where-Object Provider -eq 'fixture-event')[0]
            $providerSignature = @($reduction.Signatures | Where-Object Provider -eq 'extension:time.provider')[0]
            $findings = @(
                [pscustomobject]@{ RuleId = 'EVENT-TIME'; Key = $eventSignature.Key; Title = 'event'; Times = @($eventSignature.Times) }
                [pscustomobject]@{ RuleId = 'PROVIDER-TIME'; Key = $providerSignature.Key; Title = 'provider'; Times = @($providerSignature.Times) }
            )
            $database = [pscustomobject]@{ correlations = @([pscustomobject]@{
                id = 'LVC-TIME'; status = 'stable'
                correlation = [pscustomobject]@{ type = 'temporal'; rules = @('EVENT-TIME', 'PROVIDER-TIME'); timespan = '1m' }
                verdict = 'investigate'; title = 'same instant'; plain = 'same instant'; why = 'same instant'
                action = 'inspect'; confidence = 'high'
            }) }
            @(Resolve-LVCorrelation -Finding $findings -Database $database) | Should -HaveCount 1
        }
    }

    It 'requires explicit approval and normalizes redacted evidence without curated verdict fields' {
        { Invoke-LogVerdictProvider -Provider $script:ProviderRoot -Context @{ CollectionBudget = (InModuleScope LogVerdict { New-LVCollectionBudget -MaxBytes 1MB -MaxRecords 10 -MaxSeconds 60 }) } } |
            Should -Throw '*AllowUntrustedProvider*'

        InModuleScope LogVerdict {
            param($providerPath)
            $budget = New-LVCollectionBudget -MaxBytes 1MB -MaxRecords 10 -MaxSeconds 60
            $result = Invoke-LogVerdictProvider -Provider $providerPath -Context @{ CollectionBudget = $budget } -AllowUntrustedProvider
            $result.ProviderId | Should -BeExactly 'test.provider'
            $result.Trust | Should -BeExactly 'untrusted'
            $result.RejectedRecords | Should -Be 1
            $result.Records.Count | Should -Be 1
            $record = $result.Records[0]
            $record.Source | Should -BeExactly 'event'
            $record.Provider | Should -BeExactly 'extension:test.provider'
            $record.Channel | Should -BeExactly 'extension:test.provider/vendor-channel'
            $record.Id | Should -Be 4242
            $record.Message | Should -Not -Match 'TOPSECRET|alice@example.com|C:\\Users\\alice'
            $record.StructuredData.EventData.Secret | Should -Not -BeExactly 'TOPSECRET'
            $record.PSObject.Properties.Name | Should -Not -Contain 'Verdict'
            $record.PSObject.Properties.Name | Should -Not -Contain 'RuleId'
            $result.ReportProjection[0].ProviderId | Should -BeExactly 'test.provider'
            $result.ReportProjection[0].Fields.Summary | Should -Not -Match 'TOPSECRET'
            $result.Coverage[0].Source | Should -BeExactly 'provider'
            $result.Coverage[0].Origin | Should -BeExactly 'provider'
            $signature = (Get-LVSignatureReduction -Record @($record) -WindowDays 30).Signatures[0]
            $rule = [pscustomobject]@{
                id = 'CURATED-4242'; lvOrdinal = 0
                match = [pscustomobject]@{ source = 'event'; eventId = 4242 }
                verdict = 'critical'; title = 'Must not match'; plain = 'Must not match'; why = 'Must not match'; action = 'Must not match'
                confidence = 'high'; status = 'supported'
            }
            (Resolve-LVVerdict -Signature @($signature) -Database ([pscustomobject]@{ rules = @($rule) })).Verdict | Should -BeExactly 'unknown'
        } -Parameters @{ providerPath = $script:ProviderRoot }
    }

    It 'merges provider evidence into a live scan with explicit provenance' {
        $scan = Invoke-LogVerdictScan -DaysBack 1 -Channel 'ProviderContractMissingChannel' -SkipTextLogs -SkipReliability `
            -ProviderPath $script:ProviderRoot -AllowUntrustedProvider 6>$null
        $scan.ProviderExtensions[0].Id | Should -BeExactly 'test.provider'
        $scan.ProviderExtensions[0].RecordCount | Should -Be 1
        @($scan.Coverage | Where-Object { $_.Source -eq 'provider' -and $_.Name -match 'test.provider' }).Count | Should -BeGreaterThan 0
        $providerFinding = @($scan.Findings | Where-Object { $_.ProviderExtension -eq 'test.provider' })
        $providerFinding.Count | Should -Be 1
        $providerFinding[0].RuleId | Should -BeNullOrEmpty
        $scan.ProviderProjections[0].Fields.Summary | Should -Not -Match 'TOPSECRET'
        $reportDir = Join-Path $TestDrive 'provider-reports'
        Export-LogVerdictReport -Result $scan -OutputDir $reportDir -Format Text,Html 6>$null | Out-Null
        (Get-Content -LiteralPath (Join-Path $reportDir 'LogVerdict-Report.txt') -Raw) | Should -Match 'PROVIDER EXTENSIONS'
        (Get-Content -LiteralPath (Join-Path $reportDir 'LogVerdict-Report.html') -Raw) | Should -Match 'test\.provider'
        $standard = Export-LogVerdictStandard -Result $scan -Format Ocsf
        $standard.Document.scan.providerProjections[0].ProviderId | Should -BeExactly 'test.provider'
    }

    It 'normalizes provider timestamps before correlation and preserves source locale' {
        InModuleScope LogVerdict {
            $provider = [pscustomobject]@{
                Id = 'time.provider'; Version = '1.0.0'; Trust = 'untrusted'; ProjectionFields = @()
            }
            $payload = [pscustomobject]@{
                records = @([pscustomobject]@{
                    id = 4242; channel = 'vendor-channel'; message = 'provider event'
                    timeCreated = '2026-08-02T12:00:00Z'; level = 2; providerLocale = 'de-DE'
                })
                coverage = @()
            }
            $budget = New-LVCollectionBudget -MaxBytes 1MB -MaxRecords 10 -MaxSeconds 60
            $normalized = ConvertTo-LVProviderResult -Provider $provider -Payload $payload -CollectionBudget $budget
            $providerTime = $normalized.Records[0].TimeCreated
            $expectedTime = [datetime]::MinValue
            [datetime]::TryParse(
                '2026-08-02T12:00:00Z',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,
                [ref]$expectedTime) | Should -BeTrue
            $expectedLocalTime = $expectedTime.ToLocalTime()
            $providerTime.Kind | Should -Be ([DateTimeKind]::Local)
            $providerTime | Should -Be $expectedLocalTime
            $normalized.Records[0].ProviderLocale | Should -BeExactly 'de-DE'

            $findings = @(
                [pscustomobject]@{ RuleId = 'TIME-P'; Key = 'provider'; Title = 'provider'; Times = @($providerTime) }
                [pscustomobject]@{ RuleId = 'TIME-E'; Key = 'event'; Title = 'event'; Times = @($expectedLocalTime) }
            )
            $database = [pscustomobject]@{
                rules = @(
                    [pscustomobject]@{ id = 'TIME-P'; status = 'stable'; verified = '2026-08-01' }
                    [pscustomobject]@{ id = 'TIME-E'; status = 'stable'; verified = '2026-08-01' }
                )
                correlations = @([pscustomobject]@{
                    id = 'TIME-C'; status = 'stable'; verified = '2026-08-01'; provenance = 'internal-observation'
                    correlation = [pscustomobject]@{ type = 'temporal'; rules = @('TIME-P', 'TIME-E'); timespan = '1m' }
                    verdict = 'actionable'; title = 'same instant'; plain = 'same instant'; why = 'test'; action = 'test'; confidence = 'high'
                })
            }
            @(Resolve-LVCorrelation -Finding $findings -Database $database).Count | Should -Be 1
        }
    }

    It 'rejects a changed entrypoint or fixture before it can run' {
        Add-Content -LiteralPath $script:ProviderEntrypoint -Value '# changed'
        Test-LogVerdictProvider -Path $script:ProviderRoot -Quiet | Should -BeFalse
        $manifest = Get-Content -LiteralPath (Join-Path $script:ProviderRoot 'manifest.json') -Raw | ConvertFrom-Json
        $manifest.entrypointSha256 = Get-LVTestSha256 -Path $script:ProviderEntrypoint
        $manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $script:ProviderRoot 'manifest.json') -Encoding UTF8
        Add-Content -LiteralPath (Join-Path $script:ProviderRoot 'fixture.json') -Value 'changed'
        Test-LogVerdictProvider -Path $script:ProviderRoot -Quiet | Should -BeFalse
    }
}

Describe 'Dependency advisory knowledge' {
    It 'ships a valid hash-checked offline cache with separate fields' {
        Test-LogVerdictAdvisoryDatabase -Quiet | Should -BeTrue
        $advisory = @(Get-LogVerdictAdvisory -Package PowerShell -Version '7.4.0')
        $advisory.Count | Should -Be 2
        $advisory[0].FindingType | Should -BeExactly 'dependency-advisory'
        $advisory[0].RecordType | Should -BeExactly 'advisory'
        $advisory[0].AffectedRange | Should -Match '7\.4\.14'
        $advisory[0].FixedVersion | Should -Match '7\.4\.14'
        $advisory[0].CVSS | Should -Be 7.8
        $advisory[0].SourceHash | Should -Match '^[0-9a-f]{64}$'
        $advisory[0].PSObject.Properties.Name | Should -Not -Contain 'Verdict'
    }

    It 'declares freshness policy and verified runtime/tool coverage' {
        InModuleScope LogVerdict {
            $database = Get-LVAdvisoryDatabase
            $database.schemaVersion | Should -Be 2
            $database.freshness.Status | Should -BeExactly 'fresh'
            $database.freshness.MaxCacheAgeDays | Should -Be 60
            @($database.coverage.runtime.verifiedRuntimes) | Should -Contain 'Windows PowerShell 5.1'
            @($database.coverage.runtime.verifiedRuntimes) | Should -Contain 'PowerShell 7.6 LTS'
            foreach ($tool in @(
                [pscustomobject]@{ Name = 'Pester'; Version = '6.0.1' }
                [pscustomobject]@{ Name = 'PSScriptAnalyzer'; Version = '1.25.0' }
                [pscustomobject]@{ Name = 'ps2exe'; Version = '1.0.18' }
            )) {
                @($database.coverage.tools | Where-Object { $_.name -eq $tool.Name -and $_.version -eq $tool.Version }).Count | Should -Be 1
            }
        }
    }

    It 'reports stale and unavailable advisory state without changing scan findings' {
        $path = Join-Path $TestDrive 'stale-advisories.json'
        $cache = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data\advisories.json') -Raw | ConvertFrom-Json
        $cache.updated = '2020-01-01'
        $cache.source.retrieved = '2020-01-01'
        $cache | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8

        InModuleScope LogVerdict {
            $stale = Get-LVAdvisoryScanContext -Path $TestDrive\stale-advisories.json -Package PowerShell -Version '7.4.0'
            $stale.Status | Should -BeExactly 'stale'
            @($stale.Records).Count | Should -Be 2
            $missing = Get-LVAdvisoryScanContext -Path (Join-Path $TestDrive 'missing-advisories.json') -Package PowerShell -Version '7.4.0'
            $missing.Status | Should -BeExactly 'unavailable'
            @($missing.Records).Count | Should -Be 0
        }
    }

    It 'warns on an aged cache during ordinary release checks' {
        $root = Split-Path $PSScriptRoot -Parent
        $path = Join-Path $TestDrive 'aged-release-advisories.json'
        $cache = Get-Content -LiteralPath (Join-Path $root 'Data\advisories.json') -Raw | ConvertFrom-Json
        $cache.updated = '2020-01-01'
        $cache.source.retrieved = '2020-01-01'
        $cache | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8

        $release = Join-Path $root 'Tools\Test-LogVerdictRelease.ps1'
        $output = @(& pwsh -NoProfile -ExecutionPolicy Bypass -File $release -AdvisoryPath $path -SkipSchemaValidation 2>&1)
        $LASTEXITCODE | Should -Be 0
        ($output -join "`n") | Should -Match 'Offline advisory cache is stale'
    }

    It 'makes explicit release validation reject an aged cache' {
        $root = Split-Path $PSScriptRoot -Parent
        $path = Join-Path $TestDrive 'aged-release-validation-advisories.json'
        $cache = Get-Content -LiteralPath (Join-Path $root 'Data\advisories.json') -Raw | ConvertFrom-Json
        $cache.updated = '2020-01-01'
        $cache.source.retrieved = '2020-01-01'
        $cache | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8

        $release = Join-Path $root 'Tools\Test-LogVerdictRelease.ps1'
        $output = @(& pwsh -NoProfile -ExecutionPolicy Bypass -File $release -AdvisoryPath $path -SkipSchemaValidation -ReleaseValidation 2>&1)
        $LASTEXITCODE | Should -Not -Be 0
        ($output -join "`n") | Should -Match 'Offline advisory cache is stale'
    }

    It 'matches version ranges without treating fixed versions as affected' {
        @((Get-LogVerdictAdvisory -Package PowerShell -Version '7.4.12')).Count | Should -Be 2
        @((Get-LogVerdictAdvisory -Package PowerShell -Version '7.4.13')).Count | Should -Be 1
        @((Get-LogVerdictAdvisory -Package PowerShell -Version '7.4.14')).Count | Should -Be 0
        @((Get-LogVerdictAdvisory -Package PowerShell -Version '7.5.3')).Count | Should -Be 2
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

    It 'refuses advisory prose tampering even when normalized metadata is unchanged' {
        $path = Join-Path $TestDrive 'tampered-advisory-description.json'
        $cache = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data\advisories.json') -Raw | ConvertFrom-Json
        $cache.advisories[0].title = 'substituted title'
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
        $text | Should -Match '\[switch\]\$Redact'
        $text | Should -Match 'Redact\s*=\s*\$Redact'
        $text | Should -Match '\[switch\]\$PromoteToRule'
        $text | Should -Match 'PromoteToRule\s*=\s*\$PromoteToRule'
        $scan = Get-LVScanSourceText
        $scan | Should -Match '\[switch\]\$Redact'
        $scan | Should -Match 'Redact\s*=\s*\$Redact'
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
        $scan = Get-LVScanSourceText
        $scan | Should -Match 'HistoryWindowDays\s*=\s*30'
        $scan | Should -Match 'Update-LVScanHistory'
    }

    It 'exposes optional offline advisory settings without coupling them to verdicts' {
        $root = Split-Path $PSScriptRoot -Parent
        $entry = Get-Content -LiteralPath (Join-Path $root 'Invoke-LogVerdict.ps1') -Raw
        $scan = Get-LVScanSourceText
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
        $scan = Get-LVScanSourceText
        $entry | Should -Match '\[ValidateRange\(1, 3650\)\]\[int\]\$DaysBack'
        $scan | Should -Match '\[ValidateRange\(1, 3650\)\]\[int\]\$DaysBack'
        { Invoke-LogVerdictScan -DaysBack 0 } | Should -Throw
        { Invoke-LogVerdictScan -DaysBack 3651 } | Should -Throw
    }

    It 'gives named channels precedence and rejects contradictory broad modes' {
        $scan = Get-LVScanSourceText
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

    It 'requires false-positive guidance and an external citation for active severe rules' {
        $source = Join-Path (Split-Path $PSScriptRoot -Parent) 'Data\verdicts.json'
        $raw = Get-Content -LiteralPath $source -Raw -Encoding UTF8 | ConvertFrom-Json
        $rule = @($raw.rules | Where-Object id -eq 'LV-0011')[0]
        $rule.falsepositives = @()
        $rule.references = @()
        $path = Join-Path $TestDrive 'uncited-severe.json'
        $raw | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8

        $problems = @(Test-LogVerdictDatabase -Path $path -SkipFixture)
        @($problems | Where-Object { $_.RuleId -eq 'LV-0011' -and $_.Problem -like '*requires at least one falsepositives entry' }).Count | Should -Be 1
        $citationProblem = @($problems | Where-Object { $_.RuleId -eq 'LV-0011' -and $_.Problem -like '*requires at least one external citation*' })
        $citationProblem.Count | Should -Be 1
        $citationProblem[0].Severity | Should -BeExactly 'error'
    }

    It 'rejects a plain field that only restates its event id' {
        $source = Join-Path (Split-Path $PSScriptRoot -Parent) 'Data\verdicts.json'
        $raw = Get-Content -LiteralPath $source -Raw -Encoding UTF8 | ConvertFrom-Json
        $rule = @($raw.rules | Where-Object id -eq 'LV-0011')[0]
        $rule.plain = 'Event ID 18.'
        $path = Join-Path $TestDrive 'event-label-prose.json'
        $raw | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8

        $problems = @(Test-LogVerdictDatabase -Path $path -SkipFixture)
        $plainProblem = @($problems | Where-Object { $_.RuleId -eq 'LV-0011' -and $_.Problem -like '*only restating an event id*' })
        $plainProblem.Count | Should -Be 1
        $plainProblem[0].Severity | Should -BeExactly 'error'
    }

    It 'reports an uncompilable message or structured regex as a rule trust problem' {
        $rules = @(
            [ordered]@{
                id='BAD-MESSAGE-REGEX'; status='stable'; verified='2026-08-03'
                match=@{ source='event'; messagePattern='[' }
                verdict='benign'; title='t'; plain='p'; why='w'; action='a'; confidence='high'
            }
            [ordered]@{
                id='BAD-STRUCTURED-REGEX'; status='stable'; verified='2026-08-03'
                match=@{ source='event'; eventData=@{ field='EventData.Image'; regex='[' } }
                verdict='benign'; title='t'; plain='p'; why='w'; action='a'; confidence='high'
            }
        )
        $path = Join-Path $TestDrive 'bad-regex.json'
        [pscustomobject]@{ schemaVersion=6; name='bad-regex'; updated='2026-08-03'; rules=$rules; correlations=@() } |
            ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8

        $problems = @(Test-LogVerdictDatabase -Path $path -SkipFixture)
        @($problems | Where-Object { $_.RuleId -eq 'BAD-MESSAGE-REGEX' -and $_.Problem -match 'messagePattern.*valid regex' }).Count | Should -Be 1
        @($problems | Where-Object { $_.RuleId -eq 'BAD-STRUCTURED-REGEX' -and $_.Problem -match 'eventData\.regex.*valid regex' }).Count | Should -Be 1
        { Get-LogVerdictDatabase -Path $path } | Should -Throw '*BAD-MESSAGE-REGEX*'
    }

    It 'allows only http and https rule URIs and names the offending rule' {
        $unsafe = [ordered]@{
            'URI-JS'       = @{ field = 'references'; value = 'javascript:alert(1)' }
            'URI-FILE'     = @{ field = 'references'; value = 'file:///C:/Windows/System32/drivers/etc/hosts' }
            'URI-UNC'      = @{ field = 'sources'; value = '\\server\share\rule.html' }
            'URI-SETTINGS' = @{ field = 'sources'; value = 'ms-settings:privacy' }
        }
        $rules = foreach ($entry in $unsafe.GetEnumerator()) {
            $rule = [ordered]@{
                id = $entry.Key; status = 'stable'; verified = '2026-07-31'
                match = @{ source = 'event' }; verdict = 'benign'; title = 't'; plain = 'p'; why = 'w'; action = 'a'; confidence = 'high'
            }
            if ($entry.Value.field -eq 'references') {
                $rule.references = @($entry.Value.value)
            } else {
                $rule.sources = @(@{ uri = $entry.Value.value })
            }
            [pscustomobject]$rule
        }
        $path = Join-Path $TestDrive 'unsafe-uris.json'
        [pscustomobject]@{
            schemaVersion = 5; name = 'unsafe'; updated = '2026-07-31'; rules = @($rules); correlations = @()
        } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8

        $problems = @(Test-LogVerdictDatabase -Path $path -SkipFixture)
        foreach ($id in $unsafe.Keys) {
            $ruleProblems = @($problems | Where-Object RuleId -eq $id)
            $ruleProblems.Count | Should -Be 1 -Because "unsafe URI in $id must be rejected once"
            $ruleProblems[0].Problem | Should -Match 'only http and https are permitted|absolute http or https URI|include a host'
        }
        Test-LogVerdictDatabase -Path $path -SkipFixture -Quiet | Should -BeFalse
        { Get-LogVerdictDatabase -Path $path } | Should -Throw '*URI-JS*'
    }

    It 'accepts http and https URIs in references and sources' {
        InModuleScope LogVerdict {
            Test-LVAllowedUri -Uri 'http://example.invalid/rule' | Should -BeTrue
            Test-LVAllowedUri -Uri 'https://example.invalid/rule' | Should -BeTrue
            Test-LVAllowedUri -Uri 'javascript:alert(1)' | Should -BeFalse
            Test-LVAllowedUri -Uri 'file:///C:/Windows/hosts' | Should -BeFalse
            Test-LVAllowedUri -Uri '\\server\share\rule.html' | Should -BeFalse
            Test-LVAllowedUri -Uri 'ms-settings:privacy' | Should -BeFalse
        }
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
            $rule.modified | Should -Match '^\d{4}-\d{2}-\d{2}$' -Because "rule $($rule.id) must record when its content last changed"
        }
    }

    It 'declares the freshness policy and supports per-rule build and age bounds' {
        $database = Get-LogVerdictDatabase
        $database.freshness.maxAgeDays | Should -Be 180
        $database.freshness.dateBasis | Should -BeExactly 'UTC'

        InModuleScope LogVerdict {
            $build = Get-LVCurrentWindowsBuild
            $build | Should -BeGreaterThan 0
            $today = [datetime]::UtcNow.Date
            $rule = [pscustomobject]@{
                id = 'FRESHNESS-TEST'; status = 'test'; verified = $today.AddDays(-10).ToString('yyyy-MM-dd')
                staleAfterDays = 5; windowsBuild = [pscustomobject]@{ min = $build - 1; max = $build + 1 }
                match = [pscustomobject]@{ source = 'event'; provider = 'Freshness-Test'; eventId = 4242 }
                verdict = 'investigate'; title = 't'; plain = 'p'; why = 'w'; action = 'a'; confidence = 'medium'
                references = @('https://example.invalid/freshness')
            }
            $db = [pscustomobject]@{
                schemaVersion = 7; name = 'freshness'; updated = $today.ToString('yyyy-MM-dd')
                freshness = [pscustomobject]@{ maxAgeDays = 180; dateBasis = 'UTC' }
                rules = @($rule); correlations = @()
            }
            $summary = Get-LVDatabaseFreshnessSummary -Database $db -AsOf $today
            $summary.StaleRuleCount | Should -Be 1
            $summary.StaleRules[0].RuleId | Should -BeExactly 'FRESHNESS-TEST'
            $summary.StaleRules[0].StaleAfterDays | Should -Be 5

            $signature = [pscustomobject]@{ Key = 'event|Freshness-Test|4242'; Source = 'event'; Provider = 'Freshness-Test'; Id = 4242; SampleMessage = 'test'; Count = 1; PerDay = 1 }
            $finding = @(Resolve-LVVerdict -Signature @($signature) -Database ([pscustomobject]@{ rules = @($rule); correlations = @(); freshness = $db.freshness }))[0]
            $finding.RuleId | Should -BeExactly 'FRESHNESS-TEST'
            $finding.RuleStale | Should -BeTrue
            $finding.RuleFreshness.StaleAfterDays | Should -Be 5

            $rule.windowsBuild = [pscustomobject]@{ max = $build - 1 }
            $outOfRange = @(Resolve-LVVerdict -Signature @($signature) -Database ([pscustomobject]@{ rules = @($rule); correlations = @(); freshness = $db.freshness }))[0]
            $outOfRange.Verdict | Should -BeExactly 'unknown'
            $outOfRange.RuleId | Should -BeNullOrEmpty
        }
    }

    It 'expires a pre-fix benign ruling when its resolving KB is present' {
        InModuleScope LogVerdict {
            $database = Get-LogVerdictDatabase
            $rule = @($database.rules | Where-Object id -eq 'LV-0341')[0]
            $signature = [pscustomobject]@{
                Key = 'event|Microsoft-Windows-Windows Firewall With Advanced Security|2042'
                Source = 'event'; Channel = 'System'
                Provider = 'Microsoft-Windows-Windows Firewall With Advanced Security'; Id = 2042
                SampleMessage = 'Config Read Failed: the firewall policy could not be read.'
                Count = 1; PerDay = 1; InstalledKbs = @()
            }
            $ruleDb = [pscustomobject]@{ rules = @($rule); correlations = @(); freshness = $database.freshness }
            $before = @(Resolve-LVVerdict -Signature @($signature) -Database $ruleDb)[0]
            $before.RuleId | Should -BeExactly 'LV-0341'
            $before.Verdict | Should -BeExactly 'benign'

            $signature.InstalledKbs = @('KB5062660')
            $after = @(Resolve-LVVerdict -Signature @($signature) -Database $ruleDb)[0]
            $after.RuleId | Should -BeNullOrEmpty
            $after.Verdict | Should -BeExactly 'unknown'
        }
    }

    It 'reports a backdated shipped rule before a clean freshness run is trusted' {
        InModuleScope LogVerdict {
            $raw = Get-Content -LiteralPath (Join-Path $script:LVDataDir 'verdicts.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            $candidate = @($raw.rules | Where-Object { Test-LVRuleActive -Rule $_ } | Select-Object -First 1)[0]
            $candidate.verified = '2000-01-01'
            $path = Join-Path $TestDrive 'backdated-verdicts.json'
            $raw | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8

            $problems = @(Test-LogVerdictDatabase -Path $path -SkipFixture)
            @($problems | Where-Object { $_.RuleId -eq $candidate.id -and $_.Problem -like '*older than*' }).Count | Should -Be 1

            $loaded = Get-LogVerdictDatabase -Path $path
            $freshness = Get-LVDatabaseFreshnessSummary -Database $loaded -AsOf ([datetime]::UtcNow.Date)
            $freshness.StaleRuleCount | Should -Be 1
            $freshness.StaleRules[0].RuleId | Should -BeExactly $candidate.id
        }
    }

    It 'requires lifecycle metadata and resolves typed supersession links' {
        $database = Get-LogVerdictDatabase
        @($database.rules | Where-Object { -not $_.modified }).Count | Should -Be 0
        @($database.rules | Where-Object { $_.staleAfterDays }).Count | Should -BeGreaterThan 0
        @($database.rules | Where-Object { $_.windowsBuild }).Count | Should -BeGreaterThan 0
        @($database.rules | Where-Object status -eq 'experimental').Count | Should -BeGreaterThan 0
        @($database.rules | Where-Object status -eq 'deprecated').Count | Should -BeGreaterThan 0
        @($database.rules | Where-Object related).Count | Should -BeGreaterThan 0
        @(Test-LogVerdictDatabase | Where-Object { $_.Problem -like '*related*' }).Count | Should -Be 0
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

        $schema.definitions.correlationRule.properties.references.items.pattern | Should -BeExactly '^https?://'
        $schema.definitions.correlationRule.properties.sources.items.properties.uri.pattern | Should -BeExactly '^https?://'
        $schema.definitions.rule.properties.references.items.pattern | Should -BeExactly '^https?://'
        $schema.definitions.rule.properties.sources.items.properties.uri.pattern | Should -BeExactly '^https?://'
        $schema.properties.freshness.properties.dateBasis.const | Should -BeExactly 'UTC'
        $schema.definitions.rule.properties.staleAfterDays.minimum | Should -Be 1
        $schema.definitions.rule.properties.windowsBuild.properties.min.minimum | Should -Be 1
        $schema.definitions.rule.properties.modified.description | Should -Match 'title.*detection.*deprecated'
        $schema.definitions.rule.properties.related.items.properties.type.enum | Should -Contain 'obsolete'
        $schema.definitions.rule.properties.expiresWithKb.pattern | Should -BeExactly '^KB\d{5,}$'
        $schema.definitions.correlation.properties.type.enum | Should -Be @('temporal', 'temporal_ordered')
        $schema.definitions.correlation.properties.rules.minItems | Should -Be 2
        @($schema.definitions.correlation.properties.PSObject.Properties.Name) | Should -Not -Contain 'group-by'
        $schema.description | Should -Match 'sequentially.*never reused.*deprecated tombstone'

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
          foreach ($entry in @($catalog)) {
              $entry.sourceRepository | Should -Match '^MicrosoftDocs/'
              $entry.sourcePath | Should -Match '^(desktop-src|windows-driver-docs-pr|support)/'
              $entry.sourceRevision | Should -Match '^[0-9a-f]{40}$'
              $entry.licence | Should -BeExactly 'CC-BY-4.0'
              $entry.sourceDocumentHash | Should -Match '^[0-9a-f]{64}$'
          }

          $document = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data/error-codes.json') -Raw | ConvertFrom-Json
          $document.schemaVersion | Should -Be 3
          @($document.sources).Count | Should -Be 3
          foreach ($source in @($document.sources)) {
              $source.repository | Should -Match '^MicrosoftDocs/'
              $source.revision | Should -Match '^[0-9a-f]{40}$'
              $source.licence | Should -BeExactly 'CC-BY-4.0'
              $source.licenceHash | Should -Match '^[0-9a-f]{64}$'
        }
    }

    It 'warns once and carries a coverage note when the catalog is unavailable' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive } {
            param($Root)
            $catalogPath = Join-Path $Root 'error-codes.json'
            '{"schemaVersion":3,"entries":' | Set-Content -LiteralPath $catalogPath -Encoding UTF8
            $oldDataDir = $script:LVDataDir
            $oldCache = $script:LVErrorCatalogCache
            $oldFailureLog = $script:LVErrorCatalogFailureLog
            $oldLogLines = $script:LVLogLines
            $oldLogLinesTruncated = $script:LVLogLinesTruncated
            try {
                $script:LVDataDir = $Root
                $script:LVErrorCatalogCache = @{}
                $script:LVErrorCatalogFailureLog = @{}
                $script:LVLogLines = New-Object System.Collections.Generic.List[string]
                $script:LVLogLinesTruncated = $false
                $signature = [pscustomobject]@{ SampleMessage = 'error code 0xC1900101' }

                $first = Get-LVErrorCatalogMatch -Signature $signature
                $second = Get-LVErrorCatalogMatch -Signature $signature
                $first.ErrorCatalogStatus | Should -BeExactly 'unavailable'
                $second.ErrorCatalogStatus | Should -BeExactly 'unavailable'
                @($script:LVLogLines | Where-Object { $_ -match 'Error catalog unavailable' }).Count | Should -Be 1

                Add-LVErrorCatalogContext -Signature $signature -Match $first
                $signature.ErrorCatalogStatus | Should -BeExactly 'unavailable'
                $signature.ErrorCatalogReason | Should -Not -BeNullOrEmpty
                Get-LVErrorCatalogCoverageNote -Finding @($signature) |
                    Should -BeExactly 'The Microsoft error catalog could not be validated, so error-code names and explanations were unavailable for this scan. Repair the catalog before relying on unknown-signature context.'
            } finally {
                $script:LVDataDir = $oldDataDir
                $script:LVErrorCatalogCache = $oldCache
                $script:LVErrorCatalogFailureLog = $oldFailureLog
                $script:LVLogLines = $oldLogLines
                $script:LVLogLinesTruncated = $oldLogLinesTruncated
            }
        }
    }

    It 'continues to load legacy schema v2 catalogs' {
        $repoRoot = Split-Path $PSScriptRoot -Parent
        $current = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/error-codes.json') -Raw | ConvertFrom-Json
        $current.schemaVersion = 2
        $current.sources = @(
            'https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes'
            'https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2'
        )
        $sourceText = @($current.sources) -join "`n"
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $current.sourceHash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sourceText)))).Replace('-', '').ToLowerInvariant()
        } finally {
            $sha.Dispose()
        }
        $current.entries = @($current.entries | Select-Object -First 2)
        $entrySha = [Security.Cryptography.SHA256]::Create()
        try {
            foreach ($entry in $current.entries) {
                foreach ($property in @('sourceRepository', 'sourcePath', 'sourceRevision', 'licence', 'sourceDocumentHash')) {
                    $entry.PSObject.Properties.Remove($property)
                }
                $entrySourceText = '{0}|{1}|{2}|{3}|{4}' -f $entry.reference, $entry.source,
                    $entry.retrieved, $entry.kind, $entry.hex
                $entry.sourceHash = ([BitConverter]::ToString($entrySha.ComputeHash(
                    [Text.Encoding]::UTF8.GetBytes($entrySourceText)))).Replace('-', '').ToLowerInvariant()
            }
        } finally {
            $entrySha.Dispose()
        }
        $legacyPath = Join-Path $TestDrive 'error-codes-v2.json'
        $current | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $legacyPath -Encoding UTF8

        InModuleScope LogVerdict -Parameters @{ legacyPath = $legacyPath } {
            param($legacyPath)
            $legacy = Get-LVErrorCatalog -Path $legacyPath
            $legacy.schemaVersion | Should -Be 2
            @($legacy.entries).Count | Should -Be 2
        }
    }

    It 'binds schema v3 entry hashes to licensed-source provenance' {
        $repoRoot = Split-Path $PSScriptRoot -Parent
        $document = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/error-codes.json') -Raw | ConvertFrom-Json
        $document.entries = @($document.entries | Select-Object -First 2)
        $document.entries[0].sourcePath = 'windows-driver-docs-pr/debugger/tampered.md'
        $tamperedPath = Join-Path $TestDrive 'error-codes-tampered.json'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tamperedPath -Encoding UTF8

        InModuleScope LogVerdict -Parameters @{ tamperedPath = $tamperedPath } {
            param($tamperedPath)
            $catalogPath = $tamperedPath
            { Get-LVErrorCatalog -Path $catalogPath } | Should -Throw '*sourceHash*'
        }
    }

    It 'refuses catalog prose tampering even when provenance is unchanged' {
        $repoRoot = Split-Path $PSScriptRoot -Parent
        $document = Get-Content -LiteralPath (Join-Path $repoRoot 'Data/error-codes.json') -Raw | ConvertFrom-Json
        $document.entries = @($document.entries | Select-Object -First 2)
        $document.entries[0].description = 'substituted catalog explanation'
        $tamperedPath = Join-Path $TestDrive 'error-codes-description-tampered.json'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tamperedPath -Encoding UTF8

        InModuleScope LogVerdict -Parameters @{ tamperedPath = $tamperedPath } {
            param($tamperedPath)
            { Get-LVErrorCatalog -Path $tamperedPath } | Should -Throw '*sourceHash*'
        }
    }

    It 'imports only licence-verified local MicrosoftDocs sources' {
        $repoRoot = Split-Path $PSScriptRoot -Parent
        $importer = Join-Path $repoRoot 'Tools/Import-MicrosoftErrorCatalog.ps1'
        $source = Get-Content -LiteralPath $importer -Raw
        $source | Should -Not -Match 'Invoke-(WebRequest|RestMethod)'
        $source | Should -Match 'MicrosoftDocs/win32'
        $source | Should -Match 'MicrosoftDocs/windows-driver-docs'
        $source | Should -Match 'MicrosoftDocs/SupportArticles-docs'

        $unlicensed = Join-Path $TestDrive 'unlicensed-docs'
        New-Item -ItemType Directory -Path $unlicensed -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $unlicensed 'LICENSE'), 'MIT', (New-Object Text.UTF8Encoding($false)))
        $output = Join-Path $TestDrive 'catalog.json'
        {
            & $importer -Win32DocsPath $unlicensed -WindowsDriverDocsPath $unlicensed `
                -SupportArticlesPath $unlicensed -OutputPath $output -AllowIncomplete
        } | Should -Throw '*not recognizably CC-BY-4.0*'
        Test-Path -LiteralPath $output | Should -BeFalse

        $notice = Get-Content -LiteralPath (Join-Path $repoRoot 'NOTICE') -Raw
        $notice | Should -Match 'CC-BY-4.0'
        $notice | Should -Match 'MicrosoftDocs/win32'
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

    It 'normalizes sign-extended Int32 codes for contexts, lookups, and findings' {
        InModuleScope LogVerdict {
            ConvertTo-LVErrorHex -Value '-2146498529' | Should -BeExactly '0x800F081F'
            ConvertTo-LVErrorHex -Value '-2147024894' | Should -BeExactly '0x80070002'

            $context = New-LVErrorContext -InputObject ([pscustomobject]@{
                ResultCode = '-2146498529'; ExtendCode = '-2147024894'
            }) -Message 'signed codes'
            $context.ResultCode | Should -BeExactly '0x800F081F'
            $context.ExtendCode | Should -BeExactly '0x80070002'

            $setup = @(Get-LogVerdictErrorCatalog -Hex '-2146498529')
            $setup.Count | Should -Be 1
            $setup[0].name | Should -BeExactly 'CBS_E_SOURCE_MISSING'
            $file = @(Get-LogVerdictErrorCatalog -Hex '-2147024894')
            $file.Count | Should -Be 1
            $file[0].name | Should -BeExactly 'ERROR_FILE_NOT_FOUND'

            $signature = [pscustomobject]@{
                Key='signed/error'; Source='textlog'; Channel='SetupDiag'; Provider='Microsoft SetupDiag'; Id=0
                SampleMessage='SetupDiag ResultCode = -2146498529; ExtendCode = -2147024894'
                ResultCode=$context.ResultCode; ExtendCode=$context.ExtendCode; ErrorContext=$context
                Count=1; PerDay=0.1
            }
            $finding = @(Resolve-LVVerdict -Signature @($signature) -Database ([pscustomobject]@{ rules=@() }))[0]
            $finding.ErrorName | Should -BeExactly 'CBS_E_SOURCE_MISSING'
            $finding.ErrorCode | Should -BeExactly '0x800F081F'
        }
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
        $hash = Get-LVTestSha256 -Path $source

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
        $hash = Get-LVTestSha256 -Path $source
        Update-LogVerdictDatabase -SourcePath $source -ExpectedSha256 $hash -TargetPath $target | Out-Null

        $db.updated = '2026-08-04'
        ($db | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $source -Encoding UTF8
        $hash = Get-LVTestSha256 -Path $source
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

    It 'does not read records from a channel whose logging is disabled' {
        InModuleScope LogVerdict {
            Mock Get-WinEvent { [pscustomobject]@{ LogName='Fake'; IsEnabled=$false } } -ParameterFilter { $ListLog -eq 'Fake' }
            Mock Get-WinEvent { throw 'disabled channels must not be read' } -ParameterFilter { $LogName -eq 'Fake' }

            $status = Get-LVChannelStatus -Channel @('Fake')
            $status['Fake'].Access | Should -BeExactly 'readable'
            $status['Fake'].IsEnabled | Should -BeFalse
            $status['Fake'].Reason | Should -Match 'disabled'
            Should -Invoke Get-WinEvent -Times 0 -ParameterFilter { $LogName -eq 'Fake' }
        }
    }

    It 'always probes the restricted channels so they cannot vanish from a sweep' {
        InModuleScope LogVerdict {
            # Get-WinEvent -ListLog omits channels it cannot stat, so unelevated
            # Security disappears entirely. It must be unioned back in.
            (Get-LVPopulatedChannel).Channels | Should -Contain 'Security'
        }
    }

    It 'retains a restricted probe and records a failed channel enumeration' {
        InModuleScope LogVerdict {
            Mock Get-WinEvent { throw [InvalidOperationException]::new('channel list unavailable') } -ParameterFilter { $ListLog -eq '*' }

            $enumeration = Get-LVPopulatedChannel
            $enumeration.Channels | Should -Contain 'Security'
            $enumeration.EnumerationFailed | Should -BeTrue
            $enumeration.MetadataErrorCount | Should -BeGreaterThan 0
            $enumeration.Status | Should -BeExactly 'not-observed'
            ($enumeration.Failures -join ' | ') | Should -Match 'channel list unavailable'
        }
    }

    It 'makes an all-channel enumeration failure non-benign' {
        InModuleScope LogVerdict {
            Mock Get-LVPopulatedChannel {
                return [pscustomobject]@{
                    Channels = @('Security')
                    Metadata = @{}
                    Status = 'not-observed'
                    EnumerationFailed = $true
                    MetadataErrorCount = 1
                    Failures = @('channel list unavailable')
                }
            }
            Mock Get-LVChannelStatus {
                return @{ Security = [pscustomobject]@{ Channel='Security'; Access='missing'; IsEnabled=$null; Reason='not present' } }
            }
            Mock Get-LVEventRecord { return @() }
            Mock Get-LVDiagnosticEvidence { return [pscustomobject]@{ Records=@(); Coverage=@(); HealthProfiles=@() } }

            $result = Invoke-LogVerdictScan -AllChannels -DaysBack 1 -SkipTextLogs -SkipReliability 6>$null
            $result.ChannelEnumerationFailed | Should -BeTrue
            $result.ChannelEnumerationStatus | Should -BeExactly 'not-observed'
            $result.ChannelEnumerationFailures | Should -Contain 'channel list unavailable'
            $result.MetadataUnreadableCount | Should -Be 1
            $result.WorstVerdict | Should -BeExactly 'unknown'
            $result.ExitCode | Should -BeGreaterThan 0
            $result.CoverageNotes -join ' ' | Should -Match 'enumeration failed.*incomplete'
            $enumerationCoverage = @($result.Coverage | Where-Object { $_.Name -eq 'channel enumeration' })
            $enumerationCoverage.Count | Should -Be 1
            $enumerationCoverage[0].Status | Should -BeExactly 'not-observed'
            $enumerationCoverage[0].Reason | Should -Match 'enumeration failed'
        }
    }

    It 'keeps channels whose record count is unavailable in the enumeration plan' {
        InModuleScope LogVerdict {
            Mock Get-WinEvent { [pscustomobject]@{ LogName='UnknownCount'; RecordCount=$null } } -ParameterFilter { $ListLog -eq '*' }

            $enumeration = Get-LVPopulatedChannel -MinimumRecords 1
            $enumeration.Channels | Should -Contain 'UnknownCount'
            $enumeration.Metadata['UnknownCount'].RecordCount | Should -BeNullOrEmpty
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
                'Microsoft-Windows-Dhcp-Client/Admin'
                'Microsoft-Windows-TaskScheduler/Operational'
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
            $rec[0].Message | Should -Match 'failure 41'
            $rec[-1].Message | Should -Match 'failure 50'
            $script:LVTextLogCoverage[0].Status | Should -BeExactly 'truncated'
            $script:LVTextLogCoverage[0].Cap | Should -Be 10
            $script:LVTextLogCoverage[0].ObservedRecords | Should -Be 10
            $script:LVTextLogCoverage[0].Reason | Should -Match 'kept the newest 10.*40 older'
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

    It 'marks a text source truncated when the shared byte budget is exhausted' {
        InModuleScope LogVerdict -Parameters @{ dir = $script:FixtureDir } {
            param($dir)
            $p = Join-Path $dir 'budget.log'
            '!!!  inf: this line is intentionally larger than the budget' | Set-Content -LiteralPath $p -Encoding UTF8
            $target = @(@{ Name='BUDGET'; Path=$p; Pattern='^\s*!!!'; Area='t'; Hint='t' })
            $budget = New-LVCollectionBudget -MaxBytes 2 -MaxRecords 100 -MaxSeconds 60
            $rec = @(Get-LVTextLogRecord -DaysBack 30 -Target $target -CollectionBudget $budget)
            $rec.Count | Should -Be 0
            $script:LVTextLogCoverage[0].Status | Should -BeExactly 'truncated'
            $script:LVTextLogCoverage[0].CollectionBudget.MaxBytes | Should -Be 2
            $budget.BytesRead | Should -BeGreaterThan 0
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

    It 'reads the persisted XML artifact without executing SetupDiag' {
        $artifact = Join-Path $TestDrive 'SetupDiagResults.xml'
        $when = (Get-Date).AddMinutes(-10).ToString('o')
        @"
<?xml version="1.0" encoding="utf-8"?>
<SetupDiag xmlns="https://learn.microsoft.com/windows/deployment/upgrade/setupdiag">
  <Version>1.7.0.0</Version>
  <ProfileName>FindSPFatalError</ProfileName>
  <ProfileGuid>A4028172-1B09-48F8-AD3B-86CDD7D55852</ProfileGuid>
  <SystemInfo><UpgradeEndTime>$when</UpgradeEndTime></SystemInfo>
  <FailureData>Error: SetupDiag reports Fatal Error.</FailureData>
  <FailureDetails>ErrorCode = 0x80070057, LastOperation = Gather data, LastPhase = Downlevel</FailureDetails>
  <Remediation>Remove the incompatible component and retry the upgrade.</Remediation>
</SetupDiag>
"@ | Set-Content -LiteralPath $artifact -Encoding UTF8

        InModuleScope LogVerdict -Parameters @{ artifact=$artifact; root=$script:SetupDiagFixtureRoot } {
            param($artifact, $root)
            Mock Invoke-LVSetupDiagProcess { throw 'persisted artifact should avoid execution' }
            $status = Get-LVSetupDiagRecord -DaysBack 1 -ExecutableCandidate @((Join-Path $root 'missing.exe')) `
                -LogCandidate @($root) -ArtifactCandidate @($artifact) -RegistryCandidate @()
            $status.Status | Should -BeExactly 'artifact-read'
            $status.Used | Should -BeFalse
            $status.ExecutionStatus | Should -BeExactly 'not-executed'
            $status.Provenance | Should -BeExactly 'read-artifact'
            $status.ArtifactKind | Should -BeExactly 'xml'
            $status.ArtifactPath | Should -BeExactly (Get-Item -LiteralPath $artifact).FullName
            $status.ProfileGuid | Should -BeExactly 'A4028172-1B09-48F8-AD3B-86CDD7D55852'
            @($status.Records).Count | Should -Be 1
            $status.Records[0].ProfileGuid | Should -BeExactly $status.ProfileGuid
            $status.Records[0].Provenance | Should -BeExactly 'read-artifact'
            $status.Records[0].ExecutionStatus | Should -BeExactly 'not-executed'
            $status.Records[0].Message | Should -Match 'A4028172-1B09-48F8-AD3B-86CDD7D55852'
            $signature = @(Group-LVSignature -Record @($status.Records[0]) -WindowDays 1)[0]
            $finding = @(Resolve-LVVerdict -Signature @($signature) -Database (Get-LogVerdictDatabase))[0]
            $finding.RuleId | Should -BeExactly 'LV-0327'
            Should -Invoke Invoke-LVSetupDiagProcess -Times 0 -Exactly -Scope It
        }
    }

    It 'reads the documented registry result shape without executing SetupDiag' {
        InModuleScope LogVerdict -Parameters @{ root=$script:SetupDiagFixtureRoot } {
            param($root)
            $registry = [pscustomobject]@{
                RegistryPath = 'HKLM:\SYSTEM\Setup\SetupDiag\Results'
                ProfileName = 'FindSPFatalError'
                ProfileGuid = 'A4028172-1B09-48F8-AD3B-86CDD7D55852'
                SetupDiagVersion = '1.7.0.0'
                UpgradeEndTime = (Get-Date).AddMinutes(-15).ToString('o')
                FailureData = 'Error: SetupDiag reports Fatal Error.'
                FailureDetails = 'ErrorCode = 0x80070057, LastOperation = Gather data, LastPhase = Downlevel'
                Remediation = 'Retry after removing the incompatible component.'
            }
            Mock Invoke-LVSetupDiagProcess { throw 'persisted registry result should avoid execution' }
            $status = Get-LVSetupDiagRecord -DaysBack 1 -ExecutableCandidate @((Join-Path $root 'missing.exe')) `
                -LogCandidate @($root) -ArtifactCandidate @() -RegistryCandidate @($registry)
            $status.Status | Should -BeExactly 'artifact-read'
            $status.ArtifactKind | Should -BeExactly 'registry'
            $status.ArtifactPath | Should -BeExactly 'HKLM:\SYSTEM\Setup\SetupDiag\Results'
            $status.ExecutionStatus | Should -BeExactly 'not-executed'
            @($status.Records).Count | Should -Be 1
            $status.Records[0].ProfileGuid | Should -BeExactly 'A4028172-1B09-48F8-AD3B-86CDD7D55852'
            $status.Records[0].ResultCode | Should -BeExactly '0x80070057'
            Should -Invoke Invoke-LVSetupDiagProcess -Times 0 -Exactly -Scope It
        }
    }

    It 'normalizes provider-qualified registry paths for coverage output' {
        InModuleScope LogVerdict {
            ConvertTo-LVSetupDiagRegistryPath `
                -Path 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\Setup\SetupDiag\Results' |
                Should -BeExactly 'HKLM:\SYSTEM\Setup\SetupDiag\Results'
            ConvertTo-LVSetupDiagRegistryPath `
                -Path 'HKEY_CURRENT_USER\SYSTEM\Setup\MoSetup\Volatile\SetupDiag' |
                Should -BeExactly 'HKCU:\SYSTEM\Setup\MoSetup\Volatile\SetupDiag'
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
            $status.ExecutionStatus | Should -BeExactly 'executed'
            @($status.Records).Count | Should -Be 1
            $status.Records[0].Provenance | Should -BeExactly 'executed'
            Should -Invoke Invoke-LVSetupDiagProcess -Times 1 -Exactly -Scope It -ParameterFilter {
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
            Should -Invoke Test-LVSetupDiagExecutableTrust -Times 1 -Exactly -Scope It
            Should -Invoke Invoke-LVSetupDiagProcess -Times 0 -Exactly -Scope It
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
            Should -Invoke Test-LVSetupDiagExecutableTrust -Times 1 -Exactly -Scope It
            Should -Invoke Invoke-LVSetupDiagProcess -Times 1 -Exactly -Scope It
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
            Should -Invoke Invoke-LVSetupDiagProcess -Times 0 -Exactly -Scope It
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
        $text = Get-LVScanSourceText
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

    It 'keeps the newest WER directories when the inventory cap is reached' {
        $root = Join-Path $script:CrashFixtureDir 'capped-archive'
        1..3 | ForEach-Object {
            $directory = Join-Path $root ('Report-{0}' -f $_)
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            (Get-Item -LiteralPath $directory).LastWriteTime = (Get-Date).AddMinutes(-1 * $_)
        }
        InModuleScope LogVerdict -Parameters @{ root = $root } {
            param($root)
            $artifacts = @(Get-LVCrashArtifact -DaysBack 1 -DumpPath @() -WerRoot $root -MaxWerDirectories 1)
            $artifacts.Count | Should -Be 1
            $artifacts[0].Path | Should -Match 'Report-1$'
            $script:LVCrashCoverage.Count | Should -Be 1
            $script:LVCrashCoverage[0].Status | Should -BeExactly 'truncated'
            $script:LVCrashCoverage[0].Cap | Should -Be 1
            $script:LVCrashCoverage[0].SkippedRecords | Should -Be 2
            $script:LVCrashCoverage[0].Reason | Should -Match 'kept the newest directories'
        }
    }

    It 'stops WER enumeration at the shared collection budget and records coverage' {
        $root = Join-Path $script:CrashFixtureDir 'budget-archive'
        1..2 | ForEach-Object {
            $directory = Join-Path $root ('Report-{0}' -f $_)
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            (Get-Item -LiteralPath $directory).LastWriteTime = (Get-Date).AddMinutes(-1 * $_)
        }
        InModuleScope LogVerdict -Parameters @{ root = $root } {
            param($root)
            $budget = New-LVCollectionBudget -MaxBytes 1MB -MaxRecords 1 -MaxSeconds 60
            $artifacts = @(Get-LVCrashArtifact -DaysBack 1 -DumpPath @() -WerRoot $root -CollectionBudget $budget)
            $artifacts.Count | Should -Be 1
            $budget.RecordsRead | Should -Be 1
            $script:LVCrashCoverage[0].Status | Should -BeExactly 'truncated'
            $script:LVCrashCoverage[0].Reason | Should -Match 'shared collection.*budget'
            $script:LVCrashCoverage[0].SkippedRecords | Should -Be 1
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
        $scan = Get-LVScanSourceText
        $scan | Should -Match 'source was absent or empty, not a clean-health signal'
        $scan | Should -Match 'were not checked'
    }
}

Describe 'Provider message-template cache' {
    It 'imports a bounded export into the reader-compatible cache contract' {
        $inputPath = Join-Path $TestDrive 'provider-templates-input.json'
        $outputPath = Join-Path $TestDrive 'nested\provider-templates.json'
        [pscustomobject]@{
            source = [pscustomobject]@{ name = 'import fixture'; license = 'MIT'; revision = 'fixture-1'; uri = 'https://example.test/provider-templates' }
            templates = @([pscustomobject]@{ provider = 'Imported'; eventId = 19; locale = 'en-US'; message = 'Imported event %1' })
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $inputPath -Encoding UTF8
        $tool = Join-Path (Split-Path $PSScriptRoot -Parent) 'Tools\Import-LogVerdictProviderTemplates.ps1'
        $summary = & $tool -InputPath $inputPath -OutputPath $outputPath -SourceName 'import fixture' -License 'MIT' -SourceRevision 'fixture-2'
        $summary.Action | Should -BeExactly 'import'
        $summary.EntryCount | Should -Be 1
        Test-Path -LiteralPath $outputPath -PathType Leaf | Should -BeTrue
        $schemaPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Data\provider-templates.schema.json'
        if (Get-Command Test-Json -ErrorAction SilentlyContinue) {
            (Test-Json -LiteralPath $outputPath -SchemaFile $schemaPath -ErrorAction Stop) | Should -BeTrue
        }
        InModuleScope LogVerdict -Parameters @{ path = $outputPath } {
            param($path)
            $cache = Read-LVProviderTemplateCache -Path $path
            $cache.Source.License | Should -BeExactly 'MIT'
            $cache.Source.Revision | Should -BeExactly 'fixture-2'
            $cache.Templates[0].Template | Should -BeExactly 'Imported event %1'
        }
    }

    It 'resolves missing live provider prose from the licensed cache and records coverage' {
        $cachePath = Join-Path $TestDrive 'provider-templates.json'
        [pscustomobject]@{
            schemaVersion = 1
            name = 'LogVerdict.ProviderTemplates'
            source = [pscustomobject]@{ name = 'fixture provider resources'; license = 'Apache-2.0'; revision = ('a' * 40); uri = 'https://example.test/templates.json' }
            generatedAt = '2026-08-04T00:00:00Z'
            templates = @([pscustomobject]@{ provider = 'Orphaned'; eventId = 7; locale = 'en-US'; template = 'Recovered provider event %1' })
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $cachePath -Encoding UTF8
        InModuleScope LogVerdict -Parameters @{ path = $cachePath } {
            param($path)
            Initialize-LVProviderTemplateCache -Path $path | Should -Not -BeNullOrEmpty
            Mock Get-WinEvent {
                [pscustomobject]@{
                    ProviderName = 'Orphaned'; Id = 7; Version = 1; Level = 2; LevelDisplayName = 'Error'
                    TimeCreated = (Get-Date); MachineName = 'T'; RecordId = 1; Message = $null; ProviderLocale = 'en-US'
                    Properties = @([pscustomobject]@{ Value = 'disk-1' })
                }
            }
            $rec = @(Get-LVEventRecord -Channel @('Fake') -DaysBack 30 -MaxPerChannel 10)
            $rec.Count | Should -Be 1
            $rec[0].Message | Should -BeExactly 'Recovered provider event disk-1'
            $rec[0].ProviderTemplateSource | Should -Match 'fixture provider resources.*Apache-2.0'
            $signature = @(Get-LVSignatureReduction -Record $rec -WindowDays 30).Signatures[0]
            $signature.ProviderTemplateSource | Should -Match 'fixture provider resources.*Apache-2.0'
            $script:LVEventCoverage[0].Reason | Should -Match '1 record\(s\) had no provider message template.*1 were resolved'
            Initialize-LVProviderTemplateCache -Path $null | Should -BeNullOrEmpty
        }
    }

    It 'rejects a cache that omits licensing provenance without breaking the collector' {
        $cachePath = Join-Path $TestDrive 'provider-templates-no-license.json'
        [pscustomobject]@{
            schemaVersion = 1
            name = 'LogVerdict.ProviderTemplates'
            source = [pscustomobject]@{ name = 'unlicensed fixture'; revision = ('a' * 40) }
            generatedAt = '2026-08-04T00:00:00Z'
            templates = @([pscustomobject]@{ provider = 'Orphaned'; eventId = 7; locale = 'en-US'; template = 'unsafe' })
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $cachePath -Encoding UTF8
        InModuleScope LogVerdict -Parameters @{ path = $cachePath } {
            param($path)
            Initialize-LVProviderTemplateCache -Path $path | Should -BeNullOrEmpty
            $script:LVProviderTemplateCoverage.Cache | Should -BeNullOrEmpty
        }
    }

    It 'imports a normalized projection and emits a cache the module accepts' {
        $inputPath = Join-Path $TestDrive 'provider-templates.ndjson'
        $outputPath = Join-Path $TestDrive 'imported-provider-templates.json'
        [pscustomobject]@{
            source = [pscustomobject]@{ name = 'fixture knowledge base'; license = 'Apache-2.0'; revision = '20260413'; uri = 'https://example.test/kb' }
            entries = @([pscustomobject]@{ provider = 'Orphaned'; eventId = '0x7'; locale = 'en-US'; template = 'Imported event %1' })
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $inputPath -Encoding UTF8

        $tool = Join-Path (Split-Path $PSScriptRoot -Parent) 'Tools\Import-LogVerdictProviderTemplates.ps1'
        $import = & $tool -InputPath $inputPath -OutputPath $outputPath
        $import.Action | Should -BeExactly 'import'
        $import.EntryCount | Should -Be 1
        $document = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
        $document.name | Should -BeExactly 'LogVerdict.ProviderTemplates'
        (Get-Content -LiteralPath $outputPath -Raw) | Should -Match '"generatedAt"\s*:\s*"[^"]+Z"'
        $document.source.license | Should -BeExactly 'Apache-2.0'
        $document.templates[0].template | Should -BeExactly 'Imported event %1'

        InModuleScope LogVerdict -Parameters @{ path = $outputPath } {
            param($path)
            $cache = Initialize-LVProviderTemplateCache -Path $path
            $cache.Source.Revision | Should -BeExactly '20260413'
            (Resolve-LVProviderTemplate -Cache $cache -Provider 'Orphaned' -EventId 7 -Version 1 -Locale 'en-US').Template |
                Should -BeExactly 'Imported event %1'
        }
    }

    It 're-evaluates report-only event signatures with the carried template cache' {
        $root = Join-Path $TestDrive 'provider-offline'
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $reportPath = Join-Path $root 'LogVerdict-Report.json'
        $cachePath = Join-Path $root 'PROVIDER-TEMPLATES.json'
        [ordered]@{
            Tool = 'LogVerdict'; Version = '0.8.2'; MachineName = 'ARCHIVE-HOST'; DaysBack = 9; Elevated = $true
            Channels = @('System'); DeniedChannels = @(); CoverageNotes = @(); Coverage = @()
            Reduction = [ordered]@{ RecordCount = 2; SignatureCount = 1; InitialSignatureCount = 1 }
            Findings = @([ordered]@{
                Key = 'Orphaned/7'; Source = 'event'; Channel = 'System'; Provider = 'Orphaned'; ProviderId = $null; Id = 7; Version = 1
                Count = 2; UndatedCount = 0; FirstSeen = '2026-08-01T09:00:00Z'; LastSeen = '2026-08-01T09:05:00Z'
                WorstLevel = 2; LevelName = 'Error'; SampleMessage = '(no message template registered for this provider on this machine)'
                Samples = @('(no message template registered for this provider on this machine)')
                FallbackMessage = '(no message template registered for this provider on this machine)'; ProviderLocale = 'en-US'
                Times = @('2026-08-01T09:00:00Z', '2026-08-01T09:05:00Z'); Template = $null; PerDay = 0.2; SpanDays = 0
            })
        } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $reportPath -Encoding UTF8
        [ordered]@{
            schemaVersion = 1; name = 'LogVerdict.ProviderTemplates'; generatedAt = '2026-08-04T00:00:00Z'
            source = [ordered]@{ name = 'fixture provider resources'; license = 'Apache-2.0'; revision = 'fixture-1' }
            templates = @([ordered]@{ provider = 'Orphaned'; eventId = 7; locale = 'en-US'; message = 'Recovered offline event' })
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $cachePath -Encoding UTF8

        InModuleScope LogVerdict -Parameters @{ report = $reportPath } {
            param($report)
            $result = Invoke-LVOfflineScan -EvidencePath $report `
                -SkipTextLogs -SkipReliability -IncludeBenign -IncludeLowConfidence
            $result.Reduction.SignatureCount | Should -Be 1
            $result.Findings[0].SampleMessage | Should -BeExactly 'Recovered offline event'
            $result.Findings[0].ProviderTemplateSource | Should -Match 'fixture provider resources.*Apache-2.0'
            $result.CoverageNotes | Should -Contain '2 record(s) had no provider message template registered locally; local provider metadata was absent. 2 record(s) were restored from the provider-template cache.'
            @($result.Coverage | Where-Object { $_.Source -eq 'provider-template' -and $_.ObservedRecords -eq 2 }).Count | Should -Be 1
            Initialize-LVProviderTemplateCache -Path $null | Out-Null
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
            $script:LVEventCoverage[0].Status | Should -BeExactly 'empty'
            $script:LVEventCoverage[0].Reason | Should -Match 'No matching'
        }
    }

    It 'reports a channel with logging disabled as disabled rather than empty' {
        InModuleScope LogVerdict {
            Mock Get-WinEvent { throw 'disabled channels must not be read' }
            $status = @{ Fake = [pscustomobject]@{ Access='readable'; IsEnabled=$false; Reason=$null } }
            $rec = @(Get-LVEventRecord -Channel @('Fake') -DaysBack 30 -ChannelStatus $status)
            $rec.Count | Should -Be 0
            Should -Invoke Get-WinEvent -Times 0
            $script:LVEventCoverage[0].Status | Should -BeExactly 'disabled'
            $script:LVEventCoverage[0].Reason | Should -Match 'disabled'
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
        $missingCache = Join-Path $TestDrive 'provider-template-cache-does-not-exist.json'
        InModuleScope LogVerdict -Parameters @{ cache = $missingCache } {
            param($cache)
            Initialize-LVProviderTemplateCache -Path $cache | Should -BeNullOrEmpty
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

    It 'preserves partial event records and marks later channels when the shared record budget ends' {
        InModuleScope LogVerdict {
            Mock Get-WinEvent {
                1..3 | ForEach-Object {
                    [pscustomobject]@{
                        ProviderName = 'Fake'; Id = 1; Level = 2; LevelDisplayName = 'Error'
                        TimeCreated = (Get-Date); MachineName = 'T'; RecordId = $_; Message = "m$_"
                    }
                }
            }
            $budget = New-LVCollectionBudget -MaxBytes 100000 -MaxRecords 1 -MaxSeconds 60
            $rec = @(Get-LVEventRecord -Channel @('Fake', 'Later', 'Never') -DaysBack 30 -CollectionBudget $budget)
            $rec.Count | Should -Be 1
            @($script:LVEventCoverage | Where-Object Status -eq 'truncated').Count | Should -Be 3
            @($script:LVEventCoverage | Where-Object { $_.Name -in @('Later', 'Never') }).Count | Should -Be 2
            $budget.RecordsRead | Should -Be 1
        }
    }
}

Describe 'Cross-version, locale, and fixture coverage' {
    BeforeAll {
        $script:CoverageFixturePath = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data') 'coverage-fixtures.json'
        $script:CoverageFixtures = Get-Content -LiteralPath $script:CoverageFixturePath -Raw -Encoding UTF8 | ConvertFrom-Json
        $script:CoverageGate = Join-Path (Split-Path $PSScriptRoot -Parent) 'Tools\Test-LogVerdictCoverage.ps1'
    }

    It 'ships a versioned manifest with every required coverage kind' {
        $script:CoverageFixtures.schemaVersion | Should -Be 1
        $fixtures = @($script:CoverageFixtures.fixtures)
        @($fixtures | Group-Object id | Where-Object Count -gt 1).Count | Should -Be 0
        foreach ($kind in @('event', 'textlog', 'offline-evtx', 'elevation', 'gui', 'display')) {
            @($fixtures | Where-Object kind -eq $kind).Count | Should -BeGreaterThan 0
        }
    }

    It 'promotes a passing packaged GUI placement record into the display coverage gate' {
        $evidencePath = Join-Path $TestDrive 'gui-smoke-evidence.json'
        $reportPath = Join-Path $TestDrive 'gui-coverage.json'
        [pscustomobject]@{
            schemaVersion = 1
            passed = $true
            processId = 1234
            placement = [pscustomobject]@{ fullyInsideWorkingArea = $true; screen = '\\.\DISPLAY1' }
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding UTF8

        & $script:CoverageGate -OutputPath $reportPath -DisplayEvidencePath $evidencePath | Out-Null
        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
        $display = @($report.Coverage | Where-Object Id -eq 'gui-isolated-display')
        $display.Count | Should -Be 1
        $display[0].Status | Should -BeExactly 'readable'
        $display[0].ProcessId | Should -Be 1234
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

    It 'extracts named EventData and UserData fields from event XML with bounded values' {
        InModuleScope LogVerdict {
            $event = [pscustomobject]@{
                Xml = @'
<Event><EventData><Data Name="Image">C:\Tools\app.exe</Data><Data Name="Code">0x80070057</Data></EventData><UserData><Root><Status>Failed</Status></Root></UserData></Event>
'@
                Properties = @()
            }
            $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml } -Force
            $structured = Get-LVEventStructuredData -EventObject $event

            $structured.EventData.Image | Should -BeExactly 'C:\Tools\app.exe'
            $structured.EventData.Code | Should -BeExactly '0x80070057'
            $structured.UserData.Status | Should -BeExactly 'Failed'
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

    It 'records VSS restore-point state as advisory coverage with eviction context' {
        InModuleScope LogVerdict {
            $copy = [pscustomobject]@{
                DeviceObject = '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy9'
                InstallDate = '20260802120000.000000-240'
                State = 12
            }
            $inventory = Get-LVShadowCopyInventory -ShadowCopy @($copy)
            $storage = Get-LVShadowCopyStorageSummary -CommandResult ([pscustomobject]@{
                ExitCode = 0
                Output = @('Used Shadow Copy Storage space: 1 GB', 'Maximum Shadow Copy Storage space: 5 GB')
                Error = $null
            })
            $profile = Get-LVPointInTimeRestoreHealthProfile -Inventory $inventory -StorageSummary $storage

            $inventory.Status | Should -BeExactly 'readable'
            $profile.Status | Should -BeExactly 'readable'
            $profile.ShadowCopyCount | Should -Be 1
            $profile.RequiredConfiguration | Should -Match '72-hour|VSS limit|low-free-space'
            $profile.ObservedConfiguration | Should -Match 'Maximum Shadow Copy Storage space'
            $profile.Advice | Should -Match 'not.*tampering'
        }
    }

    It 'marks a damaged SRUM header and routes the narrow rule through the resolver' {
        InModuleScope LogVerdict {
            $database = Join-Path $TestDrive 'SRUDB.dat'
            Set-Content -LiteralPath $database -Value 'fixture' -Encoding ASCII
            $profile = Get-LVSRUMHealthProfile -DatabasePath $database -SoftwarePath (Join-Path $TestDrive 'SOFTWARE') `
                -EsentutilPath (Join-Path $TestDrive 'esentutl.exe') -HeaderResult ([pscustomobject]@{
                    ExitCode = 0; Output = @('State: Dirty Shutdown'); Error = $null
                })
            $record = ConvertTo-LVSRUMDiagnosticRecord -HealthProfile $profile
            $grouped = Get-LVSignatureReduction -Record @($record) -WindowDays 1
            $finding = @(Resolve-LVVerdict -Signature @($grouped.Signatures) -Database (Get-LogVerdictDatabase))[0]

            $profile.Status | Should -BeExactly 'readable'
            $profile.DatabaseState | Should -BeExactly 'Dirty Shutdown'
            $profile.ApplicationUsageStatus | Should -BeExactly 'not-parsed'
            $record.Message | Should -Match '^SRUM database state: Dirty Shutdown'
            $finding.RuleId | Should -BeExactly 'LV-0329'
            $finding.Verdict | Should -BeExactly 'investigate'
        }
    }

    It 'reads only shadow-copy events older than the live channel horizon' {
        InModuleScope LogVerdict {
            $copy = [pscustomobject]@{ DeviceObject = '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy9' }
            $old = [pscustomobject]@{
                Source='event'; Channel='System'; Provider='VSS'; Id=8193; Level=2; LevelName='Error'
                TimeCreated=(Get-Date).AddDays(-5); RecordId=12; Message='old shadow event'
            }
            Mock Test-Path { $true }
            Mock Read-LVArchivedEventFile {
                [pscustomobject]@{ Channel='System'; Oldest=(Get-Date).AddDays(-5); Records=@($old); Truncated=$false; BudgetStop=$null; Error=$null; ParseMilliseconds=2 }
            }
            $coverage = @{ System = [pscustomobject]@{ Oldest=(Get-Date).AddDays(-2) } }
            $evidence = Get-LVShadowCopyEventEvidence -Inventory ([pscustomobject]@{ Status='readable'; ShadowCopies=@($copy); Error=$null }) `
                -Channel @('System') -ChannelStatus $coverage -DaysBack 10

            $evidence.Records.Count | Should -Be 1
            $evidence.Records[0].Origin | Should -BeExactly 'shadow-copy'
            $evidence.Coverage[0].Status | Should -BeExactly 'readable'
            Should -Invoke Read-LVArchivedEventFile -Times 1 -Exactly
        }
    }

    It 'reports point-in-time restore inventory and VSS storage as advisory coverage' {
        InModuleScope LogVerdict {
            $copy = [pscustomobject]@{
                DeviceObject = '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3'
                InstallDate = (Get-Date).AddHours(-2)
            }
            $inventory = Get-LVShadowCopyInventory -ShadowCopy @($copy)
            $storage = Get-LVShadowCopyStorageSummary -CommandPath (Join-Path $TestDrive 'missing-vssadmin.exe')
            $profile = Get-LVPointInTimeRestoreHealthProfile -Inventory $inventory -StorageSummary $storage
            $profile.Status | Should -BeExactly 'readable'
            $profile.ShadowCopyCount | Should -Be 1
            $profile.OldestShadowCopy | Should -Not -BeNullOrEmpty
            $profile.Advice | Should -Match 'free space|VSS limit'

            $empty = Get-LVPointInTimeRestoreHealthProfile -Inventory (Get-LVShadowCopyInventory -ShadowCopy @()) -StorageSummary $storage
            $empty.Status | Should -BeExactly 'empty'
            $empty.Reason | Should -Match 'not proof'
        }
    }

    It 'records SRUM ESE state without pretending to parse application rows' {
        $sru = Join-Path $TestDrive 'sru'
        New-Item -ItemType Directory -Path $sru -Force | Out-Null
        $database = Join-Path $sru 'SRUDB.dat'
        $software = Join-Path $sru 'SOFTWARE'
        [IO.File]::WriteAllBytes($database, [byte[]](1..32))
        [IO.File]::WriteAllBytes($software, [byte[]](1..8))
        InModuleScope LogVerdict -Parameters @{ Database = $database; Software = $software } {
            param($Database, $Software)
            $header = [pscustomobject]@{ ExitCode = 0; Output = @('State: Clean Shutdown    Last Full Backup: never'); Error = $null }
            $profile = Get-LVSRUMHealthProfile -DatabasePath $Database -SoftwarePath $Software `
                -EsentutilPath (Join-Path $TestDrive 'missing-esentutil.exe') -HeaderResult $header
            $profile.Status | Should -BeExactly 'readable'
            $profile.DatabaseState | Should -BeExactly 'Clean Shutdown'
            $profile.SizeBytes | Should -Be 32
            $profile.ApplicationUsageStatus | Should -BeExactly 'not-parsed'

            $header.Output = @('State: Dirty Shutdown')
            $dirty = Get-LVSRUMHealthProfile -DatabasePath $Database -SoftwarePath $Software `
                -EsentutilPath (Join-Path $TestDrive 'missing-esentutil.exe') -HeaderResult $header
            $record = ConvertTo-LVSRUMDiagnosticRecord -HealthProfile $dirty
            $record.Message | Should -Match 'Dirty Shutdown'
            $record.Source | Should -BeExactly 'textlog'
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

    It 'uses the unfiltered event range when the collector level filter omits records' {
        InModuleScope LogVerdict {
            $script:LVTruncatedChannel = @()
            $all = 10..15 | ForEach-Object {
                [pscustomobject]@{
                    ProviderName = 'Fixture'; Id = 7; Level = if ($_ -in @(10, 15)) { 2 } else { 4 }
                    LevelDisplayName = if ($_ -in @(10, 15)) { 'Error' } else { 'Information' }
                    TimeCreated = (Get-Date '2026-08-01 10:00:00').AddSeconds($_)
                    MachineName = 'FIXTURE'; RecordId = $_; Message = "event $_"
                }
            }
            Mock Get-WinEvent {
                param($FilterHashtable)
                if ($FilterHashtable.ContainsKey('Level')) {
                    return @($all | Where-Object { $FilterHashtable.Level -contains $_.Level })
                }
                return $all
            }

            $filtered = @(Get-LVEventRecord -Channel @('Fake') -DaysBack 1 -MaxPerChannel 20)
            @($filtered).Count | Should -Be 2
            @($script:LVEventSequence).Count | Should -Be 6
            @(Get-LVEventSequenceGap -Record $filtered -SequenceRecord $script:LVEventSequence) | Should -BeNullOrEmpty

            $deleted = @($script:LVEventSequence | Where-Object RecordId -ne 13)
            @(Get-LVEventSequenceGap -Record $filtered -SequenceRecord $deleted) | Should -Match '12 to 14'
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

    It 'emits empty optional collections instead of phantom null members' {
        InModuleScope LogVerdict {
            $db = [pscustomobject]@{ schemaVersion = 2; rules = @(
                [pscustomobject]@{
                    id = 'EMPTY-OPTIONALS'; status = 'stable'; verified = '2026-07-31'
                    match = [pscustomobject]@{ source = 'event'; provider = 'Acme'; eventId = 7 }
                    verdict = 'investigate'; title = 't'; plain = 'p'; why = 'w'; action = 'a'; confidence = 'high'
                }) }
            $sig = [pscustomobject]@{
                Key = 'Acme/7'; Source = 'event'; Channel = 'System'; Provider = 'Acme'; Id = 7
                Count = 1; PerDay = 0.1; SampleMessage = 'm'; FirstSeen = (Get-Date); LastSeen = (Get-Date)
            }
            $finding = @(Resolve-LVVerdict -Signature @($sig) -Database $db)[0]
            foreach ($name in @('References', 'Sources', 'FalsePositives')) {
                @($finding.$name).Count | Should -Be 0 -Because "$name must be an empty collection"
            }
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

                $sig | Add-Member -NotePropertyName ProviderLocale -NotePropertyValue 'en-US' -Force
                (Resolve-LVVerdict -Signature @($sig) -Database $db)[0].RuleId | Should -Be 'LOC-1'
                $sig.ProviderLocale = 'de-DE'
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

    It 'matches structured EventData and UserData conditions without rendered message prose' {
        InModuleScope LogVerdict {
            $sig = [pscustomobject]@{
                Key='Acme/1'; Source='event'; Channel='System'; Provider='Acme'; Id=1
                Count=1; PerDay=0.1; SampleMessage='localized provider text'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
                StructuredData = [pscustomobject]@{
                    EventData = [pscustomobject]@{ Image='C:\Tools\app.exe'; Code='0x80070057' }
                    UserData = [pscustomobject]@{ Status='Failed' }
                }
            }
            $rule = [pscustomobject]@{
                id='STRUCT-1'; status='stable'; verified='2026-08-02'
                match=[pscustomobject]@{
                    source='event'; provider='Acme'; eventId=1
                    eventData=[pscustomobject]@{ all=@(
                        [pscustomobject]@{ field='EventData.Image'; endswith='app.exe' }
                        [pscustomobject]@{ any=@(
                            [pscustomobject]@{ field='UserData.Status'; equals='failed' }
                            [pscustomobject]@{ field='EventData.Code'; equals='0x999' }
                        ) }
                    ) }
                }
                verdict='actionable'; title='structured'; plain='p'; why='w'; action='a'; confidence='high'
            }
            $db = [pscustomobject]@{ schemaVersion=6; rules=@($rule) }
            (Resolve-LVVerdict -Signature @($sig) -Database $db)[0].RuleId | Should -BeExactly 'STRUCT-1'

            $bad = [pscustomobject]@{ field='EventData.Image'; contains='app'; wildcard='unsupported' }
            @(Get-LVStructuredConditionProblems -Condition $bad).Count | Should -BeGreaterThan 0
        }
    }

    It 'matches a structured regex through the bounded compiled path' {
        InModuleScope LogVerdict {
            $signature = [pscustomobject]@{
                Key='Acme/2'; Source='event'; Channel='System'; Provider='Acme'; Id=2
                Count=1; PerDay=0.1; SampleMessage='localized provider text'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
                StructuredData = [pscustomobject]@{
                    EventData = [pscustomobject]@{ Image='C:\Tools\app.exe' }
                }
            }
            $rule = [pscustomobject]@{
                id='STRUCT-REGEX'; status='stable'; verified='2026-08-03'
                match=[pscustomobject]@{
                    source='event'; provider='Acme'; eventId=2
                    eventData=[pscustomobject]@{ field='EventData.Image'; regex='^C:\\Tools\\.+\.exe$' }
                }
                verdict='actionable'; title='structured regex'; plain='p'; why='w'; action='a'; confidence='high'
            }
            $finding = @(Resolve-LVVerdict -Signature @($signature) -Database ([pscustomobject]@{ rules=@($rule) }))[0]
            $finding.RuleId | Should -BeExactly 'STRUCT-REGEX'
        }
    }

    It 'turns a timed-out message regex into an unknown finding' {
        InModuleScope LogVerdict {
            $rule = [pscustomobject]@{
                id='REGEX-TIMEOUT'; status='stable'; verified='2026-08-03'
                match=[pscustomobject]@{ source='event'; provider='Acme'; eventId=99; messagePattern='(a+)+$' }
                verdict='critical'; title='must not win'; plain='p'; why='w'; action='a'; confidence='high'
            }
            $signature = [pscustomobject]@{
                Key='Acme/99'; Source='event'; Channel='System'; Provider='Acme'; Id=99
                Count=1; PerDay=0.1; SampleMessage=(('a' * 10000) + 'X'); FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            $finding = @(Resolve-LVVerdict -Signature @($signature) -Database ([pscustomobject]@{ rules=@($rule); correlations=@() }))[0]
            $finding.Verdict | Should -BeExactly 'unknown'
            $finding.RegexMatchTimeout | Should -BeTrue
            $finding.RegexRuleId | Should -BeExactly 'REGEX-TIMEOUT'
            $finding.Why | Should -Match 'timeout'
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

Describe 'Incident grouping and confidence gates' {
    It 'groups rule-matched signatures into one incident with combined evidence' {
        InModuleScope LogVerdict {
            $first = [pscustomobject]@{
                Key='DISM/0x800f081f'; Source='textlog'; Channel='DISM'; Provider='DISM'; Id=0
                RuleId='LV-0093'; Verdict='investigate'; Title='Image servicing error'; Plain='plain'; Why='why'; Action='action'
                Confidence='medium'; Count=2; PerDay=0.2; FirstSeen=(Get-Date '2026-08-01'); LastSeen=(Get-Date '2026-08-01 01:00')
                ResultCode='0x800f081f'; ExtendCode=$null; ErrorCode=$null; SampleMessage='first'; References=@(); Sources=@(); FalsePositives=@()
            }
            $second = [pscustomobject]@{
                Key='DISM/0x800f0900'; Source='textlog'; Channel='DISM'; Provider='DISM'; Id=0
                RuleId='LV-0093'; Verdict='investigate'; Title='Image servicing error'; Plain='plain'; Why='why'; Action='action'
                Confidence='medium'; Count=3; PerDay=0.3; FirstSeen=(Get-Date '2026-08-02'); LastSeen=(Get-Date '2026-08-02 01:00')
                ResultCode='0x800f0900'; ExtendCode=$null; ErrorCode=$null; SampleMessage='second'; References=@(); Sources=@(); FalsePositives=@()
            }

            $reduction = Get-LVIncidentReduction -Finding @($first, $second)
            @($reduction.Incidents).Count | Should -Be 1
            $incident = @($reduction.Incidents)[0]
            $incident.IncidentId | Should -BeExactly 'Incident/LV-0093'
            $incident.SignatureCount | Should -Be 2
            $incident.Count | Should -Be 5
            @($incident.SignatureKeys) | Should -Contain 'DISM/0x800f081f'
            @($incident.SignatureKeys) | Should -Contain 'DISM/0x800f0900'
            @($incident.DistinctCodes) | Should -Be @('0x800f081f', '0x800f0900')
            $reduction.Summary.SuppressedSignatureCount | Should -Be 1
            $reduction.Summary.SuppressionRatio | Should -Be 0.5
        }
    }

    It 'hides low-confidence rulings by default while retaining unknown evidence' {
        InModuleScope LogVerdict {
            $low = [pscustomobject]@{ Confidence='low'; Verdict='informational' }
            $unknown = [pscustomobject]@{ Confidence='none'; Verdict='unknown' }
            @($low, $unknown | Where-Object { Test-LVConfidenceIncluded -Finding $_ }).Count | Should -Be 1
            (Test-LVConfidenceIncluded -Finding $low -IncludeLowConfidence) | Should -BeTrue
            (Test-LVConfidenceIncluded -Finding $unknown) | Should -BeTrue
        }
    }

    It 'does not keep the no-op LV-0072 escalation' {
        InModuleScope LogVerdict {
            $rule = @((Get-LogVerdictDatabase).rules | Where-Object id -eq 'LV-0072')[0]
            $rule.escalate | Should -BeNullOrEmpty
            $signature = [pscustomobject]@{
                Key='Microsoft-Windows-WindowsUpdateClient/20'; Source='event'; Channel='System'
                Provider='Microsoft-Windows-WindowsUpdateClient'; Id=20; Count=10; PerDay=4
                SampleMessage='Update failed'; FirstSeen=(Get-Date); LastSeen=(Get-Date)
            }
            $finding = @(Resolve-LVVerdict -Signature @($signature) -Database (Get-LogVerdictDatabase))[0]
            $finding.RuleId | Should -BeExactly 'LV-0072'
            $finding.Verdict | Should -BeExactly 'actionable'
            $finding.Why | Should -Not -Match 'Escalated'
        }
    }

    It 'uses incidents as the reader-facing report unit' {
        InModuleScope LogVerdict {
            $members = @(
                [pscustomobject]@{
                    Key='DISM/0x1'; Source='textlog'; Channel='DISM'; Provider='DISM'; Id=0; RuleId='LV-0093'
                    Verdict='investigate'; Title='Image servicing error'; Plain='plain'; Why='why'; Action='action'; Confidence='medium'
                    Count=2; PerDay=0.2; FirstSeen=(Get-Date '2026-08-01'); LastSeen=(Get-Date '2026-08-01 01:00')
                    ResultCode='0x1'; ExtendCode=$null; ErrorCode=$null; SampleMessage='first'; References=@(); Sources=@(); FalsePositives=@()
                },
                [pscustomobject]@{
                    Key='DISM/0x2'; Source='textlog'; Channel='DISM'; Provider='DISM'; Id=0; RuleId='LV-0093'
                    Verdict='investigate'; Title='Image servicing error'; Plain='plain'; Why='why'; Action='action'; Confidence='medium'
                    Count=3; PerDay=0.3; FirstSeen=(Get-Date '2026-08-02'); LastSeen=(Get-Date '2026-08-02 01:00')
                    ResultCode='0x2'; ExtendCode=$null; ErrorCode=$null; SampleMessage='second'; References=@(); Sources=@(); FalsePositives=@()
                })
            $incidentReduction = Get-LVIncidentReduction -Finding $members
            $result = [pscustomobject]@{
                Version='0.8.2'; MachineName='TESTPC'; ScanTime=(Get-Date '2026-08-03'); DaysBack=30; Elevated=$false; Channels=@('DISM')
                Reduction=[pscustomobject]@{ RecordCount=5; SignatureCount=2; Ratio=2.5 }
                Findings=$members; Incidents=@($incidentReduction.Incidents); IncidentSummary=$incidentReduction.Summary
                Correlations=@(); CoverageNotes=@(); Coverage=@(); HealthProfiles=@(); Performance=@(); CrashArtifacts=@(); Horizon=@{}; HorizonWarning=$null
                Stability=$null; DatabaseName='test'; DatabaseDate='2026-08-03'; RuleCount=1; WorstVerdict='investigate'; Redacted=$false
            }
            $text = ConvertTo-LVTextReport -Result $result
            $html = ConvertTo-LVHtmlReport -Result $result
            $ticket = ConvertTo-LVTicketSummary -Result $result
            $text | Should -Match 'Incident suppression: 50%'
            $text | Should -Match 'Occurrences : 5'
            $text | Should -Match 'Distinct codes: 0x1, 0x2'
            $html | Should -Match 'Incident suppression</div><div class="v">50%'
            $html | Should -Match '2 constituent signature\(s\)'
            $ticket | Should -Match 'Incidents needing attention:\*\* 1'
            $ticket | Should -Match 'Distinct codes.*0x1, 0x2'
        }
    }
}

Describe 'Suppression expectations' {
    It 'validates scoped dates and assigns a ninety-day review deadline' {
        InModuleScope LogVerdict {
            $path = Join-Path $TestDrive 'suppressions-valid.json'
            $hash = Get-LVSuppressionSignatureHash -Key 'Acme/99'
            $document = [ordered]@{
                schemaVersion = 1
                name = 'LogVerdict.Suppressions'
                entries = @([ordered]@{
                    id = 'SUP-ONE'
                    scope = [ordered]@{ signatureHash = $hash; machine = 'TEST-PC'; windowsBuild = '26100' }
                    action = 'hide'
                    statement = 'The vendor has documented this transient event for this build.'
                    created = '2026-01-01T00:00:00Z'
                })
            }
            $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8

            $set = Import-LVSuppressionSet -Path $path -AsOf ([datetime]'2026-01-02')
            $set.Status | Should -BeExactly 'loaded'
            $set.EntryCount | Should -Be 1
            $set.Entries[0].scope.signatureHash | Should -BeExactly $hash
            $set.Entries[0].reviewDueOn | Should -BeExactly '2026-04-01T00:00:00.0000000Z'
            $set.Entries[0].status | Should -BeExactly 'active'

            $document.entries[0].expiresOn = 'not-a-date'
            $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
            { Import-LVSuppressionSet -Path $path } | Should -Throw '*expiresOn*'

            $document.entries[0].expiresOn = '2026-12-01T00:00:00Z'
            $document.entries[0].scope = [ordered]@{ signatureHash = $hash; machine = 'TEST-PC' }
            $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
            { Import-LVSuppressionSet -Path $path } | Should -Throw '*windowsBuild or appVersion*'
        }
    }

    It 'keeps hidden findings in raw totals and applies only a real downgrade' {
        InModuleScope LogVerdict {
            $asOf = [datetime]'2026-08-03'
            $finding = [pscustomobject]@{
                Key='Acme/99'; Verdict='actionable'; Title='Acme failure'; Why='Original reason'
                Count=2; PerDay=0.2; RuleId='LV-TEST'; Confidence='high'
            }
            $hash = Get-LVSuppressionSignatureHash -Key $finding.Key
            $hidePath = Join-Path $TestDrive 'suppressions-hide.json'
            [ordered]@{
                schemaVersion=1; name='LogVerdict.Suppressions'; entries=@([ordered]@{
                    id='HIDE-ONE'; scope=[ordered]@{ signatureHash=$hash; machine='TEST-PC'; appVersion='0.8.2' }
                    action='hide'; statement='Known vendor noise in this application release.'; created='2026-08-01T00:00:00Z'
                })
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $hidePath -Encoding UTF8
            $hideSet = Import-LVSuppressionSet -Path $hidePath -AsOf $asOf
            $hidden = Apply-LVSuppression -Finding @($finding) -SuppressionSet $hideSet -MachineName 'TEST-PC' -AppVersion '0.8.2' -AsOf $asOf
            $hidden.Findings[0].Suppressed | Should -BeTrue
            $hidden.Findings[0].Verdict | Should -BeExactly 'actionable'
            $hidden.Findings[0].OriginalVerdict | Should -BeExactly 'actionable'
            $hidden.Summary.EntryCount | Should -Be 1
            $hidden.Summary.SuppressedFindingCount | Should -Be 1

            $downgradePath = Join-Path $TestDrive 'suppressions-downgrade.json'
            [ordered]@{
                schemaVersion=1; name='LogVerdict.Suppressions'; entries=@([ordered]@{
                    id='DOWN-ONE'; scope=[ordered]@{ signatureHash=$hash; machine='TEST-PC'; appVersion='0.8.2' }
                    action='downgrade'; downgradeTo='benign'; statement='This is an approved transient condition.'; created='2026-08-01T00:00:00Z'
                })
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $downgradePath -Encoding UTF8
            $downgradeSet = Import-LVSuppressionSet -Path $downgradePath -AsOf $asOf
            $downgraded = Apply-LVSuppression -Finding @($finding) -SuppressionSet $downgradeSet -MachineName 'TEST-PC' -AppVersion '0.8.2' -AsOf $asOf
            $downgraded.Findings[0].Suppressed | Should -BeTrue
            $downgraded.Findings[0].SuppressionAction | Should -BeExactly 'downgrade'
            $downgraded.Findings[0].OriginalVerdict | Should -BeExactly 'actionable'
            $downgraded.Findings[0].Verdict | Should -BeExactly 'benign'
            $downgraded.Findings[0].Why | Should -Match 'DOWN-ONE'
        }
    }

    It 'reports unmatched and expired expectations while preserving standard export metadata' {
        InModuleScope LogVerdict {
            $asOf = [datetime]'2026-08-03'
            $finding = [pscustomobject]@{
                Key='Acme/99'; Verdict='actionable'; Title='Acme failure'; Plain='plain'; Why='why'; Action='action'
                Count=2; PerDay=0.2; RuleId='LV-TEST'; Confidence='high'; Source='event'; Channel='System'; Provider='Acme'; Id=99
                FirstSeen=([datetime]'2026-08-02 10:00'); LastSeen=([datetime]'2026-08-02 11:00'); Samples=@('failure')
                References=@(); Sources=@(); FalsePositives=@(); FallbackMessage=$null
            }
            $hash = Get-LVSuppressionSignatureHash -Key $finding.Key
            $path = Join-Path $TestDrive 'suppressions-report.json'
            [ordered]@{
                schemaVersion=1; name='LogVerdict.Suppressions'; entries=@(
                    [ordered]@{ id='MATCHED'; scope=[ordered]@{ signatureHash=$hash; machine='TEST-PC'; windowsBuild='26100' }; action='hide'; statement='Known condition.'; created='2026-08-01T00:00:00Z' },
                    [ordered]@{ id='UNMATCHED'; scope=[ordered]@{ signatureHash=('a' * 64); machine='TEST-PC'; windowsBuild='26100' }; action='hide'; statement='Expected only on a different signature.'; created='2026-08-01T00:00:00Z' },
                    [ordered]@{ id='EXPIRED'; scope=[ordered]@{ signatureHash=('b' * 64); machine='TEST-PC'; windowsBuild='26100' }; action='hide'; statement='Review this old expectation.'; created='2025-01-01T00:00:00Z' }
                )
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
            $set = Import-LVSuppressionSet -Path $path -AsOf $asOf
            $applied = Apply-LVSuppression -Finding @($finding) -SuppressionSet $set -MachineName 'TEST-PC' -WindowsBuild '26100' -AsOf $asOf
            $applied.Summary.MatchedCount | Should -Be 1
            $applied.Summary.UnmatchedCount | Should -Be 1
            $applied.Summary.ExpiredCount | Should -Be 1
            $applied.Summary.ActiveCount | Should -Be 2
            $applied.Findings[0].Suppressed | Should -BeTrue

            $incident = @(Get-LVIncidentReduction -Finding @($applied.Findings)).Incidents
            $result = [pscustomobject]@{
                Tool='LogVerdict'; Version='0.8.2'; MachineName='TEST-PC'; ScanTime=$asOf; Duration=[timespan]::FromSeconds(1)
                DaysBack=30; Elevated=$false; Channels=@('System'); Reduction=[pscustomobject]@{ RecordCount=2; SignatureCount=1; Ratio=2 }
                Findings=@($applied.Findings); Incidents=@($incident); IncidentSummary=(Get-LVIncidentReduction -Finding @($applied.Findings)).Summary
                SuppressionStatus=$applied.Summary; WindowsBuild=26100; Correlations=@(); Coverage=@(); CoverageNotes=@(); HealthProfiles=@(); Performance=@()
                CrashArtifacts=@(); Stability=$null; Horizon=@{}; HorizonWarning=$null; SetupDiag=$null; DatabaseName='test'; DatabaseDate='2026-08-03'; RuleCount=1
                DatabaseFreshness=$null; WorstVerdict='actionable'; ExitCode=2; Redacted=$false; Advisories=@()
            }
            $text = ConvertTo-LVTextReport -Result $result
            $ticket = ConvertTo-LVTicketSummary -Result $result
            $text | Should -Match 'Suppression expectations: 1 signature\(s\) suppressed; 1 matched nothing; 1 expired/review due'
            $text | Should -Match 'UNMATCHED matched nothing'
            $text | Should -Match 'EXPIRED expired/review due'
            $ticket | Should -Match 'Suppression expectations'
            $ticket | Should -Match '1 matched nothing; 1 expired or due for review'

            $ecs = @((Export-LogVerdictStandard -Result $result -Format Ecs) | ForEach-Object { $_ | ConvertFrom-Json })[0]
            $ecs.logverdict.scan.windowsBuild | Should -Be 26100
            $ecs.logverdict.suppression.suppressedFindingCount | Should -Be 1
            $ecs.logverdict.finding.suppressed | Should -BeTrue
            $ecs.logverdict.finding.suppression.id | Should -BeExactly 'MATCHED'
            $sarif = (Export-LogVerdictStandard -Result $result -Format Sarif).Document
            $sarif.runs[0].results[0].baselineState | Should -BeExactly 'unchanged'
            $sarif.runs[0].results[0].suppressions[0].kind | Should -BeExactly 'external'
            $sarif.runs[0].results[0].properties.'logverdict.expiresOn' | Should -BeNullOrEmpty
            $sarif.runs[0].results[0].suppressions[0].properties.'logverdict.suppressionId' | Should -BeExactly 'MATCHED'
            $jsonl = @(Export-LogVerdictStandard -Result $result -Format Jsonl)
            $jsonlFinding = @($jsonl | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object recordType -eq 'finding')[0]
            $jsonlFinding.suppressed | Should -BeTrue
            $jsonlFinding.suppression.id | Should -BeExactly 'MATCHED'
        }
    }

    It 'exposes the set alone and records suppression transitions in scan comparisons' {
        InModuleScope LogVerdict {
            $path = Join-Path $TestDrive 'suppressions-only.json'
            [ordered]@{
                schemaVersion=1; name='LogVerdict.Suppressions'; entries=@([ordered]@{
                    id='ONLY-ONE'; scope=[ordered]@{ signatureHash=('c' * 64); machine='TEST-PC'; appVersion='0.8.2' }
                    action='hide'; statement='Reviewable expectation.'; created='2026-08-01T00:00:00Z'
                })
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
            $set = Get-LogVerdictSuppression -Path $path
            $set.schemaVersion | Should -Be 1
            $set.entries[0].id | Should -BeExactly 'ONLY-ONE'
            @(Invoke-LogVerdictScan -SuppressedOnly -SuppressionPath $path).Count | Should -Be 1

            $before = [pscustomobject]@{ ScanTime=[datetime]'2026-08-01'; Findings=@([pscustomobject]@{
                Key='Acme/99'; Title='failure'; Verdict='actionable'; Count=1; PerDay=0.1; Suppressed=$false
            }) }
            $after = [pscustomobject]@{ ScanTime=[datetime]'2026-08-02'; Findings=@([pscustomobject]@{
                Key='Acme/99'; Title='failure'; Verdict='actionable'; Count=1; PerDay=0.1; Suppressed=$true
                SuppressionId='ONLY-ONE'; SuppressionAction='hide'
            }) }
            $change = @(Compare-LogVerdictScan -Before $before -After $after)
            $change.Count | Should -Be 1
            $change[0].Change | Should -BeExactly 'suppressed'
            $change[0].SuppressionId | Should -BeExactly 'ONLY-ONE'

            $unsuppressed = @(Compare-LogVerdictScan -Before $after -After $before)
            $unsuppressed[0].Change | Should -BeExactly 'unsuppressed'
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
            Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
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

    It 'redacts the outbound model prompt without mutating the retained finding' {
        InModuleScope LogVerdict {
            $script:LVModelRequestBody = $null
            Mock Invoke-RestMethod {
                $script:LVModelRequestBody = $Body
                [pscustomobject]@{
                    response = '{"summary":"This may describe a service failure.","evidence":["The provider emitted the event."],"uncertainty":"The underlying cause is not identified."}'
                }
            }
            $finding = [pscustomobject]@{
                Key='HOST-9/99'; Source='event'; Channel='System'; Provider='HOST-9 Provider'; Id=99
                Count=2; PerDay=0.2; SampleMessage='HOST-9: jsmith opened C:\Users\jsmith\app.log'
                Verdict='unknown'; RuleId=$null
            }

            $out = @(Add-LVModelExplanation -Finding @($finding) -Model 'test-model' -Redact `
                -MachineName 'HOST-9' -UserName 'jsmith')
            $requestBody = $script:LVModelRequestBody | ConvertFrom-Json
            $requestBody.prompt | Should -Not -Match 'HOST-9'
            $requestBody.prompt | Should -Not -Match 'jsmith'
            $requestBody.prompt | Should -Not -Match 'C:\\Users\\jsmith'
            $requestBody.prompt | Should -Match '<MACHINE>|<USER>'
            $finding.SampleMessage | Should -BeExactly 'HOST-9: jsmith opened C:\Users\jsmith\app.log'
            $out[0].ModelExplanation | Should -Not -BeNullOrEmpty
        }
    }

    It 'never calls a model for a known finding' {
        InModuleScope LogVerdict {
            Mock Invoke-RestMethod { throw 'should not be called' }
            $known = [pscustomobject]@{ Key='Acme/1'; Verdict='actionable'; RuleId='LV-0001' }
            $out = @(Add-LVModelExplanation -Finding @($known))
            Should -Invoke Invoke-RestMethod -Times 0 -Exactly
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
            $expectedBurstUtc = ConvertTo-LVUtcTimestamp $finding.BurstOnset
            $csv | Should -Match ('"True".*"{0}".*"3".*"4"' -f [regex]::Escape($expectedBurstUtc))
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

    It 'round-trips structured EventData and UserData values in the JSON report' {
        $result = $script:FakeResult | Select-Object *
        $finding = $script:FakeResult.Findings[0] | Select-Object *
        $finding | Add-Member -NotePropertyName StructuredData -NotePropertyValue ([pscustomobject]@{
            EventData = [pscustomobject]@{
                Image = @('C:\Tools\one.exe', 'C:\Tools\two.exe')
                Code = '0x80070057'
            }
            UserData = [pscustomobject]@{
                Status = 'Failed'
                Component = 'CBS'
            }
        })
        $result.Findings = @($finding)
        $out = Join-Path $TestDrive 'reports-structured'
        Export-LogVerdictReport -Result $result -OutputDir $out -Format Json | Out-Null
        $json = Get-Content -LiteralPath (Join-Path $out 'LogVerdict-Report.json') -Raw
        $parsed = $json | ConvertFrom-Json
        $structured = $parsed.Findings[0].StructuredData

        @($structured.EventData.Image).Count | Should -Be 2
        @($structured.EventData.Image) | Should -Contain 'C:\Tools\one.exe'
        @($structured.EventData.Image) | Should -Contain 'C:\Tools\two.exe'
        $structured.EventData.Code | Should -BeExactly '0x80070057'
        $structured.UserData.Status | Should -BeExactly 'Failed'
        $structured.UserData.Component | Should -BeExactly 'CBS'
        $json | Should -Not -Match 'System\.Object\[\]'
    }

    It 'emits UTC ISO timestamps and ISO durations in the JSON report' {
        $result = $script:FakeResult | Select-Object *
        $finding = $script:FakeResult.Findings[0] | Select-Object *
        $finding | Add-Member -NotePropertyName Times -NotePropertyValue @(
            [datetime]'2026-07-01 00:00:00', [datetime]'2026-07-30 00:00:00'
        )
        $result.Findings = @($finding)
        $result | Add-Member -NotePropertyName Coverage -NotePropertyValue @([pscustomobject]@{
            Source='event'; Kind='channel'; Name='System'; Status='empty'; ObservedRecords=0; SkippedRecords=0
            WindowStart=[datetime]'2026-07-30 00:00:00'; WindowEnd=[datetime]'2026-07-31 00:00:00'
        })
        $out = Join-Path $TestDrive 'reports-utc'
        Export-LogVerdictReport -Result $result -OutputDir $out -Format Json | Out-Null
        $json = Get-Content -LiteralPath (Join-Path $out 'LogVerdict-Report.json') -Raw

        $json | Should -Not -Match '(?i)/Date\('
        $json | Should -Not -Match '"Duration"\s*:\s*\{'
        $json | Should -Not -Match '"Ticks"\s*:'
        $json | Should -Match '"ScanTime"\s*:\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z"'
        $json | Should -Match '"FirstSeen"\s*:\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z"'
        $json | Should -Match '"LastSeen"\s*:\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z"'
        $json | Should -Match '"Times"\s*:\s*\[\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z"'
        $json | Should -Match '"Duration"\s*:\s*"P[^"\r\n]+"'
        $json | Should -Match '"WindowStart"\s*:\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z"'
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

    It 'loads GUI, text, HTML, and CSV labels from locale resources with English fallback' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $previousLocale = $env:LOGVERDICT_LOCALE
            try {
                $env:LOGVERDICT_LOCALE = 'de-DE'
                $germanOverview = ([char]0x00dc) + 'bersicht'
                (Get-LVText -Key 'gui.nav.overview' -Default 'Overview') | Should -BeExactly $germanOverview
                (Get-LVText -Key 'missing.presentation.key' -Default 'English fallback') | Should -BeExactly 'English fallback'
                (Get-LVGuiXaml) | Should -Match ('Text="{0}"' -f $germanOverview)
                (ConvertTo-LVTextReport -Result $r) | Should -Match 'Computer'
                (ConvertTo-LVHtmlReport -Result $r) | Should -Match 'Befunde'
                (ConvertTo-LVCsvReport -Result $r) | Should -Match 'Scanzeit.*Computername'

                $env:LOGVERDICT_LOCALE = 'ja-JP'
                $japaneseOverview = ([char]0x6982) + ([char]0x8981)
                (Get-LVText -Key 'gui.nav.overview' -Default 'Overview') | Should -BeExactly $japaneseOverview
                (Get-LVGuiXaml) | Should -Match ('Text="{0}"' -f $japaneseOverview)

                $env:LOGVERDICT_LOCALE = 'fr-FR'
                (Get-LVText -Key 'gui.nav.overview' -Default 'Overview') | Should -BeExactly 'Overview'
            } finally {
                if ($null -eq $previousLocale) { Remove-Item Env:LOGVERDICT_LOCALE -ErrorAction SilentlyContinue }
                else { $env:LOGVERDICT_LOCALE = $previousLocale }
            }
        }
    }

    It 'HTML-encodes hostile report fields and contributed localization text' {
        InModuleScope LogVerdict -Parameters @{ sourceResult = $script:FakeResult } {
            param($sourceResult)
            $result = $sourceResult | Select-Object *
            $result.Version = '<script>alert(1)</script>'
            $result.DaysBack = '<svg onload=1>'
            $result.Elevated = '<img src=x>'
            $result | Add-Member -NotePropertyName CaseProfile -NotePropertyValue ([pscustomobject]@{
                profileId = ('a' * 64); name = '<b>case</b>'; sources = @(); notes = @()
                redaction = [pscustomobject]@{ requested = '<i>raw</i>' }
            }) -Force
            $result.CrashArtifacts = @([pscustomobject]@{
                Kind = '<img src=x onerror=1>'; When = Get-Date '2026-08-01'; Path = 'C:\logs\crash.wer'
            })
            $html = ConvertTo-LVHtmlReport -Result $result
            $html | Should -Not -Match '<script>alert\(1\)</script>|<svg onload=1>|<img src=x onerror=1>'
            $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;|&lt;svg onload=1&gt;|&lt;img src=x onerror=1&gt;'

            Mock Get-LVText {
                param($Key, $Default)
                if ($Key -eq 'report.heading.findings') { return '<img src=x onerror=1>' }
                return $Default
            }
            $localized = ConvertTo-LVLocalizedMarkup -Markup '<div>Findings</div>'
            $localized | Should -Not -Match '<img src=x onerror=1>'
            $localized | Should -Match '&lt;img src=x onerror=1&gt;'
        }
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
            $result.Coverage = @($result.Coverage) + @(
                [pscustomobject]@{
                    Source='reliability'; Kind='provider'; Name='Reliability Monitor'; Status='policy-disabled'
                    Reason='Configure Reliability WMI Providers is disabled'; Path=$null
                    WindowStart=(Get-Date).AddDays(-1); WindowEnd=(Get-Date); Cap=$null
                    ObservedRecords=0; SkippedRecords=0; RecordGap=$null; ParserError=$null
                    SizeBytes=$null; ParseMilliseconds=4; SHA256=$null; Origin='live'
                },
                [pscustomobject]@{
                    Source='reliability'; Kind='provider'; Name='Reliability Monitor'; Status='provider-absent'
                    Reason='ReliabilityMetricsProvider is not registered'; Path=$null
                    WindowStart=(Get-Date).AddDays(-1); WindowEnd=(Get-Date); Cap=$null
                    ObservedRecords=0; SkippedRecords=0; RecordGap=$null; ParserError=$null
                    SizeBytes=$null; ParseMilliseconds=4; SHA256=$null; Origin='live'
                }
            )
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
            @($csv | ConvertFrom-Csv | Where-Object RowType -eq 'coverage').Count | Should -Be 3
            @($csv | ConvertFrom-Csv | Where-Object RowType -eq 'health').Count | Should -Be 1
            $csv | Should -Match 'CoverageStatus'
            $csv | Should -Match 'HealthEventVersions'
            $manifest | Should -Match 'COVERAGE SOURCES'
            $manifest | Should -Match 'System: empty'
            $text | Should -Match 'reliability/provider Reliability Monitor - policy-disabled'
            $html | Should -Match 'reliability/provider - Reliability Monitor'
            $manifest | Should -Match 'Reliability Monitor: policy-disabled'
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
            $ecs = @((Export-LogVerdictStandard -Result $result -Format Ecs) | ForEach-Object { $_ | ConvertFrom-Json })[0]
            $ecs.logverdict.scan.performanceTelemetry | Should -BeTrue
            $ecs.logverdict.scan.performance[0].status | Should -BeExactly 'empty'
            $ecs.logverdict.scan.performance[0].elapsedMilliseconds | Should -Be 1200
        }
    }

    It 'surfaces stale rule guidance in text and HTML reports' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $result | Add-Member -NotePropertyName DatabaseFreshness -NotePropertyValue ([pscustomobject]@{
                DateBasis = 'UTC'; DefaultStaleAfterDays = 730; AsOf = [datetime]'2026-08-02'
                StaleRuleCount = 1; StaleRules = @([pscustomobject]@{
                    RuleId = 'LV-STALE-1'; Verified = '2024-01-01'; StaleAfterDays = 730
                })
            })
            $text = ConvertTo-LVTextReport -Result $result
            $html = ConvertTo-LVHtmlReport -Result $result
            $text | Should -Match 'STALE RULE GUIDANCE'
            $text | Should -Match 'LV-STALE-1'
            $html | Should -Match 'Stale rule guidance'
            $html | Should -Match 'LV-STALE-1'
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
            $formats = @('Ecs', 'Ocsf', 'Sarif', 'OpenTelemetry', 'Stix')
            foreach ($format in $formats) {
                if ($format -eq 'Ecs') {
                    $lines = @(Export-LogVerdictStandard -Result $result -Format Ecs)
                    $json = $lines -join [Environment]::NewLine
                    $roundTrip = $lines[0] | ConvertFrom-Json
                    $roundTrip.logverdict.adapter | Should -BeExactly 'ecs'
                } else {
                    $export = Export-LogVerdictStandard -Result $result -Format $format
                    $json = $export.Document | ConvertTo-Json -Depth 30
                    $roundTrip = $json | ConvertFrom-Json
                }
                if ($format -eq 'Sarif') {
                    $roundTrip.version | Should -BeExactly '2.1.0'
                    @($roundTrip.runs).Count | Should -Be 1
                } elseif ($format -eq 'Stix') {
                    $roundTrip.type | Should -BeExactly 'bundle'
                    $roundTrip.id | Should -Match '^bundle--[0-9a-f-]{36}$'
                } elseif ($format -ne 'Ecs') {
                    $roundTrip.schemaVersion | Should -BeExactly '1.0.0'
                    $roundTrip.adapter | Should -Not -BeNullOrEmpty
                }
                $json | Should -Match 'Acme'
                $json | Should -Match 'high'
                if ($format -ne 'Stix') { $json | Should -Match 'coverage' }
            }
            $ecs = @((Export-LogVerdictStandard -Result $result -Format Ecs) | ForEach-Object { $_ | ConvertFrom-Json })[0]
            $ecs.logverdict.finding.event.provider | Should -BeExactly 'Acme'
            $ecs.logverdict.rule.confidence | Should -BeExactly 'high'
            $ecs.logverdict.coverage[0].status | Should -BeExactly 'empty'
            $ocsf = (Export-LogVerdictStandard -Result $result -Format Ocsf).Document
            $ocsf.evidence[0].unmapped.logverdict.finding.key | Should -BeExactly 'Acme/99'
            $otel = (Export-LogVerdictStandard -Result $result -Format OpenTelemetry).Document
            @($otel.resourceLogs[0].scopeLogs[0].logRecords[0].attributes.key) | Should -Contain 'logverdict.event.provider'
            $stix = (Export-LogVerdictStandard -Result $result -Format Stix).Document
            @($stix.objects | Where-Object type -eq 'observed-data').Count | Should -Be 1
            ($stix.objects | Where-Object type -eq 'report').x_logverdict.schemaVersion | Should -BeExactly '1.0.0'
            ($stix.objects | Where-Object type -eq 'report').x_logverdict.coverage[0].status | Should -BeExactly 'empty'
            $path = Join-Path $TestDrive 'adapters\ecs.json'
            $written = Export-LogVerdictStandard -Result $result -Format Ecs -Path $path
            $written.Path | Should -BeExactly $path
            (Get-Content -LiteralPath $path | Select-Object -First 1 | ConvertFrom-Json).logverdict.adapter | Should -BeExactly 'ecs'
        }
    }

    It 'projects user templates and rejects append mode for single documents' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $lineTemplatePath = Join-Path $TestDrive 'finding-template.json'
            $lineTemplate = [ordered]@{
                schemaVersion = 1
                id = 'FindingLine'
                kind = 'line'
                mediaType = 'application/x-ndjson'
                source = 'findings'
                recordType = 'finding'
                projection = [ordered]@{
                    key = [ordered]@{ '$path' = 'key' }
                    provider = [ordered]@{ '$path' = 'event.provider' }
                    verdict = '$verdict'
                    text = [ordered]@{ '$coalesce' = @('$plain', '$title') }
                    actionable = [ordered]@{ '$equals' = @('$verdict', 'actionable') }
                    version = [ordered]@{ '$rootPath' = 'context.schemaVersion' }
                }
            }
            $lineTemplate | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $lineTemplatePath -Encoding UTF8
            $linePath = Join-Path $TestDrive 'out\findings.jsonl'

            $first = Export-LogVerdictStandard -Result ($r | Select-Object *) -Format FindingLine `
                -TemplatePath $lineTemplatePath -Path $linePath
            $first.TemplateName | Should -BeExactly 'FindingLine'
            $first.LineCount | Should -Be 1
            $record = Get-Content -LiteralPath $linePath | ConvertFrom-Json
            $record.recordType | Should -BeExactly 'finding'
            $record.key | Should -BeExactly 'Acme/99'
            $record.provider | Should -BeExactly 'Acme'
            $record.actionable | Should -BeTrue
            $record.version | Should -BeExactly '1.0.0'

            $second = Export-LogVerdictStandard -Result ($r | Select-Object *) -Format FindingLine `
                -TemplatePath $lineTemplatePath -Path $linePath -Append
            $second.Appended | Should -BeTrue
            @((Get-Content -LiteralPath $linePath)).Count | Should -Be 2

            {
                Export-LogVerdictStandard -Result ($r | Select-Object *) -Format Sarif -Path $linePath -Append
            } | Should -Throw '*single document*append mode*line-oriented*'
        }
    }

    It 'pins reserved templates, reports canonical ids, and keeps registry fallback explicit' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $standalonePath = Join-Path $TestDrive 'canonical-template.json'
            [ordered]@{
                schemaVersion = 1; id = 'FindingLine'; kind = 'line'; projection = [ordered]@{
                    key = [ordered]@{ '$path' = 'key' }
                }
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $standalonePath -Encoding UTF8
            $canonical = Export-LogVerdictStandard -Result $result -Format findingline -TemplatePath $standalonePath -Path (Join-Path $TestDrive 'canonical.jsonl')
            $canonical.Format | Should -BeExactly 'FindingLine'
            $canonical.TemplateName | Should -BeExactly 'FindingLine'

            $reservedPath = Join-Path $TestDrive 'reserved-template.json'
            [ordered]@{
                schemaVersion = 1; name = 'LogVerdict.ExportTemplates'; templates = @(
                    [ordered]@{ id = 'Ecs'; kind = 'single'; projection = 'builtin:sarif' }
                )
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reservedPath -Encoding UTF8
            { Get-LVStandardTemplate -Format Ecs -Path $reservedPath } |
                Should -Throw '*reserved*projection*'

            $singleRegistryPath = Join-Path $TestDrive 'single-registry.json'
            [ordered]@{
                schemaVersion = 1; name = 'LogVerdict.ExportTemplates'; templates = @(
                    [ordered]@{ id = 'Only'; kind = 'single'; projection = [ordered]@{ value = 'ok' } }
                )
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $singleRegistryPath -Encoding UTF8
            $warning = & {
                $captured = @()
                try { Get-LVStandardTemplate -Format Missing -Path $singleRegistryPath -WarningVariable captured } catch { $null = $_ }
                $captured
            }
            { Get-LVStandardTemplate -Format Missing -Path $singleRegistryPath } |
                Should -Throw '*No export template named*'
            ($warning -join ' ') | Should -Match 'Missing.*Only.*fallback'
        }
    }

    It 'bounds template evaluation and rejects operator objects with extra keys' {
        InModuleScope LogVerdict {
            $scope = [pscustomobject]@{
                key = 'value'
                root = [pscustomobject]@{ safe = 'ok' }
            }
            $map = [pscustomobject]@{
                '$map' = [pscustomobject]@{
                    path = 'items'
                    projection = [pscustomobject]@{ value = '$item' }
                }
            }
            $scope | Add-Member -NotePropertyName items -NotePropertyValue @('one', 'two', 'three')
            { ConvertTo-LVTemplateValue -Value $map -Scope $scope -Budget (New-LVTemplateBudget -MaxNodes 2) } |
                Should -Throw '*ExportTemplateBudgetExceeded*nodes*'
            $pathExpression = [pscustomobject]@{ '$path' = 'items' }
            { ConvertTo-LVTemplateValue -Value $pathExpression -Scope $scope -Budget (New-LVTemplateBudget -MaxNodes 2) } |
                Should -Throw '*ExportTemplateBudgetExceeded*nodes*'

            $depthBudget = New-LVTemplateBudget -MaxDepth 1
            $nested = [pscustomobject]@{ outer = [pscustomobject]@{ inner = 'value' } }
            { ConvertTo-LVTemplateValue -Value $nested -Scope $scope -Budget $depthBudget } |
                Should -Throw '*ExportTemplateBudgetExceeded*depth*'

            $clockBudget = New-LVTemplateBudget -MaxMilliseconds 1000
            $clockBudget.StartedUtc = [datetime]::UtcNow.AddSeconds(-5)
            { ConvertTo-LVTemplateValue -Value 'value' -Scope $scope -Budget $clockBudget } |
                Should -Throw '*ExportTemplateBudgetExceeded*wall clock*'

            $extra = [pscustomobject]@{ '$path' = 'key'; extra = 'must reject' }
            { ConvertTo-LVTemplateValue -Value $extra -Scope $scope } |
                Should -Throw '*one operator and no extra keys*'
            $extraDictionary = [ordered]@{ '$path' = 'key'; extra = 'must reject' }
            { ConvertTo-LVTemplateValue -Value $extraDictionary -Scope $scope } |
                Should -Throw '*one operator and no extra keys*'
            (ConvertTo-LVTemplateValue -Value ([pscustomobject]@{ '$rootPath' = 'model' }) -Scope $scope) |
                Should -BeNullOrEmpty
        }
    }

    It 'rejects oversized template files before parsing' {
        InModuleScope LogVerdict {
            $path = Join-Path $TestDrive 'oversized-template.json'
            $bytes = New-Object byte[] ($script:LVStandardTemplateMaxBytes + 1)
            [IO.File]::WriteAllBytes($path, $bytes)
            { Get-LVStandardTemplate -Format Ecs -Path $path } |
                Should -Throw '*size limit*'
        }
    }

    It 'scopes OCSF output to normalized evidence instead of a detection class' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $document = (Export-LogVerdictStandard -Result ($r | Select-Object *) -Format Ocsf).Document
            $document.contract | Should -BeExactly 'normalized-evidence'
            @($document.metadata.profiles) | Should -Contain 'logverdict.normalized-evidence'
            @($document.evidence).Count | Should -Be 1
            $record = $document.evidence[0]
            $record.time | Should -BeOfType [long]
            $record.unmapped.logverdict.recordType | Should -BeExactly 'normalized-evidence'
            $record.unmapped.logverdict.finding.key | Should -BeExactly 'Acme/99'
            $record.unmapped.logverdict.finding.verdict | Should -BeExactly 'actionable'
            $record.unmapped.logverdict.finding.event.provider | Should -BeExactly 'Acme'
            @($record.PSObject.Properties.Name) | Should -Not -Contain 'class_uid'
            @($record.PSObject.Properties.Name) | Should -Not -Contain 'category_uid'
            @($document.unmapped.logverdict.PSObject.Properties.Name) | Should -Contain 'advisories'
            @($document.unmapped.logverdict.PSObject.Properties.Name) | Should -Contain 'correlations'
            $json = $document | ConvertTo-Json -Depth 30
            $json | Should -Not -Match 'Detection Finding|"class_uid"\s*:\s*2004|"category_uid"\s*:\s*2'
        }
    }

    It 'exports SARIF rules, verdict levels, fingerprints, and source locations' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $cbs = [pscustomobject]@{
                Key='CBS/test'; Source='textlog'; Channel='CBS'; Provider='CBS'; Id=0; Count=2
                FirstSeen=(Get-Date '2026-07-30 10:00:00'); LastSeen=(Get-Date '2026-07-30 10:01:00')
                Verdict='actionable'; Title='CBS failure'; Plain='CBS failure text'; Why='why'; Action='action'
                RuleId='LV-0001'; Confidence='high'; RecordId=17; Samples=@('CBS failure'); Reference=$null; References=@()
            }
            $dism = [pscustomobject]@{
                Key='DISM/test'; Source='textlog'; Channel='DISM'; Provider='DISM'; Id=0; Count=1
                FirstSeen=(Get-Date '2026-07-30 11:00:00'); LastSeen=(Get-Date '2026-07-30 11:00:00')
                Verdict='investigate'; Title='DISM failure'; Plain='DISM failure text'; Why='why'; Action='action'
                RuleId='LV-0002'; Confidence='medium'; RecordId=23; Samples=@('DISM failure'); Reference=$null; References=@()
            }
            $result.Findings = @($r.Findings + $cbs + $dism)
            $sarif = (Export-LogVerdictStandard -Result $result -Format Sarif).Document
            $sarif.'$schema' | Should -Match 'sarif-schema-2\.1\.0\.json$'
            $sarif.version | Should -BeExactly '2.1.0'
            $run = $sarif.runs[0]
            $run.tool.driver.name | Should -BeExactly 'LogVerdict'
            $database = Get-LogVerdictDatabase
            $activeRules = @($database.rules | Where-Object { Test-LVRuleActive -Rule $_ })
            $expectedRuleIds = @($activeRules.id) + @($result.Findings.RuleId | Where-Object { $_ }) | Sort-Object -Unique
            @($run.tool.driver.rules).Count | Should -Be $expectedRuleIds.Count
            @($run.tool.driver.rules.id) | Should -Contain 'LV-0001'
            @($run.tool.driver.rules.id) | Should -Contain 'LV-0002'
            @($run.results).Count | Should -Be 3

            $eventResult = @($run.results | Where-Object { $_.properties.'logverdict.channel' -eq 'System' })[0]
            $eventResult.level | Should -BeExactly 'error'
            $eventResult.partialFingerprints.'logverdict.signature' | Should -BeExactly 'Acme/99'
            $eventResult.locations[0].logicalLocations[0].fullyQualifiedName | Should -Match 'event/System/Acme/99'

            $cbsResult = @($run.results | Where-Object { $_.properties.'logverdict.channel' -eq 'CBS' })[0]
            $cbsResult.locations[0].logicalLocations[0].fullyQualifiedName | Should -Match 'textlog/CBS/CBS/0'
            @($cbsResult.locations[0].PSObject.Properties.Name) | Should -Not -Contain 'physicalLocation'

            $dismResult = @($run.results | Where-Object { $_.properties.'logverdict.channel' -eq 'DISM' })[0]
            $dismResult.level | Should -BeExactly 'warning'
            $dismResult.locations[0].logicalLocations[0].fullyQualifiedName | Should -Match 'textlog/DISM/DISM/0'
            @($dismResult.locations[0].PSObject.Properties.Name) | Should -Not -Contain 'physicalLocation'
            $json = $sarif | ConvertTo-Json -Depth 30
            $roundTrip = $json | ConvertFrom-Json
            $roundTrip.runs[0].tool.driver.rules[0].id | Should -Not -BeNullOrEmpty
            $roundTrip.runs[0].results[0].partialFingerprints.'logverdict.signature' | Should -Not -BeNullOrEmpty
        }
    }

    It 'maps each standard adapter field-by-field instead of trusting an envelope' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $finding = $r.Findings[0] | Select-Object *
            $finding | Add-Member -NotePropertyName LevelName -NotePropertyValue 'Error' -Force
            $finding | Add-Member -NotePropertyName WorstLevel -NotePropertyValue 2 -Force
            $finding | Add-Member -NotePropertyName SourcePath -NotePropertyValue 'C:\Windows\Logs\CBS\CBS.log' -Force
            $finding | Add-Member -NotePropertyName SourceLine -NotePropertyValue 42 -Force
            $finding.RuleId = 'LOCAL-HISTORIC'
            $result.Findings = @($finding)

            $ecsLines = @(Export-LogVerdictStandard -Result $result -Format Ecs)
            $ecsLines.Count | Should -Be 1
            $ecs = $ecsLines[0] | ConvertFrom-Json
            @($ecs.PSObject.Properties.Name) | Should -Not -Contain 'findings'
            $ecs.log.level | Should -BeExactly 'error'
            @($ecs.event.PSObject.Properties.Name) | Should -Not -Contain 'count'
            @($ecs.rule.PSObject.Properties.Name) | Should -Not -Contain 'confidence'
            $ecs.logverdict.rule.confidence | Should -BeExactly 'high'

            $sarif = (Export-LogVerdictStandard -Result $result -Format Sarif).Document
            $sarif.'$schema' | Should -Match '/cos02/schemas/sarif-schema-2\.1\.0\.json$'
            $sarif.runs[0].tool.driver.rules.id | Should -Contain 'LOCAL-HISTORIC'
            $sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri | Should -BeExactly 'file:///C:/Windows/Logs/CBS/CBS.log'
            $sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine | Should -Be 42
            $sarif.runs[0].invocations[0].executionSuccessful | Should -BeFalse

            $stix1 = (Export-LogVerdictStandard -Result $result -Format Stix).Document
            $stix2 = (Export-LogVerdictStandard -Result $result -Format Stix).Document
            $stix1.PSObject.Properties.Name | Should -Not -Contain 'spec_version'
            (@($stix1.objects | ForEach-Object id) -join '|') | Should -Be ((@($stix2.objects | ForEach-Object id) -join '|'))
            ($stix1.objects | Where-Object type -eq 'identity').identity_class | Should -BeExactly 'system'
            $observed = @($stix1.objects | Where-Object type -eq 'observed-data')[0]
            $observed.created | Should -Not -BeNullOrEmpty
            $observed.modified | Should -Not -BeNullOrEmpty
            [int64]$observed.number_observed | Should -BeGreaterOrEqual 1
            @($observed.object_refs).Count | Should -Be 1

            $otel = (Export-LogVerdictStandard -Result $result -Format OpenTelemetry).Document
            $record = $otel.resourceLogs[0].scopeLogs[0].logRecords[0]
            $record.timeUnixNano | Should -BeOfType [string]
            $record.observedTimeUnixNano | Should -BeOfType [string]
            $record.droppedAttributesCount | Should -BeOfType [int32]
            $record.timeUnixNano | Should -Not -BeExactly '0'
            foreach ($attribute in @($record.attributes | Where-Object { $_.value.PSObject.Properties['intValue'] })) {
                $attribute.value.intValue | Should -BeOfType [string]
            }

            $undated = $finding | Select-Object *
            $undated.FirstSeen = $null; $undated.LastSeen = $null
            $result.Findings = @($undated)
            $undatedRecord = ((Export-LogVerdictStandard -Result $result -Format OpenTelemetry).Document).resourceLogs[0].scopeLogs[0].logRecords[0]
            @($undatedRecord.PSObject.Properties.Name) | Should -Not -Contain 'timeUnixNano'
        }
    }

    It 'keeps every machine-readable standard timestamp in RFC3339 UTC form' {
        $result = $script:FakeResult | Select-Object *
        $result | Add-Member -NotePropertyName Coverage -NotePropertyValue @([pscustomobject]@{
            Source='event'; Kind='channel'; Name='System'; Status='empty'; Reason='No matching event'
            Path=$null; WindowStart=[datetime]'2026-07-30 00:00:00'; WindowEnd=[datetime]'2026-07-31 00:00:00'
            Cap=20; ObservedRecords=0; SkippedRecords=0; RecordGap=$null; ParserError=$null
            SizeBytes=$null; ParseMilliseconds=4; SHA256=$null; Origin='live'
        })
        $timestampPattern = '(?im)"(?:generatedAt|scanTime|scanTimes|firstObserved|lastObserved|windowStart|windowEnd|oldestRecord|timestampUtc|endTimestampUtc|startTimeUtc|endTimeUtc|firstDetectionTimeUtc|lastDetectionTimeUtc)"\s*:\s*"([^"]+)"'
        foreach ($format in @('Ecs', 'Ocsf', 'Sarif', 'OpenTelemetry', 'Stix')) {
            $documents = if ($format -eq 'Ecs') {
                @(Export-LogVerdictStandard -Result $result -Format Ecs | ForEach-Object { $_ | ConvertFrom-Json })
            } else {
                @((Export-LogVerdictStandard -Result $result -Format $format).Document)
            }
            foreach ($document in $documents) {
                $json = $document | ConvertTo-Json -Depth 30
                $json | Should -Not -Match '(?i)/Date\('
                $timestampMatches = [regex]::Matches($json, $timestampPattern)
                $timestampMatches.Count | Should -BeGreaterThan 0 -Because "$format must carry machine-readable timestamps"
                foreach ($match in $timestampMatches) {
                    $match.Groups[1].Value | Should -Match 'Z$' -Because "$format timestamps must be UTC"
                }
            }
        }

        $lines = @(Export-LogVerdictStandard -Result $result -Format Jsonl)
        $lines.Count | Should -BeGreaterThan 0
        foreach ($line in $lines) {
            $line | Should -Not -Match '(?i)/Date\('
            foreach ($match in [regex]::Matches($line, $timestampPattern)) {
                $match.Groups[1].Value | Should -Match 'Z$' -Because 'JSONL timestamps must be UTC'
            }
        }
    }

    It 'streams a redacted JSONL timeline with stable records and no BOM' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $finding = $r.Findings[0] | Select-Object *
            $finding | Add-Member -NotePropertyName Samples -NotePropertyValue @('raw HOST-9 C:\Users\bob\secret.txt')
            $finding | Add-Member -NotePropertyName RecordId -NotePropertyValue 'evt-99'
            $finding | Add-Member -NotePropertyName RecordIds -NotePropertyValue @('evt-99', 'evt-100')
            $result.Findings = @($finding)
            $result.MachineName = 'HOST-9'
            $result | Add-Member -NotePropertyName Redacted -NotePropertyValue $false
            $result | Add-Member -NotePropertyName Coverage -NotePropertyValue @([pscustomobject]@{
                Source='event'; Kind='channel'; Name='C:\Users\bob\System.evtx'; Status='readable'
                Reason=$null; Path='C:\Users\bob\System.evtx'; WindowStart=(Get-Date '2026-07-01')
                WindowEnd=(Get-Date '2026-07-30'); Cap=20000; ObservedRecords=12; SkippedRecords=0
                RecordGap=$null; ParserError=$null; SizeBytes=512; ParseMilliseconds=4; SHA256=('a' * 64); Origin='live'
            })

            $path = Join-Path $TestDrive 'timeline\LogVerdict-Timeline.jsonl'
            $written = Export-LogVerdictStandard -Result $result -Format Jsonl -Path $path -Redact
            $bytes = [System.IO.File]::ReadAllBytes($path)
            ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse
            $lines = @(Get-Content -LiteralPath $path)
            $written.LineCount | Should -Be $lines.Count
            $records = @($lines | ForEach-Object { $_ | ConvertFrom-Json })
            $records[0].recordType | Should -BeExactly 'metadata'
            $records[0].format | Should -BeExactly 'LogVerdict.Timeline'
            $eventRecord = $records | Where-Object recordType -eq 'event' | Select-Object -First 1
            $findingRecord = $records | Where-Object recordType -eq 'finding' | Select-Object -First 1
            $eventRecord.recordId | Should -BeExactly 'evt-99'
            @($eventRecord.recordIds) | Should -Contain 'evt-100'
            $findingRecord.provenance.ruleId | Should -BeExactly 'T-1'
            $findingRecord.privacy.state | Should -BeExactly 'redacted'
            ($records | ConvertTo-Json -Depth 30) | Should -Not -Match 'HOST-9|C:\\\\Users\\\\bob'

            $pipeline = @(Export-LogVerdictStandard -Result $result -Format Jsonl -Redact)
            $pipeline.Count | Should -Be $records.Count
            $pipeline | ForEach-Object { $_ | ConvertFrom-Json | Should -Not -BeNullOrEmpty }
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
            $line = @(Export-LogVerdictStandard -Result $result -Format Ecs -Redact)[0]
            $document = $line | ConvertFrom-Json
            $json = $document | ConvertTo-Json -Depth 30
            $document.logverdict.privacy.redacted | Should -BeTrue
            $document.logverdict.privacy.rawEvidenceIncluded | Should -BeFalse
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

    It 'renders unsafe finding URIs as inert text instead of links' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $finding = $r.Findings[0] | Select-Object *
            $finding | Add-Member -NotePropertyName Sources -NotePropertyValue @(
                [pscustomobject]@{ uri = 'javascript:alert(1)'; author = 'unsafe' },
                [pscustomobject]@{ uri = 'https://example.invalid/good'; author = 'safe' }
            ) -Force
            $finding | Add-Member -NotePropertyName Reference -NotePropertyValue 'file:///C:/Windows/hosts' -Force
            $result.Findings = @($finding)

            $html = ConvertTo-LVHtmlReport -Result $result
            $html | Should -Match 'javascript:alert\(1\)'
            $html | Should -Match 'file:///C:/Windows/hosts'
            $html | Should -Match 'href="https://example.invalid/good"'
            $html | Should -Not -Match 'href="javascript:'
            $html | Should -Not -Match 'href="file:'
            $html | Should -Match 'not a link: only http/https URIs are allowed'
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

    It 'renders an accessible report structure with non-colour verdict cues' {
        InModuleScope LogVerdict -Parameters @{ r = $script:FakeResult } {
            param($r)
            $result = $r | Select-Object *
            $finding = $r.Findings[0] | Select-Object *
            $finding.RuleId = 'T-<rule>&'
            $finding.Confidence = 'high&'
            $finding | Add-Member -NotePropertyName Verified -NotePropertyValue '2026-08-02 <UTC>' -Force
            $result.Findings = @($finding)
            $result | Add-Member -NotePropertyName Correlations -NotePropertyValue @([pscustomobject]@{
                Verdict='critical'; Title='Together'; RuleIds=@('T-1'); Type='co-occurrence'; Timespan='10m'
                Windows=@([pscustomobject]@{ Start=[datetime]'2026-07-30 10:00:00'; End=[datetime]'2026-07-30 10:01:00'; Occurrences=@() })
                InvolvedKeys=@('Acme/99'); Plain='plain'; Why='why'; Action='action'; FalsePositives=@()
            }) -Force

            $html = ConvertTo-LVHtmlReport -Result $result
            $html | Should -Match '<nav aria-label="Report navigation"><a class="skip-link" href="#finding-list">Skip to findings</a>'
            $html | Should -Match '<main id="main-content" tabindex="-1">'
            $html | Should -Match '<section aria-labelledby="findings-heading"><h2 id="findings-heading">'
            $html | Should -Match '<article class="f finding" data-verdict="actionable"'
            $html | Should -Match '<h3 id="finding-heading-1"><span class="badge" data-verdict="actionable"'
            $html | Should -Match 'Verdict: ACTIONABLE'
            $html | Should -Match 'data-rule-id="T-&lt;rule&gt;&amp;"'
            $html | Should -Match 'data-confidence="high&amp;"'
            $html | Should -Match 'data-verified="2026-08-02 &lt;UTC&gt;"'
            $html | Should -Match 'rule T-&lt;rule&gt;&amp;'
            $html | Should -Match 'confidence high&amp;'
            $html | Should -Match 'verified 2026-08-02 &lt;UTC&gt;'
            $html | Should -Match '<h3 id="correlation-heading-1"><span class="badge" data-verdict="critical"'
            $html | Should -Not -Match '<div class="h"><span class="v"'
            $html | Should -Not -Match '<h2><span class="badge"'
            $html | Should -Match '@media\(prefers-color-scheme:light\)'
            $html | Should -Match '@media\(forced-colors:active\)'
            $html | Should -Match '@media\(prefers-reduced-motion:reduce\)'
            $html | Should -Match '\.badge\[data-verdict="actionable"\]:before'
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

    It 'does not retain unreachable controls or a hidden log sink' {
        InModuleScope LogVerdict {
            $xaml = Get-LVGuiXaml
            $dead = @(
                'TxtMachine', 'ChipElevation', 'TxtElevation',
                'TxtDays', 'ChkAllChannels', 'ChkSkipText', 'ChkIncludeBenign', 'BtnScan', 'BtnCancel',
                'PnlSummary', 'ChipCritical', 'ChipActionable', 'ChipInvestigate', 'ChipUnknown',
                'ChipInformational', 'ChipBenign', 'TxtRecords', 'TxtSignatures', 'TxtReduction', 'TxtRules',
                'PnlCoverage', 'LstCoverage', 'PnlCrash', 'LstCrash', 'PnlCorrelation', 'LstCorrelation',
                'RowLog', 'BtnToggleLog', 'TxtLastLine', 'TxtLog'
            )
            foreach ($name in $dead) {
                $xaml | Should -Not -Match ('x:Name="{0}"' -f [regex]::Escape($name))
                $script:LVGuiElement | Should -Not -Contain $name
            }
            $script:LVGuiSortKey.Keys | Should -Not -Contain 'WHERE FROM'
            $xaml | Should -Not -Match 'Width="0"'
        }
        $gui = Get-LVGuiSourceText
        $gui | Should -Not -Match '\$ui\.(TxtLog|BtnToggleLog|RowLog|TxtLastLine)'
    }

    It 'keeps unsafe references as inert GUI text and guards navigation' {
        InModuleScope LogVerdict {
            $buckets = Get-LVGuiReferenceBucket -Reference @(
                'https://example.invalid/good',
                'javascript:alert(1)',
                'file:///C:/Windows/hosts',
                '\\server\share\rule.html',
                'ms-settings:privacy'
            )
            @($buckets.Allowed) | Should -Be @('https://example.invalid/good')
            @($buckets.Blocked).Count | Should -Be 4
            $buckets.Blocked -join ' ' | Should -Match 'javascript:alert(1)|file:///C:/Windows/hosts|\\server\\share\\rule.html|ms-settings:privacy'
        }
        $gui = Get-LVGuiSourceText
        $gui | Should -Match 'Get-LVAllowedUriProblem'
        $gui | Should -Match 'Start-Process -FilePath \$uri'
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
                DaysBack=14; AllChannels=$true; DiagnosticChannels=$true; SkipTextLogs=$true
                SkipReliability=$true; IncludeBenign=$true; IncludeLowConfidence=$true; NamedChannels='System, Application'
                DatabasePath='C:\rules\verdicts.json'; SuppressionPath='C:\rules\suppressions.json'; OutputDirectory='C:\reports'
                Redact=$true; IncludeEvidence=$true
                WindowWidth=1500.4; WindowHeight=820.4
            }
            Save-LVGuiSetting -Settings $value -Path $path | Should -BeTrue

            $read = Get-LVGuiSetting -Path $path
            $read.DaysBack | Should -Be 14
            $read.AllChannels | Should -BeTrue
            $read.DiagnosticChannels | Should -BeTrue
            $read.SkipTextLogs | Should -BeTrue
            $read.SkipReliability | Should -BeTrue
            $read.IncludeBenign | Should -BeTrue
            $read.IncludeLowConfidence | Should -BeTrue
            $read.NamedChannels | Should -BeExactly 'System, Application'
            $read.DatabasePath | Should -BeExactly 'C:\rules\verdicts.json'
            $read.SuppressionPath | Should -BeExactly 'C:\rules\suppressions.json'
            $read.OutputDirectory | Should -BeExactly 'C:\reports'
            $read.Redact | Should -BeTrue
            $read.IncludeEvidence | Should -BeTrue
            $read.WindowWidth | Should -Be 1500
            $read.WindowHeight | Should -Be 820

            $bytes = [IO.File]::ReadAllBytes($path)
            ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) |
                Should -BeFalse
        }
    }

    It 'resets persisted options to safe first-launch defaults atomically' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive } {
            param($Root)
            $path = Join-Path $Root 'prefs/settings.json'
            Save-LVGuiSetting -Settings ([pscustomobject]@{
                DaysBack=365; AllChannels=$true; DiagnosticChannels=$true; SkipTextLogs=$true
                SkipReliability=$true; IncludeBenign=$true; IncludeLowConfidence=$true; NamedChannels='System'
                DatabasePath='C:\rules.json'; OutputDirectory='C:\reports'; Redact=$true; IncludeEvidence=$true
                WindowWidth=2200; WindowHeight=1200
            }) -Path $path | Should -BeTrue

            Reset-LVGuiSetting -Path $path | Should -BeTrue
            $read = Get-LVGuiSetting -Path $path
            $read.DaysBack | Should -Be 30
            $read.AllChannels | Should -BeFalse
            $read.DiagnosticChannels | Should -BeFalse
            $read.SkipTextLogs | Should -BeFalse
            $read.SkipReliability | Should -BeFalse
            $read.IncludeBenign | Should -BeFalse
            $read.IncludeLowConfidence | Should -BeFalse
            $read.NamedChannels | Should -BeExactly ''
            $read.DatabasePath | Should -BeExactly ''
            $read.OutputDirectory | Should -BeExactly ''
            $read.Redact | Should -BeFalse
            $read.IncludeEvidence | Should -BeFalse
            $read.WindowWidth | Should -Be 1440
            $read.WindowHeight | Should -Be 800
        }
    }

    It 'loads an older v1 settings file with safe defaults for newer options' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive } {
            param($Root)
            $path = Join-Path $Root 'legacy/settings.json'
            New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
            '{"schemaVersion":1,"daysBack":21,"allChannels":false,"skipTextLogs":true,"includeBenign":false,"windowWidth":1440,"windowHeight":800}' |
                Set-Content -LiteralPath $path -Encoding UTF8

            $read = Get-LVGuiSetting -Path $path
            $read.DaysBack | Should -Be 21
            $read.DiagnosticChannels | Should -BeFalse
            $read.SkipReliability | Should -BeFalse
            $read.NamedChannels | Should -BeExactly ''
            $read.DatabasePath | Should -BeExactly ''
            $read.OutputDirectory | Should -BeExactly ''
            $read.Redact | Should -BeFalse
            $read.IncludeEvidence | Should -BeFalse
            $read.IncludeLowConfidence | Should -BeFalse
        }
    }

    It 'ignores malformed, future, and invalid settings instead of failing launch' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive } {
            param($Root)
            $path = Join-Path $Root 'bad-settings.json'
            foreach ($content in @(
                '{ definitely not json',
                '{"schemaVersion":2,"daysBack":30,"allChannels":false,"skipTextLogs":false,"includeBenign":false,"windowWidth":1440,"windowHeight":800}',
                '{"schemaVersion":1,"daysBack":0,"allChannels":"false","skipTextLogs":false,"includeBenign":false,"windowWidth":100,"windowHeight":100}',
                '{"schemaVersion":1,"daysBack":30,"allChannels":false,"skipTextLogs":false,"includeBenign":false,"diagnosticChannels":"false","windowWidth":1440,"windowHeight":800}'
            )) {
                Set-Content -LiteralPath $path -Value $content -Encoding UTF8
                $status = $null
                { Get-LVGuiSetting -Path $path -Status ([ref]$status) } | Should -Not -Throw
                $read = Get-LVGuiSetting -Path $path -Status ([ref]$status)
                $read | Should -BeNullOrEmpty
                $status.State | Should -BeIn @('invalid', 'unreadable')
                $status.Reason | Should -Not -BeNullOrEmpty
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
        $text = Get-LVGuiSourceText
        $text | Should -Match "PSBoundParameters\.ContainsKey\('DaysBack'\)"
        $text | Should -Match 'Get-LVGuiSetting'
        $text | Should -Match 'Save-LVGuiSetting'
        $text | Should -Match 'Reset-LVGuiSetting'
        $text | Should -Match 'BtnResetSettings'
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
        $text = Get-LVGuiSourceText
        foreach ($argument in @('Channel', 'AllChannels', 'DiagnosticChannels', 'SkipTextLogs',
                'SkipReliability', 'IncludeBenign', 'IncludeLowConfidence', 'DatabasePath', 'SuppressionPath')) {
            $text | Should -Match ("scanArgs\['{0}'\]|{0}\s*=" -f $argument) -Because "$argument must reach Invoke-LogVerdictScan"
        }
    }

    It 'wires report destination, redaction, and evidence choices into export' {
        $text = Get-LVGuiSourceText
        $text | Should -Match "exportArgs\['OutputDir'\]"
        $text | Should -Match 'Redact\s*=\s*\[bool\]\$ui\.ChkOverviewRedact\.IsChecked'
        $text | Should -Match 'IncludeEvidence\s*=\s*\[bool\]\$ui\.ChkOverviewEvidence\.IsChecked'
        $text | Should -Match 'AllowRawEvidence\s*=\s*\[bool\]'
        $xaml = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Private\50-LVGuiXaml.ps1') -Raw
        $xaml | Should -Match 'raw channels if unredacted'
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
    It 'builds a headless render projection without WPF controls' {
        InModuleScope LogVerdict {
            $finding = [pscustomobject]@{
                Key='event|System|7'; Source='event'; Channel='System'; Provider='Test'; Id=7
                Count=2; PerDay=1; LastSeen=(Get-Date); UndatedCount=0; SampleMessage='x'
                Verdict='investigate'; Title='T'; RuleId='LV-1'
            }
            $projection = Get-LVGuiRenderProjection -Result ([pscustomobject]@{
                Findings = @($finding)
                Correlations = @([pscustomobject]@{ Id='C-1'; InvolvedKeys=@('event|System|7') })
            })

            @($projection.FindingStore).Count | Should -Be 1
            @($projection.Rows).Count | Should -Be 1
            $projection.Rows[0].FindingIndex | Should -Be 0
            @($projection.Rows[0].CorrelationIds) | Should -BeExactly @('C-1')
            $projection.VerdictCounts.investigate | Should -Be 1
            @($projection.VerdictCounts.Keys).Count | Should -Be 6
            @($projection.CorrelationIdsByKey['event|System|7']) | Should -BeExactly @('C-1')
        }
    }

    It 'reveals a priority finding hidden by the active findings filters' {
        InModuleScope LogVerdict {
            $row = [pscustomobject]@{
                Verdict='actionable'; Title='Priority failure'; Source='event'; Channel='System'; Provider='Disk'; EventId='7'
                RuleStatus='stable'; CorrelationIds=@(); Haystack='priority failure on disk'
            }
            $ui = [pscustomobject]@{
                TxtStatus=[pscustomobject]@{ Text='' }
                TxtSearch=[pscustomobject]@{ Text='disk' }
                TxtSearchHint=[pscustomobject]@{ Visibility='Collapsed' }
            }
            $state = @{
                View=$null; Rows=@($row); FindingStore=@($row); Search='disk'
                Chips=@{ critical=$true; actionable=$false; investigate=$true; unknown=$true; informational=$true; benign=$true }
                StructuredFilters=@{ Source='event'; Channel=''; Provider='Disk'; EventId=''; Correlation=''; RuleStatus='' }
            }
            $chips = @{}
            foreach ($verdict in $script:LVVerdictDisplayOrder) {
                $chips[$verdict] = [pscustomobject]@{ IsChecked=$false }
            }
            $filters = @{}
            foreach ($kind in $state.StructuredFilters.Keys) {
                $filters[$kind] = [pscustomobject]@{ SelectedIndex=4 }
            }
            $context = [pscustomobject]@{
                Ui=$ui; State=$state; Window=[pscustomobject]@{}; StructuredFilterControl=$filters; ChipControl=$chips
                PageControl=@{}; NavControl=@{}; ActivityMaxLines=100; ActivityMaxCharacters=1000
            }

            $actions = New-LVGuiActions -Context $context
            (& $actions.RevealPriorityFinding $row) | Should -BeTrue
            $state.Search | Should -BeExactly ''
            @($state.Chips.Values | Where-Object { -not $_ }).Count | Should -Be 0
            @($state.StructuredFilters.Values | Where-Object { $_ }).Count | Should -Be 0
            $ui.TxtStatus.Text | Should -Match 'hidden by active filters; filters were cleared'
        }
    }

    It 'builds a redacted clipboard payload without retaining machine or account identifiers' {
        InModuleScope LogVerdict {
            $finding = [pscustomobject]@{
                Verdict='investigate'; Title='HOST-9 finding'; Key='event|System|7'; Count=2; PerDay=1
                LastSeen=(Get-Date).AddMinutes(-5); RuleId='LV-7'; Plain='Review HOST-9 activity'
                Why='Account jsmith saw C:\Users\jsmith\event.log'; Action='Check the event'
                References=@('https://example.invalid/HOST-9'); SampleMessage='HOST-9: jsmith opened C:\Users\jsmith\event.log'
            }
            $raw = ConvertTo-LVGuiClipboardText -Finding $finding -MachineName 'HOST-9' -UserName 'jsmith'
            $raw.Text | Should -Match 'HOST-9|jsmith'
            $raw.Redacted | Should -BeFalse
            $raw.Status | Should -Match 'unredacted'

            $redacted = ConvertTo-LVGuiClipboardText -Finding $finding -Redact `
                -MachineName 'HOST-9' -UserName 'jsmith'
            $redacted.Text | Should -Not -Match 'HOST-9|jsmith|C:\\Users\\jsmith'
            $redacted.Text | Should -Match '<MACHINE>|<USER>'
            $redacted.Redacted | Should -BeTrue
            $redacted.Status | Should -Match 'identifiers redacted'
        }
    }

    It 'routes the clipboard handler through the redaction toggle and states the copied mode' {
        $gui = Get-LVGuiSourceText
        $gui | Should -Match 'ConvertTo-LVGuiClipboardText'
        $gui | Should -Match 'Redact:\(\[bool\]\$ui\.ChkOverviewRedact\.IsChecked\)'
        $gui | Should -Match '\$clipboard\.Status'
        $gui | Should -Match 'ConvertTo-LVTicketSummary'
        $gui | Should -Match 'BtnCopySummary'
        $xaml = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Private\50-LVGuiXaml.ps1') -Raw
        $xaml | Should -Match 'Redact reports and clipboard'
        $xaml | Should -Match 'Copy summary for ticket'
    }

    It 'redacts the shared ticket summary without retaining identifiers' {
        InModuleScope LogVerdict {
            $result = [pscustomobject]@{
                Tool='LogVerdict'; Version='0.8.2'; MachineName='HOST-9'; ScanTime=(Get-Date)
                DaysBack=30; WorstVerdict='actionable'; DatabaseName='test'; DatabaseDate='2026-08-03'
                Reduction=[pscustomobject]@{ RecordCount=10; SignatureCount=2; Ratio=5 }
                Findings=@([pscustomobject]@{
                    Verdict='actionable'; Title='HOST-9 failure'; Action='Check C:\Users\jsmith\event.log'
                    Count=4; PerDay=1; LastSeen=(Get-Date); Key='event|System|7'
                }); CoverageNotes=@('Access to HOST-9 was partial'); Coverage=@(); HealthProfiles=@()
                HorizonWarning=$null
            }
            $summary = ConvertTo-LVTicketSummary -Result $result -Redact -MachineName 'HOST-9' -UserName 'jsmith'
            $summary | Should -Not -Match 'HOST-9|jsmith|C:\\Users\\jsmith'
            $summary | Should -Match '<MACHINE>|<USER>'
            $summary.Length | Should -BeLessThan 25000000
        }
    }

    It 'gives the Overview a bounded timing hint for each look-back tier' {
        InModuleScope LogVerdict {
            Get-LVGuiScanTimingHint -DaysBack 1 | Should -BeExactly 'Typical 1-day scan: under 30 seconds. All-channel sweeps can take longer.'
            Get-LVGuiScanTimingHint -DaysBack 7 | Should -BeExactly 'Typical 7-day scan: 30-90 seconds. All-channel sweeps can take longer.'
            Get-LVGuiScanTimingHint -DaysBack 30 | Should -BeExactly 'Typical 30-day scan: 1-3 minutes. All-channel sweeps can take longer.'
            Get-LVGuiScanTimingHint -DaysBack 3650 | Should -BeExactly 'Typical 3650-day scan: 2-5 minutes. All-channel sweeps can take longer.'
        }
    }

    It 'keeps cancellation visible, timed, and explicit about partial coverage' {
        $root = Split-Path $PSScriptRoot -Parent
        $gui = Get-LVGuiSourceText
        $xaml = Get-Content -LiteralPath (Join-Path $root 'Private/50-LVGuiXaml.ps1') -Raw
        $hostFile = Get-Content -LiteralPath (Join-Path $root 'Private/51-LVGuiHost.ps1') -Raw

        $xaml | Should -Match 'x:Name="BtnOverviewCancel"'
        $xaml | Should -Match 'x:Name="TxtOverviewTimingHint"'
        $gui | Should -Match '\$state\.ScanStartedAt\s*=\s*Get-Date'
        $gui | Should -Match 'Running for \{0:N1\}s'
        $gui | Should -Match 'Stop-LVScanJob -Job \$state\.Job'
        $gui | Should -Match 'coverage is partial and no report was saved'
        $gui | Should -Match 'BtnOverviewCancel\.Add_Click'
        $gui | Should -Match '\$window\.Add_Closing'
        $hostFile | Should -Match 'Get-LVGuiScanTimingHint'
    }

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

    It 'filters rows by structured source metadata without copying the finding graph' {
        InModuleScope LogVerdict {
            $findings = @(
                [pscustomobject]@{
                    Key='Disk/7'; Source='event'; Channel='System'; Provider='Disk'; Id=7
                    Count=4; PerDay=2; LastSeen=(Get-Date); UndatedCount=0; SampleMessage='bad block'
                    Verdict='investigate'; Title='Disk failure'; RuleId='LV-TEST'; Status='stable'
                },
                [pscustomobject]@{
                    Key='CBS/test'; Source='textlog'; Channel='CBS'; Provider='CBS'; Id=0
                    Count=1; PerDay=0.5; LastSeen=(Get-Date).AddDays(-1); UndatedCount=1; SampleMessage='servicing failure'
                    Verdict='unknown'; Title='Servicing failure'; RuleId=$null; Status=$null
                }
            )
            $rows = @(ConvertTo-LVGuiRow -Finding $findings -CorrelationIdsByKey @{ 'Disk/7' = @('C-1') })
            $row = $rows[0]
            $row.PSObject.Properties.Name | Should -Not -Contain 'Finding'
            $row.Source | Should -BeExactly 'event'
            $row.Provider | Should -BeExactly 'Disk'
            $row.EventId | Should -BeExactly '7'
            $row.RuleStatus | Should -BeExactly 'stable'
            @($row.CorrelationIds) | Should -Be @('C-1')

            $options = @(Get-LVGuiFilterOption -Row $rows -Kind Correlation)
            @($options | Where-Object { $_.Value -eq '' -and $_.Label -eq 'All correlations' }).Count | Should -Be 1
            @($options | Where-Object { $_.Value -eq 'C-1' }).Count | Should -Be 1

            $enabled = @{ investigate=$true; unknown=$true }
            $filter = @{
                Source='event'; Channel='System'; Provider='Disk'; EventId='7'
                Correlation='C-1'; RuleStatus='stable'
            }
            Test-LVGuiFindingVisible -Row $row -EnabledVerdict $enabled -Search '' -StructuredFilter $filter | Should -BeTrue
            $filter.Correlation = '__uncorrelated__'
            Test-LVGuiFindingVisible -Row $row -EnabledVerdict $enabled -Search '' -StructuredFilter $filter | Should -BeFalse
            $filter.Correlation = 'C-1'; $filter.Provider = 'CBS'
            Test-LVGuiFindingVisible -Row $row -EnabledVerdict $enabled -Search '' -StructuredFilter $filter | Should -BeFalse
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
        $public = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'Public/Show-LogVerdictGui.ps1') -Raw
        $helpers = Get-LVGuiSourceText
        $public | Should -Match 'New-LVGuiSession'
        $public | Should -Match 'New-LVGuiActions'
        $public | Should -Match 'Register-LVGui'
        $helpers | Should -Match 'Test-LVGuiFindingVisible'
        $helpers | Should -Match 'Get-LVGuiVerdictCount'
        $helpers | Should -Match 'ConvertTo-LVGuiDetail'
        $public | Should -Not -Match '\$state\.Chips\[\$Item\.Verdict\]'
    }

    It 'passes optional advisory settings through the GUI wiring' {
        $root = Split-Path $PSScriptRoot -Parent
        $gui = Get-LVGuiSourceText
        $entry = Get-Content -LiteralPath (Join-Path $root 'LogVerdict-GUI.ps1') -Raw
        $gui | Should -Match '\[string\]\$AdvisoryPath'
        $gui | Should -Match "scanArgs\['AdvisoryPackage'\]"
        $gui | Should -Match 'DEPENDENCY ADVISORIES \(SEPARATE FROM EVENT FINDINGS\)'
        $entry | Should -Match '\[string\]\$AdvisoryVersion'
        $entry | Should -Match "guiArgs\['AdvisoryVersion'\]"
    }

    It 'keeps an advisory-enabled headless render refreshing its filter and finding count' {
        $gui = Get-LVGuiSourceText
        $gui | Should -Match '\$advisoryState\s*=\s*if\s*\(\$advisory\.Matched\)'
        $gui | Should -Not -Match '\$state\s*=\s*if\s*\(\$advisory\.Matched\)'

        # This is the closure contract used by the WPF render callback, exercised
        # without starting a window: an advisory label must not replace the mutable
        # state object before the nested filter callback runs.
        $state = @{
            Result = $null
            Rows = @()
            AdvisoryLabels = @()
            View = [pscustomobject]@{ RefreshCount = 0 }
        }
        $state.View | Add-Member -MemberType ScriptMethod -Name Refresh -Value { $this.RefreshCount++ } -Force
        $ui = [pscustomobject]@{ TxtShown = [pscustomobject]@{ Text = '' } }
        $applyFilter = {
            $state.View.Refresh()
            $ui.TxtShown.Text = '{0} finding(s)' -f @($state.Rows).Count
        }
        $renderResult = {
            param($Result)
            $state.Result = $Result
            $state.Rows = @($Result.Findings)
            foreach ($advisory in @($Result.Advisories | Where-Object { $_ })) {
                $advisoryState = if ($advisory.Matched) { 'AFFECTED' } else { 'CACHE ENTRY' }
                $state.AdvisoryLabels += $advisoryState
            }
            & $applyFilter
        }

        & $renderResult ([pscustomobject]@{
            Findings = @([pscustomobject]@{ Verdict = 'actionable' })
            Advisories = @([pscustomobject]@{ Matched = $true })
        })

        $state.View.RefreshCount | Should -Be 1
        $ui.TxtShown.Text | Should -BeExactly '1 finding(s)'
        @($state.AdvisoryLabels) | Should -Be @('AFFECTED')
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

Describe 'Operator-state-safe tooling' {
    It 'uses basic parsing for every production web request' {
        $root = Split-Path $PSScriptRoot -Parent
        $paths = @(
            Get-ChildItem -LiteralPath (Join-Path $root 'Private') -Filter '*.ps1' -File -Recurse
            Get-ChildItem -LiteralPath (Join-Path $root 'Public') -Filter '*.ps1' -File -Recurse
            Get-ChildItem -LiteralPath (Join-Path $root 'Tools') -Filter '*.ps1' -File -Recurse
        )
        foreach ($path in $paths) {
            foreach ($line in @(Get-Content -LiteralPath $path.FullName | Where-Object { $_ -match 'Invoke-(?:WebRequest|RestMethod)\b' })) {
                $line | Should -Match '-UseBasicParsing'
            }
        }
    }

    It 'does not create advisory output or contact NVD under WhatIf' {
        $root = Split-Path $PSScriptRoot -Parent
        $refresh = Join-Path $root 'Tools/Refresh-LogVerdictAdvisoryCache.ps1'
        $output = Join-Path $TestDrive 'whatif/advisories.json'
        & $refresh -OutputPath $output -CveId 'CVE-NOT-REQUESTED' -WhatIf | Out-Null

        Test-Path -LiteralPath $output | Should -BeFalse
        Test-Path -LiteralPath (Split-Path -Parent $output) | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $root 'Data/advisories.json.previous.json') | Should -BeFalse

        $source = Get-Content -LiteralPath $refresh -Raw
        $source.IndexOf('ShouldProcess', [StringComparison]::Ordinal) |
            Should -BeLessThan $source.IndexOf('Invoke-WebRequest', [StringComparison]::Ordinal)
        $source | Should -Match "GetTempPath\(\).*LogVerdict-advisory-backups"
    }

    It 'isolates GUI smoke settings and closes through the window path first' {
        $root = Split-Path $PSScriptRoot -Parent
        $source = Get-Content -LiteralPath (Join-Path $root 'Tools/Test-LogVerdictGuiArtifact.ps1') -Raw
        $source | Should -Match '\$env:LOCALAPPDATA\s*=\s*\$smokeLocalAppData'
        $source | Should -Match 'settingsPreserved'
        $closeIndex = $source.IndexOf('WindowPattern.Close', [StringComparison]::Ordinal)
        $forceIndex = $source.IndexOf('Stop-Process -Id', [StringComparison]::Ordinal)
        $closeIndex | Should -BeGreaterThan -1
        $forceIndex | Should -BeGreaterThan $closeIndex
    }

    It 'requires an explicit caller-owned screenshot directory instead of an environment hook' {
        $root = Split-Path $PSScriptRoot -Parent
        $gui = Get-LVGuiSourceText
        $entry = Get-Content -LiteralPath (Join-Path $root 'LogVerdict-GUI.ps1') -Raw
        $gui | Should -Not -Match 'LOGVERDICT_GUI_SCREENSHOT_PATH'
        $gui | Should -Match 'ScreenshotDirectory'
        $gui | Should -Match 'ScreenshotPath must remain inside ScreenshotDirectory'
        $gui | Should -Match 'GUI screenshot written to'
        $entry | Should -Match 'ScreenshotPath'
        $entry | Should -Match 'ScreenshotDirectory'
    }

    It 'bounds the GUI activity buffer and filters it literally' {
        $gui = Get-LVGuiSourceText
        $gui | Should -Match '\$activityMaxLines\s*=\s*\$script:LVMaxGuiActivityLines'
        $gui | Should -Match '\$activityMaxCharacters\s*=\s*524288'
        $gui | Should -Match 'ActivityCharacters'
        $gui | Should -Match 'ActivityDropped'
        $gui | Should -Match 'ActivityLines\.RemoveAt\(0\)'
        $gui | Should -Match 'IndexOf\(\$needle, \[StringComparison\]::OrdinalIgnoreCase\)'
    }

    It 'bounds the shared transcript used by GUI and report output' {
        $root = Split-Path $PSScriptRoot -Parent
        $common = Get-Content -LiteralPath (Join-Path $root 'Private/00-LVCommon.ps1') -Raw
        $common | Should -Match '\$script:LVMaxLogLines\s*=\s*5000'
        $common | Should -Match 'function Add-LVLogLine'
        $common | Should -Match 'LVLogLinesTruncated'

        InModuleScope LogVerdict {
            $list = New-Object 'System.Collections.Generic.List[string]'
            $previous = $script:LVLogLinesTruncated
            try {
                $script:LVLogLinesTruncated = $false
                for ($i = 0; $i -lt ($script:LVMaxLogLines + 100); $i++) {
                    Add-LVLogLine -List $list -Line ('line-{0}' -f $i)
                }
                $list.Count | Should -BeLessOrEqual $script:LVMaxLogLines
                $script:LVLogLinesTruncated | Should -BeTrue
            } finally {
                $script:LVLogLinesTruncated = $previous
            }
        }
    }
}

Describe 'Release supply-chain metadata' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:SupplyChainTool = Join-Path $root 'Tools/New-LogVerdictSupplyChain.ps1'
        $script:SupplyChainVerifier = Join-Path $root 'Tools/Test-LogVerdictSupplyChain.ps1'
        $script:SupplyChainVersion = (& (Join-Path $root 'Tools/Get-LogVerdictVersion.ps1')).Trim()
    }

    It 'generates per-asset SPDX and provenance records that verify offline' {
        $assetDirectory = Join-Path $TestDrive 'supply-assets'
        $metadataDirectory = Join-Path $TestDrive 'supply-metadata'
        $null = New-Item -ItemType Directory -Path $assetDirectory
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict.exe'), [byte[]](1, 2, 3, 4))
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict-GUI.exe'), [byte[]](5, 6, 7))

        $generated = & $script:SupplyChainTool -Version $script:SupplyChainVersion -AssetDirectory $assetDirectory -OutputDirectory $metadataDirectory
        & $script:SupplyChainVerifier -Version $script:SupplyChainVersion -MetadataDirectory $metadataDirectory -AssetDirectory $assetDirectory

        $index = Get-Content -LiteralPath (Join-Path $metadataDirectory 'logverdict-supply-chain.json') -Raw | ConvertFrom-Json
        @($index.assets).Count | Should -Be 2
        $index.sourceDirty | Should -BeFalse
        $index.sourceRevision | Should -Match '^[0-9a-f]{40}$'
        $index.sourceManifestSha256 | Should -Match '^[0-9a-f]{64}$'
        $index.dependencyManifestSha256 | Should -Match '^[0-9a-f]{64}$'
        foreach ($asset in @($index.assets)) {
            $asset.sha256 | Should -Match '^[0-9a-f]{64}$'
            (Test-Path -LiteralPath (Join-Path $metadataDirectory $asset.sbom)) | Should -BeTrue
            (Test-Path -LiteralPath (Join-Path $metadataDirectory $asset.cyclonedx)) | Should -BeTrue
            (Test-Path -LiteralPath (Join-Path $metadataDirectory $asset.provenance)) | Should -BeTrue
            $spdx = Get-Content -LiteralPath (Join-Path $metadataDirectory $asset.sbom) -Raw | ConvertFrom-Json
            $spdx.spdxVersion | Should -BeExactly 'SPDX-2.3'
            $cycloneDx = Get-Content -LiteralPath (Join-Path $metadataDirectory $asset.cyclonedx) -Raw | ConvertFrom-Json
            $cycloneDx.'$schema' | Should -BeExactly 'https://cyclonedx.org/schema/bom-1.7.schema.json'
            $cycloneDx.bomFormat | Should -BeExactly 'CycloneDX'
            $cycloneDx.specVersion | Should -BeExactly '1.7'
            $cycloneDx.components[0].name | Should -BeExactly $asset.name
            $cycloneDx.components[0].hashes[0].content | Should -BeExactly $asset.sha256
            @($cycloneDx.components[0].properties | Where-Object { $_.name -eq 'logverdict:provenance-signed' -and $_.value -eq 'false' }).Count | Should -Be 1
            $provenance = Get-Content -LiteralPath (Join-Path $metadataDirectory $asset.provenance) -Raw | ConvertFrom-Json
            $provenance.subject[0].digest.sha256 | Should -BeExactly $asset.sha256
            $provenance.cyclonedx.path | Should -BeExactly $asset.cyclonedx
            $provenance.cyclonedx.sha256 | Should -BeExactly $asset.cyclonedxSha256
            $provenance.build.unsigned | Should -BeTrue
        }
        $generated.AssetCount | Should -Be 2
    }

    It 'rejects provenance generated from a dirty checkout' {
        $assetDirectory = Join-Path $TestDrive 'dirty-assets'
        $metadataDirectory = Join-Path $TestDrive 'dirty-metadata'
        $null = New-Item -ItemType Directory -Path $assetDirectory
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict.exe'), [byte[]](1, 2))
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict-GUI.exe'), [byte[]](3, 4))
        & $script:SupplyChainTool -Version $script:SupplyChainVersion -AssetDirectory $assetDirectory -OutputDirectory $metadataDirectory | Out-Null
        $indexPath = Join-Path $metadataDirectory 'logverdict-supply-chain.json'
        $index = Get-Content -LiteralPath $indexPath -Raw | ConvertFrom-Json
        $index.sourceDirty = $true
        $index | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $indexPath -Encoding UTF8
        { & $script:SupplyChainVerifier -Version $script:SupplyChainVersion -MetadataDirectory $metadataDirectory -AssetDirectory $assetDirectory } |
            Should -Throw '*Source checkout dirty state*'
    }

    It 'rejects a source manifest that omits a tracked file' {
        $assetDirectory = Join-Path $TestDrive 'missing-source-assets'
        $metadataDirectory = Join-Path $TestDrive 'missing-source-metadata'
        $null = New-Item -ItemType Directory -Path $assetDirectory
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict.exe'), [byte[]](1, 2))
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict-GUI.exe'), [byte[]](3, 4))
        & $script:SupplyChainTool -Version $script:SupplyChainVersion -AssetDirectory $assetDirectory -OutputDirectory $metadataDirectory | Out-Null
        $manifestPath = Join-Path $metadataDirectory 'source-manifest.json'
        $indexPath = Join-Path $metadataDirectory 'logverdict-supply-chain.json'
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifest.files = @($manifest.files | Select-Object -Skip 1)
        $canonical = ((@($manifest.files) | ForEach-Object { '{0}|{1}|{2}' -f $_.path, $_.sha256, $_.bytes }) -join "`n") + "`n"
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $manifest.sourceTreeSha256 = ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical)))).Replace('-', '').ToLowerInvariant() } finally { $hash.Dispose() }
        $manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
        $index = Get-Content -LiteralPath $indexPath -Raw | ConvertFrom-Json
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $index.sourceManifestSha256 = ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($manifestPath)))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
        $index | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $indexPath -Encoding UTF8
        { & $script:SupplyChainVerifier -Version $script:SupplyChainVersion -MetadataDirectory $metadataDirectory -AssetDirectory $assetDirectory } |
            Should -Throw '*Source manifest is missing tracked file*'
    }

    It 'rejects a release asset whose bytes no longer match the provenance record' {
        $assetDirectory = Join-Path $TestDrive 'tampered-assets'
        $metadataDirectory = Join-Path $TestDrive 'tampered-metadata'
        $null = New-Item -ItemType Directory -Path $assetDirectory
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict.exe'), [byte[]](8, 9))
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict-GUI.exe'), [byte[]](10, 11))
        & $script:SupplyChainTool -Version $script:SupplyChainVersion -AssetDirectory $assetDirectory -OutputDirectory $metadataDirectory | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $assetDirectory 'LogVerdict.exe'), [byte[]](12, 13))

        { & $script:SupplyChainVerifier -Version $script:SupplyChainVersion -MetadataDirectory $metadataDirectory -AssetDirectory $assetDirectory } |
            Should -Throw '*Release hash LogVerdict.exe*'
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
        $guiText = Get-LVGuiSourceText
        InModuleScope LogVerdict -Parameters @{ GuiText = $guiText } {
            param($GuiText)
            $xaml = Get-LVGuiXaml
            $xaml | Should -Match 'VirtualizingPanel\.IsVirtualizing="True"'
            $xaml | Should -Match 'VirtualizingPanel\.VirtualizationMode="Recycling"'
            $GuiText | Should -Match 'FindingStore'
            $GuiText | Should -Match 'FindingIndex'
            $GuiText | Should -Not -Match '\$Row\.Finding\b'
        }
    }

    It 'never hands a bare string to an ItemsSource' {
        # A string is IEnumerable. Assigning one directly to ItemsSource binds to its
        # characters, and a rule caveat renders one letter per line - which is exactly
        # what happened until it was caught on screen. Every assignment must cast.
        $assignments = [regex]::Matches((Get-LVGuiSourceText), '(?m)\.ItemsSource\s*=\s*(.+)$')
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

            foreach ($name in @('TxtOverviewDays', 'TxtSearch', 'LvFindings', 'TxtSample', 'TxtActivityLog')) {
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

    It 'requires severe active rules to document false positives and an external citation' {
        $rule = [ordered]@{
            id = 'SEVERE-PROSE'; status = 'stable'; verified = '2026-08-03'; modified = '2026-08-03'
            match = @{ source = 'event'; provider = 'Contoso'; eventId = 4242 }
            verdict = 'critical'; title = 'A severe test ruling'; plain = 'The component failed.'
            why = 'The failure can affect the system.'; action = 'Investigate the component.'; confidence = 'high'
            provenance = 'internal-observation'; references = @(); falsepositives = @()
        }
        $path = Join-Path $TestDrive 'severe-prose.json'
        [ordered]@{ schemaVersion = 7; name = 'severe-prose'; updated = '2026-08-03'; rules = @($rule); correlations = @() } |
            ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8

        $problems = @(Test-LogVerdictDatabase -Path $path -SkipFixture)
        @($problems | Where-Object { $_.Problem -like '*requires at least one falsepositives*' }).Count | Should -Be 1
        @($problems | Where-Object { $_.Problem -like '*requires at least one external citation*' }).Count | Should -Be 1
        @($problems | Where-Object { $_.Severity -ne 'error' }).Count | Should -Be 0

        $rule.falsepositives = @('A test harness can deliberately trigger this failure.')
        $rule.references = @('https://example.invalid/severe')
        [ordered]@{ schemaVersion = 7; name = 'severe-prose'; updated = '2026-08-03'; rules = @($rule); correlations = @() } |
            ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
        Test-LogVerdictDatabase -Path $path -SkipFixture -Quiet | Should -BeTrue

        $rule.status = 'deprecated'; $rule.falsepositives = @(); $rule.references = @(); $rule.Remove('provenance')
        [ordered]@{ schemaVersion = 7; name = 'severe-prose'; updated = '2026-08-03'; rules = @($rule); correlations = @() } |
            ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
        Test-LogVerdictDatabase -Path $path -SkipFixture -Quiet | Should -BeTrue
    }

    It 'gives every active shipped rule source metadata or explicit provenance' {
        InModuleScope LogVerdict {
            $database = Get-LogVerdictDatabase
            $missing = @($database.rules | Where-Object {
                (Test-LVRuleActive -Rule $_) -and
                @($_.sources | Where-Object { $_ }).Count -eq 0 -and
                [string]$_.provenance -ne 'internal-observation'
            })
            $missing.Count | Should -Be 0 -Because ("unattributed active rules: {0}" -f (@($missing.id) -join ', '))
        }
    }

    It 'reuses the populated channel metadata during the status probe' {
        InModuleScope LogVerdict {
            $metadataLog = [pscustomobject]@{
                LogName = 'Fake'
                RecordCount = 2
                MaximumSizeInBytes = 1024
                LogMode = 'Circular'
                IsEnabled = $true
                LogFilePath = 'C:\\Windows\\System32\\winevt\\Logs\\Fake.evtx'
            }
            Mock Get-WinEvent { $metadataLog } -ParameterFilter { $ListLog -eq '*' }
            Mock Get-WinEvent { [pscustomobject]@{ TimeCreated = (Get-Date).AddDays(-1) } } -ParameterFilter { $LogName -eq 'Fake' }

            Get-LVPopulatedChannel -MinimumRecords 1 | Out-Null
            $status = Get-LVChannelStatus -Channel @('Fake') -Metadata $script:LVChannelMetadata
            $status['Fake'].Access | Should -BeExactly 'readable'
            $status['Fake'].RecordCount | Should -Be 2
            Should -Invoke Get-WinEvent -Times 0 -ParameterFilter { $ListLog -eq 'Fake' }
        }
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
        $gui = Get-LVGuiSourceText
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
        $gui = Get-LVGuiSourceText
        $gui | Should -Match 'Format-LVCorrelation'
        $gui | Should -Match 'LstCorrelationPage'
        $xaml = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'Private\50-LVGuiXaml.ps1') -Raw
        $xaml | Should -Match 'x:Name="LstCorrelationPage"'
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

    It 'drops oversized redacted raw excerpts before the hard attachment ceiling' {
        InModuleScope LogVerdict -Parameters @{ Drive = $TestDrive } {
            param($Drive)
            $dir = Join-Path $Drive 'bundle-budget'
            $report = Join-Path $dir 'LogVerdict-Report.json'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            '{"retained":"signature evidence"}' | Set-Content -LiteralPath $report -Encoding UTF8
            $random = New-Object byte[] 5200000
            $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
            try { $rng.GetBytes($random) } finally { $rng.Dispose() }
            $largeSample = [Convert]::ToBase64String($random)
            $result = [pscustomobject]@{
                Version='0.8.2'; MachineName='BUDGET-PC'; ScanTime=(Get-Date); DaysBack=1; Elevated=$false
                Reduction=[pscustomobject]@{ RecordCount=1; SignatureCount=1; Ratio=1 }
                DatabaseName='fixture'; RuleCount=1; DatabaseDate='2026-08-03'; WorstVerdict='investigate'
                Findings=@([pscustomobject]@{ Source='textlog'; Channel='CBS'; Key='text|CBS|1'; Count=1; FirstSeen=(Get-Date); LastSeen=(Get-Date); Samples=@($largeSample) })
                Correlations=@(); Coverage=@(); HealthProfiles=@(); CoverageNotes=@()
            }
            $audit = $null
            $zip = New-LVEvidenceBundle -Result $result -OutputDir $dir -ReportFile @($report) -Redact `
                -OriginalMachineName 'BUDGET-PC' -OriginalUserName 'budget-user' -Audit ([ref]$audit)
            $zip | Should -Not -BeNullOrEmpty
            (Get-Item -LiteralPath $zip).Length | Should -BeLessThan 4500000
            $archive = [IO.Compression.ZipFile]::OpenRead($zip)
            try {
                @($archive.Entries | Where-Object Name -eq 'CBS-excerpt.txt').Count | Should -Be 0
                $manifestEntry = $archive.Entries | Where-Object Name -eq 'MANIFEST.txt' | Select-Object -First 1
                $reader = New-Object IO.StreamReader($manifestEntry.Open())
                try { $manifest = $reader.ReadToEnd() } finally { $reader.Dispose() }
                $manifest | Should -Match 'raw-evidence-dropped|raw text evidence.*dropped'
                $manifest | Should -Match 'Attachment budget: 4,500,000 bytes pre-base64'
            } finally { $archive.Dispose() }
        }
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
                Version='0.8.1'; MachineName='HOST-9'; ScanTime=(Get-Date); DaysBack=1; Elevated=$false
                Channels=@(); Reduction=[pscustomobject]@{ RecordCount=0; SignatureCount=0; Ratio=0 }
                DatabaseName='fixture'; RuleCount=0; DatabaseDate='2026-08-02'; WorstVerdict='benign'
                Findings=@(); Correlations=@(); Coverage=@(); HealthProfiles=@(); CoverageNotes=@()
            }
            $audit = $null
            $status = $null
            $zip = New-LVEvidenceBundle -Result $result -OutputDir $dir -ReportFile @($report) -Redact `
                -OriginalMachineName 'HOST-9' -OriginalUserName 'jsmith' -Audit ([ref]$audit) -Status ([ref]$status)
            $zip | Should -BeNullOrEmpty
            $audit.Status | Should -BeExactly 'blocked'
            $audit.FindingCount | Should -BeGreaterThan 0
            $status.State | Should -BeExactly 'privacy-blocked'
            $status.Reason | Should -Match 'Privacy audit blocked'
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
        $out.EvidenceBundleStatus.State | Should -BeExactly 'not-requested'
        $out.EvidenceBundleStatus.Reason | Should -Match 'not requested'
        @(Get-ChildItem -LiteralPath $dir -Filter '*.zip').Count | Should -Be 0
    }

    It 'reports when evidence packaging is declined by WhatIf policy' {
        InModuleScope LogVerdict -Parameters @{ Root = $TestDrive; Scan = $script:Scan } {
            param($Root, $Scan)
            $status = $null
            $zip = New-LVEvidenceBundle -Result $Scan -OutputDir (Join-Path $Root 'bundle-declined') `
                -ReportFile @() -Redact -WhatIf -Status ([ref]$status) 6>$null
            $zip | Should -BeNullOrEmpty
            $status.State | Should -BeExactly 'declined'
            $status.Reason | Should -Match 'declined'
        }
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

Describe 'Windows log parsing benchmark' {
    It 'ships a pinned content-free annotation manifest' {
        $root = Split-Path $PSScriptRoot -Parent
        $manifest = Get-Content -LiteralPath (Join-Path $root 'Data\windows-log-benchmark.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $schema = Get-Content -LiteralPath (Join-Path $root 'Data\windows-log-benchmark.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json

        $manifest.schemaVersion | Should -Be 1
        $manifest.annotationLicense | Should -BeExactly 'MIT'
        $manifest.source.revision | Should -Match '^[0-9a-f]{40}$'
        $manifest.source.sha256 | Should -Match '^[0-9a-f]{64}$'
        @($manifest.annotations).Count | Should -Be 2000
        $manifest.budgets.minimumGroupingPurity | Should -Be 0.99
        $manifest.budgets.minimumParsingAccuracy | Should -Be 0.65
        $schema.properties.annotationLicense.const | Should -BeExactly 'MIT'
        $schema.properties.source.required | Should -Contain 'sha256'
    }

    It 'evaluates a local fixture through the real template masker' {
        $root = Split-Path $PSScriptRoot -Parent
        $corpusPath = Join-Path $TestDrive 'windows-fixture.csv'
        $annotationPath = Join-Path $TestDrive 'windows-annotations.json'
        $outputPath = Join-Path $TestDrive 'windows-result.json'
        $rows = @(
            [pscustomobject][ordered]@{ LineId=1; Date='2026-08-03'; Time='10:00:00'; Level='Error'; Component='Disk'; Content='Disk error 123'; EventId='E1'; EventTemplate='Disk error <*>' }
            [pscustomobject][ordered]@{ LineId=2; Date='2026-08-03'; Time='10:00:01'; Level='Error'; Component='Disk'; Content='Disk error 124'; EventId='E1'; EventTemplate='Disk error <*>' }
            [pscustomobject][ordered]@{ LineId=3; Date='2026-08-03'; Time='10:00:02'; Level='Info'; Component='Service'; Content='Service started'; EventId='E2'; EventTemplate='Service started' }
        )
        $csv = (($rows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine) + [Environment]::NewLine
        [IO.File]::WriteAllText($corpusPath, $csv, (New-Object Text.UTF8Encoding($false)))
        $hashText = {
            param([string]$Text)
            $sha = [Security.Cryptography.SHA256]::Create()
            try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
            finally { $sha.Dispose() }
        }.GetNewClosure()
        $annotations = @($rows | ForEach-Object {
            [pscustomobject][ordered]@{
                id = 'fixture-{0}' -f $_.LineId
                lineId = [int]$_.LineId
                lineSha256 = & $hashText ([string]$_.Content)
                eventId = [string]$_.EventId
                eventTemplate = [string]$_.EventTemplate
                component = [string]$_.Component
                level = [string]$_.Level
                stratum = [string]$_.Component
            }
        })
        $fileSha = [Security.Cryptography.SHA256]::Create()
        try { $sourceSha = ([BitConverter]::ToString($fileSha.ComputeHash([IO.File]::ReadAllBytes($corpusPath)))).Replace('-', '').ToLowerInvariant() }
        finally { $fileSha.Dispose() }
        $manifest = [pscustomobject][ordered]@{
            schemaVersion = 1
            name = 'fixture'
            annotationLicense = 'MIT'
            source = [pscustomobject][ordered]@{
                dataset = 'fixture'
                file = 'Windows_2k.log_structured.csv'
                revision = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                uri = 'https://raw.githubusercontent.com/logpai/loghub/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Windows/Windows_2k.log_structured.csv'
                sourceLicense = 'fixture'
                sha256 = $sourceSha
            }
            budgets = [pscustomobject][ordered]@{ minimumRows=3; minimumGroupingPurity=1.0; minimumParsingAccuracy=1.0 }
            annotations = $annotations
        }
        [IO.File]::WriteAllText($annotationPath, ($manifest | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))

        $tool = Join-Path $root 'Tools\Test-LogVerdictWindowsBenchmark.ps1'
        $output = @(& $tool -CorpusPath $corpusPath -AnnotationPath $annotationPath -OutputPath $outputPath)
        $result = Get-Content -LiteralPath $outputPath -Raw -Encoding UTF8 | ConvertFrom-Json
        ($output -join [Environment]::NewLine) | Should -Match 'Windows benchmark: 3 rows'
        $result.Rows | Should -Be 3
        $result.Metrics.GroupingPurity | Should -Be 1
        $result.Metrics.ParsingAccuracy | Should -Be 1
        $result.Failures | Should -BeNullOrEmpty
    }
}

Describe 'Content-free performance benchmark gate' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:PerformanceTool = Join-Path $root 'Tools\Test-LogVerdictPerformance.ps1'
        $script:PerformanceBudget = Join-Path $root 'Data\performance-budgets.json'
    }

    It 'runs every fixture and writes only aggregate timing and count fields' {
        $report = Join-Path $TestDrive 'performance.json'
        $output = @(& $script:PerformanceTool -OutputPath $report -BudgetPath $script:PerformanceBudget)
        $? | Should -BeTrue

        $json = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
        $json.SchemaVersion | Should -Be 1
        $json.Passed | Should -BeTrue
        @($json.Fixtures).Count | Should -Be 5
        @($json.Fixtures | Where-Object { $_.Id -eq 'text-small' -and $_.Status -eq 'readable' }).Count | Should -Be 1
        @($json.Fixtures | Where-Object { $_.Id -eq 'text-large' -and $_.ObservedRecords -ge 10000 }).Count | Should -Be 1
        @($json.Fixtures | Where-Object { $_.Id -eq 'text-malformed' -and $_.UndatedRecords -eq 128 }).Count | Should -Be 1
        @($json.Fixtures | Where-Object { $_.Id -eq 'evtx-malformed' -and $_.Status -eq 'unreadable' }).Count | Should -Be 1
        @($json.Fixtures | Where-Object { $_.Id -eq 'evtx-malformed' -and $_.ParserMilliseconds -le 5000 }).Count | Should -Be 1
        @($json.Fixtures | Where-Object { $_.Id -eq 'reduction-medium' -and $_.Status -eq 'reduced' -and $_.ObservedRecords -eq 2359 -and $_.InputLines -gt 0 }).Count | Should -Be 1
        $raw = Get-Content -LiteralPath $report -Raw
        $raw | Should -Not -Match 'Message|SampleMessage|MachineName|Path|C:\\|secret'
        $output -join "`n" | Should -Match 'Performance gate: passed'
    }
}

Describe 'Windows log parsing benchmark' {
    It 'ships fingerprint-only MIT annotations with a pinned external corpus' {
        $root = Split-Path $PSScriptRoot -Parent
        $manifestPath = Join-Path $root 'Data\windows-log-benchmark.json'
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $manifest.schemaVersion | Should -Be 1
        $manifest.annotationLicense | Should -BeExactly 'MIT'
        $manifest.source.revision | Should -Match '^[0-9a-f]{40}$'
        $manifest.source.sha256 | Should -Match '^[0-9a-f]{64}$'
        @($manifest.annotations).Count | Should -Be $manifest.budgets.minimumRows
        @($manifest.annotations | Select-Object -ExpandProperty id -Unique).Count | Should -Be @($manifest.annotations).Count
        @($manifest.annotations | Where-Object { $_.lineSha256 -notmatch '^[0-9a-f]{64}$' }).Count | Should -Be 0
        @($manifest.annotations | Where-Object { $_.PSObject.Properties.Name -contains 'content' }).Count | Should -Be 0
        @($manifest.annotations | Select-Object -ExpandProperty eventId -Unique).Count | Should -BeGreaterThan 1
    }

    It 'keeps the fetch and scoring tools pinned, external-data-only, and content-free' {
        $root = Split-Path $PSScriptRoot -Parent
        $fetch = Get-Content -LiteralPath (Join-Path $root 'Tools\Fetch-LogVerdictWindowsBenchmark.ps1') -Raw
        $score = Get-Content -LiteralPath (Join-Path $root 'Tools\Test-LogVerdictWindowsBenchmark.ps1') -Raw
        $fetch | Should -Match 'ExpectedSha256'
        $fetch | Should -Match 'raw\.githubusercontent\.com/logpai/loghub'
        $fetch | Should -Match 'Refusing to use an unreviewed source revision'
        $score | Should -Match 'ConvertTo-LVTemplateData'
        $score | Should -Match 'GroupingPurity'
        $score | Should -Match 'ParsingAccuracy'
        $score | Should -Match 'lineSha256'
        $score | Should -Not -Match '\$.*Content.*ConvertTo-Json'
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
            Should -Invoke Get-LVChannelStatus -Times 0
            Should -Invoke Get-LVTextLogRecord -Times 0
            Should -Invoke Get-LVReliabilityRecord -Times 0
            Should -Invoke Get-LVCrashArtifact -Times 0
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
            ($result.Coverage | Where-Object { $_.Source -eq 'offline-evtx' } | Select-Object -First 1).Status | Should -BeExactly 'readable'
            @($result.Coverage | Where-Object { $_.Status -eq 'parsed' }).Count | Should -Be 0
            $manifest = Format-LVEvidenceManifest -Result $result -Content @()
            $manifest | Should -Match ('SHA-256 ' + $result.EvidenceManifest[0].SHA256)
        }
    }

    It 'maps a parsed EVTX with no records to empty coverage' {
        $evtx = Join-Path $TestDrive 'empty.evtx'
        [IO.File]::WriteAllBytes($evtx, [byte[]](0x45, 0x56, 0x54, 0x58, 0x03))
        InModuleScope LogVerdict -Parameters @{ EvtxPath = $evtx } {
            param($EvtxPath)
            Mock Get-WinEvent {
                param($Oldest)
                if ($Oldest) { return [pscustomobject]@{ LogName = 'System'; TimeCreated = (Get-Date).AddHours(-1) } }
                return @()
            }
            $result = Invoke-LVOfflineScan -EvidencePath $EvtxPath -DaysBack 1 -SkipTextLogs -SkipReliability
            $result.EvidenceManifest[0].Status | Should -BeExactly 'parsed'
            ($result.Coverage | Where-Object { $_.Source -eq 'offline-evtx' } | Select-Object -First 1).Status | Should -BeExactly 'empty'
        }
    }

    It 'labels EVTX recovered from a preserved shadow-copy path' {
        $root = Join-Path $TestDrive 'ShadowCopy1\Windows\System32\winevt\Logs'
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $evtx = Join-Path $root 'System.evtx'
        [IO.File]::WriteAllBytes($evtx, [byte[]](0x45, 0x56, 0x54, 0x58, 0x02))
        InModuleScope LogVerdict -Parameters @{ Root = (Join-Path $TestDrive 'ShadowCopy1') } {
            param($Root)
            Mock Get-WinEvent {
                param($Oldest)
                if ($Oldest) { return [pscustomobject]@{ LogName = 'System'; TimeCreated = (Get-Date).AddDays(-2) } }
                return [pscustomobject]@{
                    LogName = 'System'; ProviderName = 'Disk'; Id = 7; Level = 2; LevelDisplayName = 'Error'
                    TimeCreated = (Get-Date).AddDays(-2); MachineName = 'ARCHIVE-HOST'; RecordId = 42; Message = 'recovered event'
                }
            }
            $result = Invoke-LVOfflineScan -EvidencePath $Root -DaysBack 30 -SkipTextLogs -SkipReliability
            $result.EvidenceManifest[0].Origin | Should -BeExactly 'shadow-copy'
            ($result.Coverage | Where-Object { $_.Source -eq 'offline-evtx' } | Select-Object -First 1).Origin | Should -BeExactly 'shadow-copy'
            @($result.CoverageNotes | Where-Object { $_ -match 'preserved shadow-copy' }).Count | Should -Be 1
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

    It 'rejects archive payload bytes beyond the expansion cap even when headers understate them' {
        $zipPath = Join-Path $TestDrive 'understated.zip'
        $stream = [IO.File]::Open($zipPath, [IO.FileMode]::CreateNew)
        $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create)
        try {
            $entry = $zip.CreateEntry('payload.evtx', [IO.Compression.CompressionLevel]::NoCompression)
            $payload = [byte[]](0..15)
            $entryStream = $entry.Open()
            try { $entryStream.Write($payload, 0, $payload.Length) } finally { $entryStream.Dispose() }
        } finally {
            $zip.Dispose()
            $stream.Dispose()
        }

        $bytes = [IO.File]::ReadAllBytes($zipPath)
        $centralSignature = [byte[]](0x50, 0x4b, 0x01, 0x02)
        $centralOffset = -1
        for ($index = 0; $index -le $bytes.Length - $centralSignature.Length; $index++) {
            if ($bytes[$index] -eq $centralSignature[0] -and
                $bytes[$index + 1] -eq $centralSignature[1] -and
                $bytes[$index + 2] -eq $centralSignature[2] -and
                $bytes[$index + 3] -eq $centralSignature[3]) {
                $centralOffset = $index
                break
            }
        }
        $centralOffset | Should -BeGreaterThan -1
        [BitConverter]::GetBytes([uint32]1).CopyTo($bytes, $centralOffset + 24)
        [IO.File]::WriteAllBytes($zipPath, $bytes)

        InModuleScope LogVerdict -Parameters @{ ZipPath = $zipPath } {
            param($ZipPath)
            $archivePath = $ZipPath
            { Expand-LVEvidencePackage -Path $archivePath -MaxEntryBytes 8 -MaxTotalBytes 32 } |
                Should -Throw '*per-entry cap*'
            { Expand-LVEvidencePackage -Path $archivePath -MaxEntryBytes 32 -MaxTotalBytes 8 } |
                Should -Throw '*total cap*'
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
        @($got[0].Windows[0].Occurrences).Count | Should -Be 40
    }

    It 'keeps a 4000-occurrence correlation within the linear budget' {
        InModuleScope LogVerdict {
            $base = [datetime]'2026-06-20 09:00:00'
            $occurrences = New-Object System.Collections.Generic.List[object]
            for ($i = 0; $i -lt 2000; $i++) {
                $first = $base.AddMilliseconds($i)
                $occurrences.Add([pscustomobject]@{ Time = $first; RuleId = 'R-1'; Key = "a-$i" }) | Out-Null
                $occurrences.Add([pscustomobject]@{ Time = $first.AddMilliseconds(0.5); RuleId = 'R-2'; Key = "b-$i" }) | Out-Null
            }

            $timer = [Diagnostics.Stopwatch]::StartNew()
            $windows = @(Get-LVCorrelationMatch -Occurrence $occurrences.ToArray() -RuleId @('R-1', 'R-2') -Timespan ([timespan]::FromMinutes(5)))
            $timer.Stop()

            @($windows).Count | Should -Be 1
            @($windows[0].Occurrences).Count | Should -Be 4000
            $timer.Elapsed.TotalSeconds | Should -BeLessThan 5
        }
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

    It 'rejects unsupported correlation types before they can be loaded' {
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
        { Get-LogVerdictDatabase -Path $path } | Should -Throw '*unknown correlation type*event_count*'
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

    It 'emits empty correlation provenance collections instead of null members' {
        $findings = @(
            Build-Sig -RuleId 'R-1' -Key 'a' -Times @([datetime]'2026-06-20 09:00:00')
            Build-Sig -RuleId 'R-2' -Key 'b' -Times @([datetime]'2026-06-20 09:00:10')
        )
        $correlation = @(Invoke-Correlate -Finding $findings -Database (Build-CorrDb))[0]
        foreach ($name in @('References', 'Sources', 'FalsePositives')) {
            @($correlation.$name).Count | Should -Be 0 -Because "$name must be an empty collection"
        }
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

    It 'fails closed when a result grows an unrecognised top-level property' {
        InModuleScope LogVerdict {
            $result = [pscustomobject]@{
                MachineName = 'HOST-9'; Findings = @(); CrashArtifacts = @(); CoverageNotes = @()
                FutureEvidence = 'SECRET-HOST and C:\Users\jsmith\secret.log'
            }
            { ConvertTo-LVRedactedResult -Result $result } | Should -Throw '*unknown result property*'
        }
    }

    It 'redacts live-watch records and model explanation errors' {
        InModuleScope LogVerdict {
            $account = [string]$env:USERNAME
            $result = [pscustomobject]@{
                MachineName = 'SECRET-HOST'; Findings = @([pscustomobject]@{
                    SampleMessage = ('SECRET-HOST failed for {0}' -f $account)
                    ModelExplanationError = ('model failed while reading C:\Users\{0}\token.txt on SECRET-HOST' -f $account)
                }); CrashArtifacts = @(); CoverageNotes = @()
                Records = @([pscustomobject]@{
                    Source = 'event'; Channel = 'System'; Provider = 'Acme'; ProviderId = 'id'
                    Id = 7; TimeCreated = (Get-Date); MachineName = 'SECRET-HOST'; RecordId = 9
                    Message = ('S-1-5-21-1-2-3-1000 from {0}@contoso.test' -f $account)
                    StructuredData = [pscustomobject]@{ EventData = [pscustomobject]@{ Data0 = ('C:\Users\{0}\secret.txt' -f $account) } }
                })
            }
            $redacted = ConvertTo-LVRedactedResult -Result $result
            $json = $redacted | ConvertTo-Json -Depth 20
            $json | Should -Not -Match ('SECRET-HOST|{0}|S-1-5-21-1-2-3-1000|contoso\.test' -f [regex]::Escape($account))
            $redacted.Records[0].Message | Should -Match '<USER>|<SID>|<UPN>'
            $redacted.Findings[0].ModelExplanationError | Should -Not -Match ('SECRET-HOST|{0}' -f [regex]::Escape($account))
        }
    }

    It 'redacts the result returned by Invoke-LogVerdictScan when requested' {
        InModuleScope LogVerdict {
            $account = [string]$env:USERNAME
            Mock Invoke-LVOfflineScan {
                [pscustomobject]@{
                    Tool = 'LogVerdict'; Version = '0.8.2'; MachineName = 'SECRET-HOST'
                    Findings = @(); Records = @([pscustomobject]@{ Message = ('SECRET-HOST; {0}' -f $account); MachineName = 'SECRET-HOST' })
                    CoverageNotes = @(); CrashArtifacts = @(); Reduction = [pscustomobject]@{ RecordCount = 1; SignatureCount = 1; Ratio = 1 }
                }
            }
            $redacted = Invoke-LogVerdictScan -EvidencePath 'mock.evidence' -Redact
            $redacted.Redacted | Should -BeTrue
            $redacted.MachineName | Should -BeExactly '<MACHINE>'
            ($redacted | ConvertTo-Json -Depth 20) | Should -Not -Match ('SECRET-HOST|{0}' -f [regex]::Escape($account))
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
                    ExecutablePath='C:\Users\bob\SetupDiag.exe'; LogsPath='C:\Users\bob\Panther'; ArtifactPath='C:\Users\bob\Logs\SetupDiagResults.xml'
                }
            }
            $redacted = ConvertTo-LVRedactedResult -Result $result
            foreach ($name in @('Message', 'ExecutablePath', 'LogsPath', 'ArtifactPath')) {
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

    It 'writes and validates the versioned report contract' {
        $result = Invoke-LogVerdictScan -DaysBack 1 -SkipTextLogs -SkipReliability 6>$null
        $dir = Join-Path $TestDrive 'contract-v1'
        Export-LogVerdictReport -Result $result -OutputDir $dir -Format Json 6>$null | Out-Null
        $document = Get-Content (Join-Path $dir 'LogVerdict-Report.json') -Raw | ConvertFrom-Json

        $document.Contract.schemaVersion | Should -Be 1
        $document.Contract.name | Should -BeExactly 'LogVerdict.Report'
        $document.Contract.mode | Should -BeExactly 'live'
        $document.Contract.privacy.redacted | Should -BeFalse
        InModuleScope LogVerdict -Parameters @{ document = $document } {
            param($document)
            Test-LVReportContract -InputObject $document -Quiet | Should -BeTrue
        }

        $schemaPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Data/report-contract.schema.json'
        $schema = Get-Content $schemaPath -Raw | ConvertFrom-Json
        $schema.properties.Contract.properties.schemaVersion.const | Should -Be 1

        $evidenceDir = Join-Path $TestDrive 'contract-evidence'
        $evidenceExport = Export-LogVerdictReport -Result $result -OutputDir $evidenceDir -Format Json -Redact -IncludeEvidence 6>$null
        $evidenceExport.EvidenceBundle | Should -Not -BeNullOrEmpty
        $zip = [IO.Compression.ZipFile]::OpenRead($evidenceExport.EvidenceBundle)
        try {
            $entry = @($zip.Entries | Where-Object { $_.FullName -eq 'EVIDENCE-CONTRACT.json' })
            $entry.Count | Should -Be 1
            $reader = New-Object IO.StreamReader($entry[0].Open())
            try { $evidenceDocument = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        } finally { $zip.Dispose() }
        InModuleScope LogVerdict -Parameters @{ evidence = $evidenceDocument } {
            param($evidence)
            Test-LVEvidenceContract -InputObject $evidence -Quiet | Should -BeTrue
        }
        $evidenceDocument.Contract.name | Should -BeExactly 'LogVerdict.Evidence'
        $evidenceDocument.Privacy.redacted | Should -BeTrue
        $evidenceDocument.Privacy.rawEvidence | Should -BeFalse
        $evidenceSchemaPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Data/evidence-contract.schema.json'
        (Get-Content $evidenceSchemaPath -Raw | ConvertFrom-Json).properties.Contract.properties.schemaVersion.const | Should -Be 1
    }

    It 'marks unversioned reports as migrated and rejects future contracts' {
        InModuleScope LogVerdict {
            $legacy = [pscustomobject]@{
                Tool = 'LogVerdict'; Version = '0.8.0'; ScanTime = Get-Date
                DaysBack = 1; Coverage = @(); Findings = @(); WorstVerdict = 'benign'; ExitCode = 0
            }
            $migrated = ConvertFrom-LVReportContract -InputObject $legacy
            $migrated.Contract.compatibility.migration | Should -BeExactly 'legacy-unversioned-to-v1'

            $future = [pscustomobject]@{ Contract = [pscustomobject]@{ schemaVersion = 2 } }
            { ConvertFrom-LVReportContract -InputObject $future } | Should -Throw '*newer*'
        }
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

    It 'masks generated secrets and network identifiers across every redacted report and bundle member' {
        $secretValues = @(
            'super-secret-2026',
            'abcdefghijklmnop',
            'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue',
            'AKIA1234567890ABCDEF',
            'ghp_abcdefghijklmnopqrstuvwxyz123456',
            'S-1-5-21-111111111-222222222-333333333-1000',
            'C:\Users\secret-user\Desktop\evidence.log',
            '10.20.30.40',
            '00:11:22:33:44:55'
        )
        $secretLine = 'password=super-secret-2026 Bearer abcdefghijklmnop jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue AWS AKIA1234567890ABCDEF GitHub ghp_abcdefghijklmnopqrstuvwxyz123456 SID S-1-5-21-111111111-222222222-333333333-1000 path C:\Users\secret-user\Desktop\evidence.log ip 10.20.30.40 mac 00:11:22:33:44:55 token=https://example.test/reset?token=abcdefghijklmnop'
        $result = Invoke-LogVerdictScan -DaysBack 1 -SkipTextLogs -SkipReliability 6>$null
        $result.Findings = @($result.Findings) + @([pscustomobject]@{
            FirstSeen=(Get-Date).AddMinutes(-1); LastSeen=Get-Date; Source='event'; Channel='System'; Provider='PrivacyFixture'; Id=9001
            Title='Privacy fixture'; RuleId='PRIVACY-FIXTURE'; Verdict='investigate'; Count=1; PerDay=1; Key='event|System|9001'
            SampleMessage=$secretLine; Samples=@($secretLine); Ruling='Review the captured event.'; Remediation='Use the evidence context.'
            OfficialReference=$null; Area='test'; SpanDays=0
        })
        $dir = Join-Path $TestDrive 'privacy-all-formats'
        $export = Export-LogVerdictReport -Result $result -OutputDir $dir -Format Text,Json,Csv,Html -Redact -IncludeEvidence 6>$null

        @('LogVerdict-Report.txt', 'LogVerdict-Report.json', 'LogVerdict-Report.csv', 'LogVerdict-Report.html', 'LogVerdict-Run.log') | ForEach-Object {
            $text = Get-Content -LiteralPath (Join-Path $dir $_) -Raw
            foreach ($secret in $secretValues) { $text | Should -Not -Match ([regex]::Escape($secret)) -Because "$_ must not contain generated sensitive data" }
        }
        $export.EvidenceBundle | Should -Not -BeNullOrEmpty
        $zip = [IO.Compression.ZipFile]::OpenRead($export.EvidenceBundle)
        try {
            foreach ($entry in @($zip.Entries)) {
                if ($entry.FullName -match '\.(evtx|dmp)$') { continue }
                $reader = New-Object IO.StreamReader($entry.Open())
                try { $memberText = $reader.ReadToEnd() } finally { $reader.Dispose() }
                foreach ($secret in $secretValues) { $memberText | Should -Not -Match ([regex]::Escape($secret)) -Because "$($entry.FullName) must not contain generated sensitive data" }
            }
        } finally { $zip.Dispose() }

        $dirty = Join-Path $TestDrive 'privacy-dirty.txt'
        Set-Content -LiteralPath $dirty -Value $secretLine -Encoding UTF8
        InModuleScope LogVerdict -Parameters @{ p = $dirty; machine = 'HOST-9' } {
            param($p, $machine)
            $audit = New-LVPrivacyAudit -Path @($p) -MachineName $machine -UserName 'secret-user' -Redacted
            $audit.Status | Should -BeExactly 'blocked'
            $audit.Findings[0].PSObject.Properties.Name | Should -Not -Contain 'Value'
            ($audit | ConvertTo-Json -Depth 8) | Should -Not -Match 'super-secret-2026|AKIA1234567890ABCDEF|ghp_abcdefghijklmnopqrstuvwxyz123456'
        }
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
            Mock Get-ItemProperty { [pscustomobject]@{} } -ParameterFilter { $LiteralPath -like '*Reliability Analysis*' }
            Mock Get-CimInstance { throw 'Invalid class' } -ParameterFilter { $ClassName -eq 'Win32_ReliabilityRecords' }
            Mock Get-CimInstance { @() } -ParameterFilter { $ClassName -eq '__Provider' }

            $script:LVReliabilityAvailable = $true
            @(Get-LVReliabilityRecord -DaysBack 30).Count | Should -Be 0
            $script:LVReliabilityAvailable | Should -BeFalse
            $script:LVReliabilitySkipReason | Should -Not -BeNullOrEmpty
            $script:LVReliabilityStatus | Should -BeExactly 'provider-absent'
        }
    }

    It 'reports an explicitly disabled Reliability policy separately from an absent provider' {
        InModuleScope LogVerdict {
            Mock Get-ItemProperty { [pscustomobject]@{ WMIEnable = 0 } } -ParameterFilter { $LiteralPath -like '*Reliability Analysis*' }
            Mock Get-CimInstance { throw 'the disabled policy should stop before the provider query' }

            @(Get-LVReliabilityRecord -DaysBack 30).Count | Should -Be 0
            $script:LVReliabilityAvailable | Should -BeFalse
            $script:LVReliabilityStatus | Should -BeExactly 'policy-disabled'
            $script:LVReliabilitySkipReason | Should -Match 'WMIEnable=0'
            Should -Invoke Get-CimInstance -Times 0
        }
    }

    It 'recognizes the default-disabled Reliability policy on Windows Server' {
        InModuleScope LogVerdict {
            Mock Get-ItemProperty { [pscustomobject]@{} } -ParameterFilter { $LiteralPath -like '*Reliability Analysis*' }
            Mock Get-CimInstance {
                param($ClassName)
                if ($ClassName -eq 'Win32_ReliabilityRecords') { throw 'Provider load failure' }
                if ($ClassName -eq '__Provider') { return [pscustomobject]@{ Name='ReliabilityMetricsProvider' } }
                if ($ClassName -eq 'Win32_OperatingSystem') { return [pscustomobject]@{ ProductType=3 } }
            }

            @(Get-LVReliabilityRecord -DaysBack 30).Count | Should -Be 0
            $script:LVReliabilityAvailable | Should -BeFalse
            $script:LVReliabilityStatus | Should -BeExactly 'policy-disabled'
            $script:LVReliabilitySkipReason | Should -Match 'Windows Server disables'
        }
    }

    It 'reports an enabled provider whose records cannot be read as unreadable' {
        InModuleScope LogVerdict {
            Mock Get-ItemProperty { [pscustomobject]@{ WMIEnable = 1 } } -ParameterFilter { $LiteralPath -like '*Reliability Analysis*' }
            Mock Get-CimInstance { throw 'record query failed' } -ParameterFilter { $ClassName -eq 'Win32_ReliabilityRecords' }
            Mock Get-CimInstance { [pscustomobject]@{ Name='ReliabilityMetricsProvider' } } -ParameterFilter { $ClassName -eq '__Provider' }

            @(Get-LVReliabilityRecord -DaysBack 30).Count | Should -Be 0
            $script:LVReliabilityAvailable | Should -BeFalse
            $script:LVReliabilityStatus | Should -BeExactly 'unreadable'
            $script:LVReliabilitySkipReason | Should -Match 'record query failed'
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

    It 'rules known reliability sources without demoting unmatched evidence' {
        # Known install records retain their specific rulings. An unrecognized Reliability
        # family must remain unknown so the catch-all cannot demote a lead below the rank
        # promised by the resolver contract.
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
                if ($f.Key -like '*Anything/9999') {
                    $f.Verdict | Should -BeExactly 'unknown' -Because "$($f.Key) has no specific ruling"
                } else {
                    $f.Verdict | Should -Not -BeExactly 'unknown' -Because "$($f.Key) has a specific Reliability ruling"
                }
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
        $candidates[0].match.eventData.all[0].field | Should -BeExactly 'EventData.Image'
        $candidates[0].match.eventData.all[0].endswith | Should -BeExactly '\\powershell.exe'
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

Describe 'Redacted review artifacts' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $script:ReviewExporter = Join-Path $root 'Tools\Export-LogVerdictReviewArtifact.ps1'
        $script:ReviewImporter = Join-Path $root 'Tools\Import-LogVerdictReviewArtifact.ps1'

        function Export-ReviewResultFixture {
            param([string]$Path)

            $result = [pscustomobject][ordered]@{
                Contract = [pscustomobject][ordered]@{ schemaVersion = 1; name = 'LogVerdict.Report'; mode = 'offline' }
                Tool = 'LogVerdict'; Version = '0.8.1'; MachineName = 'HOST-9'
                ScanTime = [datetime]'2026-08-02T12:00:00Z'; DaysBack = 7; Offline = $true
                DatabaseFreshness = [pscustomobject][ordered]@{
                    DateBasis = 'UTC'; DefaultStaleAfterDays = 730; AsOf = [datetime]'2026-08-02'
                    StaleRuleCount = 0; StaleRules = @()
                }
                Coverage = @(); WorstVerdict = 'unknown'; ExitCode = 1
                Findings = @([pscustomobject][ordered]@{
                    Key = 'event|System|100'; RuleId = $null; Verdict = 'unknown'; Confidence = 'none'; Title = 'Unrecognized activity'
                    Source = 'event'; Channel = 'System'; Provider = 'Test'; Id = 100; Count = 2; PerDay = 0.2
                    FirstSeen = [datetime]'2026-08-02T11:00:00Z'; LastSeen = [datetime]'2026-08-02T11:00:01Z'
                    SampleMessage = 'HOST-9 failed for C:\Users\bob'; Samples = @('HOST-9 failed for C:\Users\bob')
                    StructuredData = [pscustomobject]@{ EventData = [pscustomobject]@{ Image = 'C:\Users\bob\app.exe' } }
                })
            }
            $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding UTF8
        }

        function Export-ReviewCandidateFixture {
            param([string]$Path)

            $queue = [pscustomobject][ordered]@{
                schemaVersion = 1
                rules = @([pscustomobject][ordered]@{
                    id = 'SIGMA-review-1'; status = 'unsupported'; confidence = 'draft'; title = '[Sigma review] Test'
                    match = [pscustomobject][ordered]@{ source = 'event'; channel = 'System'; provider = 'Test'; eventId = 100 }
                    falsepositives = @('maintenance by HOST-9')
                    sigma = [pscustomobject][ordered]@{ reviewStatus = 'pending'; sourcePath = 'rules\test.yml'; sourceHash = ('a' * 64) }
                })
            }
            $queue | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding UTF8
        }
    }

    It 'combines stable unknown and candidate ids while redacting evidence' {
        $resultPath = Join-Path $TestDrive 'review-result.json'
        $candidatePath = Join-Path $TestDrive 'review-candidates.json'
        $artifactPath = Join-Path $TestDrive 'review-artifact.json'
        Export-ReviewResultFixture -Path $resultPath
        Export-ReviewCandidateFixture -Path $candidatePath

        $first = & $script:ReviewExporter -ResultPath $resultPath -CandidatePath @($candidatePath, $candidatePath) `
            -OutputPath $artifactPath -GeneratedAt '2026-08-02T12:00:00.0000000Z'
        @($first.items).Count | Should -Be 2
        @($first.items | Select-Object -ExpandProperty id) | Should -Contain 'SIGMA-review-1'
        $unknown = @($first.items | Where-Object { $_.kind -eq 'unknown' })[0]
        $unknown.id | Should -Match '^UNKNOWN-[0-9A-F]{12}$'
        $unknown.evidence.sampleMessage | Should -BeExactly '<MACHINE> failed for C:\Users\<USER>'
        $unknown.evidence.structuredData.EventData.Image | Should -BeExactly 'C:\Users\<USER>\app.exe'
        $unknown.contribution.label | Should -BeExactly 'Rule to write: Test 100'
        $unknown.contribution.status | Should -BeExactly 'test'
        $unknown.contribution.rule.status | Should -BeExactly 'test'
        $unknown.contribution.rule.sources[0].retrieved | Should -BeExactly '2026-08-02'
        $unknown.contribution.issue.title | Should -BeExactly 'Rule to write: Test 100'
        ($unknown | ConvertTo-Json -Depth 30) | Should -Not -Match 'HOST-9'
        $first.privacy.redacted | Should -BeTrue
        $first.privacy.rawEvidence | Should -BeFalse
        $candidate = @($first.items | Where-Object { $_.kind -eq 'candidate' })[0]
        $candidate.falsePositives[0] | Should -BeExactly 'maintenance by <MACHINE>'
        $candidate.provenance.sourceType | Should -BeExactly 'sigma'
        $candidate.fixture.origin | Should -BeExactly 'review-scaffold'
    }

    It 'withholds contribution scaffolds until the result declares UTC freshness' {
        $resultPath = Join-Path $TestDrive 'review-no-freshness.json'
        $artifactPath = Join-Path $TestDrive 'review-no-freshness-artifact.json'
        Export-ReviewResultFixture -Path $resultPath
        $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        $result.PSObject.Properties.Remove('DatabaseFreshness')
        $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $resultPath -Encoding UTF8

        $artifact = & $script:ReviewExporter -ResultPath $resultPath -OutputPath $artifactPath `
            -GeneratedAt '2026-08-02T12:00:00.0000000Z'
        $unknown = @($artifact.items | Where-Object { $_.kind -eq 'unknown' })[0]
        $unknown.PSObject.Properties.Name | Should -Not -Contain 'contribution'
        Test-Path -LiteralPath $artifactPath | Should -BeTrue
    }

    It 'imports review changes as a diff without touching the curated database' {
        $resultPath = Join-Path $TestDrive 'review-diff-result.json'
        $candidatePath = Join-Path $TestDrive 'review-diff-candidates.json'
        $firstPath = Join-Path $TestDrive 'review-first.json'
        $secondPath = Join-Path $TestDrive 'review-second.json'
        $diffPath = Join-Path $TestDrive 'review-diff.json'
        Export-ReviewResultFixture -Path $resultPath
        Export-ReviewCandidateFixture -Path $candidatePath
        & $script:ReviewExporter -ResultPath $resultPath -CandidatePath $candidatePath -OutputPath $firstPath `
            -GeneratedAt '2026-08-02T12:00:00.0000000Z' | Out-Null

        $reviewed = Get-Content -LiteralPath $firstPath -Raw | ConvertFrom-Json
        $unknownId = @($reviewed.items | Where-Object { $_.kind -eq 'unknown' })[0].id
        $candidateId = @($reviewed.items | Where-Object { $_.kind -eq 'candidate' })[0].id
        @($reviewed.items | Where-Object { $_.id -eq $unknownId })[0].review.status = 'accepted'
        $reviewed.items = @($reviewed.items | Where-Object { $_.id -ne $candidateId })
        $reviewed | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $secondPath -Encoding UTF8

        $before = Get-LVTestSha256 -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data\verdicts.json')
        $diff = & $script:ReviewImporter -ArtifactPath $secondPath -ExistingPath $firstPath -OutputPath $diffPath
        $after = Get-LVTestSha256 -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data\verdicts.json')
        $diff.diff.counts.added | Should -Be 0
        $diff.diff.counts.changed | Should -Be 1
        $diff.diff.counts.removed | Should -Be 1
        $diff.reviewed | Should -Contain $unknownId
        $diff.curatedDatabaseUpdated | Should -BeFalse
        $after | Should -BeExactly $before
        (Get-Content -LiteralPath $diffPath -Raw) | Should -Match 'curatedDatabaseUpdated'
    }

    It 'rejects an artifact that claims to contain raw evidence' {
        $path = Join-Path $TestDrive 'review-invalid.json'
        $artifact = [pscustomobject]@{
            schemaVersion = 1; name = 'LogVerdict.ReviewArtifact'; privacy = [pscustomobject]@{ redacted = $false; rawEvidence = $true }
            items = @()
        }
        $artifact | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
        { & $script:ReviewImporter -ArtifactPath $path } | Should -Throw '*redacted=true*'
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

    It 'pairs every structured rule with a positive and rejecting near-miss fixture' {
        InModuleScope LogVerdict {
            $db = Get-LogVerdictDatabase
            $fixtures = Get-LVFixtureSet
            foreach ($rule in @($db.rules | Where-Object { $_.match.eventData })) {
                @($fixtures.fixtures | Where-Object { $_.ruleId -eq $rule.id -and $_.nearMiss -ne $true }).Count |
                    Should -BeGreaterThan 0 -Because "$($rule.id) must prove a positive structured match"
                @($fixtures.fixtures | Where-Object { $_.ruleId -eq $rule.id -and $_.nearMiss -eq $true }).Count |
                    Should -BeGreaterThan 0 -Because "$($rule.id) must prove its structured near miss is rejected"
            }
        }
    }

    It 'catches a structured rule broadened past its near miss' {
        $path = Export-BrokenPair -MutateDatabase {
            param($db)
            $rule = @($db.rules | Where-Object id -eq 'LV-0170')[0]
            $rule.match.PSObject.Properties.Remove('eventData')
        }
        $problems = @(Test-LogVerdictDatabase -Path $path -IncludeWarnings | Where-Object RuleId -eq 'LV-0170')
        @($problems | Where-Object { $_.Problem -like '*near-miss fixture*' }).Count | Should -Be 1
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
                if ($f.signature.Channel -eq 'SRUM') {
                    $f.signature.Provider | Should -BeExactly 'Microsoft SRUM ESE' -Because "$($f.ruleId)'s sample must retain SRUM attribution"
                    $f.signature.SampleMessage | Should -Match '^SRUM database state: ' -Because "$($f.ruleId)'s sample must be a line the SRUM collector produces"
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
