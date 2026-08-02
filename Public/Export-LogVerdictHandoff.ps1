function Export-LogVerdictHandoff {
    <#
        .SYNOPSIS
        Write deterministic collection recipes and attributed Timesketch/Hayabusa CSV and JSONL timelines.

        .DESCRIPTION
        The handoff contains no raw EVTX. It projects normalized findings into the
        mandatory Timesketch fields, a Hayabusa-style CSV timeline, and a versioned
        JSONL timeline, retaining the LogVerdict profile id and source hashes on every row.
        KAPE and Velociraptor
        recipes describe the bounded collection scope and are emitted alongside a
        JSON manifest. No network or external tool is required.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Result,
        [string]$ProfilePath,
        [object]$Profile,
        [string]$OutputDir,
        [switch]$Redact
    )

    process {
        if ($ProfilePath -and $Profile) { throw 'Supply either -ProfilePath or -Profile, not both.' }
        if ($ProfilePath) { $Profile = Read-LVCaseProfile -Path $ProfilePath }
        if (-not $Profile -and $Result.PSObject.Properties['CaseProfile'] -and $Result.CaseProfile) { $Profile = $Result.CaseProfile }
        if (-not $Profile) { $Profile = New-LVCaseProfileObject -Result $Result -Redact:$Redact }
        $profileProblems = @(Get-LVCaseProfileProblems -Profile $Profile)
        if ($profileProblems.Count -gt 0) { throw ('Case profile validation failed: ' + ($profileProblems -join '; ')) }
        if ($Redact -and -not $Profile.redaction.requested) {
            $Profile = ConvertTo-LVCaseRedactedProfile -Profile $Profile -MachineName $Result.MachineName
        }

        if (-not $OutputDir) {
            $OutputDir = Join-Path ([Environment]::GetFolderPath('Desktop')) ('LogVerdict-Handoff_{0}' -f $Profile.profileId.Substring(0, 16))
        }
        if (-not $PSCmdlet.ShouldProcess($OutputDir, 'Write LogVerdict collection handoff')) { return }
        if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

        $rows = @(ConvertTo-LVCaseHandoffRows -Result $Result -Profile $Profile -Redact:([bool]($Redact -or $Profile.redaction.requested)))
        $timesketch = foreach ($row in $rows) {
            [pscustomobject][ordered]@{
                message = $row.message
                timestamp = $row.timestamp
                datetime = $row.datetime
                timestamp_desc = $row.timestamp_desc
                source = $row.source; channel = $row.channel; provider = $row.provider
                event_id = $row.event_id; computer = $row.computer
                rule_title = $row.rule_title; rule_id = $row.rule_id; verdict = $row.verdict
                occurrence_count = $row.occurrence_count; signature_key = $row.signature_key
                logverdict_tool = $row.logverdict_tool; logverdict_version = $row.logverdict_version
                logverdict_profile_id = $row.logverdict_profile_id; logverdict_source_sha256 = $row.logverdict_source_sha256
            }
        }
        $hayabusa = foreach ($row in $rows) {
            [pscustomobject][ordered]@{
                Timestamp = $row.datetime
                RuleTitle = $row.rule_title
                RuleFile = 'LogVerdict/' + $row.rule_id
                Level = $row.verdict.ToUpperInvariant()
                Computer = $row.computer
                Channel = $row.channel
                EventID = $row.event_id
                RecordID = $null
                Details = $row.message
                ExtraFieldInfo = ('LogVerdict profile {0}; source SHA-256 {1}' -f $row.logverdict_profile_id, $row.logverdict_source_sha256)
                MitreTactics = $null
                MitreTags = $null
                logverdict_profile_id = $row.logverdict_profile_id
                logverdict_source_sha256 = $row.logverdict_source_sha256
            }
        }

        $files = [ordered]@{
            profile = 'LogVerdict-CaseProfile.json'
            kape = 'LogVerdict-Collection.tkape'
            velociraptor = 'LogVerdict-Collection.yaml'
            timesketch = 'LogVerdict-Timesketch.csv'
            hayabusa = 'LogVerdict-Hayabusa.csv'
            timeline = 'LogVerdict-Timeline.jsonl'
            manifest = 'LogVerdict-Handoff.json'
        }
        $profilePathOut = Join-Path $OutputDir $files.profile
        Write-LVTextFile -Path $profilePathOut -Content ($Profile | ConvertTo-Json -Depth 30)
        Write-LVTextFile -Path (Join-Path $OutputDir $files.kape) -Content (Get-LVCaseKapeRecipe -Profile $Profile)
        Write-LVTextFile -Path (Join-Path $OutputDir $files.velociraptor) -Content (Get-LVCaseVelociraptorRecipe -Profile $Profile)
        $timesketchContent = if (@($timesketch).Count -gt 0) { (($timesketch | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine) + [Environment]::NewLine } else { '' }
        $hayabusaContent = if (@($hayabusa).Count -gt 0) { (($hayabusa | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine) + [Environment]::NewLine } else { '' }
        Write-LVTextFile -Path (Join-Path $OutputDir $files.timesketch) -Content $timesketchContent
        Write-LVTextFile -Path (Join-Path $OutputDir $files.hayabusa) -Content $hayabusaContent
        $timelineResult = if ($Redact -or $Profile.redaction.requested) { ConvertTo-LVRedactedResult -Result $Result } else { $Result }
        $timeline = Write-LVJsonlTimeline -Result $timelineResult -Path (Join-Path $OutputDir $files.timeline) `
            -Redact:([bool]($Redact -or $Profile.redaction.requested))

        $manifest = [pscustomobject][ordered]@{
            schemaVersion = $script:LVCaseHandoffSchemaVersion
            profileId = $Profile.profileId
            attribution = [pscustomobject][ordered]@{ tool = 'LogVerdict'; version = $Result.Version; source = 'normalized findings'; profileId = $Profile.profileId }
            redacted = [bool]($Redact -or $Profile.redaction.requested)
            scan = [pscustomobject][ordered]@{ scanTime = ConvertTo-LVCaseUtcText $Result.ScanTime; daysBack = $Result.DaysBack; findingCount = $rows.Count; correlationCount = @($Result.Correlations | Where-Object { $_ }).Count }
            files = $files
            formats = [pscustomobject][ordered]@{
                timesketch = 'CSV with message, datetime, and timestamp_desc mandatory fields'
                hayabusa = 'CSV timeline projection with RuleTitle, Level, Computer, Channel, EventID, and Details'
                timeline = 'UTF-8 JSONL with one versioned metadata, event, finding, correlation, coverage, or provider record per line'
                recipes = @('KAPE .tkape target', 'Velociraptor CLIENT artifact YAML')
            }
            timelineLineCount = $timeline.LineCount
        }
        Write-LVTextFile -Path (Join-Path $OutputDir $files.manifest) -Content ($manifest | ConvertTo-Json -Depth 30)
        return [pscustomobject][ordered]@{
            OutputDir = $OutputDir
            Profile = $Profile
            Files = @($files.Values | ForEach-Object { Join-Path $OutputDir $_ })
            Manifest = $manifest
        }
    }
}
