@{
    # Auto-discovered by PSScriptAnalyzer when the project root is passed as -Path:
    #   Invoke-ScriptAnalyzer -Path . -Recurse -Settings PSScriptAnalyzerSettings.psd1
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # PSAvoidUsingWriteHost
        #
        # Deliberate, and load-bearing. In this codebase a function's output stream IS
        # its return value: Get-LVEventRecord returns records, Resolve-LVVerdict returns
        # findings, ConvertTo-LVTextReport returns a document. Emitting diagnostics on
        # that same stream would have callers silently capture progress chatter as data
        # - an array return where an object was expected, and swallowed logs.
        #
        # Write-Host is therefore the correct channel for human-facing progress here,
        # and Write-LVLog (Private/00-LVCommon.ps1) routes every diagnostic through it
        # while also accumulating a transcript that ships in LogVerdict-Run.log. The
        # analyzer's objection - that Write-Host cannot be captured or redirected - is
        # exactly the property being relied on.
        #
        # Without this exclusion the analyzer reports 25 findings of this one rule and
        # nothing else, which trains contributors to ignore its output entirely.
        'PSAvoidUsingWriteHost',

        # This optional PSScriptAnalyzer 1.25.0 rule is run by the dedicated CI
        # constrained-language audit. Its findings are intentionally non-blocking in
        # the ordinary quality gate because the README documents the deliberate
        # FullLanguage boundary for typed scan, privacy, and WPF paths.
        'PSUseConstrainedLanguageMode',

        # New-LVCoverageRecord is an in-memory object factory. Its New-* verb is part of
        # the project's existing constructor naming convention and does not mutate state.
        'PSUseShouldProcessForStateChangingFunctions'
    )

    Rules = @{
        PSUseConstrainedLanguageMode = @{ Enable = $true }
    }
}
