param(
    [string]$Filter = ""
)
# Runs the interop harness end-to-end on Windows PowerShell.
#
# Prereqs:
#   - Go (matches go.mod)
#   - Python 3 with: pip install rns lxmf
#   - rnsd.exe on PATH (provided by `pip install rns`)
#
# Usage:
#   pwsh tests/interop/run.ps1                     # run all cases
#   pwsh tests/interop/run.ps1 -Filter ".*short.*" # filter cases via go -run
$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $repoRoot

Write-Host "==> interop harness"
$goArgs = @("test", "-tags=interop", "-v", "-count=1", "-timeout", "5m",
            "./tests/interop/...", "-run", "TestHarness")
if ($Filter -ne "") {
    $goArgs[$goArgs.Length - 1] = "TestHarness/$Filter"
}
& go @goArgs
exit $LASTEXITCODE
