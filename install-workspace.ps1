[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $InstallerArguments
)

$ErrorActionPreference = "Stop"
$Installer = Join-Path $PSScriptRoot "install_workspace.py"

if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
    throw "Workspace installer was not found: $Installer"
}

$IsWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT

if ($IsWindowsHost) {
    $Candidates = @(
        @{ Name = "python"; Prefix = @() },
        @{ Name = "py"; Prefix = @("-3") },
        @{ Name = "python3"; Prefix = @() }
    )
}
else {
    $Candidates = @(
        @{ Name = "python3"; Prefix = @() },
        @{ Name = "python"; Prefix = @() }
    )
}

$PythonExecutable = $null
$PythonPrefix = @()
foreach ($Candidate in $Candidates) {
    $Resolved = Get-Command $Candidate.Name -ErrorAction SilentlyContinue
    if (-not $Resolved) {
        continue
    }
    & $Resolved.Source @($Candidate.Prefix) -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" *> $null
    if ($LASTEXITCODE -eq 0) {
        $PythonExecutable = $Resolved.Source
        $PythonPrefix = @($Candidate.Prefix)
        break
    }
}

if (-not $PythonExecutable) {
    throw "Python 3.11 or newer was not found in PATH."
}

& $PythonExecutable @PythonPrefix $Installer @InstallerArguments
$InstallerExitCode = $LASTEXITCODE
exit $InstallerExitCode
