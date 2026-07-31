#Requires -Version 5.1
<#
.SYNOPSIS
    tomofound installer for Windows (PowerShell 5.1+).

.DESCRIPTION
    Windows counterpart of setup.sh. Installs the tomofound MCP server and
    scan-rule prompt into %USERPROFILE%\.tomofound\ and registers the server
    with Claude Desktop, Codex, and/or Gemini CLI.

    Re-running is always safe (idempotent): server files and the skill prompt
    are refreshed, while the venv, cached ATR catalogs, the Trivy binary, and
    historical scan reports are preserved.

    When run from a cloned repo (server\trivy_server.py exists next to this
    script) the installer copies local files; otherwise (e.g. `irm ... | iex`)
    it downloads them from https://raw.githubusercontent.com/rotoyang/tomofound/main/.

.PARAMETER All
    Install shared tomofound assets and configure Claude, Codex, and Gemini
    (default).

.PARAMETER Claude
    Configure Claude Desktop only.

.PARAMETER Codex
    Configure Codex only.

.PARAMETER Gemini
    Configure Gemini CLI only.

.PARAMETER Clean
    Remove all of %USERPROFILE%\.tomofound\ (including reports, catalogs, and
    the Trivy binary) before installing. Confirms with a 5-second abort window.
    Default behaviour preserves these, so -Clean is only needed when you want
    a genuinely fresh install.

.EXAMPLE
    .\setup.ps1
    Configure Claude, Codex, and Gemini CLI (same as -All).

.EXAMPLE
    .\setup.ps1 -Claude
    Configure Claude Desktop only.

.EXAMPLE
    irm https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.ps1 | iex
    Remote one-liner install (defaults to -All).
#>
[CmdletBinding()]
param(
    [switch]$All,
    [switch]$Claude,
    [switch]$Codex,
    [switch]$Gemini,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

# Path of this script when run as a file; $null when piped through
# `irm ... | iex`. Used by Stop-Setup to pick the right abort mechanism.
$ScriptFilePath = $MyInvocation.MyCommand.Path

function Stop-Setup {
    # Abort the installer. `exit 1` is correct for a script file, but under
    # `irm ... | iex` it would close the user's interactive console (hiding
    # the guidance we just printed), so throw instead in that case.
    param([Parameter(Mandatory = $true)][string]$Reason)
    if ($script:ScriptFilePath) { exit 1 }
    throw $Reason
}

# PowerShell 7+ also runs on macOS/Linux; this installer is Windows-only
# (setup.sh covers macOS). Windows PowerShell 5.1 has no $IsWindows variable
# and is always Windows, so only Core needs the check.
if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    Write-Host 'setup.ps1 supports Windows only. On macOS, use setup.sh instead. Aborting.'
    Stop-Setup -Reason 'tomofound setup aborted: Windows only (use setup.sh on macOS).'
}

# Stock Windows PowerShell 5.1 defaults to TLS 1.0 for Invoke-WebRequest;
# GitHub requires TLS 1.2+.
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# The progress bar makes Invoke-WebRequest several times slower on Windows
# PowerShell 5.1; this script downloads five files.
$ProgressPreference = 'SilentlyContinue'

# Resolve the home directory the SERVER will use, not the one PowerShell
# prefers. trivy_server.py builds every path from os.path.expanduser("~"),
# and CPython's ntpath.expanduser reads USERPROFILE first, falling back to
# HOMEDRIVE+HOMEPATH. PowerShell's $HOME is always HOMEDRIVE+HOMEPATH. Those
# agree on a stock machine but diverge under Active Directory home-folder
# redirection, where HOMEPATH points at a network share: the installer would
# write to H:\.tomofound while the server looked in C:\Users\<name>\.tomofound,
# leaving it with no venv, no catalogs, and assets sitting outside the read
# prefixes its own path checks derive from "~".
$UserHome         = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }

$BaseUrl          = 'https://raw.githubusercontent.com/rotoyang/tomofound/main'
$DataRoot         = Join-Path $UserHome '.tomofound'
$ServerDir        = Join-Path $DataRoot 'server'
$SkillDir         = Join-Path $DataRoot 'skills\security-scan'
$VenvDir          = Join-Path $DataRoot 'venv'
$CatalogsDir      = Join-Path $DataRoot 'catalogs'
$ToolsDir         = Join-Path $DataRoot 'tools'
$ReportsDir       = Join-Path $DataRoot 'reports'
$ClaudeConfigPath = Join-Path $env:APPDATA 'Claude\claude_desktop_config.json'
$CodexConfigPath  = Join-Path $UserHome '.codex\config.toml'
$CodexSkillDir    = Join-Path $UserHome '.codex\skills\security-scan'
$GeminiSkillDir   = Join-Path $UserHome '.gemini\skills\security-scan'
$ServerPath       = Join-Path $ServerDir 'trivy_server.py'

# Every Python module trivy_server.py imports at runtime must be listed here.
# When adding a new file under server/, also add it to this list, to the
# SERVER_FILES list in setup.sh, AND to the README Supply chain > Repository
# assets table (enforced by CLAUDE.md).
$ServerFiles = @(
    'trivy_server.py',
    'python_analyzer.py',
    'atr_catalog.py'
)

# -----------------------------------------------------------------------------
# Flag resolution: -All (default) configures every client; naming one or more
# of -Claude/-Codex/-Gemini restricts configuration to just those clients.
# -----------------------------------------------------------------------------
$installClaude = $true
$installCodex  = $true
$installGemini = $true
if (($Claude -or $Codex -or $Gemini) -and -not $All) {
    $installClaude = [bool]$Claude
    $installCodex  = [bool]$Codex
    $installGemini = [bool]$Gemini
}

# -----------------------------------------------------------------------------
# Local checkout vs remote install. setup.sh's `curl | bash` flow always
# fetches from BASE_URL; the PowerShell equivalent (`irm ... | iex`) has no
# $PSScriptRoot, so it downloads too. When the script runs from a cloned repo,
# copy the working-tree files instead so local changes are installable.
# -----------------------------------------------------------------------------
$RepoRoot = $null
if ($PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'server\trivy_server.py'))) {
    $RepoRoot = $PSScriptRoot
}

function Install-Asset {
    param(
        [Parameter(Mandatory = $true)][string]$RelPath,   # forward-slash relative path in the repo
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if ($script:RepoRoot) {
        $src = Join-Path $script:RepoRoot ($RelPath -replace '/', '\')
        Copy-Item -LiteralPath $src -Destination $Destination -Force
    } else {
        Invoke-WebRequest -UseBasicParsing -Uri "$script:BaseUrl/$RelPath" -OutFile $Destination
    }
}

# -----------------------------------------------------------------------------
# Python detection. The registered MCP command must point at a real CPython
# 3.10+. `py -3` (the official Windows launcher) is preferred; `python` on
# PATH is the fallback. The Microsoft Store alias stub
# (%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe) just opens the Store and
# exits non-zero when given `-c`, so probing filters it out.
# -----------------------------------------------------------------------------
function Get-PythonInfo {
    # Probe a candidate interpreter; return @{ Path; Major; Minor; Version }
    # or $null if it isn't a working CPython. The probe deliberately contains
    # no quote characters (Windows PowerShell 5.1 mangles embedded quotes when
    # passing arguments to native executables).
    param([Parameter(Mandatory = $true)][string[]]$Command)
    $probe = 'import sys; print(sys.executable); print(sys.version_info[0]); print(sys.version_info[1])'
    $exe = $Command[0]
    $extraArgs = @()
    if ($Command.Count -gt 1) { $extraArgs = @($Command[1..($Command.Count - 1)]) }
    $allArgs = $extraArgs + @('-c', $probe)
    $out = $null
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $exe @allArgs 2>$null
    } catch {
        $out = $null
    } finally {
        $ErrorActionPreference = $prevEap
    }
    if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
    $lines = @(@($out) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($lines.Count -lt 3) { return $null }
    $major = 0
    $minor = 0
    if (-not [int]::TryParse($lines[$lines.Count - 2], [ref]$major)) { return $null }
    if (-not [int]::TryParse($lines[$lines.Count - 1], [ref]$minor)) { return $null }
    return @{
        Path    = $lines[0]
        Major   = $major
        Minor   = $minor
        Version = "$major.$minor"
    }
}

function Test-PythonVersionOk {
    param([Parameter(Mandatory = $true)][hashtable]$Info)
    return ($Info.Major -gt 3 -or ($Info.Major -eq 3 -and $Info.Minor -ge 10))
}

function Find-Python310 {
    # Returns the first CPython >= 3.10 found (py launcher first, then python
    # on PATH), or $null. Collects human-readable diagnostics in
    # $script:PythonDiagnostics for the failure message.
    $script:PythonDiagnostics = @()

    if (Get-Command py -ErrorAction SilentlyContinue) {
        $info = Get-PythonInfo -Command @('py', '-3')
        if ($info) {
            if (Test-PythonVersionOk -Info $info) { return $info }
            $script:PythonDiagnostics += "py launcher: Python $($info.Version) at $($info.Path) is too old (need 3.10+)"
        } else {
            $script:PythonDiagnostics += "py launcher is present but 'py -3' did not run (no Python 3 registered with it)"
        }
    }

    $pyCmd = Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pyCmd) {
        $src = $pyCmd.Source
        if (-not $src) { $src = $pyCmd.Path }
        $info = Get-PythonInfo -Command @($src)
        if ($info) {
            if (Test-PythonVersionOk -Info $info) { return $info }
            $script:PythonDiagnostics += "python on PATH: Python $($info.Version) at $($info.Path) is too old (need 3.10+)"
        } elseif ($src -like '*\Microsoft\WindowsApps\*') {
            $script:PythonDiagnostics += "python on PATH at $src is the Microsoft Store alias stub (it opens the Store instead of running Python) - ignored"
        } else {
            $script:PythonDiagnostics += "python on PATH at $src failed to run - ignored"
        }
    }

    return $null
}

function Write-FileAtomic {
    # Replace a file in one step. WriteAllText truncates in place, so a failure
    # part-way through (full disk, AV interception, power loss) would leave the
    # target half-written — and for claude_desktop_config.json that means the
    # user loses every OTHER MCP server they had registered, not just ours.
    # Same .tmp-then-replace shape trivy_server._save_scan_state() already uses.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $tmp = "$Path.tomofound-tmp"
    [System.IO.File]::WriteAllText($tmp, $Content)
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Backup-FileOnce {
    # Keep one pre-tomofound copy of a config file we did not author. Rewriting
    # it round-trips the whole document through ConvertFrom-Json/ConvertTo-Json,
    # which is not byte-faithful (non-ASCII is escaped, key order is not
    # preserved). The result is valid JSON, but the user should still have their
    # original. Only the first run backs up, so re-running never overwrites it.
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $backup = "$Path.tomofound-backup"
    if (Test-Path -LiteralPath $backup) { return }
    try {
        Copy-Item -LiteralPath $Path -Destination $backup -ErrorAction Stop
        Write-Host "[i] Backed up your existing config to $backup"
    } catch {
        Write-Host "[!] Could not back up ${Path}: $($_.Exception.Message)"
    }
}

function ConvertTo-TomlString {
    # Prefer a TOML literal string (no escaping needed for Windows
    # backslashes); fall back to a basic string when the value contains a
    # single quote.
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value.Contains("'")) {
        return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
    }
    return "'" + $Value + "'"
}

# -----------------------------------------------------------------------------
# Pre-flight: detect existing install and tell the user what we'll touch.
# Re-running setup.ps1 is safe - server files and the skill prompt are
# overwritten, the venv self-refreshes deps via the _DEPS_VERSION marker, and
# catalogs / Trivy binary / historical reports are explicitly preserved.
# -----------------------------------------------------------------------------
if (Test-Path -LiteralPath $DataRoot) {
    Write-Host ''
    Write-Host "Existing install detected at ${DataRoot}:"
    if (Test-Path -LiteralPath $ServerDir) {
        $serverCount = @(Get-ChildItem -LiteralPath $ServerDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -eq '.py' }).Count
        Write-Host "   - server\        - $serverCount Python module(s) (will be refreshed)"
    }
    if (Test-Path -LiteralPath $SkillDir) {
        Write-Host '   - skills\        - security-scan prompt (will be refreshed)'
    }
    if (Test-Path -LiteralPath $VenvDir) {
        $markerPath = Join-Path $VenvDir '.tomofound-deps'
        if (Test-Path -LiteralPath $markerPath) {
            $marker = ''
            try { $marker = (Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop).Trim() } catch { }
            if (-not $marker) { $marker = '?' }
            Write-Host "   - venv\          - preserved (deps version $marker; will auto-refresh on next server start if changed)"
        } else {
            Write-Host '   - venv\          - preserved (legacy install; will auto-install missing deps on next server start)'
        }
    }
    if (Test-Path -LiteralPath $CatalogsDir) {
        $catalogCount = @(Get-ChildItem -LiteralPath $CatalogsDir -Directory -ErrorAction SilentlyContinue).Count
        Write-Host "   - catalogs\      - $catalogCount cached catalog(s) preserved (run atr_update via Claude to refresh)"
    }
    if (Test-Path -LiteralPath $ToolsDir) {
        if ((Test-Path -LiteralPath (Join-Path $ToolsDir 'trivy.exe')) -or (Test-Path -LiteralPath (Join-Path $ToolsDir 'trivy'))) {
            Write-Host '   - tools\trivy    - preserved (auto-managed by Trivy itself)'
        } else {
            Write-Host '   - tools\         - preserved'
        }
    }
    if (Test-Path -LiteralPath $ReportsDir) {
        $reportCount = @(Get-ChildItem -LiteralPath $ReportsDir -File -ErrorAction SilentlyContinue).Count
        if ($reportCount -gt 0) {
            Write-Host "   - reports\       - $reportCount historical scan(s) preserved"
        }
    }
    Write-Host ''
}

if ($Clean -and (Test-Path -LiteralPath $DataRoot)) {
    Write-Host "-Clean: about to delete the entire $DataRoot directory."
    Write-Host '   This wipes reports, cached catalogs, the Trivy binary, and the venv.'
    Write-Host '   Press Ctrl-C within 5 seconds to abort.'
    for ($i = 5; $i -ge 1; $i--) {
        Write-Host -NoNewline "   $i... "
        Start-Sleep -Seconds 1
    }
    Write-Host ''
    Remove-Item -LiteralPath $DataRoot -Recurse -Force
    Write-Host '   Removed.'
    Write-Host ''
}

Write-Host 'Setting up tomofound...'
if ($RepoRoot) {
    Write-Host "   (installing from local checkout at $RepoRoot)"
} else {
    Write-Host "   (downloading files from $BaseUrl)"
}

# -----------------------------------------------------------------------------
# Python check (fail fast, before touching any config). The MCP entries
# written for Claude / Codex must point at a real interpreter.
# -----------------------------------------------------------------------------
$python = Find-Python310
if ($python) {
    Write-Host "[OK] Using Python $($python.Version) at $($python.Path)"
} else {
    Write-Host ''
    Write-Host '[X] No usable Python 3.10+ found.'
    foreach ($d in $script:PythonDiagnostics) {
        Write-Host "    - $d"
    }
    Write-Host ''
    Write-Host '    Install Python with:'
    Write-Host ''
    Write-Host '        winget install Python.Python.3.12'
    Write-Host ''
    Write-Host '    then open a NEW terminal window and re-run this installer.'
    Write-Host '    Note: the python.exe under %LOCALAPPDATA%\Microsoft\WindowsApps is a'
    Write-Host '    Microsoft Store alias stub, not a real Python. Disable it under'
    Write-Host '    Settings > Apps > Advanced app settings > App execution aliases,'
    Write-Host '    or just install real Python via winget as above.'
    if ($installClaude -or $installCodex) {
        Stop-Setup -Reason 'tomofound setup aborted: no usable Python 3.10+ found (see guidance above).'
    }
    Write-Host ''
    Write-Host '    Continuing (Gemini-only mode does not write an MCP command), but the'
    Write-Host '    tomofound server itself still needs Python 3.10+ at scan time.'
}

New-Item -ItemType Directory -Force -Path $ServerDir, $SkillDir | Out-Null

foreach ($f in $ServerFiles) {
    Install-Asset -RelPath "server/$f" -Destination (Join-Path $ServerDir $f)
}
Install-Asset -RelPath 'skills/security-scan/security-scan.md' -Destination (Join-Path $SkillDir 'security-scan.md')
Write-Host "[OK] Server ($($ServerFiles.Count) modules) + prompt source installed to $DataRoot"

# -----------------------------------------------------------------------------
# Post-install reconciliation: warn about orphan .py files in server\ that the
# current version doesn't ship. We don't auto-delete - leftover files are
# harmless, but the user deserves to know what's there.
# -----------------------------------------------------------------------------
$orphans = @(Get-ChildItem -LiteralPath $ServerDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -eq '.py' -and $ServerFiles -notcontains $_.Name })
if ($orphans.Count -gt 0) {
    Write-Host ''
    Write-Host "[!] Orphan files in $ServerDir\ - not used by this version:"
    foreach ($o in $orphans) {
        Write-Host "   - $($o.Name)"
    }
    $orphanList = ($orphans | ForEach-Object { "'$($_.FullName)'" }) -join ', '
    Write-Host "   Safe to remove. Run: Remove-Item $orphanList"
}

# -----------------------------------------------------------------------------
# Claude Desktop: merge the tomofound entry into claude_desktop_config.json,
# preserving every other key (other MCP servers, preferences, ...).
# -----------------------------------------------------------------------------
if ($installClaude) {
    $claudeDir = Split-Path -Parent $ClaudeConfigPath
    New-Item -ItemType Directory -Force -Path $claudeDir | Out-Null

    $config = $null
    if (Test-Path -LiteralPath $ClaudeConfigPath) {
        try {
            $raw = Get-Content -LiteralPath $ClaudeConfigPath -Raw -ErrorAction Stop
            if ($raw -and $raw.Trim()) { $config = $raw | ConvertFrom-Json }
        } catch {
            $config = $null   # unparseable config -> start fresh, same as setup.sh
        }
    }
    if ($null -eq $config -or $config.GetType().Name -ne 'PSCustomObject') {
        $config = New-Object -TypeName PSObject
    }

    $serversProp = $config.PSObject.Properties['mcpServers']
    if (-not $serversProp -or $null -eq $serversProp.Value -or $serversProp.Value.GetType().Name -ne 'PSCustomObject') {
        $config | Add-Member -Force -MemberType NoteProperty -Name 'mcpServers' -Value (New-Object -TypeName PSObject)
    }
    $servers = $config.mcpServers

    $unchanged = $false
    $existingProp = $servers.PSObject.Properties['tomofound']
    if ($existingProp -and $null -ne $existingProp.Value) {
        $existing = $existingProp.Value
        try {
            $existingArgs = @($existing.args)
            if ("$($existing.command)" -ceq $python.Path -and
                $existingArgs.Count -eq 1 -and
                "$($existingArgs[0])" -ceq $ServerPath -and
                @($existing.PSObject.Properties).Count -eq 2) {
                $unchanged = $true
            }
        } catch {
            $unchanged = $false
        }
    }

    if ($unchanged) {
        Write-Host '[i] MCP server already registered (no change)'
    } else {
        $entry = [PSCustomObject]@{
            command = $python.Path
            args    = @([string]$ServerPath)
        }
        $servers | Add-Member -Force -MemberType NoteProperty -Name 'tomofound' -Value $entry
        $json = $config | ConvertTo-Json -Depth 32
        Backup-FileOnce -Path $ClaudeConfigPath
        Write-FileAtomic -Path $ClaudeConfigPath -Content ($json + "`n")
        Write-Host "[OK] MCP server registered in $ClaudeConfigPath"
    }
}

# -----------------------------------------------------------------------------
# Codex: install the skill wrapper and register the MCP server in config.toml
# (replace our existing block in place, or append; never touch other tables).
# -----------------------------------------------------------------------------
if ($installCodex) {
    New-Item -ItemType Directory -Force -Path $CodexSkillDir, (Split-Path -Parent $CodexConfigPath) | Out-Null
    Install-Asset -RelPath 'integrations/codex/skills/security-scan/SKILL.md' -Destination (Join-Path $CodexSkillDir 'SKILL.md')
    Write-Host "[OK] Codex skill installed to $CodexSkillDir"

    $block = "[mcp_servers.tomofound]`n" +
             "args = [$(ConvertTo-TomlString -Value $ServerPath)]`n" +
             "command = $(ConvertTo-TomlString -Value $python.Path)`n" +
             "startup_timeout_sec = 120`n"

    $text = ''
    if (Test-Path -LiteralPath $CodexConfigPath) {
        $raw = Get-Content -LiteralPath $CodexConfigPath -Raw -ErrorAction SilentlyContinue
        if ($raw) { $text = $raw }
    }

    $pattern = '(?ms)^\[mcp_servers\.tomofound\][ \t]*\r?\n.*?(?=^\[|\z)'
    if ([regex]::IsMatch($text, $pattern)) {
        $replacement = $block.Replace('$', '$$')   # escape for .NET regex substitution
        $newText = ([regex]::Replace($text, $pattern, $replacement)).TrimEnd() + "`n"
    } else {
        $sep = ''
        if ($text.Trim()) { $sep = "`n`n" }
        $newText = $text.TrimEnd() + $sep + $block
    }

    if ($newText -ceq $text) {
        Write-Host '[i] Codex MCP server already registered (no change)'
    } else {
        Backup-FileOnce -Path $CodexConfigPath
        Write-FileAtomic -Path $CodexConfigPath -Content $newText
        Write-Host "[OK] Codex MCP server registered in $CodexConfigPath"
    }
}

# -----------------------------------------------------------------------------
# Gemini CLI: install the skill wrapper.
# -----------------------------------------------------------------------------
if ($installGemini) {
    New-Item -ItemType Directory -Force -Path $GeminiSkillDir | Out-Null
    Install-Asset -RelPath 'integrations/gemini/skills/security-scan/SKILL.md' -Destination (Join-Path $GeminiSkillDir 'SKILL.md')
    Write-Host "[OK] Gemini skill installed to $GeminiSkillDir"
}

Write-Host ''
Write-Host '---------------------------------------------'
Write-Host 'Installation complete. Next steps:'
Write-Host ''
if ($installClaude) {
    Write-Host '  - Quit Claude Desktop fully (right-click the system-tray icon and'
    Write-Host '    choose Quit - closing the window is not enough) and reopen it.'
    Write-Host '    Type "/" in any chat - you should see /security_scan.'
}
if ($installCodex) {
    Write-Host '  - Restart Codex or open a new Codex thread.'
    Write-Host '    Invoke the security-scan skill when auditing extensions.'
}
if ($installGemini) {
    Write-Host '  - Restart Gemini CLI or open a new session.'
    Write-Host '    Invoke the security-scan skill when auditing extensions.'
}
Write-Host '---------------------------------------------'
