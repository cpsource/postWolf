<#
.SYNOPSIS
  Register the postWolf mqc native-messaging host with Chrome (and
  optionally Edge) for the current user.

.DESCRIPTION
  Substitutes absolute paths + the caller-supplied extension ID into
  com.postwolf.mqc.json.template, writes the resulting manifest next
  to this script, and creates the HKCU registry entry that Chrome /
  Edge use to discover native-messaging hosts.

  Nothing here requires admin; everything lives in HKCU.

.PARAMETER ExtensionId
  The 32-character Chrome extension ID (e.g.
  abcdefghijklmnopqrstuvwxyzabcdef).  Find it at chrome://extensions
  after loading the unpacked extension.

.PARAMETER Browser
  'chrome' (default), 'edge', or 'both'.

.PARAMETER WslDistro
  If set, the shim passes `-d <distro>` to wsl.exe on every call.
  Useful when the default WSL distro doesn't have mqc installed.

.PARAMETER WslUser
  If set, the shim passes `-u <user>` to wsl.exe.  Useful when your
  Windows username maps to a WSL user that lacks mqc but a different
  user (e.g. 'ubuntu') has it.

.PARAMETER MqcPath
  Absolute path to the mqc binary inside WSL.  Default
  /usr/local/bin/mqc matches what install-mqc-kit.sh installs.
  Only override if you've put mqc somewhere else.

.EXAMPLE
  .\install.ps1 -ExtensionId abcdefghijklmnopqrstuvwxyzabcdef

.EXAMPLE
  .\install.ps1 -ExtensionId abcdefghijklmnopqrstuvwxyzabcdef `
                -WslDistro Ubuntu -WslUser ubuntu
#>
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId,

    [ValidateSet('chrome','edge','both')]
    [string]$Browser = 'chrome',

    [string]$WslDistro = '',
    [string]$WslUser   = '',
    [string]$MqcPath   = '/usr/local/bin/mqc'
)

$ErrorActionPreference = 'Stop'

$HostName     = 'com.postwolf.mqc'
$Here         = Split-Path -Parent $MyInvocation.MyCommand.Path
$Template     = Join-Path $Here 'com.postwolf.mqc.json.template'
$Manifest     = Join-Path $Here 'com.postwolf.mqc.json'
$HostLauncher = Join-Path $Here 'mqc_native_host.cmd'
$HostScript   = Join-Path $Here 'mqc_native_host.py'

# Sanity checks
if (-not (Test-Path $Template)) { throw "missing template: $Template" }
if (-not (Test-Path $HostScript)) { throw "missing host script: $HostScript" }
if (-not (Test-Path $HostLauncher)) { throw "missing host launcher: $HostLauncher" }

# Persist WSL/mqc knobs for the user, so mqc_native_host.py reads
# them whenever Chrome spawns it.  These are plain user env vars —
# no admin needed, visible via `[Environment]::GetEnvironmentVariable(...)`.
function Set-UserEnvVar([string]$Name, [string]$Value) {
    if ($Value) {
        [Environment]::SetEnvironmentVariable($Name, $Value, 'User')
        Write-Host "set env (user): $Name=$Value"
    } else {
        # Explicit empty string → clear the var.
        if ([Environment]::GetEnvironmentVariable($Name, 'User')) {
            [Environment]::SetEnvironmentVariable($Name, $null, 'User')
            Write-Host "cleared env (user): $Name"
        }
    }
}
Set-UserEnvVar 'MQC_WSL_DISTRO' $WslDistro
Set-UserEnvVar 'MQC_WSL_USER'   $WslUser
if ($MqcPath -ne '/usr/local/bin/mqc') {
    Set-UserEnvVar 'MQC_WSL_PATH' $MqcPath
} else {
    Set-UserEnvVar 'MQC_WSL_PATH' ''
}

# Write the manifest with absolute paths + extension ID baked in
$t = Get-Content -Raw $Template
$t = $t.Replace('__HOST_PATH__', ($HostLauncher -replace '\\','\\'))
$t = $t.Replace('__EXTENSION_ID__', $ExtensionId)
Set-Content -Path $Manifest -Value $t -Encoding UTF8
Write-Host "wrote manifest: $Manifest"

# Register under HKCU for the requested browser(s)
function Register-Browser([string]$browserKey) {
    $regPath = "HKCU:\Software\$browserKey\NativeMessagingHosts\$HostName"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name '(Default)' -Value $Manifest
    Write-Host "registered: $regPath -> $Manifest"
}

switch ($Browser) {
    'chrome' { Register-Browser 'Google\Chrome' }
    'edge'   { Register-Browser 'Microsoft\Edge' }
    'both'   {
        Register-Browser 'Google\Chrome'
        Register-Browser 'Microsoft\Edge'
    }
}

Write-Host ""
Write-Host "Done.  Sanity-check mqc reachability from Windows:"
$wslArgs = @()
if ($WslDistro) { $wslArgs += @('-d', $WslDistro) }
if ($WslUser)   { $wslArgs += @('-u', $WslUser) }
$wslPreview = "wsl " + ($wslArgs -join ' ') + " $MqcPath --help"
Write-Host "    $wslPreview"
Write-Host ""
Write-Host "Then reload the extension at chrome://extensions and click"
Write-Host "the extension's toolbar icon -> 'Ping native host'."
Write-Host ""
Write-Host "Note: env vars take effect in NEW processes only.  Close and"
Write-Host "re-open Chrome so its child processes see the updated"
Write-Host "MQC_WSL_* variables."
