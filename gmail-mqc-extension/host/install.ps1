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

.EXAMPLE
  .\install.ps1 -ExtensionId abcdefghijklmnopqrstuvwxyzabcdef

.EXAMPLE
  .\install.ps1 -ExtensionId abcdefghijklmnopqrstuvwxyzabcdef -Browser both
#>
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId,

    [ValidateSet('chrome','edge','both')]
    [string]$Browser = 'chrome'
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
Write-Host "Done.  Test with (from a WSL-enabled shell):"
Write-Host "    wsl mqc --help"
Write-Host ""
Write-Host "Then from Windows:"
Write-Host "    & '$HostLauncher'  # should wait for length-prefixed stdin"
Write-Host ""
Write-Host "Reload the extension at chrome://extensions after this."
