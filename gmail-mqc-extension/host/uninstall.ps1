<#
.SYNOPSIS
  Remove the postWolf mqc native-messaging host registrations for
  the current user.  Leaves the manifest + scripts on disk — delete
  the gmail-mqc-extension/host/ folder to finish cleanup.
#>
param(
    [ValidateSet('chrome','edge','both')]
    [string]$Browser = 'both'
)

$ErrorActionPreference = 'Stop'
$HostName = 'com.postwolf.mqc'

function Unregister-Browser([string]$browserKey) {
    $regPath = "HKCU:\Software\$browserKey\NativeMessagingHosts\$HostName"
    if (Test-Path $regPath) {
        Remove-Item -Path $regPath -Force
        Write-Host "removed: $regPath"
    } else {
        Write-Host "not present: $regPath"
    }
}

switch ($Browser) {
    'chrome' { Unregister-Browser 'Google\Chrome' }
    'edge'   { Unregister-Browser 'Microsoft\Edge' }
    'both'   {
        Unregister-Browser 'Google\Chrome'
        Unregister-Browser 'Microsoft\Edge'
    }
}

# Clear MQC_WSL_* user env vars that install.ps1 may have set.
foreach ($v in @('MQC_WSL_DISTRO','MQC_WSL_USER','MQC_WSL_PATH')) {
    if ([Environment]::GetEnvironmentVariable($v, 'User')) {
        [Environment]::SetEnvironmentVariable($v, $null, 'User')
        Write-Host "cleared env (user): $v"
    }
}
