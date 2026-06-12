# Compatibility wrapper. Prefer: iex (irm 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/menu.ps1')
param([switch]$Always, [switch]$IncludeWinget, [switch]$InstallWingetIfMissing)
$baseUrl = if ($env:WINUPDATE_BASEURL) { $env:WINUPDATE_BASEURL.TrimEnd('/') } else { 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main' }
$commonCode = (New-Object Net.WebClient).DownloadString("$baseUrl/Common.ps1")
. ([ScriptBlock]::Create($commonCode))
$mode = if ($Always) { 'Always' } else { 'IfNeeded' }
$args = @('-RebootMode',$mode)
if ($IncludeWinget) { $args += '-IncludeWinget' }
if ($InstallWingetIfMissing) { $args += '-InstallWingetIfMissing' }
Invoke-WumRemoteScript -Name 'Invoke-WinUpdate.ps1' -ArgumentList $args
