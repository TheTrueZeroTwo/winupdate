Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Install-PackageProvider -Name NuGet -Force
Import-PackageProvider -Name NuGet
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Get-PSRepository -Name PSGallery | Format-List * -Force
Install-Module -Name PSWindowsUpdate -Force
Import-Module -Name PSWindowsUpdate
Get-WUInstall -MicrosoftUpdate -AcceptAll -Download -Install -IgnoreReboot
