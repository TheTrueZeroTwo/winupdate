If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}


# Function to update Windows using PowerShell commands
function Update-WindowsWithPowerShell {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    Install-PackageProvider -Name NuGet -Force
    Import-PackageProvider -Name NuGet
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Get-PSRepository -Name PSGallery | Format-List * -Force
    Install-Module -Name PSWindowsUpdate -Force
    Import-Module -Name PSWindowsUpdate
    Get-WUInstall -MicrosoftUpdate -AcceptAll -Download -Install -IgnoreReboot
}

# Function to update Windows using winget
# Define a global variable to track the number of times winget was tried
$global:Tried_Winget = 0

function Update-WindowsWithWinget {
    # Check if winget is available
    $wingetInstalled = Get-Command -Name winget -ErrorAction SilentlyContinue

    if ($wingetInstalled -ne $null) {
        # If winget is available, use it to upgrade all packages
        winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --disable-interactivity --Force
    } else {
        if ($global:Tried_Winget -eq 0) {
            Write-Host "winget is not installed. Attempting to install it using Install-WinGet function."
            # Call Install-WinGet function to install winget
            Install-WinGet
            # Set the counter to 1
            $global:Tried_Winget = 1
            # Try to run the function again after installing winget
            Update-WindowsWithWinget
        } else {
            Write-Error "Failed to install winget and update packages after retrying. Exiting script."
            return
        }
    }
}

Function Install-WinGet {
	$progressPreference = 'silentlyContinue'
	Write-Information "Downloading WinGet and its dependencies..."
	Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
	Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
	Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx -OutFile Microsoft.UI.Xaml.2.8.x64.appx
	Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
	Add-AppxPackage Microsoft.UI.Xaml.2.8.x64.appx
	Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
}


# Run both functions sequentially
Update-WindowsWithPowerShell
Update-WindowsWithWinget
