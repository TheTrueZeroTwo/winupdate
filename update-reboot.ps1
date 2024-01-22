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
function Update-WindowsWithWinget {
    # Check if winget is available
    $wingetInstalled = Get-Command -Name winget -ErrorAction SilentlyContinue

    if ($wingetInstalled -ne $null) {
        # If winget is available, use it to upgrade all packages
        winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --disable-interactivity --Force
    } else {
        Write-Host "winget is not installed. Run the Update-WindowsWithPowerShell function instead."
    }
}

# Run both functions sequentially
Update-WindowsWithPowerShell
Update-WindowsWithWinget

# Reboot the system
Restart-Computer -Force
