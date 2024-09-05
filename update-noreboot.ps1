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
    #Install the latest package from GitHub
    [cmdletbinding(SupportsShouldProcess)]
    [alias("iwg")]
    [OutputType("None")]
    [OutputType("Microsoft.Windows.Appx.PackageManager.Commands.AppxPackage")]
    Param(
        [Parameter(HelpMessage = "Display the AppxPackage after installation.")]
        [switch]$Passthru
    )

    Write-Verbose "[$((Get-Date).TimeofDay)] Starting $($myinvocation.mycommand)"

    if ($PSVersionTable.PSVersion.Major -eq 7) {
        Write-Warning "This command does not work in PowerShell 7. You must install in Windows PowerShell."
        return
    }

    # Test for requirement
    $Requirement = Get-AppPackage "Microsoft.DesktopAppInstaller"
    if (-Not $requirement) {
        Write-Verbose "Installing Desktop App Installer requirement"
        Try {
            Add-AppxPackage -Path "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -ErrorAction Stop
        }
        Catch {
            Throw $_
        }
    }

    $uri = "https://api.github.com/repos/microsoft/winget-cli/releases"

    Try {
        Write-Verbose "[$((Get-Date).TimeofDay)] Getting information from $uri"
        $get = Invoke-RestMethod -uri $uri -Method Get -ErrorAction stop

        Write-Verbose "[$((Get-Date).TimeofDay)] Getting latest release"
        $data = $get[0].assets | Where-Object name -Match 'msixbundle'

        $appx = $data.browser_download_url
        Write-Verbose "[$((Get-Date).TimeofDay)] $appx"
        If ($pscmdlet.ShouldProcess($appx, "Downloading asset")) {
            $file = Join-Path -path $env:temp -ChildPath $data.name

            Write-Verbose "[$((Get-Date).TimeofDay)] Saving to $file"
            Invoke-WebRequest -Uri $appx -UseBasicParsing -DisableKeepAlive -OutFile $file

            Write-Verbose "[$((Get-Date).TimeofDay)] Adding Appx Package"
            Add-AppxPackage -Path $file -ErrorAction Stop

            if ($Passthru) {
                Get-AppxPackage microsoft.desktopAppInstaller
            }
        }
    }
    Catch {
        Write-Verbose "[$((Get-Date).TimeofDay)] There was an error."
        Throw $_
    }
    Write-Verbose "[$((Get-Date).TimeofDay)] Ending $($myinvocation.mycommand)"
}


# Run both functions sequentially
Update-WindowsWithPowerShell
Update-WindowsWithWinget
