#function Show-Menu {
#    param (
#        [string]$Title = 'Menu'
#    )
#    Clear-Host
#    Write-Host "================ $Title ================"
#
#    # Get the content of the current script
#    $currentScriptContent = Get-Content -Path $MyInvocation.MyCommand.ScriptBlock.File -Raw
#
#    # Use regex to find all function definitions in the script
#    $functionNames = [Regex]::Matches($currentScriptContent, 'function\s+([A-Za-z0-9-_]+)\s*{') | ForEach-Object { $_.Groups[1].Value }
#
#    for ($i = 0; $i -lt $functionNames.Count; $i++) {
#        Write-Host "$($i+1): $($functionNames[$i])"
#    }
#    Write-Host "v2"
#    Write-Host "Q: Press 'Q' to quit."
#}



function Download-File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url,
        [string]$Destination = "C:\Intel\"
    )

    if (-not (Test-Path $Destination)) {
        Write-Host "The destination folder $($Destination) does not exist. Creating it now..."
        $null = New-Item -ItemType Directory -Path $Destination
    }

    if ($Destination.EndsWith('\')) {
        $Destination += [System.IO.Path]::GetFileName($Url)
    }

    if (Test-Path $Destination) {
        Write-Host "File $($Destination) already exists. Skipping download."
        return
    }

    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($Url, $Destination)
        Write-Output "File downloaded successfully to $($Destination)"
    } catch {
        Write-Error "Failed to download file: $($_.Exception.Message)"
    }

    if (!(Test-Path $Destination)) {
        Write-Error "Failed to download file to $($Destination)"
    }
}



function Restart-VPNServices {
    # Restart all OpenVPN services
    $openVpnServices = Get-Service | Where-Object { $_.DisplayName -like "OpenVPN*" }
    foreach ($service in $openVpnServices) {
        try {
            Write-Host "Restarting OpenVPN service: $($service.DisplayName)..."
            Restart-Service -InputObject $service
            Write-Host "OpenVPN service $($service.DisplayName) restarted successfully."
        } catch {
            Write-Error "Failed to restart OpenVPN service $($service.DisplayName): $($_.Exception.Message)"
        }
    }

    # Delete all Mini WAN devices
    $miniWanDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.Description -like "*Mini WAN*" }
    foreach ($device in $miniWanDevices) {
        try {
            Write-Host "Deleting Mini WAN device: $($device.Description)..."
            $device.Uninstall()
            Write-Host "Mini WAN device $($device.Description) deleted successfully."
        } catch {
            Write-Error "Failed to delete Mini WAN device $($device.Description): $($_.Exception.Message)"
        }
    }

    # Restart WireGuard if found
    $wireGuardService = Get-Service -Name "WireGuardTunnel$*"
    if ($wireGuardService -ne $null) {
        try {
            Write-Host "Restarting WireGuard service: $($wireGuardService.DisplayName)..."
            Restart-Service -InputObject $wireGuardService
            Write-Host "WireGuard service $($wireGuardService.DisplayName) restarted successfully."
        } catch {
            Write-Error "Failed to restart WireGuard service $($wireGuardService.DisplayName): $($_.Exception.Message)"
        }
    }
}



function Remove-NonDefaultPrintersAndDrivers {
    <#
    Removes non-default printers and their drivers using the PrintManagement module.
    Excludes Microsoft drivers, OneNote, Nitro PDF, fax, and PDF printers.
    #>

    try {
        # Enumerate all printers and filter out non-default printers to remove
        $printers = Get-Printer | Where-Object {
            -not $_.IsDefault -and
            $_.Name -notlike "Microsoft*" -and
            $_.Name -notlike "*OneNote*" -and
            $_.Name -notlike "*Nitro PDF*" -and
            $_.Name -notlike "*Fax*" -and
            $_.Name -notlike "*PDF*"
        }

        foreach ($printer in $printers) {
            $printerName = $printer.Name
            Write-Host "Removing Printer: $printerName"
            Remove-Printer -Name $printerName
        }

        Write-Host "Non-default printers removed, excluding Microsoft drivers, OneNote, Nitro PDF, fax, and PDF printers."

        # Enumerate all printer drivers and filter out non-Microsoft drivers to remove
        $drivers = Get-PrinterDriver | Where-Object { $_.Name -notlike "Microsoft*" }

        foreach ($driver in $drivers) {
            $driverName = $driver.Name
            Write-Host "Removing Printer Driver: $driverName"
            Remove-PrinterDriver -Name $driverName
        }

        Write-Host "Non-Microsoft printer drivers removed."

        # Run gpupdate /force
        Write-Host "Running gpupdate /force..."
        Invoke-Expression -Command "gpupdate /force"
        Write-Host "gpupdate /force completed."
    } catch {
        Write-Error "An error occurred: $($_.Exception.Message)"
    }
}

function explorer {
    # Explorer++
    $smPath = "C:\Intel\ExplorerPlusPlusPortable_1.4.0_Beta_2.paf.exe"
    if (Test-Path $smPath) {
        Write-Host "Explorer++ Portable is already installed at $($smPath)."
        Start-Process $smPath
    } else {
        # Download and run Explorer++ Portable
        Write-Host "Downloading and running Explorer++ Portable"
        $url = "https://download2.portableapps.com/portableapps/Explorer++Portable/ExplorerPlusPlusPortable_1.4.0_Beta_2.paf.exe"
        $downloadPath = "C:\Intel\ExplorerPlusPlusPortable_1.4.0_Beta_2.paf.exe"
        if (Test-Path $downloadPath) {
            Write-Host "File $($downloadPath) already exists. Skipping download."
        } else {
            try {
                Download-File -Url $url -Destination $downloadPath
                Write-Host "Downloaded Explorer++ Portable to $($downloadPath)."
            } catch {
                Write-Error "Failed to download Explorer++ Portable: $($_.Exception.Message)"
            }
        }
        if (Test-Path $downloadPath) {
            Start-Process $downloadPath
        } else {
            Write-Host "Failed to download Explorer++ Portable."
        }
    }
}






function browser {
    # Check if Sea Monkey Portable is already installed
    $smPath = "C:\Intel\SeaMonkeyPortable_2.53.16_English.paf.exe"
    if (Test-Path $smPath) {
        Write-Host "Sea Monkey Portable is already installed at $($smPath)."
        Start-Process $smPath
    } else {
        # Download and run Sea Monkey Portable
        Write-Host "Downloading and running Sea Monkey Portable"
        $url = "https://download2.portableapps.com/portableapps/SeaMonkeyPortable/SeaMonkeyPortable_2.53.16_English.paf.exe"
        $downloadPath = "C:\Intel\SeaMonkeyPortable_2.53.16_English.paf.exe"
        if (Test-Path $downloadPath) {
            Write-Host "File $($downloadPath) already exists. Skipping download."
        } else {
            try {
                Download-File -Url $url -Destination $downloadPath
                Write-Host "Downloaded Sea Monkey Portable to $($downloadPath)."
            } catch {
                Write-Error "Failed to download Sea Monkey Portable: $($_.Exception.Message)"
            }
        }
        if (Test-Path $downloadPath) {
            Start-Process $downloadPath
        } else {
            Write-Host "Failed to download Sea Monkey Portable."
        }
    }
}

function add_local_user {
    # Add local user
    Write-Host "Adding local user"
    $fullname = Read-Host "Enter full name"
    if ([string]::IsNullOrWhiteSpace($fullname)) {
        Write-Host "Full name cannot be empty."
        return
    }
    $username = Read-Host "Enter username"
    if ([string]::IsNullOrWhiteSpace($username)) {
        Write-Host "Username cannot be empty."
        return
    }
    if (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) {
        Write-Host "Username $($username) already exists."
        return
    }
    $password = Read-Host "Enter password" -AsSecureString
    $confirmPassword = Read-Host "Confirm password" -AsSecureString
    if ($password -ne $confirmPassword) {
        Write-Host "Passwords do not match."
        return
    }
    $logonPasswordChange = Read-Host "Require user to change password at next logon? [Y/N]"
    $logonPasswordChange = ($logonPasswordChange.ToLower() -eq "y")
    $password = ConvertFrom-SecureString $password
    $password = [System.Text.Encoding]::Unicode.GetString($password)
    try {
        New-LocalUser -Name $username -Password $password -AccountNeverExpires $true -PasswordNeverExpires $true -logonpasswordchange $logonPasswordChange -FullName $fullname
        Write-Host "User $($username) has been created."
    } catch {
        Write-Error "Failed to create user: $($_.Exception.Message)"
    }
}


function remove_local_user {
    # Display local users and select one to remove
    Write-Host "Removing local user"
    $users = Get-LocalUser
    if ($users.Count -eq 0) {
        Write-Host "No local users found."
        return
    }
    $users | Format-Table -Property Name, FullName
    $user = Read-Host "Enter username to remove"
    if ([string]::IsNullOrWhiteSpace($user)) {
        Write-Host "User name cannot be empty."
        return
    }
    $userToRemove = $users | Where-Object { $_.Name -eq $user }
    if (!$userToRemove) {
        Write-Host "User $($user) was not found."
        return
    }
    if ($userToRemove.Enabled -eq $false) {
        Write-Host "User $($userToRemove.Name) is disabled and cannot be removed."
        return
    }
    $confirmation = Read-Host "Are you sure you want to remove user $($userToRemove.Name)? [Y/N]"
    if ($confirmation.ToLower() -ne "y") {
        Write-Host "User $($userToRemove.Name) was not removed."
        return
    }
    try {
        Remove-LocalUser -Name $userToRemove.Name
        Write-Host "User $($userToRemove.Name) has been removed."
    } catch {
        Write-Error "Failed to remove user: $($_.Exception.Message)"
    }
}

function dont_sleep_when_lid_closed{
    # don't sleep when lid is closed
    Write-Host "Disabling sleep when lid is closed"
    try {
        powercfg /change -monitor-timeout-ac 0
        powercfg /change -monitor-timeout-dc 0
        powercfg -SETACVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
        powercfg -SETDCVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
        Write-Host "Sleep when lid is closed has been disabled"
    } catch {
        Write-Error "Failed to disable sleep when lid is closed: $($_.Exception.Message)"
    }
}

function gpupdate {
    <#
    Updates group policy on the local computer.
    #>
    Write-Host "Updating group policy"
    try {
        $gpupdate = Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -PassThru -Wait
        if ($gpupdate.ExitCode -eq 0) {
            Write-Host "Group policy updated successfully"
        } else {
            Write-Host "Failed to update group policy. Creating gp report in C:\Intel."
            $reportPath = "C:\Intel\gpupdate_report.html"
            Get-GPReport -Path $reportPath -Domain $env:USERDNSDOMAIN -ReportType Html
        }
    } catch {
        Write-Error "Failed to update group policy: $($_.Exception.Message)"
    }
}

function disable_hwa {
    <#
    Disables hardware acceleration for browsers.
    #>
    $chrome_path = 'HKCU:\Software\Google\Chrome'
    $firefox_path = 'HKCU:\Software\Mozilla\Firefox'
    $edge_path = 'HKCU:\Software\Microsoft\Edge'
    if (Test-Path $chrome_path) {
        Write-Host "Disabling hardware acceleration for Google Chrome"
        try {
            Set-ItemProperty -Path "$chrome_path\HardwareAccelerationModeEnabled" -Name "ValueName" -Value 0
        } catch {
            Write-Error "Failed to disable hardware acceleration for Google Chrome: $($_.Exception.Message)"
        }
    }
    if (Test-Path $firefox_path) {
        Write-Host "Disabling hardware acceleration for Mozilla Firefox"
        try {
            Set-ItemProperty -Path "$firefox_path\Layers.acceleration.disabled" -Name "ValueName" -Value 1
        } catch {
            Write-Error "Failed to disable hardware acceleration for Mozilla Firefox: $($_.Exception.Message)"
        }
    }
    if (Test-Path $edge_path) {
        Write-Host "Disabling hardware acceleration for Microsoft Edge"
        try {
            Set-ItemProperty -Path "$edge_path\GPUAcceleration" -Name "ValueName" -Value 0
        } catch {
            Write-Error "Failed to disable hardware acceleration for Microsoft Edge: $($_.Exception.Message)"
        }
    }
}


function dickcheck{
    # check disk status
    Write-Host "Checking disk status"
    try {
        start powershell {Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/DiskCheck.ps1')}
    } catch {
        Write-Error "Failed to Check Disk: $($_.Exception.Message)"
    }
}


function update_reboot{
    # update and reboot
    Write-Host "Updating and rebooting"
    try {
        start powershell {Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/update-reboot.ps1')}
    } catch {
        Write-Error "Failed to update and reboot: $($_.Exception.Message)"
    }
}

function update_noreboot{
    # update and don't reboot
    Write-Host "Updating and not rebooting"
    try {
        start powershell {Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/update-noreboot.ps1')}
    } catch {
        Write-Error "Failed to update and not reboot: $($_.Exception.Message)"
    }
}

function bluescreen{
    # bluescreen
    Write-Host "Bluescreening"
    try {
        start powershell {Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/peewpw/Invoke-BSOD/master/Invoke-BSOD.ps1')}
    } catch {
        Write-Error "Failed to bluescreen: $($_.Exception.Message)"
    }
}

function check_system_integrity{
    # check system integrity using sfc and dism (restorehealt, component check, scanhealth)
    Write-Host "Checking system integrity"
    try {
        sfc /scannow; dism /online /cleanup-image /restorehealth; Dism /online /Cleanup-Image /StartComponentCleanup
    } catch {
        Write-Error "Failed to check system integrity: $($_.Exception.Message)"
    }
}

function remove_old_profiles {
    <#
    removes profiles that are older than 30 days, excluding the current user and any default Microsoft accounts, as well as any profile with "admin" in the name
    #>
    try {
        $profiles = Get-ChildItem -Path "C:\Users" -Directory | Where-Object {
            $_.Name -ne "Administrator" -and
            $_.Name -notlike "*admin*" -and
            $_.Name -ne "All Users" -and
            $_.Name -ne "Default" -and
            $_.Name -ne "Default User" -and
            $_.Name -ne "Public"
        }
        if ($profiles.Count -eq 0) {
            Write-Host "No user profiles found."
            return
        }
        $current_user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
        $profiles | ForEach-Object {
            $profile = $_
            $profile_age = (Get-Date) - $profile.CreationTime
            if ($profile_age.Days -gt 30 -and $profile.Name -ne $current_user) {
                try {
                    Write-Host "Removing profile $($profile.Name)"
                    Remove-Item -Path $profile.FullName -Recurse -Force
                    Write-Host "Profile $($profile.Name) has been removed."
                } catch {
                    Write-Error "Failed to remove profile $($profile.Name): $($_.Exception.Message)"
                }
            }
        }
    } catch {
        Write-Error "An error occurred while enumerating profiles: $($_.Exception.Message)"
    }
}


function reboot{
    # reboot
    Write-Host "Rebooting"
    try {
        shutdown /r /f /T 0
    } catch {
        Write-Error "Failed to reboot: $($_.Exception.Message)"
    }
}

#Keep this at the bottom of the script


# Specify the functions you want to include in the menu
$functionList = @(
    "update_noreboot",
    "update_reboot",
    "bluescreen",
    "dickcheck",
    "remove_old_profiles",
    "check_system_integrity",
    "disable_hwa",
    "dont_sleep_when_lid_closed",
    "add_local_user",
    "remove_local_user",
    "GPUpdate",
    "browser",
    "explorer",
    "Test",
    "Reboot",
    "Remove-NonDefaultPrintersAndDrivers"
)

do {
    Clear-Host
    Write-Host "             Menu               "
    Write-Host "            V 0.52              "
    Write-Host "================================"
    
    # Display the list of functions
    for ($i = 0; $i -lt $functionList.Count; $i++) {
        Write-Host "$($i+1): $($functionList[$i])"
    }
    
    Write-Host "q. Quit"
    
    $selection = Read-Host "Please make a selection"
    
    if ($selection -eq 'q') {
        break
    }
    
    # Check if the selection is a valid menu option
    if ($selection -in '1'..'15') {  # Adjust the range based on the number of functions
        $selectedFunction = $functionList[$selection - 1]
        Write-Host "You selected: $selectedFunction"
        
        # Execute the selected function
        Invoke-Expression "& `$selectedFunction"
    }
    else {
        Write-Host "Invalid selection. Please try again."
    }
    
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Write-Host ""
} while ($true)


