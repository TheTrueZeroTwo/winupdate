
function Show-Menu {
    param (
        [string]$Title = 'Menu'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    Get-File
    Write-Host "1: Update and reboot."
    Write-Host "2: Update and don't reboot."
    Write-Host "3: Safe bluescreen of computer."
    Write-Host "4: Remove old profiles."
    Write-Host "5: Check system integrity."
    Write-Host "6: Disable hardware acceleration for browsers."
    Write-Host "7: Disable sleep when lid is closed."
    Write-Host "8: Add local user."
    Write-Host "9: Remove local user."
    Write-Host "10: GPUpdate."
    Write-Host "11: Download and run Sea Monkey Portable."
    Write-Host "12: Test."
    Write-Host "13: Reboot."
    Write-Host "Q: Press 'Q' to quit."
}

function Get-File {
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
        Write-Error "Failed to download file: $_.Exception.Message"
    }

    if (!(Test-Path $Destination)) {
        Write-Error "Failed to download file to $($Destination)"
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
            Get-File -Url $url -Destination $downloadPath
            Write-Host "Downloaded Sea Monkey Portable to $($downloadPath)."
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
    New-LocalUser -Name $username -Password $password -AccountNeverExpires $true -PasswordNeverExpires $true -logonpasswordchange $logonPasswordChange -FullName $fullname
    Write-Host "User $($username) has been created."
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
    Remove-LocalUser -Name $userToRemove.Name
    Write-Host "User $($userToRemove.Name) has been removed."
}


function dont_sleep_when_lid_closed{
    # don't sleep when lid is closed
    Write-Host "Disabling sleep when lid is closed"
    powercfg /change -monitor-timeout-ac 0
    powercfg -SETACVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
    powercfg -SETDCVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
}

function gpupdate {
    <#
    Updates group policy on the local computer.
    #>
    Write-Host "Updating group policy"
    $gpupdate = Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -PassThru -Wait
    if ($gpupdate.ExitCode -eq 0) {
        Write-Host "Group policy updated successfully"
    } else {
        Write-Host "Failed to update group policy. Creating gp report in C:\Intel."
        $reportPath = "C:\Intel\gpupdate_report.html"
        Get-GPReport -Path $reportPath -Domain $env:USERDNSDOMAIN -ReportType Html
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
        Set-ItemProperty -Path "$chrome_path\HardwareAccelerationModeEnabled" -Value 0
    }
    if (Test-Path $firefox_path) {
        Write-Host "Disabling hardware acceleration for Mozilla Firefox"
        Set-ItemProperty -Path "$firefox_path\Layers.acceleration.disabled" -Value 1
    }
    if (Test-Path $edge_path) {
        Write-Host "Disabling hardware acceleration for Microsoft Edge"
        Set-ItemProperty -Path "$edge_path\GPUAcceleration" -Value 0
    }
}



function update_reboot{
    # update and reboot
    Write-Host "Updating and rebooting"
    Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/update-reboot.ps1')
}

function update_noreboot{
    # update and don't reboot
    Write-Host "Updating and not rebooting"
    Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/update-noreboot.ps1')
}

function bluescreen{
    # bluescreen
    Write-Host "Bluescreening"
    Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/peewpw/Invoke-BSOD/master/Invoke-BSOD.ps1')
}

function check_system_integrity{
    # check system integrity using sfc and dism (restorehealt, component check, scanhealth)
    Write-Host "Checking system integrity"
sfc /scannow; dism /online /cleanup-image /restorehealth; Dism /online /Cleanup-Image /StartComponentCleanup    
}


function remove_old_profiles{
    <#
    removes profiles that are older than 30 days, excluding the Administrator profile
    #>
    $user_profiles = Get-ChildItem -Path "C:\Users" -Directory | Where-Object { $_.Name -ne "Administrator" }
    if ($user_profiles.Count -eq 0) {
        Write-Host "No user profiles found."
        return
    }
    $current_user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[1]
    $user_profiles | ForEach-Object {
        $user_profile = $_
        $profile_age = (Get-Date) - $user_profile.CreationTime
        if ($profile_age.Days -gt 30 -and $user_profile.Name -ne $current_user -and $user_profile.Name -ne "Administrator") {
            Write-Host "Removing profile $($user_profile.Name)"
            Remove-Item -Path $user_profile.FullName -Recurse -Force
        }
    }
}



function reboot{
    # reboot
    Write-Host "Rebooting"
    shutdown /r /f /T 0
}

do {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection) {
        '1' {
            update_reboot
        } '2' {
            update_noreboot
        } '3' {
            bluescreen
        } '4' {
            remove_old_profiles
        } '5' {
            check_system_integrity
        } '6' {
            disable_hwa
        } '7' {
            dont_sleep_when_lid_closed
        } '8' {
            add_local_user
        } '9' {
            remove_local_user
        } '10' {
            gpupdate
        } '11' {
            browser
        } '12' {
            print_test
        } '13' {
            reboot
        } 'q' {
            break
        }
        default {
            Write-Host "Invalid selection. Please try again."
        }
    }
    if ($selection -ne 'q') {
        Write-Host "Press any key to continue..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Write-Host ""
    }
} while ($selection -ne 'q')
