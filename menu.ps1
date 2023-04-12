
function Show-Menu {
    param (
        [string]$Title = 'Menu'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    
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

function Download-File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url,
        [Parameter(Mandatory=$true)]
        [string]$Destination
    )

    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($Url, $Destination)
        Write-Output "File downloaded successfully to $Destination"
    } catch {
        Write-Error "Failed to download file: $_.Exception.Message"
    }
}







function print_test{
    # test function
    Write-Host "test"
}

function browser{
    # download and run sea monkey portable
    Write-Host "Downloading and running Sea Monkey Portable"
    Download-File -Url "https://download2.portableapps.com/portableapps/SeaMonkeyPortable/SeaMonkeyPortable_2.53.16_English.paf.exe" -Destination "C:\Intel\SeaMonkeyPortable_2.53.16_English.paf.exe"
    Start-Process "C:\Intel\SeaMonkeyPortable_2.53.16_English.paf.exe"
}


function add_local_user{
    # add local user
    Write-Host "Adding local user"
    $fullname = Read-Host "Enter full name"
    $username = Read-Host "Enter username"
    $password = Read-Host "Enter password"
    $password = ConvertTo-SecureString $password -AsPlainText -Force
    New-LocalUser -Name $username -Password $password -logonpasswordchange:$true -PasswordNeverExpires:$true -AccountNeverExpires:$true -FullName $fullname
}

function remove_local_user{
    # display local users and select one to remove
    Write-Host "Removing local user"
    $users = Get-LocalUser
    $users | Format-Table -Property Name, FullName
    $user = Read-Host "Enter username to remove"
    $userToRemove = $users | Where-Object { $_.Name -eq $user }
    if($userToRemove){
        Remove-LocalUser -Name $userToRemove.Name
        Write-Host "User $($userToRemove.Name) has been removed."
    }else{
        Write-Host "User $($user) was not found."
    }
}


function dont_sleep_when_lid_closed{
    # don't sleep when lid is closed
    Write-Host "Disabling sleep when lid is closed"
    powercfg /change -monitor-timeout-ac 0
    powercfg -SETACVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
    powercfg -SETDCVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
}

function gpupdate{
    # update group policy
    gpupdate /force
}
function disbale_hwa{
    # disable hardware acceleration for browsers
    Write-Host "Disabling hardware acceleration for browsers"
    # Google Chrome
    Set-ItemProperty -Path 'HKCU:\Software\Google\Chrome\HardwareAccelerationModeEnabled' -Value 0
    
    # Mozilla Firefox
    Set-ItemProperty -Path 'HKCU:\Software\Mozilla\Firefox\Layers.acceleration.disabled' -Value 1
    
    # Microsoft Edge
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Edge\GPUAcceleration' -Value 0
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
    $profiles = Get-ChildItem -Path "C:\Users" -Directory | Where-Object { $_.Name -ne "Administrator" }
    $profiles | ForEach-Object {
        $profile = $_
        $profile_age = (Get-Date) - $profile.CreationTime
        if ($profile_age.Days -gt 30) {
            Write-Host "Removing profile $($profile.Name)"
            Remove-Item -Path $profile.FullName -Recurse -Force
        }
    }
}


function reboot{
    # reboot
    Write-Host "Rebooting"
    Restart-Computer -Force
}

do {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection) {
        '1' {
            update_noreboot
        } '2' {
            update_reboot
        } '3' {
            bluescreen
        } '4' {
            remove_old_profiles
        } '5' {
            check_system_integrity
        } '6' {
            disbale_hwa
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
