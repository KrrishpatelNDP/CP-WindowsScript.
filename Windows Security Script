# Windows Security Script
# by Krrish Patel

# Check for administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Please run this script as an administrator."
    Exit
}

function Get-Choice {
    param([string]$prompt)
    $choice = Read-Host "$prompt (y/n/c)"
    switch ($choice.ToLower()) {
        'y' { return $true }
        'n' { return $false }
        'c' { Exit }
        default { return Get-Choice $prompt }
    }
}

function Enable-Firewall {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Host "Firewall enabled for all profiles."
}

function Disable-Services {
    $mode = Read-Host "Choose mode for disabling services (manual/automatic)"
    $services = @(
        "RemoteRegistry",
        "TelnetClient",
        "SNMP"
        # Add more services as needed
    )

    foreach ($service in $services) {
        if ($mode -eq "manual") {
            if (Get-Choice "Disable $service?") {
                Stop-Service -Name $service -Force
                Set-Service -Name $service -StartupType Disabled
                Write-Host "$service disabled."
            }
        } elseif ($mode -eq "automatic") {
            Stop-Service -Name $service -Force
            Set-Service -Name $service -StartupType Disabled
            Write-Host "$service disabled."
        } else {
            Write-Host "Invalid mode. Skipping services."
            break
        }
    }
}

function Disable-RemoteDesktop {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
    Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Write-Host "Remote Desktop disabled."
}

function Set-RegistryKeys {
    # Add registry modifications here
    # Example:
    # Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0
    Write-Host "Registry keys updated."
}

function Import-Policies {
    $policyPath = ".\Policies"
    if (Test-Path $policyPath) {
        Get-ChildItem $policyPath -Filter *.pol | ForEach-Object {
            secedit /configure /db secedit.sdb /cfg $_.FullName /areas SECURITYPOLICY
        }
        Write-Host "Policies imported."
    } else {
        Write-Host "Policies folder not found."
    }
}

function Disable-DefaultAccounts {
    Disable-LocalUser -Name "Guest"
    Disable-LocalUser -Name "Administrator"
    Write-Host "Guest and Administrator accounts disabled."
}

function Audit-Users {
    $authorizedUsers = Get-Content ".\authorizedusers.txt"
    $currentUsers = Get-LocalUser | Select-Object -ExpandProperty Name

    foreach ($user in $currentUsers) {
        if ($user -notin $authorizedUsers -and $user -notin @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount")) {
            Remove-LocalUser -Name $user
            Write-Host "Removed unauthorized user: $user"
        }
    }

    foreach ($user in $authorizedUsers) {
        if ($user -notin $currentUsers) {
            $password = ConvertTo-SecureString "q1W@e3R`$t5Y^u7I*o9" -AsPlainText -Force
            New-LocalUser -Name $user -Password $password -PasswordNeverExpires
            Write-Host "Added missing user: $user"
        }
    }
}

function Manage-Admins {
    $admins = Get-Content ".\admins.txt"
    $currentAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name

    foreach ($admin in $currentAdmins) {
        if ($admin -notin $admins -and $admin -ne "Administrator") {
            Remove-LocalGroupMember -Group "Administrators" -Member $admin
            Write-Host "Removed from Administrators group: $admin"
        }
    }

    foreach ($admin in $admins) {
        if ($admin -notin $currentAdmins) {
            Add-LocalGroupMember -Group "Administrators" -Member $admin
            Write-Host "Added to Administrators group: $admin"
        }
    }
}

function Set-UserPasswords {
    $currentUser = $env:USERNAME
    $newPassword = ConvertTo-SecureString "q1W@e3R`$t5Y^u7I*o9" -AsPlainText -Force

    Get-LocalUser | Where-Object { $_.Name -ne $currentUser } | ForEach-Object {
        Set-LocalUser -Name $_.Name -Password $newPassword
        Write-Host "Password changed for user: $($_.Name)"
    }
}

function Remove-DisallowedMediaFiles {
    $fileTypes = @("*.mp3", "*.mov", "*.mp4", "*.avi", "*.mpg", "*.mpeg", "*.flac", "*.m4a", "*.flv", "*.ogg", "*.gif", "*.png", "*.jpg", "*.jpeg")
    $mode = Read-Host "Choose mode for deleting files (manual/automatic)"

    foreach ($fileType in $fileTypes) {
        if ($mode -eq "manual") {
            if (Get-Choice "Search for $fileType files?") {
                Get-ChildItem -Path C:\Users -Recurse -Include $fileType | ForEach-Object {
                    $choice = Read-Host "Delete $($_.FullName)? (y/n/o)"
                    switch ($choice.ToLower()) {
                        'y' { Remove-Item $_.FullName -Force }
                        'o' { Start-Process explorer.exe -ArgumentList "/select,$($_.FullName)" }
                    }
                }
            }
        } elseif ($mode -eq "automatic") {
            Get-ChildItem -Path C:\Users -Recurse -Include $fileType | Remove-Item -Force
        } else {
            Write-Host "Invalid mode selected."
            return
        }
    }
}

# Main script execution
Write-Host "Windows Security Script"
Write-Host "----------------------"

if (Get-Choice "Enable Firewall?") { Enable-Firewall }
if (Get-Choice "Disable Services?") { Disable-Services }
if (Get-Choice "Disable Remote Desktop?") { Disable-RemoteDesktop }
if (Get-Choice "Set Registry Keys?") { Set-RegistryKeys }
if (Get-Choice "Import Policies?") { Import-Policies }
if (Get-Choice "Disable Guest and Admin accounts?") { Disable-DefaultAccounts }
if (Get-Choice "Audit Users?") { Audit-Users }
if (Get-Choice "Manage Admins?") { Manage-Admins }
if (Get-Choice "Set User Passwords?") { Set-UserPasswords }
if (Get-Choice "Remove Disallowed Media Files?") { Remove-DisallowedMediaFiles }

Write-Host "Script execution completed."
