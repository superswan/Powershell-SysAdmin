<# 
Prep script
Intended to be ran on fresh Win10 image out of box

-Software Install
	- Chrome
	- Adobe Reader
	- Java	 
	- C++ runtime
	- 7-zip
	- Teamviewer Host
- Configuration Step
    - Enable File & Printer Sharing
    - Allow Ping
    - Power sleep settings
    - Set explorer to This PC
    - Add Desktop Icons
        - This PC
        - User Files
- Install Teamviewer
- Windows Updates
- Cleanup
#>

$banner = "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKUlJSUlJSUlJSUlJSUlJSUlIgICAgICAgICYmJiYmJiYmJiYgICAgQkJCQkJCQkJCQkJCQkJCQkIgICAKUjo6Ojo6Ojo6Ojo6Ojo6OjpSICAgICAgJjo6Ojo6Ojo6OjomICAgQjo6Ojo6Ojo6Ojo6Ojo6OjpCICAKUjo6Ojo6OlJSUlJSUjo6Ojo6UiAgICAmOjo6OiYmJjo6Ojo6JiAgQjo6Ojo6OkJCQkJCQjo6Ojo6QiAKUlI6Ojo6OlIgICAgIFI6Ojo6OlIgICY6Ojo6JiAgICY6Ojo6JiAgQkI6Ojo6OkIgICAgIEI6Ojo6OkIKICBSOjo6OlIgICAgIFI6Ojo6OlIgICY6Ojo6JiAgICY6Ojo6JiAgICBCOjo6OkIgICAgIEI6Ojo6OkIKICBSOjo6OlIgICAgIFI6Ojo6OlIgICAmOjo6OiYmJjo6OjomICAgICBCOjo6OkIgICAgIEI6Ojo6OkIKICBSOjo6OlJSUlJSUjo6Ojo6UiAgICAmOjo6Ojo6Ojo6OiYgICAgICBCOjo6OkJCQkJCQjo6Ojo6QiAKICBSOjo6Ojo6Ojo6Ojo6OlJSICAgICAgJjo6Ojo6OjomJiAgICAgICBCOjo6Ojo6Ojo6Ojo6OkJCICAKICBSOjo6OlJSUlJSUjo6Ojo6UiAgICY6Ojo6Ojo6OiYgICAmJiYmICBCOjo6OkJCQkJCQjo6Ojo6QiAKICBSOjo6OlIgICAgIFI6Ojo6OlIgJjo6Ojo6JiY6OiYgICY6OjomICBCOjo6OkIgICAgIEI6Ojo6OkIKICBSOjo6OlIgICAgIFI6Ojo6OlImOjo6OjomICAmOjomJjo6OiYmICBCOjo6OkIgICAgIEI6Ojo6OkIKICBSOjo6OlIgICAgIFI6Ojo6OlImOjo6OjomICAgJjo6Ojo6JiAgICBCOjo6OkIgICAgIEI6Ojo6OkIKUlI6Ojo6OlIgICAgIFI6Ojo6OlImOjo6OjomICAgICY6Ojo6JiAgQkI6Ojo6OkJCQkJCQjo6Ojo6OkIKUjo6Ojo6OlIgICAgIFI6Ojo6OlImOjo6Ojo6JiYmJjo6Ojo6OiYmQjo6Ojo6Ojo6Ojo6Ojo6Ojo6QiAKUjo6Ojo6OlIgICAgIFI6Ojo6OlIgJiY6Ojo6Ojo6OiYmJjo6OjomQjo6Ojo6Ojo6Ojo6Ojo6OjpCICAKUlJSUlJSUlIgICAgIFJSUlJSUlIgICAmJiYmJiYmJiAgICYmJiYmQkJCQkJCQkJCQkJCQkJCQkIgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKU1lTVEVNIFBSRVAgdjEgLSAwMy8xMS8yMDIy"

# VARIABLES

# Install Winget
Invoke-WebRequest -Uri "https://github.com/microsoft/winget-cli/releases/download/v1.1.12653/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -OutFile "C:\WinGet.msixbundle"
Add-AppxPackage "C:\WinGet.msixbundle"

$explorerParams = @{
    Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    Name = 'LaunchTo'
    Value = 1
}

$teamviewer_path = '\\10.10.0.62\Utilities\PC BUILDS\Installers\TeamViewer_Host_Setup.exe'

# Banner
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($banner))

# Install Packages via Winget
Write-Host -Foreground Yellow "[!] Installing software packages..."
winget install --id=Microsoft.DotNet.Framework.DeveloperPack_4 -e  ; winget install --id=Google.Chrome -e  ; winget install --id=Microsoft.VCRedist.2013.x64 -e  ; winget install --id=Microsoft.VCRedist.2013.x86 -e  ; winget install --id=Microsoft.VCRedist.2015+.x64 -e  ; winget install --id=Microsoft.VCRedist.2015+.x86 -e  ; winget install --id=Microsoft.VCRedist.2012.x64 -e  ; winget install --id=Microsoft.VCRedist.2012.x86 -e  ; winget install --id=Microsoft.VCRedist.2010.x64 -e  ; winget install --id=Microsoft.VCRedist.2010.x86 -e  ; winget install --id=Microsoft.VCRedist.2005.x86 -e  ; winget install --id=Microsoft.VCRedist.2008.x86 -e  ; winget install --id=Microsoft.VCRedist.2008.x64 -e  ; winget install --id=Oracle.JavaRuntimeEnvironment -e  ; winget install --id=7zip.7zip -e  ; winget install --id=Adobe.Acrobat.Reader.64-bit -e 

# Install TeamViewer
Write-Host -Foreground Yellow "[!] Copying TeamViewer Installer"
Copy-Item $teamviewer_path ~/Desktop
#Start-Process -Wait -FilePath "~/TeamViewer_Host_Setup.exe" -ArgumentList "/S" -PassThru


# CONFIGURATION 
Write-Host -Foreground Yellow "[!] Configuring things..."
# Enable File and Printer Sharing
Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True

# Enable ICMP
netsh advfirewall firewall add rule name="Allow incoming ping requests IPv4" dir=in action=allow protocol=icmpv4

# Power Configuration 
powercfg /x -hibernate-timeout-ac 0
powercfg /x -monitor-timeout-ac 0
powercfg /x -standby-timeout-ac 0

powercfg /hibernate off

# Time Zone
Set-TimeZone -Id "Eastern Standard Time" -PassThru
w32tm /resync

# Set Explorer launch options
Set-ItemProperty @explorerParams

# Set Desktop icons
$path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$name="{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
$exist="Get-ItemProperty -Path $path -Name $name"
if ($exist)
{
    Set-ItemProperty -Path $path -Name $name -Value 0
}
Else
{
    New-ItemProperty -Path $path -Name $name -Value 0
}

$path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$name="{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
$exist="Get-ItemProperty -Path $path -Name $name"
if ($exist)
{
    Set-ItemProperty -Path $path -Name $name -Value 0
}
Else
{
    New-ItemProperty -Path $path -Name $name -Value 0
}

$path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$name="{59031a47-3f72-44a7-89c5-5595fe6b30ee}"
$exist="Get-ItemProperty -Path $path -Name $name"
if ($exist)
{
    Set-ItemProperty -Path $path -Name $name -Value 0
}
Else
{
    New-ItemProperty -Path $path -Name $name -Value 0
}


$path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$name="{59031a47-3f72-44a7-89c5-5595fe6b30ee}"
$exist="Get-ItemProperty -Path $path -Name $name"
if ($exist)
{
    Set-ItemProperty -Path $path -Name $name -Value 0
}
Else
{
    New-ItemProperty -Path $path -Name $name -Value 0
}


# Enable WinRM 
Enable-PSRemoting -force -SkipNetworkProfileCheck

# Restart Explorer
gps explorer | spps

# Windows Updates
<# NuGet provider confirmatation step #>
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -confirm:$false

Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted 

Install-Module PSWindowsUpdate -confirm:$false
Add-WUServiceManager -ServiceID "7971f918-a847-4430-9279-4a52d1efe18d" -AddServiceFlag 7

Write-Host "[!] Fetching Windows Updates"
Get-WindowsUpdate -MicrosoftUpdate -confirm:$false

Write-Host "[!] Installing Windows Updates"
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -confirm:$false | Out-File "c:\$(get-date -f yyyy-MM-dd)-WindowsUpdate.log" -force

# Remove Icons
Remove-Item "~\Desktop\*.bat"

# Summary
Write-Host -Foreground Green "Setup Complete!"
whoami
hostname

pause
