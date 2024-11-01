# Load JSON from URL
$url = "https://raw.githubusercontent.com/superswan/Powershell-SysAdmin/refs/heads/master/commands.json"
$commands = Invoke-RestMethod -Uri $url

Write-Host "☆ PowerShell Reference ☆"
Write-Host "https://github.com/superswan/Powershell-SysAdmin/`n"


# Display Menu
function Show-Menu {
    $i = 1 
    $menuItems = @() 

    foreach ($command in $commands) {
        Write-Host "$i." -NoNewline
        Write-Host "$($command.title)" -ForegroundColor Yellow -NoNewline
        Write-Host ": $($command.description)"
        $menuItems += [PSCustomObject]@{
            Index = $i
            Title = $command.title
            Command = $command.command
        }
        $i++
    }

    return $menuItems
}

function Execute-Command {
    param (
        [int]$choice,
        [array]$menuItems
    )
    $selectedCommand = $menuItems | Where-Object { $_.Index -eq $choice }
    if ($selectedCommand) {
        Invoke-Expression $selectedCommand.Command
        Read-Host -Prompt "`nPress Enter to return to the menu."
    } else {
        Write-Host "Invalid selection."
    }
}

# Main Loop
while ($true) {
    $menuItems = Show-Menu
    $choice = Read-Host -Prompt "Enter the number of the command to run or 'q' to quit"

    if ($choice -eq 'q') { break }

    if ($choice -match '^\d+$' -and ([int]$choice -le $menuItems.Count) -and ([int]$choice -gt 0)) {
        Execute-Command -choice ([int]$choice) -menuItems $menuItems
    } else {
        Write-Host "Invalid choice. Please enter a valid number."
    }
}
