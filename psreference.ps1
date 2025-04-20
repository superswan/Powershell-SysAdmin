<#
.SYNOPSIS
  Interactive command menu loaded via IEX.
#>

param(
    [string]$JsonUrl = 'https://raw.githubusercontent.com/superswan/Powershell-SysAdmin/master/commands.json'
)

try {
    $raw = Invoke-RestMethod -Uri $JsonUrl -UseBasicParsing -ErrorAction Stop
}
catch {
    Write-Error "❌ Failed to load commands.json from $JsonUrl"
    return
}

function Show-Categories {
    Clear-Host
    Write-Host "=== Categories ===" -ForegroundColor Cyan
    for ($i = 0; $i -lt $raw.Count; $i++) {
        "{0,2}) {1}" -f ($i+1), $raw[$i].category | Write-Host
    }
    Write-Host " Q) Quit"
}

function Show-CommandsInCategory {
    param([pscustomobject]$categoryObj)
    Clear-Host
    Write-Host "=== $($categoryObj.category) Commands ===" -ForegroundColor Cyan
    for ($j = 0; $j -lt $categoryObj.commands.Count; $j++) {
        "{0,2}) {1}" -f ($j+1), $categoryObj.commands[$j].title | Write-Host
    }
    Write-Host " B) Back"
}

while ($true) {
    Show-Categories
    $catChoice = Read-Host "Select a category"

    if ($catChoice -match '^[Qq]$') { break }

    if ($catChoice -match '^\d+$' -and $catChoice -ge 1 -and $catChoice -le $raw.Count) {
        $categoryObj = $raw[$catChoice - 1]
        while ($true) {
            Show-CommandsInCategory $categoryObj
            $cmdChoice = Read-Host "Select a command"

            if ($cmdChoice -match '^[Bb]$') { break }

            if ($cmdChoice -match '^\d+$' -and $cmdChoice -ge 1 -and $cmdChoice -le $categoryObj.commands.Count) {
                $cmdObj = $categoryObj.commands[$cmdChoice - 1]
                Clear-Host
                Write-Host ">>> Running: $($cmdObj.title)`n" -ForegroundColor Yellow
                $script = if ($cmdObj.command -is [System.Array]) {
                    $cmdObj.command -join "; "
                } else {
                    $cmdObj.command
                }
                Invoke-Expression $script
                Read-Host "`nPress Enter to return..."
            }
            else {
                Write-Host "Invalid selection!" -ForegroundColor Red
                Start-Sleep 1
            }
        }
    }
    else {
        Write-Host "Invalid category!" -ForegroundColor Red
        Start-Sleep 1
    }
}
