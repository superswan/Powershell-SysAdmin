$url = 'https://raw.githubusercontent.com/superswan/Powershell-SysAdmin/master/commands.json'

try {
    $raw = Invoke-RestMethod -Uri $url -ErrorAction Stop
} catch {
    Write-Error "Failed to load commands.json from $url"
    exit 1
}

function Show-Categories {
    Clear-Host
    Write-Host "=== Categories ===" -ForegroundColor Cyan
    for ($i = 0; $i -lt $raw.Count; $i++) {
        $n = $i + 1
        "{0,2}) {1}" -f $n, $raw[$i].category | Write-Host
    }
    " Q) Quit" | Write-Host
}

function Show-CommandsInCategory {
    param($categoryObj)
    Clear-Host
    Write-Host "=== $($categoryObj.category) Commands ===" -ForegroundColor Cyan
    for ($j = 0; $j -lt $categoryObj.commands.Count; $j++) {
        $m = $j + 1
        "{0,2}) {1}" -f $m, $categoryObj.commands[$j].title | Write-Host
    }
    " B) Back" | Write-Host
}

while ($true) {
    Show-Categories
    $catChoice = Read-Host "Select a category"

    if ($catChoice -match '^[Qq]$') { break }

    if ($catChoice -match '^\d+$' -and ($catChoice -as [int]) -ge 1 -and ($catChoice -as [int]) -le $raw.Count) {
        $categoryObj = $raw[($catChoice - 1)]
        while ($true) {
            Show-CommandsInCategory $categoryObj
            $cmdChoice = Read-Host "Select a command"

            if ($cmdChoice -match '^[Bb]$') { break }

            if ($cmdChoice -match '^\d+$' -and ($cmdChoice -as [int]) -ge 1 -and ($cmdChoice -as [int]) -le $categoryObj.commands.Count) {
                $cmdObj = $categoryObj.commands[($cmdChoice - 1)]
                Clear-Host
                Write-Host ">>> Running: $($cmdObj.title)`n" -ForegroundColor Yellow
                $script = if ($cmdObj.command -is [System.Array]) { $cmdObj.command -join "; " } else { $cmdObj.command }
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
