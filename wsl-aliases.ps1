function Set-AliasForce {
    param (
        [string]$Name,
        [string]$Value
    )
    
    if (Get-Alias -Name $Name -ErrorAction SilentlyContinue) {
        Remove-Item -Path "Alias:$Name" -ErrorAction SilentlyContinue
    }

    Set-Alias -Name $Name -Value $Value
}

# Define WSL aliases for common Linux commands
Set-Alias -Name sed -Value "wsl sed"
Set-Alias -Name awk -Value "wsl awk"
Set-Alias -Name grep -Value "wsl grep"
Set-Alias -Name jq -Value "wsl jq"
Set-Alias -Name find -Value "wsl find"
Set-Alias -Name lsort -Value "wsl sort"
Set-Alias -Name uniq -Value "wsl uniq"
Set-Alias -Name cut -Value "wsl cut"
Set-Alias -Name wc -Value "wsl wc"
Set-Alias -Name tr -Value "wsl tr"
Set-Alias -Name xargs -Value "wsl xargs"
Set-AliasForce -Name curl -Value "wsl curl"
Set-Alias -Name awk -Value "wsl awk"
Set-Alias -Name tar -Value "wsl tar"
Set-Alias -Name head -Value "wsl head"
Set-Alias -Name more -Value "wsl more"
Set-AliasForce -Name wget -Value "wsl wget"
