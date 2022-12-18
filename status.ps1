# Import the Active Directory module
Import-Module ActiveDirectory

# Get all computers in Active Directory
$computers = Get-ADComputer -Filter *

# Initialize an array to store the computer status
$computerStatus = @()

# Loop through each computer
foreach ($computer in $computers)
{
    # Check if the computer is online
    $status = Test-Connection -ComputerName $computer.Name -Count 1 -Quiet
    if ($status)
    {
        $statusText = "Online"
    }
    else
    {
        $statusText = "Offline"
    }

    # Add the computer name and status to the array
    $computerStatus += [PSCustomObject]@{
        ComputerName = $computer.Name
        Status = $statusText
    }
}

# Output the computer status in a table
$computerStatus | Format-Table -Property ComputerName, Status
