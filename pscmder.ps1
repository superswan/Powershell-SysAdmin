Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Load predefined commands from an external file
$commandsFilePath = 'commands.txt'  # Path to the file containing commands
$commands = @{}

if (Test-Path $commandsFilePath) {
    $commandLines = Get-Content $commandsFilePath
    foreach ($line in $commandLines) {
        if ($line -match '^(.*?):(.*)$') {
            $name = $matches[1].Trim()
            $command = $matches[2].Trim()
            $commands[$name] = $command
        }
    }
} else {
    [System.Windows.Forms.MessageBox]::Show("Commands file not found at $commandsFilePath", "Error", 'OK', 'Error')
    exit
}

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Network Management Tool'
$form.Size = New-Object System.Drawing.Size(820, 720)
$form.StartPosition = 'CenterScreen'

# Label for the list box
$listLabel = New-Object System.Windows.Forms.Label
$listLabel.Location = New-Object System.Drawing.Point(20, 20)
$listLabel.Size = New-Object System.Drawing.Size(300, 20)
$listLabel.Text = 'Available Computers:'
$form.Controls.Add($listLabel)

# List box for computers
$listBox = New-Object System.Windows.Forms.ListBox
$listBox.Location = New-Object System.Drawing.Point(20, 45)
$listBox.Size = New-Object System.Drawing.Size(300, 300)
$listBox.SelectionMode = 'MultiExtended'
$form.Controls.Add($listBox)

# Scan Network button
$scanButton = New-Object System.Windows.Forms.Button
$scanButton.Location = New-Object System.Drawing.Point(20, 355)
$scanButton.Size = New-Object System.Drawing.Size(300, 30)
$scanButton.Text = 'Scan Network'
$form.Controls.Add($scanButton)

# Install MSI Package button (placed under the Scan Network button)
$installMsiButton = New-Object System.Windows.Forms.Button
$installMsiButton.Location = New-Object System.Drawing.Point(20, 395)
$installMsiButton.Size = New-Object System.Drawing.Size(300, 30)
$installMsiButton.Text = 'Install MSI Package'
$form.Controls.Add($installMsiButton)

# Label for predefined commands
$commandLabel = New-Object System.Windows.Forms.Label
$commandLabel.Location = New-Object System.Drawing.Point(340, 20)
$commandLabel.Size = New-Object System.Drawing.Size(300, 20)
$commandLabel.Text = 'Predefined Commands:'
$form.Controls.Add($commandLabel)

# Panel for command buttons
$commandPanel = New-Object System.Windows.Forms.Panel
$commandPanel.Location = New-Object System.Drawing.Point(340, 45)
$commandPanel.Size = New-Object System.Drawing.Size(450, 380)
$form.Controls.Add($commandPanel)

# Arrange command buttons in a grid
$buttonWidth = 210
$buttonHeight = 30
$buttonsPerRow = 2
$buttonIndex = 0

# Ensure $commands.Keys is always an array
$commandKeys = @($commands.Keys)

foreach ($cmdName in $commandKeys) {
    # Ensure variables are integers
    [int]$col = $buttonIndex % $buttonsPerRow
    [int]$row = [math]::Floor($buttonIndex / $buttonsPerRow)
    [int]$xPos = $col * ($buttonWidth + 10)
    [int]$yPos = $row * ($buttonHeight + 10)

    $cmdButton = New-Object System.Windows.Forms.Button
    $cmdButton.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
    $cmdButton.Location = New-Object System.Drawing.Point($xPos, $yPos)
    $cmdButton.Text = $cmdName
    $cmdButton.Add_Click({
        $textBox.Text = $commands[$this.Text]
    })
    $commandPanel.Controls.Add($cmdButton)
    $buttonIndex++
}

# TextBox for command input
$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Location = New-Object System.Drawing.Point(20, 440)
$textBox.Size = New-Object System.Drawing.Size(660, 30)
$form.Controls.Add($textBox)

# Execute Command button
$executeButton = New-Object System.Windows.Forms.Button
$executeButton.Location = New-Object System.Drawing.Point(690, 440)
$executeButton.Size = New-Object System.Drawing.Size(100, 30)
$executeButton.Text = 'Execute'
$form.Controls.Add($executeButton)

# Output TextBox
$outputBox = New-Object System.Windows.Forms.TextBox
$outputBox.Location = New-Object System.Drawing.Point(20, 480)
$outputBox.Size = New-Object System.Drawing.Size(770, 160)
$outputBox.Multiline = $true
$outputBox.ScrollBars = 'Vertical'
$form.Controls.Add($outputBox)

# Open Output in Notepad button
$openNotepadButton = New-Object System.Windows.Forms.Button
$openNotepadButton.Location = New-Object System.Drawing.Point(20, 650)
$openNotepadButton.Size = New-Object System.Drawing.Size(200, 30)
$openNotepadButton.Text = 'Open Output in Notepad'
$form.Controls.Add($openNotepadButton)

# Event handler for Scan Network button
$scanButton.Add_Click({
    $listBox.Items.Clear()
    $computers = Get-ADComputer -Filter {Enabled -eq $true} | Select-Object -ExpandProperty Name
    foreach ($computer in $computers) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            $listBox.Items.Add($computer)
        }
    }
})

# Event handler for Execute Command button
$executeButton.Add_Click({
    $selectedComputers = $listBox.SelectedItems
    $command = $textBox.Text
    $outputBox.Clear()
    foreach ($computer in $selectedComputers) {
        try {
            $result = Invoke-Command -ComputerName $computer -ScriptBlock {
                param($cmd)
                $output = Invoke-Expression $cmd | Out-String -Width 4096
                return $output.Trim()
            } -ArgumentList $command -ErrorAction Stop
            $outputBox.AppendText("$computer :`r`n$result`r`n`r`n")
        }
        catch {
            $outputBox.AppendText("$computer : Error - $($_.Exception.Message)`r`n`r`n")
        }
    }
})

# Event handler for Install MSI Package button
$installMsiButton.Add_Click({
    # Open a file dialog to select the MSI package
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "MSI Packages (*.msi)|*.msi"
    $openFileDialog.Multiselect = $false
    if ($openFileDialog.ShowDialog() -eq 'OK') {
        $msiPath = $openFileDialog.FileName
        $msiFileName = [System.IO.Path]::GetFileName($msiPath)
        $selectedComputers = $listBox.SelectedItems
        foreach ($computer in $selectedComputers) {
            try {
                # Create a new session
                $session = New-PSSession -ComputerName $computer

                # Copy the MSI file to the remote computer's temp folder
                Copy-Item -Path $msiPath -Destination "C:\Windows\Temp\$msiFileName" -ToSession $session

                # Install the MSI package
                Invoke-Command -Session $session -ScriptBlock {
                    param($msiFileName)
                    $msiFullPath = "C:\Windows\Temp\$msiFileName"
                    Start-Process msiexec.exe -ArgumentList "/i `"$msiFullPath`" /qn" -Wait -PassThru
                } -ArgumentList $msiFileName -ErrorAction Stop

                $outputBox.AppendText("$computer : MSI package installation initiated.`r`n`r`n")

                # Remove the session
                Remove-PSSession -Session $session
            }
            catch {
                $outputBox.AppendText("$computer : Error - $($_.Exception.Message)`r`n`r`n")
            }
        }
    }
})

# Event handler for Open Output in Notepad button
$openNotepadButton.Add_Click({
    $tempFile = [System.IO.Path]::GetTempFileName() + ".txt"
    $outputBox.Text | Out-File -FilePath $tempFile -Encoding UTF8
    Start-Process notepad.exe -ArgumentList $tempFile
})

# Show the form
$form.ShowDialog()
