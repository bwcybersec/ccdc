# Usefull commands

            # MAC Address
Get-WmiObject win32_networkadapterconfiguration | select description, macaddress
            # Device name
$env:computername
            # Current username
$env:username
            # Get IP's , add Select * to show more info. 
Get-NetIPAddress | Select InterfaceAlias, IPAddress
            # Computer INFO, add '| Select [insert your properties] | FL' for better formatting. 
Get-ComputerInfo
            # List installed programs
Get-ChildItem -Path HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty |  Select DisplayName
Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Select DisplayName