#Disable Vulnerable Services/Features
Get-WindowsFeature FS-SMB1 
Remove-WindowsFeature FS-SMB1
Stop-Service -Name "Print Spooler"
Stop-Service -Name "Windows Mobile Hotspot Service"

(New-Object -ComObject HNetCfg.FwPolicy2).RestoreLocalFirewallDefaults()