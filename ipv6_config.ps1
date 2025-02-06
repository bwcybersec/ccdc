$option = Read-Host -prompt "Enable or disable IPv6? "

if ( $option -eq "enable" ) {

    $Adapter = get-netadapter -includehidden | where-object { $_.Name -like 'Ethernet' -and !($_.Name -like "Kernel")} | Select-Object Name
    $index = get-netadapter -includehidden | where-object Name -EQ $Adapter | Select-Object ifIndex
    Set-NetAdapterBinding -Name $Adapter.Name -ComponentID ms_tcpip6 -Enabled $true
    new-netipaddress -interfaceindex $index.ifIndex -IPAdress 2001:db8:1::300 -prefixlength 64 -defaultgateway 2001:db8:1::1

} elseif ( $option -eq "disable" ) {

    $Adapter = get-netadapter -includehidden | where-object { $_.Name -like 'Ethernet' -and !($_.Name -like "Kernel")} | Select-Object Name
    Set-NetAdapterBinding -Name $Adapter.Name -ComponentID ms_tcpip6 -Enabled $false

} else { Write-output "Please enter a valid response..." }

