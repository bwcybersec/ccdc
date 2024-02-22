$zones = Get-DNSServerZone
ForEach ($zone in $zones){
    $zname = $zone.ZoneName
    $fname = $zname + ".bak"
    Export-DnsServerZone -Name $zname -FileName "$fname.bak"
}

# Export
$fname = $zname + ".bak"
Export-DnsServerZone -Name $zname -FileName $fname


# adding a zone
$fname = $zname + ".bak"
dnscmd $env:computername /zoneadd $zname /primtary /file $fname /load
dnscmd $env:computername /zoneresettype $zname /DsPrimary