

Function Unwanted_Service {


        #Start-Process does not parse quotes well. Encrypting and decrypting gets around this. Any changes should be made to the $Script varible
    $script = @'
write-host "Starting Terminal: Unwanted Services"
while ($true) {
    $BadServices = @("sshd","ssh-agent","tlntsvr")
    foreach ($n in $BadServices) {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq "Running") {
            Get-Date
            Write-Host "$n was detected!" -ForegroundColor Red
        }
    }
    Start-Sleep -Seconds 120
}
'@

    $bytes  = [System.Text.Encoding]::Unicode.GetBytes($script)
    $encoded = [Convert]::ToBase64String($bytes)

    Start-Process powershell.exe -ArgumentList "-NoExit","-EncodedCommand",$encoded
}


Function Wanted_Service{

        #Start-Process does not parse quotes well. Encrypting and decrypting gets around this. Any changes should be made to the $Script varible
    $script = @'
write-host "Starting Terminal: Wanted Services"
$GoodServices = @()
Do{
    $service = Read-Host "What service(s) do you want? type DONE to start the terminal"
    if($Service -ne "DONE"){
        $GoodServices += $service
    }
}until($service -eq "DONE")
cls
write-host "Starting Wanted Service terminal"
while ($true) {
    
    foreach ($n in $GoodServices) {
        try{
            $s = Get-Service -Name $n -ErrorAction
            if ($s -and $s.Status -ne "Running") {
                Get-Date
                Write-Host "$n has been stopped!" -ForegroundColor Red
            }
        } Catch {
            Get-Date
            Write-Host "$n has been Removed!" -ForegroundColor Red
        }
    }
    Start-Sleep -Seconds 120
}
'@

    $bytes  = [System.Text.Encoding]::Unicode.GetBytes($script)
    $encoded = [Convert]::ToBase64String($bytes)

    Start-Process powershell.exe -ArgumentList "-NoExit","-EncodedCommand",$encoded
}

Function FTP_tshark{
    $script = @'
        do{
            Write-Host "Choose any additional parameters"
            write-Host "Default will show FTP User logins"
            write-host ""
            Write-Host "[1] - Get Password"
            Write-Host "[2] - Check if transfers complete"
            Write-Host "[3] - Exclude users"


            $choice = Read-Host "What additional parameters would you like? DONE to continue"

            $addparam =""
            $ExcUsers = @()
            switch ($choice) {
                1 {$addparam += " or ftp.request.command contains PASS”}
                2 {$addparam += " or ftp.response.arg contains complete”}
                3 {do{$ExcUser = Read-host "What users do you want to exclude? DONE to continue"
                  $ExcUsers += $ExcuUser
                  }until($ExcUser -eq "DONE")
                  forEach($user in $ExcUsers){
                    $addparam +=" and not (ftp.request.arg contains $user)“
                  }
            }
         }
          }until ($choice -eq "DONE")

        Write-Host "Starting tshark capture..."

        & "C:\Program Files\Wireshark\tshark.exe" `
        #-i ethernet `
        -Y “ftp.request.command contains USER$addparam”

'@

    $bytes   = [System.Text.Encoding]::Unicode.GetBytes($script)
    $encoded = [Convert]::ToBase64String($bytes)

    Start-Process powershell.exe -ArgumentList "-NoExit", "-EncodedCommand", $encoded
}

Function DNS_tshark{
    $script = @'

        Write-Host "Starting tshark capture..."

        & "C:\Program Files\Wireshark\tshark.exe" `
        -i ethernet `
        -f "dst port 53 and not (src net 172.20.240.0/24 or src host 1.1.1.1)" -n -T fields -e dns.qry.name -e ip.dst -e ip.src -e frame.time
'@

    $bytes   = [System.Text.Encoding]::Unicode.GetBytes($script)
    $encoded = [Convert]::ToBase64String($bytes)

    Start-Process powershell.exe -ArgumentList "-NoExit", "-EncodedCommand", $encoded
}

Function HTTP_tshark{
    $script = @'

        Write-Host "Starting tshark capture..."

        & "C:\Program Files\Wireshark\tshark.exe" `
        -i ethernet `
        -Y 'http.request.uri contains \"c=\" or http.request.uri contains \"cmd=*\"' 

'@

    $bytes   = [System.Text.Encoding]::Unicode.GetBytes($script)
    $encoded = [Convert]::ToBase64String($bytes)

    Start-Process powershell.exe -ArgumentList "-NoExit", "-EncodedCommand", $encoded
}
Function High_CPU{
    $script = @'
    Write-Host "Starting CPU Terminal"
    while($True){
        Get-Date
        $TotalCPUTime = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors * 100
        $Result = (get-counter -Counter "\Process(*)\% Processor Time" -SampleInterval 5 -MaxSamples 12 -ErrorAction SilentlyContinue).CounterSamples.where({$_.InstanceName -notmatch "^(_total)$"}) | Group {$_.Instancename} | Select @{Name="Computername";Expression={$_.group.path.split("\\")[2]}}, @{Name="Process";Expression={$_.Name}}, @{Name="AvgCPUTime";Expression={($_.group.cookedvalue | measure-object -average).average}}, @{Name='AvgCPUTime%';E={($_.group.cookedvalue | measure-object -average).average / $TotalCPUTime*100} } | Sort AvgCPUTime -descending
        $Result | Select-Object -First 5
        start-sleep -Seconds 240
    }
'@
    $bytes   = [System.Text.Encoding]::Unicode.GetBytes($script)
    $encoded = [Convert]::ToBase64String($bytes)

    Start-Process powershell.exe -ArgumentList "-NoExit", "-EncodedCommand", $encoded
}


        #### End of Function Row ####

Do{
    Write-Host "------Terminal Options------" -BackgroundColor Black -ForegroundColor White
    Write-Host "[1] - Unwanted Services"
    Write-Host "[2] - Wanted Services"
    Write-Host "[3] - FTP tshark"
    Write-Host "[4] - DNS tshark"
    Write-Host "[5] - Malicious HTTP traffic tshark"
    Write-Host "[6] - High CPU usage"
    
    $choice = Read-Host "What terminal do you want? (DONE to end script)"

    switch ($choice) {
    1 {Unwanted_Service}
    2 {Wanted_Service}
    3 {FTP_tshark}
    4 {DNS_tshark}
    5 {HTTP_tshark}
    6 {High_CPU}
    
    }
    
}until($choice -eq "DONE")