# ADMT
# AD User & Group Management
Function Breaks {
    $breaks =@(1,2) 
    ForEach($break in $breaks){Write-Host ""}
}
Function User_Info {
        Write-Host ""
    Write-Host "                                                ----User Info Module----"
    Breaks
                                        # Main blocl
    cls
    Do {
        Write-Host ""
        Write-Host "Enter the current username. Example: johndoe   "
        $user = Read-Host -Prompt "Username"

        #cls
        Write-Host ""
        $adinfo = Get-ADUser -Identity $user -property *
        $name = $adinfo.Name
        $username = $adinfo.SAMAccountName
        $title = $adinfo.Title
        $email = $adinfo.EmailAddress
        $phone = $adinfo.OfficePhone
        $pass = $adinfo.PasswordLastSet
        $groups = $groups = Get-ADPrincipalGroupMembership $user
        $groups = $groups.Name
        Write-Host "--------------------------------"
        Write-Host ""
        Write-Host "Name: $name"
        Write-Host "Username: $username"
        Write-Host "Title: $title"
        Write-Host "Email Address: $email"
        Write-Host "Office Phone: $phone"
        Write-Host "Password Last Set: $pass"
        Write-Host ""
        Write-Host "--------Groups--------"
        $groups
        Write-Host ""
        Write-Host "--------------------------------"
        Write-Host ""
        $data = Read-Host -Prompt "Would you like more data on this user? Y/N"
        Start-Sleep -s 1
        If (($data -eq "Y") -or ($data -eq "y")){
            $adinfo
        }
        $answer = Read-Host "      Search for new user (Y) Exit (N)"
    }   Until (($answer -eq "N") -or ($answer -eq "n"))
   
}
Function Add_User_To_Group {
    Write-Host ""
    Write-Host "                                                ----Add a User to a Group Module----"
    Breaks
                         # Main block
    Do{
        Do{
        $user = Read-Host "Enter the username"
        If(Get-ADUser -filter {SamAccountName -eq $user}){
            Write-Host "User found."
            $found = "True"
            }
        If(!(Get-ADUser -filter {SamAccountName -eq $user})){
            Write-Warning "User not found."
            $found = "False"
            Start-Sleep -s 1
            }
        } Until ($found -eq "True")
        Get-ADUser -filter {SamAccountName -eq $user}
        $answer = Read-Host "Is this the correct user? (Y/N)"
        } Until(($answer -eq "Y") -or ($answer -eq "y"))    
        Do{
                # group name
        $group = Read-Host "What is the target group name?"
        If(Get-ADGroup -Identity $group){
            Write-Host "Group found."
            $move = "True"
            }
        If(!(Get-ADGroup -Identity $group)){
            Write-Warning "Group not found."
            }
        } Until ($move -eq "True")
        Write-Host "Checking group membership..."
        If(Get-ADGroupMember -Identity $group | Where {$_.SamAccountName -eq $user}){
            Write-Warning "User: $user is already in this group."
            }
        If(!(Get-ADGroupMember -Identity $group | Where {$_.SamAccountName -eq $user})){
        Write-Host "Proceeding to add $user to $group"
        Add-ADGroupMember -Identity $group -Members $user -Server DCINT03
            }

}

Function Bulk_Users_To_Group {
    Write-Host ""
    Write-Host "                                                ----Add Bulk Users to a Group Module----"
    Breaks

                    # Main block
    cls
    Write-Warning "Currently accepted formats:"
    Write-Warning ".txt file w/ Usernames"
    Write-Warning ".csv file w/ Usernames"
    Do{
    $path = Read-Host "Please enter the file path"
    If (Test-Path "$path"){
        Write-Host "File found"
        $found  = "True"
        }
    If (!(Test-Path "$path")){
        Write-Warning "File path not found. Please try again"
        }
    } Until ($found -eq "True")
    $users = Get-Content $path
    
                # group name
    Do{
    $group = Read-Host "What is the target group name?"
    If(Get-ADGroup -Identity $group){
        Write-Host "Group found."
        $move = "True"
        }
    If(!(Get-ADGroup -Identity $group)){
        Write-Warning "Group not found."
        }
    } Until ($move -eq "True")
                    # adding to group
    ForEach ($user in $users){
        Write-Host "Checking group membership..."
        If(Get-ADGroupMember -Identity $group | Where {$_.SamAccountName -eq $user}){
            Write-Warning "User: $user is already in this group."
            }
        If(!(Get-ADGroupMember -Identity $group | Where {$_.SamAccountName -eq $user})){
        Write-Host "Proceeding to add $user to $group"
        Add-ADGroupMember -Identity $group -Members $user -Server DCINT03
            }
    }
}

Function User_Like_User {
    Write-Host ""
    Write-Host "                                                ----User Like Another User Module----"
    ForEach($break in $breaks){Write-Host ""}
        
        
        
                    # Main block

            # This process will copy the groups of the first user, then add the 2nd user to all the copied groups if they exist. 
Do{
    Do{
        Write-Host "This process will copy the groups of the first user, then add the 2nd user to all the copied groups if they exist."
        Write-Host "Enter the username which is to be copied."
        $user1 = Read-Host -Prompt "User to be copied:"
        Write-Host "Enter the username who will get the groups."
        $user2 = Read-Host -Prompt "New User"
        Write-Host "$user2 should have the same groups as $user1, is this correct?"
        $answer = Read-Host -Prompt "Enter Y/N"
        } Until ($answer -like "y")
        $groups = ADPrincipalGroupMembership $user1 | Select Name
        $missing = @()
        ForEach($group in $groups.Name){
            $sam = Get-Adgroup -filter * | Where {$_.Name -eq "$group"}
            $sam = $sam.SamAccountName
            Add-ADGroupMember -Identity $sam -Members $user2
            Write-Host "Adding $user2 to Group: $sam"
        }
        If($missing){
        Write-Host "There was an issue with the following groups"
        $missing
        }
        Write-Host "Process complete."
        $answer = Read-Host "      Search for new user (Y) Exit (N)"
    }   Until (($answer -eq "N") -or ($answer -eq "n"))

}

Function Name_Change {
    Write-Host ""
    Write-Host "                                                ----User Name Change Module----"
    Breaks
    Write-Host "Welome to Module A"	
        
        
                        # Main block
    Do{
        Do {
            Write-Host "Enter the current username. Example: johndoe   "
            $oldUser = Read-Host -Prompt "Username"
            Write-Host "Enter the new last name. Example: Miller   "
            $newLast = Read-Host -Prompt "Last Name, capitalized"
            $ADinfo = Get-ADUser -Identity $oldUser
            $oldLast = $ADinfo.Surname
            $oldName = $ADinfo.Name
            $first = $ADinfo.GivenName
            $user = ("$first"+ "$newLast").ToLower()
            $newFullName = "$first" + " " + "$newLast"
            Write-Host "Old Name: $oldLast, $oldName, $oldUser."
            Write-Host "New Name: $newLast, $newFullName, $user."
            Write-Host ""
            $answer = Read-Host "      Is this Information correct?  Y/N"}  Until (($answer -eq "Y") -or ($answer -eq "y"))
            Write-Host "Processing..."
            Set-ADUser $oldUser -Surname $newLast -DisplayName "$newFullName" -UserPrincipalName "$user@quadax.com" -Description "Formerly $first $oldLast" 
            Get-ADuser -identity $oldUser | Select -ExpandProperty SAMAccountName | Set-ADuser -samaccountname $user
            #old name is now essentially gone within PS
            $userInfo = Get-ADUser -identity $user -Property *
            $first = $userInfo.GivenName
            $last = $userInfo.Surname
            Rename-ADObject -Identity $userInfo -NewName "$first $last"
            Start-Sleep -s 2
            get-aduser $user -prop MailNickName | Set-ADuser -replace @{MailNickName = $user}
            get-aduser $user -prop mail | Set-ADuser -replace @{mail = "$user@quadax.com"}
            $addresses = @()
                ForEach ($addy in $userInfo.proxyAddresses){
                            $addresses += $addy
                            If ($addy -like "SMTP:*"){$SMTP= $addy
                            ForEach ($addy in $SMTP){
                                Set-ADUser $user -remove @{proxyAddresses="$addy"}}}}
            Start-Sleep -s 1
            Set-ADUser $user -add @{ProxyAddresses="smtp:$user@quadax.mail.onmicrosoft.com"}
            Set-ADUser $user -add @{ProxyAddresses="smtp:$oldUser@quadax.mail.onmicrosoft.com"}
            Set-ADUser $user -add @{ProxyAddresses="smtp:$oldUser@quadax.com"}
            Set-ADUser $user -add @{ProxyAddresses="X400:C=us;A=;P=Quadax Exchange ;O=Exchange;S=$last;G=$first;"}
            Set-ADUser $user -add @{ProxyAddresses="SMTP:$user@quadax.com"}
            Set-ADUser $user -replace @{targetAddress="smtp:$user@quadax.mail.onmicrosoft.com"}
            Write-Host "Complete"
            $answer = Read-Host "      Search for new user (Y) Exit (N)"
        }   Until (($answer -eq "N") -or ($answer -eq "n"))

}

Function Remove_Users_Groups {
    Write-Host ""
    Write-Host "                                                ----Remove a User's Groups Module----"
    Breaks
    Do{
                # This process leaves them as just a domain user. 
        Do{
            Write-Host "Enter the username which is to be removed from all groups their current groups. Example: johndoe   "
            $user = Read-Host -Prompt "User to be removed:"
            Write-Host "$user is to be removed from each of their groups, is this correct?"
            $answer = Read-Host -Prompt "Enter Y/N"
            } Until ($answer -like "y")
            $groups = ADPrincipalGroupMembership $user | Select Name
            $groups = $groups.Name
            Write-Host "Removing user:$user" 
            Write-Host "Groups:"
            ForEach ($group in $groups){
            If ($group -ne "Domain Users") {
                $sam = Get-Adgroup -filter * | Where {$_.Name -eq "$group"}
                $sam = $sam.SamAccountName
                Write-Host "$sam"
                Remove-ADGroupMember -Identity $sam -Members $user -Confirm:$false
                }
            }
            Write-Host "Process complete."
            $answer = Read-Host "      Search for new user (Y) Exit (N)"
        }   Until (($answer -eq "N") -or ($answer -eq "n"))
}

Function Get_Group_Info {
    Write-Host ""
    Write-Host "                                                ----Get Group Membership Info Module----"
    Breaks
    Do{
        Write-Host "Please enter the name of the group you wish to lookup."
        $identity = Read-Host "Group Name"
        $members = Get-ADGroupMember -Identity $identity | Select Name
        $members = $members.name
        Write-Host "Here are all the members of group: $identity "
        Write-Host "----------------------------------------------"
        $members | Sort
        Write-Host "----------------------------------------------"
        Write-Host "Process complete."
        Write-Host ""
        $answer = Read-Host "      Search for new group (Y) Exit (N)"
    }   Until (($answer -eq "N") -or ($answer -eq "n"))
}


Function Restart_ {
            # Restart segment
        Write-Host "{1} - Return to Menu"
        Write-Host "{0} - Exit AD Management Tool"
        $Ranswer = Read-Host -Prompt "Input Option Number"
        Write-Host ""
        If($Ranswer -eq 1){
            Write-Host "Returning to the Menu"
            Start-Sleep -s 0.5
            $exit = "N"

        }
        If($Ranswer -eq "0"){
            Write-Host "Exiting AD Management Tool...."
            Start-Sleep -s 2
            Exit 0
        }  
}
                                    ############ END OF FUNCTIONS ############

		# Checking for AD tools
If (!(Get-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online | Where {$_.State -eq "Installed"})){
Write-Host "AD tools not found. Proceeding to install..."
Add-WindowsCapability -Name Rsat.ACtiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -online
    Do{
    Write-Host "Waiting for installation to complete..."
    Start-Sleep -s 5
        } Until (Get-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online | Where {$_.State -eq "Installed"})
}
Do {
    cls
    Write-Host ""
    Write-Host "Welcome to the AD Management Tool!"
    Write-Host ""
    Write-Host ""
    Write-Host "Available Options"
    Write-Host "{1} - Get User Info"
    Write-Host "{2} - Add a User to a Group"
    Write-Host "{3} - Add Bulk Users to a Group "
    Write-Host "{4} - User Like Another User"
    Write-Host "{5} - User Name change"
    Write-Host "{6} - Remove User's Groups"
    Write-Host "{7} - Get Group Info"
    Write-Host "{0} - Exit"
    Write-Host ""
    $answer = Read-Host -Prompt "Input Option Number"
                                # Option 0 - Exit
    If($answer -eq "0"){
            Exit 0
        }
                                # Option 1 - Get User Info
    If($answer -eq "1"){
        cls
        User_Info
        Restart_
    }
                                # Option 2 - Add a User to a Group
    If($answer -eq "2"){
        cls
        Add_User_To_Group
        Restart_
    }
                                # Option 3 - Add Bulk Users to a group
    If($answer -eq "3"){
        cls
        Bulk_Users_To_Group   
        Restart_
    }
                                # Option 4 - User Like Other User
    If($answer -eq "4"){
        cls
        User_Like_User   
        Restart_
    }
                                # Option 5 - User Name Change
    If($answer -eq "5"){
        cls
        Name_Change
        Restart_
    }
                                # Option 6 - Remove a User's Groups
    If($answer -eq "6"){
        cls
        Remove_Users_Groups
        Restart_
    }
                                # Option 7 - Get Group Info
    If($answer -eq "7"){
        cls
        Get_Group_Info
        Restart_
    }
}
Until (($exit -eq "Y") -or ($exit -eq "y"))

<#    # module template 
If($answer -eq ""){
    cls
    Function
                # Restart segment
    Write-Host "{1} - Return to Menu"
    Write-Host "{0} - Exit AD Management Tool"
    $answer = Read-Host -Prompt "Input Option Number"
    Write-Host ""
    If($answer -eq 1){
        Write-Host "Returning to the Menu"
        Start-Sleep -s 0.5
        $exit = "N"

    }
    If($answer -eq "0"){
        Write-Host "Exiting AD Management Tool...."
        Start-Sleep -s 2
        $exit = "Y"
    }   
}
#>