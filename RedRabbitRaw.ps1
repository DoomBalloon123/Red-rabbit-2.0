$l1 = @('               
                                                                                           /|      __
    ██▀███  ▓█████ ▓█████▄  ██▀███   ▄▄▄       ▄▄▄▄    ▄▄▄▄    ██▓▄▄▄█████▓               / |    /  /
 ▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌▓██ ▒ ██▒▒████▄    ▓█████▄ ▓█████▄ ▓██▒▓  ██▒ ▓▒                Y  |  //  /
 ▓██ ░▄█ ▒▒███   ░██   █▌▓██ ░▄█ ▒▒██  ▀█▄  ▒██▒ ▄██▒██▒ ▄██▒██▒▒ ▓██░ ▒░                |  | /( .^   
 ▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌▒██▀▀█▄  ░██▄▄▄▄██ ▒██░█▀  ▒██░█▀  ░██░░ ▓██▓ ░                 >-"~"-v"
 ░██▓ ▒██▒░▒████▒░▒████▓ ░██▓ ▒██▒ ▓█   ▓██▒░▓█  ▀█▓░▓█  ▀█▓░██░  ▒██▒ ░               /       Y
 ░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░▒▓███▀▒░▒▓███▀▒░▓    ▒ ░░                / X <    |
 ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒   ░▒ ░ ▒░  ▒   ▒▒ ░▒░▒   ░ ▒░▒   ░  ▒ ░    ░                  ( ~T~     j
  ░░   ░    ░    ░ ░  ░   ░░   ░   ░   ▒    ░    ░  ░    ░  ▒ ░  ░                    >._-'' _./
   ░        ░  ░   ░       ░           ░  ░ ░       ░       ░                       /   "~"  |
                 ░                               ░       ░                          Y     _,  |
                                                                                   /| ;-"~ _  l
                                                                                 / l/ ,-"~    \
   Creator: https://securethelogs.com / @securethelogs                            \//\/      .- \
                                                                                   l  RR! /    Y 
                                                                                   /      I     !
                                                                                   \      _\    /"\
                                                                                 (" ~----( ~   Y.  ))')


$l1; 


# Section 1

$h = hostname
$u = $env:UserName
$d = (Get-WmiObject -Class Win32_ComputerSystem).Domain

$sesh = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)


if ($sesh -eq "True"){

    $sessionadmin = "Admin Session"
    $tc = "Green"

    } else {

           $sessionadmin = "User Session"
           $tc = "Red"

           }



if ($d -eq "WORKGROUP"){

    $dom = "WORKGROUP" 
    $dtc = "Red"
    
    } else {

            $a = net group "domain admins" /domain

            $idom = select-string -pattern "$u" -InputObject $a

            if ($idom -eq $null){
            
                                  $dom =  "False"
                                  $dtc = "Red"
                                    
                                    } else {
                                    
                                            $dom = "True"
                                            $dtc = "Green"
                                            
                                            }

}


Write-Host " Current User: $u     |  Current Machine: $h"

Write-Host " Session: " -NoNewline ; Write-Host "$sessionadmin " -ForegroundColor $tc -NoNewline ; Write-Host "  |  Domain Admin: " -NoNewline ; Write-Host "$dom" -ForegroundColor $dtc

Write-Host ""


while($true){ 


$option = Read-Host -Prompt "[RedRabbit]:"


if ($option -eq "exit"){ exit }



    if ($option -eq "h" -or $option -eq "help"){


    $help = ('
    
         Please enter one of the following numbers | Options with * require admin

                           Enter "exit" to end RedRabbit      
             
                           
    Option 1: Quick Recon                               Option 10: Encode / Decode Commands (Base64)
    Option 2: Subnet Scanner                          * Option 11: Query DLLs
    Option 3: SMB Scanner                               Option 12: Reverse Shell (Netcat)
    Option 4: Network Scanner                           Option 13: Scan Socials For Usernames
    Option 5: NetBios Scanner                           Option 14: Flood Powershell Event Logs 
   
   
    Option 6: DNS Resolver                              Option 15: PassVol Search
    Option 7: Brute Force ZIP                           Option 16: File / Web Crawler
    Option 8: Brute Force WinRM                         Option 17: KeyLogger
    Option 9: Password Extraction                       Option 18: Clipboard Logger
                                                        
    
                            ---------------------------------


    Option 19: Scan Gateway

    
    ')

    $help

    } # End Of Help


   
    if ($option -eq "1"){
    

    $user = whoami
    $currenthost = hostname 
    $networkinfo = (Get-NetIPAddress).IPAddress
    $Publicip = (curl http://ipinfo.io/ip -UseBasicParsing).content


    Write-Output ""

    Write-Host " User: $user"
    Write-Host " Hostname: $currenthost"
    Write-Host " Public IP: " -NoNewline; Write-Host $Publicip

    Write-Output ""

    Write-Host " [*] Getting AntiVirus ... "
    Start-Sleep -Seconds 2

    try {
    
        Get-CimInstance -Namespace root/securitycenter2 -ClassName antivirusproduct | Select-Object displayName | Format-Table -HideTableHeaders
    
        } catch{
        
        write-host "Failed To Get AntiVirus" -ForegroundColor Red

                }

    Write-Output ""

    Write-Host " [*] Getting Network IP/s ..."
    Start-Sleep -Seconds 2
   
    Write-Output ""

    $networkinfo

    Write-Output ""

        
    $lad = @(Get-WmiObject win32_useraccount | Select name,sid)

        foreach ($l in $lad){
        
          [string]$sid = $l.sid

            if ($sid.EndsWith("500")){

            $ladstatus = (Get-WmiObject win32_useraccount | Where-Object {$_.name -like $l.name}).Disabled 

            if ($ladstatus -eq "True"){
