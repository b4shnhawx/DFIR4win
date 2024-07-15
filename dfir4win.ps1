# This script automates the collection of data from a host. The script must be run on the host with
# administrator permissions in order to collect meaningful data in the DFIR process.
#
# You must be clear about the whole process to avoid any data corruption.
#
# The original script belongs to AlrikRr.
# I have tried to optimise, add the function to collect the hives and traded the code.
#
# 
# My social media
#     GitHub: https://www.linkedin.com/in/darribash/
#    YouTube: https://www.youtube.com/channel/UCxvS-XzNNYFOq45-ScuLrxA
#   LinkedIn: https://github.com/b4shnhawx
#
#
# Credits:
# https://github.com/AlrikRr/Forensic-Extract
# https://github.com/Bert-JanP/Incident-Response-Powershell
# https://medium.com/@rihanmujahid46/live-windows-forensics-using-powershell-and-sysinternals-c6997e869075


#########################################################################################
####################################### INITIATION #######################################
#########################################################################################

Write-Host "
    ____  ______________  __ __          _     
   / __ \/ ____/  _/ __ \/ // /_      __(_)___ 
  / / / / /_   / // /_/ / // /| | /| / / / __ \
 / /_/ / __/ _/ // _, _/__  __/ |/ |/ / / / / /
/_____/_/   /___/_/ |_|  /_/  |__/|__/_/_/ /_/ v1.0

"
$ErrorActionPreference= 'silentlycontinue'

#Verification of admin
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if ( $IsAdmin -eq $true ){
    Write-Host "[+] Administrator" -ForegroundColor Green
}
else{
    Write-Host "[-] Administrator" -ForegroundColor Red
    exit
}

#Verification of Microsoft Defender
Write-Host "
[!] To pick up the hives from the system you will need to disable the real-time protection of Microsof Defender.
[!] If Microsoft Defender is not disabled, the script will skip the collection of the hives.
[!] In case you have another antivirus (AV) it is possible that the script will not detect it. Make sure to disable real-time protection.
[!] If it is another AV and it is not disabled, it is possible that some, but not all, of the hives will be collected. The antivirus will only block the collection of some of the hives, but the script will extract the rest of the information.
[!] If you want to collect ALL hives, be sure to disable protection NOW.
" -ForegroundColor Yellow

Read-Host "Press ENTER to continue"

$DefenderDisabled = ((Get-MpPreference).DisableRealtimeMonitoring)
if ( $DefenderDisabled -eq $true ){
    Write-Host "[+] Microsoft Defender disabled" -ForegroundColor Green
}
else{
    Write-Host "[-] Microsoft Defender disabled" -ForegroundColor Red
}

#########################################################################################
####################################### VARIABLES #######################################
#########################################################################################

Write-Host "[!] The extraction will be stored in a folder containing the job name and the current date." -ForegroundColor Yellow
Write-Host "[!] This folder will then be compressed into a ZIP archive and deleted." -ForegroundColor Yellow
$StorePath = Read-Host "Absolute path where to store the extraction? [Example = D:\ ] "

# Add backslash if not already present
if ($StorePath -and $StorePath[-1] -ne "\") {
    $StorePath = $StorePath + "\"
} else {
    $StorePath = "C:\"
}

$PathSystem32 = "C:\Windows\System32\"

# Separators
$SeparatorInit = "################################# ---- "
$SeparatorFin = " ---- #################################"

$Hostname = $env:computername
$Date_ddmmyyyy = Get-Date -Format "dd-MM-yyyy"

# Store the full path
$PathExtract = $StorePath + $Hostname + "_" + $Date_ddmmyyyy + "\"

# Timestamp + Hostname on file names
# Format: [filename]_Hostname_01/12/2020[extension]
$FormatFile = "_" + $Hostname + "_" + $Date_ddmmyyyy

# Create file name in path
$PathFile = $StorePath + $Hostname + "_" + $Date_ddmmyyyy + ".zip"

# Point de départ archive
$PathFilePoint = $PathExtract + "*"

#Get username
$User = $env:USERNAME

#########################################################################################
####################################### FUNCTIONS #######################################
#########################################################################################

################ INIT ################
# Check the command executed and mark it as informational, positive or error
function TryCheck {
    param (
        [scriptblock]$Command,
        [string]$Log,
        [string]$IsInformational,
        [string]$IgnoreError
    )

    & $Command

    if($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $null -or $LASTEXITCODE -eq 80){
        if ($IsInformational -eq "no") {
            Write-Host "[+] ${Log}" -ForegroundColor Green
        }
        elseif ($IsInformational -eq "yes") {
            Write-Host "[!] ${Log}" -ForegroundColor Yellow
        }
    }
    else{
        if ($IgnoreError -eq "no") {
            Write-Host "[-] ${Log}" -ForegroundColor Red
            exit
        }
        elseif ($IgnoreError -eq "yes") {
            Write-Host "[-] ${Log}" -ForegroundColor Red
        }
    }
}

################ EVENT COLLECTING ################
Function CollectEvents{
    param (
        [string]$Events,
        [string]$FileName
    )
    $Command = { .\wevtutil epl "$Events" "${PathExtract}\REGS\${FileName}${FormatFile}.evtx" 2> $null }
    TryCheck -Command $Command -Log "Collect : ${Events}" -IsInformational "no" -IgnoreError "yes"
}

################ HOST INFORMATION RECUPERATION ################
function CollectInfo {
    param (
        [string]$InfoType,
        [scriptblock]$CommandBlock
    )

    $Commands = {
        echo "${SeparatorInit}${InfoType}${SeparatorFin}" | Out-File -Append $HostInfoPath
        & $CommandBlock | Out-File -Append $HostInfoPath
    }

    TryCheck -Command $Commands -Log "Collect : ${InfoType}" -IsInformational "no" -IgnoreError "yes"
}

################ SCRIPT END ################
Function ScriptEnd{# Compression in file ZIP
    try{
        $compress = @{
            Path = $PathFilePoint
            CompressionLevel = "Fastest"
            DestinationPath = $PathFile
        }
        Compress-Archive @compress
        Write-Host "[+] Archive : "$PathFile -ForegroundColor Green
    }
    catch{
        Write-Host "[-] Archive : "$PathFile -ForegroundColor Red
    }

    Delete folder
    try{
        cd ../
        Remove-Item $PathExtract -Recurse -Force -Confirm:$false
        Write-Host "[+] Supression : "$PathExtract -ForegroundColor Green
    }
    catch{
        Write-Host "[-] Supression : "$PathExtract -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "[!] Script ended" -ForegroundColor Yellow
    Write-Host ""

    $DefenderDisabled = ((Get-MpPreference).DisableRealtimeMonitoring)

    if ( $DefenderDisabled -eq $true ){
        Write-Host "[!] Microsoft Defender disabled" -ForegroundColor Yellow
        Write-Host "[!] Don't forget to re-enable real-time protection!" -ForegroundColor Yellow
    }

    cd $PSScriptRoot

    exit
}

#########################################################################################
######################################## SCRIPT #########################################
#########################################################################################

################ INIT ################

# Check the path
if ( Test-Path $StorePath){
    Write-Host "[+] Checking the path entered" -ForegroundColor Green
}
else{
    Write-Host "[-] Checking the path entered" -ForegroundColor Red
    exit
}

# Creation of the folder where the logs will be stored
$Command = { $NoWriteOuput = New-Item -ItemType directory -Path "${PathExtract}" | Out-String }
TryCheck -Command $Command -Log "Creating the destination folder : ${PathExtract}" -IsInformational "no" -IgnoreError "no"


################ EVENT COLLECTING ################
Write-Host "[!] Collecting system events" -ForegroundColor Yellow

# Move to system32
$Command = { cd $PathSystem32 }
TryCheck -Command $Command -Log "Moving to system32 folder" -IsInformational "yes" -IgnoreError "no"

# Creation of the folder where the logs will be stored
$Command = { $NoWriteOuput = New-Item -ItemType directory -Path "${PathExtract}REGS" | Out-String }
TryCheck -Command $Command -Log "Creating the destination folder : ${PathExtract}REGS" -IsInformational "no" -IgnoreError "no"

CollectEvents -Events "Application" -FileName "Application"
CollectEvents -Events "Security" -FileName "Security"
CollectEvents -Events "Microsoft-Windows-AppLocker/EXE and DLL" -FileName "AppLocker-EXE-and-DLL"
CollectEvents -Events "Microsoft-Windows-AppLocker/MSI and Script" -FileName "AppLocker-MSI-and-Script"
CollectEvents -Events "System" -FileName "System"
CollectEvents -Events "Microsoft-Windows-WindowsUpdateClient/Operational" -FileName "WindowsUpdateClient-Operational"
CollectEvents -Events "Setup" -FileName "Setup"
CollectEvents -Events "Microsoft-Windows-WindowsFirewall With Advanced Security/Firewall" -FileName "WindowsFirewall"
CollectEvents -Events "Microsoft-Windows-Application-Experience/Program-Inventory" -FileName "Application-Exeperience-Program-Inventory"
CollectEvents -Events "Microsoft-Windows-CodeIntegrity/Operational" -FileName "Windows-CodeIntegrity-Operational"
CollectEvents -Events "Microsoft-Windows-WindowsDefender/Operational" -FileName "WindowsDefender-Operational"
CollectEvents -Events "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -FileName "TerminalServices-LocalSessionManager-Operational"
CollectEvents -Events "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -FileName "TerminalServices-RemoteConnectionManager-Operational"
CollectEvents -Events "Microsoft-Windows-TaskScheduler/Operational" -FileName "Windows-TaskScheduler-Operational"
CollectEvents -Events "Windows PowerShell" -FileName "Windows-PowerShell"
CollectEvents -Events "Microsoft-Windows-PowerShell/Operational" -FileName "Windows-PowerShell-Operational"


################ HOST INFORMATION RECUPERATION ################
Write-Host "[!] Collecting information of host" -ForegroundColor Yellow

# Delete all content in the previous file
Set-Content -Path $HostInfoPath -Value ""

# Move to out path
$Command = { cd $PathExtract }
TryCheck -Command $Command -Log "Moving to out path : ${PathExtract}" -IsInformational "yes" -IgnoreError "yes"

$HostInfoPath = "${PathExtract}Host-Info${FormatFile}.txt"
echo "${SeparatorInit}INDEX HOST INFO COLLECTED${SeparatorFin}
- Date
- Interfaces
- Netstat port connection
- Netstat port connection processes
- Running processes
- Services list
- Routes
- Mounted volumes
- Task Scheduler
- Shared  SMB volumes
- Command history
- Drivers list
" | Out-File -Append $HostInfoPath

# Date
$CommandBlock = {
    Get-Date -Format 'dddd dd/MM/yyyy HH:mm'
}

CollectInfo -InfoType "Date" -CommandBlock $CommandBlock

# Interfaces
$CommandBlock = {
    Get-NetIPAddress | Out-String
}
                                    
CollectInfo -InfoType "Interfaces" -CommandBlock $CommandBlock

# Netstat port connection
$CommandBlock = {
    Get-NetTCPConnection | ft -auto
}
                                                
CollectInfo -InfoType "Netstat port connection" -CommandBlock $CommandBlock

# Netstat port connection processes
$CommandBlock = {
    $processes = (Get-NetTCPConnection).OwningProcess
    foreach ($process in $processes) {Get-Process -PID $process | select ID,ProcessName}
}
                                                
CollectInfo -InfoType "Netstat port connection processes" -CommandBlock $CommandBlock

# Running processes
$CommandBlock = {
    Get-Process | ft -auto
}
                                                
CollectInfo -InfoType "Running processeses" -CommandBlock $CommandBlock

# Services list
$CommandBlock = {
    Get-Service | ft -auto
}
                                                
CollectInfo -InfoType "Services list" -CommandBlock $CommandBlock

# Routes
$CommandBlock = {
    Get-NetRoute | ft -auto
}
                                                
CollectInfo -InfoType "Routes" -CommandBlock $CommandBlock

# Mounted volumes
$CommandBlock = {
    Get-PSDrive | ft -auto
}
                                                
CollectInfo -InfoType "Mounted volumes" -CommandBlock $CommandBlock

# Task Scheduler
$CommandBlock = {
    Get-ScheduledTask | ft -auto
}
                                                
CollectInfo -InfoType "Task Scheduler" -CommandBlock $CommandBlock

# Shared  SMB volumes
$CommandBlock = {
    Get-SmbShare | ft -auto 
}
                                                
CollectInfo -InfoType "Shared  SMB volumes" -CommandBlock $CommandBlock

# Command history
$CommandBlock = {
    Get-History | ft -auto 
}
                                                
CollectInfo -InfoType "Command history" -CommandBlock $CommandBlock

# Drivers list
$CommandBlock = {
    Get-WindowsDriver –Online -All | ft -auto 
}
                                                
CollectInfo -InfoType "Drivers list" -CommandBlock $CommandBlock


################ HIVE GATHERING ################
$DefenderDisabled = ((Get-MpPreference).DisableRealtimeMonitoring)
if ( $DefenderDisabled -eq $false ){
    ScriptEnd
}

Write-Host "[!] Collecting hives of host" -ForegroundColor Yellow

# Creation of the folder where the logs will be stored
$Command = { $NoWriteOuput = New-Item -ItemType directory -Path "${PathExtract}HIVES" | Out-String }
TryCheck -Command $Command -Log "Creating the destination folder : ${PathExtract}HIVES" -IsInformational "no" -IgnoreError "no"

function CollectHive {
    param (
        [string]$Hive,
        [string]$HiveType
    )

    $Commands = {
        reg save "${Hive}" "${PathExtract}HIVES\${HiveType}" /y > $null 2>&1
    }

    TryCheck -Command $Commands -Log "Collect : ${HiveType}" -IsInformational "no" -IgnoreError "yes"
}


CollectHive -Hive "HKU\.DEFAULT" -HiveType "DEFAULT.hiv"
CollectHive -Hive "HKLM\SAM" -HiveType "SAM.hiv"
CollectHive -Hive "HKLM\Security" -HiveType "Security.hiv"
CollectHive -Hive "HKLM\Software" -HiveType "Software.hiv"
CollectHive -Hive "HKLM\System" -HiveType "System.hiv"
CollectHive -Hive "HKEY_CURRENT_USER" -HiveType "NTUSER_$User.DAT"
CollectHive -Hive "HKEY_CURRENT_USER\Software\Classes" -HiveType "USRCLASS_$User.DAT"

Copy-Item -Path "C:\Windows\AppCompat\Programs\Amcache.hve" -Destination "${PathExtract}HIVES\Amcache.hve"

################ SCRIPT END ################

ScriptEnd
