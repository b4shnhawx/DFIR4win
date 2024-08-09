# DFIR4win

<p align="center">
  <img src="https://github.com/b4shnhawx/DFIR4win/blob/main/img/dfir4win.png" width="95%">
</p>

This script automates the collection of data from a host. The script must be run on the host with administrator permissions in order to collect meaningful data in the DFIR process.

You must be clear about the whole process to avoid any data corruption.

The original script belongs to AlrikRr.
I have tried to optimise, add the function to collect the hives and traded the code.

## USAGE
This script is capable of automating the collection of much of the data needed to analyse activity on a Windows machine and compress it in a ZIP file.
- Relevant info of the host
- Event logs
- Registry Hives (for more info see [Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives))

In case of the hives extraction, it's possibly you need to disable the real time protection in your antivirus (AV) for considering as souspicious actions. By default, Windows use Windows Defender.

This scripts detects if your active AV its Windows Defender or any other 3rd party AV. If it is the second case, it is possibly that other modules of your AV blocks the extraction of the hives, so I recommend to check manually if all your needed hives has been extracted properly.

If the script isn’t working properly with the extraction of the hives, extract them manually with any program (as [Registry Explorer](https://ericzimmerman.github.io/#!index.md) from Eric Zimmerman).

### First of all
You must have enable the execution of scripts in powershell

```
Get-ExecutionPolicy -List
Set-ExecutionPolicy Bypass -Scope CurrentUser
```
Finally, it is advisable to change the policy back to 'RemoteSigned'.
```
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Use
Download the script on the machine you want to collect the artefacts and run it in PowerShell with administrator permissions.
```
powershell.exe .\dfir4win.ps1
```
Every step performed by the script will be checked and shows the result in the terminal:
<p style="color:green;">[+] Operation executed successfully</p>
<p style="color:red;">[-] Operation not executed due to an error</p>
<p style="color:orange;">[!] Informational</p>

Then, the script will ask you for some parameters:

1. Enter the path where you want to save the ZIP with all the data.
...```
[!] The extraction will be stored in a folder containing the job name and the current date.
[!] This folder will then be compressed into a ZIP archive and deleted.

Absolute path where to store the extraction? [ Example = D:\extraction\ ] [ Default = C:\ ] :
...```
2. After that, you can decide to disable or not the AV in order to improve the hives collection. When you decide, press ENTER.
```
[!] To pick up the hives from the system you will need to disable the real-time protection of Microsoft Defender.
[!] If it is another AV and it is not disabled, it is possible that some, but not all, of the hives will be collected. The antivirus will only block the collection of some of the hives, but the script will extract the rest of the information.
[!] If you want to collect ALL hives, be sure to disable protection NOW.

Press ENTER to continue:
```
3. In case you decide to mantain enable the AV (or ), the script will ask you to force the hives data collection, or ignore this step.
```
Do you want to try to collect as many hives as possible? [ y / n ] :
```
4. Finally, the extraction will start.

## TREE DIRECTORY
```
./HOST_DD-MM-YYYY.zip
 |
 |-- REGS
 |    |-- *_HOST_DD-MM-YYYY.evtx
 |
 |-- HIVES
 |    |-- Security.hiv
 |    |-- SAM.hiv
 |    |-- DEFAULT.hiv
 |    |-- NTUSER_USERNAME.DAT
 |    |-- System.hiv
 |    |-- USRCLASS_USERNAME.DAT
 |    |-- Software.hiv
 |
 |-- Host-Info_HOST_DD-MM-YYYY.txt
```

## EXAMPLES OF EXECUTION
- Collection with the AV disabled
  <p align="center">
    <img src="https://github.com/b4shnhawx/DFIR4win/blob/main/img/dfir4win_demo_noav.gif" width="80%">
  </p>
- Collection with the AV enabled and try to collect hives
  <p align="center">
    <img src="https://github.com/b4shnhawx/DFIR4win/blob/main/img/dfir4win_demo_avy.gif" width="80%">
  </p>
- Collection with the AV enabled but only collect the regs
  <p align="center">
    <img src="https://github.com/b4shnhawx/DFIR4win/blob/main/img/dfir4win_demo_avn.gif" width="80%">
  </p>
