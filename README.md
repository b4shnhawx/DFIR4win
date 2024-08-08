# DFIR4win

<p align="center">
  <img src="https://github.com/b4shnhawx/DFIR4win/blob/main/img/dfir4win.png" width="95%">
</p>

This script automates the collection of data from a host. The script must be run on the host with administrator permissions in order to collect meaningful data in the DFIR process.

You must be clear about the whole process to avoid any data corruption.

The original script belongs to AlrikRr.
I have tried to optimise, add the function to collect the hives and traded the code.

## Usage
This script is capable of automating the collection of much of the data needed to analyse activity on a Windows machine.
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

## Tree directory
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

## Examples of execution
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
