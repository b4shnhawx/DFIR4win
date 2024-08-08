# DFIR4win

This script automates the collection of data from a host. The script must be run on the host with administrator permissions in order to collect meaningful data in the DFIR process.

You must be clear about the whole process to avoid any data corruption.

The original script belongs to AlrikRr.
I have tried to optimise, add the function to collect the hives and traded the code.

## Usage

### Before
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
1. Collection with the AV disabled
  <p align="center">
    <img src="https://github.com/b4shnhawx/DFIR4win/blob/main/img/dfir4win_demo_noav.gif">
  </p>
3. Collection with the AV enabled and try to collect hives
  <p align="center">
    <img src="https://github.com/b4shnhawx/DFIR4win/blob/main/img/dfir4win_demo_avy.gif">
  </p>
4. Collection with the AV enabled but only collect the regs
  <p align="center">
    <img src="https://github.com/b4shnhawx/DFIR4win/blob/main/img/dfir4win_demo_avn.gif">
  </p>
