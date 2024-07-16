# DFIR4win

This script automates the collection of data from a host. The script must be run on the host with administrator permissions in order to collect meaningful data in the DFIR process.

You must be clear about the whole process to avoid any data corruption.

The original script belongs to AlrikRr.
I have tried to optimise, add the function to collect the hives and traded the code.

## Usage

You must have enable the execution of scripts in powershell

```
Get-ExecutionPolicy -List
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```
