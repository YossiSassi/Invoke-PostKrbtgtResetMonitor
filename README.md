# Invoke-PostKrbtgtResetMonitor

Centralized detection of Golden Ticktes via event ID 4769 (TGS) with Error code 0x1f & TGT Anomalies. 

Useful when coming to a site recently After a krbtgt double-reset.

NOTE: Run this script AFTER resetting the krbtgt password TWICE (for more info, see: https://github.com/microsoft/New-KrbtgtKeys.ps1). 

No Dependencies/modules. Requires Event Log Redears or equivalent (preferrably - run elevated on the PDC/one of the DCs, for better Performance and continued operation of the monitoring process)

by 1nTh35h311 (Comments to yossis@protonmail.com)
