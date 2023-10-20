# Sophos Powershell Scripts

A collection of powershell scripts we use for Sophos internally.

### Sophos Tamper Key Export
This can be used to export all of the tamper keys for all of the devices in a specific tenant. 

You just need to fill in Sophos API details and the export location. It will then dump a CSV file into that location with all of the devices and their tamper protection keys.


### Sophos Alerts Cleanup
This script will cleanup alerts in Sophos. It is expected to be used with the [Sophos Alerts Autotask Integration](https://github.com/seatosky-chris/SophosAlerts-AutotaskIntegration) Azure function that I have created. 

The script will go through all alerts for each tenant in your Sophos portal. It will do the following:
1. Go through Up alerts that are more than a week old, find any other related up/down alerts and close them. 
2. Find closed Autotask tickets that were for Sophos alerts and will close any Sophos alerts related to these.
3. Close any low severity alerts more than 1 month old.

To set it up you must fill in an Autotask API key and Sophos API key. This script makes use of the Device Audit config files for easier configuration. Set `$DeviceAuditConfigLoc` to the path of your **Device Audit\Config Files** folder. If you do not use the device audit script, you can create a folder with config files based on the device audit, just make sure each file is named like "Config-*.ps1" and contains the variables `$Sophos_Company =` and `$Autotask_ID =` set to the Sophos company name and Autotask company ID respectively. 