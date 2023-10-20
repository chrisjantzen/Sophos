###
# File: \SophosAlertsCleanup.ps1
# Project: Misc
# Created Date: Thursday, October 19th 2023, 10:53:52 am
# Author: Chris Jantzen
# -----
# Last Modified: Fri Oct 20 2023
# Modified By: Chris Jantzen
# -----
# Copyright (c) 2023 Sea to Sky Network Solutions
# License: MIT License
# -----
# 
# HISTORY:
# Date      	By	Comments
# ----------	---	----------------------------------------------------------
###

#####################################

# This script can be used to clean up Sophos alerts.
# It relies on the Device Audit to work (it uses the config files)

#####################################
$AutotaskAPIKey = @{
	Url = "https://webservicesX.autotask.net/atservicesrest"
	IntegrationCode = ""
	Username = ""
	Key = ''
}

$SophosAPIKey = @{
	ClientID = ""
	Secret = ""
}

$DeviceAuditConfigLoc = "<Device Audit Config Files Location>" # The path to the device audit config files

$UpDownEventTypes = @{
	"Event::Endpoint::SavEnabled" = "Event::Endpoint::SavDisabled"
	"Event::Endpoint::ServiceRestored" = "Event::Endpoint::ServiceNotRunning"
	"Event::Endpoint::HeartbeatRestored" = "Event::Endpoint::HeartbeatMissing"
	"Event::Firewall::FirewallGatewayUp" = "Event::Firewall::FirewallGatewayDown"
	"Event::Firewall::FirewallHAStateRestored" = "Event::Firewall::FirewallHAStateDegraded"
	"Event::Firewall::FirewallREDTunnelUp" = "Event::Firewall::FirewallREDTunnelDown"
	"Event::Firewall::FirewallVPNTunnelUp" = "Event::Firewall::FirewallVPNTunnelDown"
	"Event::Firewall::Reconnected" = "Event::Firewall::LostConnectionToSophosCentral"
	"Event::Mobile::ApnsCertificateRenewed" = "Event::Mobile::ApnsCertificateExpired"
}
#####################################

$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Write-Output "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
	Write-PSFMessage -Level Warning -Message "Temporarily changed TLS to TLS v1.2."
}

If (Get-Module -ListAvailable -Name "AutotaskAPI") {Import-module AutotaskAPI -Force} Else { install-module AutotaskAPI -Force; import-module AutotaskAPI -Force}

# Connect to Autotask
$AutotaskConnected = $false
$DeviceAuditConfigs = @()
if ($AutotaskAPIKey.Key -and $DeviceAuditConfigLoc) {
	$Secret = ConvertTo-SecureString $AutotaskAPIKey.Key -AsPlainText -Force
	$Creds = New-Object System.Management.Automation.PSCredential($AutotaskAPIKey.Username, $Secret)
	Add-AutotaskAPIAuth -ApiIntegrationcode $AutotaskAPIKey.IntegrationCode -credentials $Creds
	Add-AutotaskBaseURI -BaseURI $AutotaskAPIKey.Url
	
	# Verify the Autotask API key works
	$AutotaskConnected = $true
	try { 
		Get-AutotaskAPIResource -Resource Companies -ID 0 -ErrorAction Stop 
		Write-Host "Successfully connected to Autotask."
	} catch { 
		$CleanError = ($_ -split "/n")[0]
		if ($_ -like "*(401) Unauthorized*") {
			$CleanError = "API Key Unauthorized. ($($CleanError))"
		}
		Write-Warning $CleanError
		$AutotaskConnected = $false
	}

	$OrgMapping = @()
	if ($AutotaskConnected) {
		$DeviceAuditConfigs = Get-ChildItem -Path  $DeviceAuditConfigLoc
		if ($DeviceAuditConfigs) {
			$DeviceAuditConfigs = $DeviceAuditConfigs | Where-Object { $_.Name -like "Config-*.ps1" }
		}

		if ($DeviceAuditConfigs) {
			foreach ($DeviceAuditConfig in $DeviceAuditConfigs) {
				$ConfigFile = New-Object System.IO.StreamReader -ArgumentList $DeviceAuditConfig.FullName
				$CompanyOrgMapping = @{
					SophosCompany = $false
					AutotaskID = $false
				}

				:loop while ($true) { 
					$line = $ConfigFile.ReadLine() 
					if ($line -eq $null) { 
						#If the line was $null, we're at the end of the file, let's break 
						$ConfigFile.close() 
						break loop 
					} 
					if($line.StartsWith('$Sophos_Company =')) { 
						if ($line -match 'Sophos_Company += +"([\w\d ]+)"') {
							$CompanyOrgMapping.SophosCompany = $Matches[1]
						}
					}
					if($line.StartsWith('$Autotask_ID =')) { 
						if ($line -match 'Autotask_ID += +"([\d]+)"') {
							$CompanyOrgMapping.AutotaskID = $Matches[1]
						}
					}

					if ($CompanyOrgMapping.SophosCompany -ne $false -and $CompanyOrgMapping.AutotaskID -ne $false) {
						break loop
					}
				}

				$OrgMapping += $CompanyOrgMapping
			}
		} else {
			$AutotaskConnected = $false
		}
	}
}

# Connect to Sophos
$SophosPartnerID = $false
$SophosGetTokenBody = @{
	grant_type = "client_credentials"
	client_id = $SophosAPIKey.ClientID
	client_secret = $SophosAPIKey.Secret
	scope = "token"
}

# Auth
$SophosToken = Invoke-RestMethod -Method POST -Body $SophosGetTokenBody -ContentType "application/x-www-form-urlencoded" -uri "https://id.sophos.com/api/v2/oauth2/token"
$SophosJWT = $SophosToken.access_token
$SophosToken | Add-Member -NotePropertyName expiry -NotePropertyValue $null
$SophosToken.expiry = (Get-Date).AddSeconds($SophosToken.expires_in - 60)
$SophosHeader = @{
	Authorization = "Bearer $SophosJWT"
}

if (!$SophosJWT) {
	Write-Error "Could not authorize with Sophos: No JWT token was returned"
	exit
}

# Who am I
$SophosTenantInfo = Invoke-RestMethod -Method GET -Headers $SophosHeader -uri "https://api.central.sophos.com/whoami/v1"
$SophosPartnerID = $SophosTenantInfo.id

if (!$SophosPartnerID) {
	Write-Error "Could not get the Sophos Partner ID"
	exit
}

# Get Sophos Tenants
$SophosHeader = @{
	Authorization = "Bearer $SophosJWT"
	"X-Partner-ID" = $SophosPartnerID
}
$TenantsAPIUrl = "https://api.central.sophos.com/partner/v1/tenants?page"
$SophosTenants = Invoke-RestMethod -Method GET -Headers $SophosHeader -uri ($TenantsAPIUrl + "Total=true")

if ($SophosTenants -and $SophosTenants.pages -and $SophosTenants.pages.total -gt 1) {
	$SophosTenants.items = [System.Collections.Generic.List[PSCustomObject]]$SophosTenants.items
	$TotalPages = $SophosTenants.pages.total

	for ($i = 2; $i -le $TotalPages; $i++) {
		$SophosTenants_Temp = Invoke-RestMethod -Method GET -Headers $SophosHeader -uri ($TenantsAPIUrl + "=" + $i)
		foreach ($Tenant in $SophosTenants_Temp.items) {
			$SophosTenants.items.Add($Tenant)
		}
	}
}

if (!$SophosTenants -or ($SophosTenants | Measure-Object).Count -lt 1) {
	Write-Error "Could not get the Sophos Tenants"
	exit
}

Start-Sleep -Seconds 1 # wait a second to prevent rate limiting

function closeSophosAlert($Tenant, $AlertID, $AllowedActions = @("acknowledge")) {
	$Url = 'https://api-' + $Tenant.dataRegion + '.central.sophos.com/common/v1/alerts/' + $AlertID + '/actions'

	$Action = "acknowledge"
	if ("acknowledge" -notin $AllowedActions) {
		if ("clearThreat" -in $AllowedActions) {
			$Action = "clearThreat"
		} elseif ("clearHmpa" -in $AllowedActions) {
			$Action = "clearHmpa"
		} else {
			Write-Warning "Failed to close alert: $($AlertID). Reason: Found no useable actions."
			return $false
		}
	}

	$Header = @{
		Authorization = "Bearer $SophosJWT"
		"X-Tenant-ID" = $Tenant.id
		"Accept" = "application/json"
		"Content-Type" = "application/json"
	}
	$RequestBody = @{
		action = $Action
		message = "Acknowledged by Sophos Alert Cleanup"
	} | ConvertTo-Json

	try {
		$Response = Invoke-RestMethod -Method POST -Headers $Header -Body $RequestBody -Uri $Url
	} catch {
		if ($_.Exception.Message -like "*Not Found.") {
			return $true
		} else {
			Write-Warning "Failed to close alert: $($AlertID). Retrying..."
			Start-Sleep -Seconds 1
			try {
				$Response = Invoke-RestMethod -Method POST -Headers $Header -Body $RequestBody -Uri $Url
			} catch {
				Write-Warning "Failed to close alert: $($AlertID). Reason: $($_.Exception.Message)"
				return $false
			}
		}
	}

	if ($Response -and $Response.result -eq "success") {
		Write-Verbose "Successfully removed alert: $($AlertID)"
		return $true
	} else {
		Write-Warning "Failed to close alert: $($AlertID). Retrying..."
		Start-Sleep -Seconds 1
		$Response = Invoke-RestMethod -Method POST -Headers $Header -Body $RequestBody -Uri $Url

		if ($Response -and $Response.result -eq "success") {
			Write-Verbose "Successfully removed alert: $($AlertID)"
			return $true
		} else {
			Write-Warning "Failed to close alert: $($AlertID). Reason: $($_.Exception.Message)"
			return $false
		}
	}
}

$CurrentTimestamp = (Get-Date).AddDays(-7).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

# Loop through each tenant
foreach ($SophosTenant in $SophosTenants.items) {
	Write-Host "Checking alerts for: $($SophosTenant.name)"

	# Refresh token if it has expired or expires in the next 5 minutes
	if (($SophosToken.expiry.AddMinutes(-5)) -lt (Get-Date)) {
		$SophosToken = Invoke-RestMethod -Method POST -Body $SophosGetTokenBody -ContentType "application/x-www-form-urlencoded" -uri "https://id.sophos.com/api/v2/oauth2/token"
		$SophosJWT = $SophosToken.access_token
		$SophosToken | Add-Member -NotePropertyName expiry -NotePropertyValue $null
		$SophosToken.expiry = (Get-Date).AddSeconds($SophosToken.expires_in)
	}

	$SophosHeader = @{
		Authorization = "Bearer $SophosJWT"
		"X-Tenant-ID" = $SophosTenant.id
		"Accept" = "application/json"
	}

	# Get tenants alerts
	$BaseUrl = "https://api-" + $SophosTenant.dataRegion + ".central.sophos.com/common/v1/alerts?pageSize=1000"
	$Alerts = Invoke-RestMethod -Method GET -Headers $SophosHeader -uri ($BaseUrl + "&sort=raisedAt:desc")

	$NextKey = $false
	if ($Alerts.pages.nextKey) {
		$Alerts.items = [System.Collections.Generic.List[PSCustomObject]]$Alerts.items
		$NextKey = $Alerts.pages.nextKey
	}
	while ($NextKey) {
		$Alerts_NextPage = $false
		$Alerts_NextPage = Invoke-RestMethod -Method GET -Headers $SophosHeader -uri ($BaseUrl + "&pageFromKey=$NextKey")
		foreach ($Alert in $Alerts_NextPage.items) {
			$Alerts.items.Add($Alert)
		}

		$NextKey = $false
		if ($Alerts_NextPage.pages.nextKey) {
			$NextKey = $Alerts_NextPage.pages.nextKey
		}
	}

	# Parse alerts
	if ($Alerts -and $Alerts.items -and ($Alerts.items | Measure-Object).Count -gt 0) {
		$Alerts.items = $Alerts.items | Sort-Object -Property raisedAt -Descending

		$QueryAutotask = $false
		if ($AutotaskConnected -and $DeviceAuditConfigLoc) {
			$AutotaskID = ($OrgMapping | Where-Object { $_.SophosCompany -like $SophosTenant.name }).AutotaskID
			if ($AutotaskID) {
				$AutotaskID = ($OrgMapping | Where-Object { $_.SophosCompany -like $SophosTenant.showAs }).AutotaskID
			}
			if ($AutotaskID) {
				$QueryAutotask = $true
			}
		}

		$ClosedAlerts = @()

		# First go through old up alerts looking for any that should close a down alert and close both
		$UpAlerts = $Alerts.items | Where-Object { $_.type -in $UpDownEventTypes.Keys -and $_.raisedAt -lt $CurrentTimestamp }
		foreach ($Alert in $UpAlerts) {
			if ($Alert.id -in $ClosedAlerts) {
				continue
			}

			# Find any related down alerts
			$RelatedDownAlerts = $Alerts.items | Where-Object { $_.type -eq $UpDownEventTypes[$Alert.type] -and $_.managedAgent.id -eq $Alert.managedAgent.id -and $_.raisedAt -le $Alert.raisedAt -and $_.id -notin $ClosedAlerts }
			$RelatedUpAlerts = $Alerts.items | Where-Object { $_.type -eq $Alert.type -and $_.managedAgent.id -eq $Alert.managedAgent.id -and $_.raisedAt -le $Alert.raisedAt -and $_.id -ne $Alert.id -and $_.id -notin $ClosedAlerts }

			if (closeSophosAlert -Tenant $SophosTenant -AlertID $Alert.id -AllowedActions $Alert.allowedActions) {
				$ClosedAlerts += $Alert.id
			}

			foreach ($RelatedDownAlert in $RelatedDownAlerts) {
				if ($RelatedDownAlert.allowedActions -contains "acknowledge") {
					if (closeSophosAlert -Tenant $SophosTenant -AlertID $RelatedDownAlert.id -AllowedActions $RelatedDownAlert.allowedActions) {
						$ClosedAlerts += $RelatedDownAlert.id
					}
				}
			}

			foreach ($RelatedUpAlert in $RelatedUpAlerts) {
				if ($RelatedUpAlert.allowedActions -contains "acknowledge") {
					if (closeSophosAlert -Tenant $SophosTenant -AlertID $RelatedUpAlert.id -AllowedActions $RelatedUpAlert.allowedActions) {
						$ClosedAlerts += $RelatedUpAlert.id
					}
				}
			}
		}

		$Alerts.items = $Alerts.items | Where-Object { $_.id -notin $ClosedAlerts }

		if ($QueryAutotask -and $Alerts -and $Alerts.items -and ($Alerts.items | Measure-Object).Count -gt 0) {
			# Get related Autotask tickets in the respective time frame
			$OldestAlertDate = $Alerts.items[-1].raisedAt

			$SophosTickets = Get-AutotaskAPIResource -Resource Tickets -SearchQuery ('{"filter":[{"op":"and","items": [{"op":"eq","field":"CompanyID","value":' + $AutotaskID + '}, {"op":"contains","field":"title","value":"Sophos Alert: "}, {"op":"exist","field":"CompletedDate"}, {"op":"gte","field":"createDate","value":"' + $OldestAlertDate + '"}]}]}')
		
			# Go through remaining alerts and close any that correspond to a closed Autotask ticket
			foreach ($Alert in $Alerts.items) {
				if ($Alert.severity -eq "low" -or $Alert.id -in $ClosedAlerts) {
					continue
				}

				$RelatedTickets = $SophosTickets | Where-Object { $_.description -like "*ID: $($Alert.id)*" -and $_.description -like "*$($Alert.managedAgent.name)*" }

				if ($RelatedTickets -and ($RelatedTickets | Measure-Object).Count -gt 0) {
					# Find any up ticket as well to close
					$UpTicket = $false
					if ($Alert.type -in $UpDownEventTypes.Values) {
						$UpDownType = $UpDownEventTypes.GetEnumerator() | Where-Object { $_.Value -eq $Alert.type }
						if ($UpDownType) {
							$UpType = $UpDownType.Name
							$UpTicket = $Alerts.items | Where-Object { $_.type -eq $UpType -and $_.managedAgent.id -eq $Alert.managedAgent.id -and $_.raisedAt -ge $Alert.raisedAt } | Sort-Object raisedAt | Select-Object -First 1
						}
					}

					# Found a related closed ticket, close the Sophos alert (and the up alert if found)
					if (closeSophosAlert -Tenant $SophosTenant -AlertID $Alert.id -AllowedActions $Alert.allowedActions) {
						$ClosedAlerts += $Alert.id
					}
					if ($UpTicket) {
						if (closeSophosAlert -Tenant $SophosTenant -AlertID $UpTicket.id -AllowedActions $UpTicket.allowedActions) {
							$ClosedAlerts += $UpTicket.id
						}
					}
				}
			}
		}

		# Close any old 'low' severity alerts
		foreach ($Alert in $Alerts.items) {
			if ($Alert.severity -ne "low" -or $Alert.id -in $ClosedAlerts) {
				continue
			}

			if ($Alert.raisedAt -lt (Get-Date).AddDays(-30)) {
				if (closeSophosAlert -Tenant $SophosTenant -AlertID $Alert.id -AllowedActions $Alert.allowedActions) {
					$ClosedAlerts += $Alert.id
				}
			}
		}

		if ($ClosedAlerts) {
			$ClosedAlerts = $ClosedAlerts | Sort-Object -Unique
			Write-Host "Cleanup complete for $($SophosTenant.name). Closed $($ClosedAlerts.count) alerts." -ForegroundColor Green
		}
	}
}