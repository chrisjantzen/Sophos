###
# File: \Sophos Tamper Key Mass Disable.ps1
# Project: Sophos
# Created Date: Monday, November 27th 2023, 4:12:33 pm
# Author: Chris Jantzen
# -----
# Last Modified: Tue Nov 28 2023
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

############################
# $SophosAPIKey
#
# Your Sophos API key details 
#
$SophosAPIKey = @{
	ClientID = ""
	Secret = ""
}

############################
# $CustomerName
#
# The customer's full name as shown in Sophos
#
$CustomerName = ""

############################
# $ComputerList
#
# The hostnames of the computers to disable tamper protection on
#
$ComputerList = @()
############################


# Connect to Sophos
$SophosTenantID = $false
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

if ($SophosJWT) {
	# Get our partner ID
	$SophosHeader = @{
		Authorization = "Bearer $SophosJWT"
	}
	$SophosPartnerInfo = Invoke-RestMethod -Method GET -Headers $SophosHeader -uri "https://api.central.sophos.com/whoami/v1"
	$SophosPartnerID = $SophosPartnerInfo.id

	if ($SophosPartnerID) {
		# Get list of tenants, so we can get the companies ID in sophos
		$SophosHeader = @{
			Authorization = "Bearer $SophosJWT"
			"X-Partner-ID" = $SophosPartnerID
		}
		$SophosTenants = Invoke-RestMethod -Method GET -Headers $SophosHeader -uri "https://api.central.sophos.com/partner/v1/tenants?pageTotal=true"

		if ($SophosTenants.pages -and $SophosTenants.pages.total -gt 1) {
			$TotalPages = $SophosTenants.pages.total
			for ($i = 2; $i -le $TotalPages; $i++) {
				$SophosTenants.items += (Invoke-RestMethod -Method GET -Headers $SophosHeader -uri "https://api.central.sophos.com/partner/v1/tenants?page=$i").items
			}
		}

		# Get the tenants ID and URL
		if ($SophosTenants.items -and $CustomerName) {
			$CompanyInfo = $SophosTenants.items | Where-Object { $_.name -like $CustomerName }
			$SophosTenantID = $CompanyInfo.id
			$TenantApiHost = $CompanyInfo.apiHost
		}
	}
}

# Get all endpoints
$SophosEndpoints = $false
$Sophos_AllDevices = @()
if ($SophosTenantID -and $TenantApiHost) {
	$SophosHeader = @{
		Authorization = "Bearer $SophosJWT"
		"X-Tenant-ID" = $SophosTenantID
	}
	$SophosEndpoints = Invoke-RestMethod -Method GET -Headers $SophosHeader -uri ($TenantApiHost + "/endpoint/v1/endpoints?pageSize=500")

	$NextKey = $false
	if ($SophosEndpoints.pages.nextKey) {
		$SophosEndpoints.items = [System.Collections.Generic.List[PSCustomObject]]$SophosEndpoints.items
		$NextKey = $SophosEndpoints.pages.nextKey
	}
	while ($NextKey) {
		$SophosEndpoints_NextPage = $false
		$SophosEndpoints_NextPage = Invoke-RestMethod -Method GET -Headers $SophosHeader -uri ($TenantApiHost + "/endpoint/v1/endpoints?pageFromKey=$NextKey")
		foreach ($Endpoint in $SophosEndpoints_NextPage.items) {
			$SophosEndpoints.items.Add($Endpoint)
		}

		$NextKey = $false
		if ($SophosEndpoints_NextPage.pages.nextKey) {
			$NextKey = $SophosEndpoints_NextPage.pages.nextKey
		}
	}

	if (!$SophosEndpoints) {
		Write-Host "Failed to get: Device List from Sophos" -ForegroundColor Red
	}
} else {
	Write-Host "Failed to connect to: Sophos (No Tenant ID or API Host)" -ForegroundColor Red
}

if ($SophosEndpoints -and $SophosEndpoints.items) {
	$Sophos_AllDevices = $SophosEndpoints.items
} else {
	$Sophos_AllDevices = @()
	Write-Warning "Warning! Could not get device list from Sophos!"
}

# Filter devices down to the ones we want to disable tamper protection on
$Sophos_DisableDevices = @()
if ($Sophos_AllDevices) {
	$Sophos_DisableDevices = $Sophos_AllDevices | Where-Object { $_.hostname -in $ComputerList }
}

# Turn off tamper protection on the targeted devices
$TamperKeys = @()
if ($Sophos_DisableDevices) {
	$SophosHeader = @{
		Authorization = "Bearer $SophosJWT"
		"X-Tenant-ID" = $SophosTenantID
		Accept = "application/json"
		"Content-Type" = "application/json"
	}

	$body = @{
		enabled = $false
	} | ConvertTo-Json

	$i = 0
	foreach ($Device in $Sophos_DisableDevices) {
		$Result = $false
		try {
			$Result = Invoke-RestMethod -Method POST -Headers $SophosHeader -uri ($TenantApiHost + "/endpoint/v1/endpoints/$($Device.id)/tamper-protection") -Body $body
			Start-Sleep -Milliseconds 200
		} catch {
			if ($_.Exception.Response.StatusCode.value__ -eq 429 -or $_.Exception.Response.StatusCode.value__ -match "5\d{2}") {
				Write-Host "Retry Sophos API call."
				Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
				Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

				Start-Sleep -Seconds 2
				$Result = Invoke-RestMethod -Method POST -Headers $SophosHeader -uri ($TenantApiHost + "/endpoint/v1/endpoints/$($Device.id)/tamper-protection") -Body $body
			}
		}

		if ($Result -and $Result.enabled -eq $false) {
			Write-Host "Disabled Tamper Protection on: $($Device.hostname)" -ForegroundColor Green
			$TamperKeys += [PSCustomObject]@{
				Hostname = $Device.hostname
				TamperProtectionKey = $Result.password
			}
			$i++
		} else {
			Write-Host "Failed to disable tamper protection on: $($Device.hostname)" -ForegroundColor Red
		}
	}

	Write-Host "Tamper protection disabled on $i devices."
	$TamperKeys | Out-GridView
}
