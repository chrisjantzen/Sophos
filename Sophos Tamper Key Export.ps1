###
# File: \Sophos Tamper Key Export.ps1
# Project: Misc
# Created Date: Friday, March 24th 2023, 10:36:19 am
# Author: Chris Jantzen
# -----
# Last Modified: Fri Mar 24 2023
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
$ExportLocation = "C:\temp\SophosTamperKeys.csv"
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
$SophosHeader = @{
	Authorization = "Bearer $SophosJWT"
}

# Who am I
$SophosTenantInfo = Invoke-RestMethod -Method GET -Headers $SophosHeader -uri "https://api.central.sophos.com/whoami/v1"
$SophosTenantID = $SophosTenantInfo.id
$TenantApiHost = $SophosTenantInfo.apiHosts.dataRegion

# Get endpoints
$SophosEndpoints = $false
$Sophos_Devices = @()
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
	$Sophos_Devices = $SophosEndpoints.items
} else {
	$Sophos_Devices = @()
	Write-Warning "Warning! Could not get device list from Sophos!"
}

# Get tamper protection keys
if ($Sophos_Devices -and $SophosTenantID -and $TenantApiHost) {
	$SophosTamperKeys = [System.Collections.ArrayList]@()

	$SophosDeviceCount = ($Sophos_Devices | Measure-Object).Count
	$i = 0
	$SophosFailedSleepTime = 0
	$MaxFailTime = 180000 # 3 minutes
	$FailsInARow = 0
	:foreachSophosDevice foreach ($Device in $Sophos_Devices) {
		$i++
		[int]$PercentComplete = ($i / $SophosDeviceCount * 100)
		Write-Progress -Activity "Retrieving Sophos Tamper Protection Keys" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%")

		# Refresh token if it has expired
		if ($SophosToken.expiry -lt (Get-Date)) {
			try {
				$SophosToken = Invoke-RestMethod -Method POST -Body $SophosGetTokenBody -ContentType "application/x-www-form-urlencoded" -uri "https://id.sophos.com/api/v2/oauth2/token"
				$SophosJWT = $SophosToken.access_token
				$SophosToken | Add-Member -NotePropertyName expiry -NotePropertyValue $null
				$SophosToken.expiry = (Get-Date).AddSeconds($SophosToken.expires_in)
			} catch {
				$SophosToken = $false
			}
		}

		if (!$SophosToken) {
			$FailsInARow++
			if ($FailsInARow -gt 10) {
				break
			}
			continue;
		}
		$FailsInARow = 0

		$SophosHeader = @{
			Authorization = "Bearer $SophosJWT"
			"X-Tenant-ID" = $SophosTenantID
		}

		$SophosTamperInfo = $false
		$attempt = 0
		while (!$SophosTamperInfo -and $SophosFailedSleepTime -lt $MaxFailTime) {
			try {
				$SophosTamperInfo = Invoke-RestMethod -Method GET -Headers $SophosHeader -uri ($TenantApiHost + "/endpoint/v1/endpoints/$($Device.id)/tamper-protection")
			} catch {
				if ($_.Exception.Response.StatusCode.value__ -eq 429 -or $_.Exception.Response.StatusCode.value__ -match "5\d{2}") {
					Write-Host "Retry Sophos API call."
					Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
					Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
					$SophosTamperInfo = $false

					$backoff = Get-Random -Minimum 0 -Maximum (@(30000, (1000 * [Math]::Pow(2, $attempt)))| Measure-Object -Minimum).Minimum
					$attempt++
					$SophosFailedSleepTime += $backoff
					Write-Host "Sleep for: $([int]$backoff)"
					Start-Sleep -Milliseconds ([int]$backoff)
				}
			}
		}

		if ($SophosFailedSleepTime -ge $MaxFailTime) {
			break foreachSophosDevice
		}

		if ($SophosTamperInfo -and $SophosTamperInfo.password) {
			$SophosTamperKeys.Add([PsCustomObject]@{
				id = $Device.id
				password = $SophosTamperInfo.password
				enabled = $SophosTamperInfo.enabled
			}) | Out-Null;
		}
	}
	Write-Progress -Activity "Retrieving Sophos Tamper Protection Keys" -Status "Ready" -Completed
}

$Sophos_Devices | ForEach-Object { 
	$DeviceID = $_.id
	Add-Member -InputObject $_ -NotePropertyName "TamperPassword" -NotePropertyValue $null

	$DeviceTamperInfo = $SophosTamperKeys | Where-Object { $_.id -eq $DeviceID }
	if ($DeviceTamperInfo) {
		$_.TamperPassword = $DeviceTamperInfo.password
	}
}

# Export CSV
if ($Sophos_Devices -and $SophosTamperKeys.Count -gt 0) {
	$Sophos_Devices | Export-Csv -Path $ExportLocation
}