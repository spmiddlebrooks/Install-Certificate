<#
.SYNOPSIS
.DESCRIPTION
.PARAMETER
.EXAMPLE
.NOTES
	Version: 1.2
	Updated: 10/23/2017
	Author : Scott Middlebrooks
.LINK
.CHANGELOG
	1.2	Added Remove-ExpiredCertificates function and updated Set-CertificateFriendlyName function to make appending cert expiry optional
	1.1.3	Updated Enable-KempCertificate function to ignore self signed certificate warnings
	1.1.3	Updated Get-LatestPfx function return logic and remove PfxPassword parameter
	1.1.2	Added ParameterSetName to main script parameters
	1.1.1	Changed variable ServerRole to Role and function/parameter value SfbEdge to SfbExternalEdge
	1.1.0	Added Enable-KempCertificate function & Kemp parameters to main script
	1.0.1	Added Set-CertFriendlyName function & CertFriendlyName parameter to main script
#>
#Requires -Version 3.0

[cmdletbinding(DefaultParameterSetName="Windows")]
param(
	[Parameter(Mandatory=$True,Position=0)]
		[ValidateSet('SfbEdgeExternal','RdGateway', 'Adfs', 'AdfsProxy', 'Kemp', 'Generic')]
		[string] $Role,
	[Parameter(Mandatory=$False,Position=1)]
		[ValidateNotNullorEmpty()]
		[ValidateScript({
			if ([system.uri]::IsWellFormedUriString($_,[System.UriKind]::Absolute) -AND $_.Split(':')[0] -match 'https?') { $True }
			else { Throw 'Invalid URI format - only anonymous HTTP(s) is supported' }
		})]
		[string] $PfxUrl = 'http://www.spklm.net/certificates/spklm.net.pfx',
	[Parameter(Mandatory=$False,Position=2)]
		[ValidateNotNullorEmpty()]
		[ValidateScript({
			if ( Test-Path (Split-Path $_) ) {$True}
			else {Throw 'Invalid path'}
		})]
		[string] $PfxFilePath = 'c:\tools\scripts\spklm.net.pfx',
	[Parameter(Mandatory=$False,Position=3)]
		[ValidateNotNullorEmpty()]
		[string] $PfxPassword,
	[Parameter(Mandatory=$False,ParameterSetName='Windows')]
		[ValidateNotNullorEmpty()]
		[string] $CertFriendlyName = 'LetsEncrypt - spklm.net',
	[Parameter(Mandatory=$True,ParameterSetName='Kemp')]
		[ValidateNotNullorEmpty()]
		[string] $KempUsername = 'bal',
	[Parameter(Mandatory=$True,ParameterSetName='Kemp')]
		[ValidateNotNullorEmpty()]
		[string] $KempPassword,
	[Parameter(Mandatory=$True,ParameterSetName='Kemp')]
		[ValidateNotNullorEmpty()]
		[string] $KempAddress = 'sm01-net-vlm01.internal.spklm.net',
	[Parameter(Mandatory=$True,ParameterSetName='Kemp')]
		[ValidateNotNullorEmpty()]
		[string] $KempCertId = 'spklm.net'
)

function Get-LatestPfxFile {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.1
		Updated: 7/14/2017
		Author : Scott Middlebrooks
	.LINK
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$True,Position=0)]
			[string] $PfxUrl,
		[Parameter(Mandatory=$True,Position=1)]
			[string] $PfxFilePath
	)

	# Get the last modified timestamp of the PFX file on the webserver
	[datetime] $ServerPfxTimestamp = (Invoke-WebRequest -UseBasicParsing -Uri $PfxUrl).headers.'last-modified'
	
	If ( (Test-Path $PfxFilePath) -eq $False -or $ServerPfxTimestamp -gt (Get-Date).AddDays(-1) ) {
		# Missing local PFX file or PFX file on server is newer than 1 day, fetch the latest copy
		Invoke-WebRequest -UseBasicParsing -Uri $PfxUrl -Outfile $PfxFilePath
		return $True
	}
	else {
		return $False
	}

}


function Get-PfXThumbprint {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0
		Updated: 5/21/2017
		Author : Scott Middlebrooks
	.LINK
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$True,Position=0)]
			[string] $PfxFilePath, 
		[Parameter(Mandatory=$True,Position=1)]
			[string] $PfxPassword
	)

	$PfxSecurePassword = (ConvertTo-SecureString -String $PfxPassword -Force –AsPlainText)

	# Get attributes of the PFX file
	$PfxObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
	$PfxObject.Import($PfxFilePath, $PfxSecurePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
	return [string] $PfxObject.Thumbprint
}

function Import-PfxToMachineCertStore {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0.1
		Updated: 5/23/2017
		Author : Scott Middlebrooks
	.LINK
	.CHANGELOG
		1.0.1 - Fixed Import-PfxCertificate to use SecureString
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$True,Position=0)]
			[string] $PfxFilePath, 
		[Parameter(Mandatory=$True,Position=1)]
			[string] $PfxPassword
	)

	$PfxSecurePassword = (ConvertTo-SecureString -String $PfxPassword -Force –AsPlainText)

	$null = Import-PfxCertificate –FilePath $PfxFilePath -CertStoreLocation Cert:\LocalMachine\MY -Password $PfxSecurePassword -Exportable
		
}

function Set-CertificateFriendlyName {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.1
		Updated: 10/23/2017
		Author : Scott Middlebrooks
	.LINK
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$True,Position=0)]
			[string] $Thumbprint,
		[Parameter(Mandatory=$False)]
			[string] $CertFriendlyName,
		[Parameter(Mandatory=$False)]
			[switch] $AppendExpireDateToCertFriendlyName = $true
	)

	$Certificate = (Get-ChildItem -Path Cert:\LocalMachine\MY\$Thumbprint)
	$CertificateExpiry = Get-Date -Date $Certificate.NotAfter -Format 'yyyyMMdd'
	if ($AppendExpireDateToCertFriendlyName) {
		$Certificate.FriendlyName = "$CertFriendlyName_$CertificateExpiry"
	}
	else {
		$Certificate.FriendlyName = "$CertFriendlyName"
	}
}

function Remove-ExpiredCertificates {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0
		Updated: 10/23/2017
		Author : Scott Middlebrooks
	.LINK
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$False,Position=0)]
			[ValidateSet('CurrentUser','LocalMachine')]
			[string] $CertificateStore = 'LocalMachine',
		[Parameter(Mandatory=$False,Position=1)]
			[datetime] $ExpirationDate = (Get-Date)
	)
	$CertificateStorePath = "Cert:\$CertificateStore\My"
	
	Get-ChildItem $CertificateStorePath | Where-Object NotAfter -lt $ExpirationDate | Remove-Item -Confirm
}

function Enable-SfbEdgeExternalCertificate {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0
		Updated: 5/21/2017
		Author : Scott Middlebrooks
	.LINK
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$True,Position=0)]
			[string] $PfxFilePath,
		[Parameter(Mandatory=$True,Position=1)]
			[string] $PfxPassword,
		[Parameter(Mandatory=$True,Position=2)]
			[string] $Thumbprint
	)

	Import-Module SkypeforBusiness
	Stop-CsWindowsService
	Start-Sleep -Seconds 10
	Import-CsCertificate -Path $PfxFilePath -Password $PfxPassword -PrivateKeyExportable $True
	Set-CsCertificate -Type AccessEdgeExternal, DataEdgeExternal, AudioVideoAuthentication -Thumbprint $Thumbprint
	Start-CsWindowsService

}

function Enable-RdGwCertificate {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0
		Updated: 5/21/2017
		Author : Scott Middlebrooks
	.LINK
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$True,Position=0)]
			[string] $Thumbprint
	)

	Import-Module RemoteDesktopServices
	Stop-Service TSGateway
	Start-Sleep -Seconds 10
	Set-Item -Path "RDS:\GatewayServer\SSLCertificate\Thumbprint" $Thumbprint
	Start-Service TSGateway
}

function Enable-AdfsCertificate {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0
		Updated: 5/21/2017
		Author : Scott Middlebrooks
	.LINK
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$True,Position=0)]
			[string] $Thumbprint
	)

	Import-Module ADFS
	Set-AdfsSslCertificate –Thumbprint $Thumbprint
	Restart-Service AdfsSrv
}

function Enable-AdfsProxyCertificate {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.0
		Updated: 5/21/2017
		Author : Scott Middlebrooks
	.LINK
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$True,Position=0)]
			[string] $Thumbprint
	)

	# https://sts.domain.com/adfs/ls/IdpInitiatedSignon.aspx

	Import-Module WebApplicationProxy
	Stop-Service appproxysvc
	Stop-Service appproxyctrl
	Start-Sleep -Seconds 10
	Get-WebApplicationProxyApplication –Name "ADFS" | Set-WebApplicationProxyApplication –ExternalCertificateThumbprint $Thumbprint
	&netsh http delete sslcert ipport=0.0.0.0:443
	&netsh http add sslcert ipport=0.0.0.0:443 certhash=$Thumbprint appid="{"5d89a20c-beab-4389-9447-324788eb944a"}"
	Start-Service appproxyctrl
	Start-Service appproxysvc
}

function Enable-KempCertificate {
	<#
	.SYNOPSIS
	.DESCRIPTION
	.PARAMETER
	.EXAMPLE
	.NOTES
		Version: 1.1
		Updated: 7/17/2017
		Author : Scott Middlebrooks
	.LINK
		Kemp REST API - https://support.kemptechnologies.com/hc/en-us/articles/203863435-RESTful-API#_Toc477424086
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$True,Position=0)]
			[string] $KempUsername,
		[Parameter(Mandatory=$True,Position=1)]
			[string] $KempPassword,
		[Parameter(Mandatory=$True,Position=2)]
			[string] $KempAddress,
		[Parameter(Mandatory=$True,Position=3)]
			[string] $KempCertId,
		[Parameter(Mandatory=$True,Position=4)]
			[string] $PfxFilePath,
		[Parameter(Mandatory=$True,Position=5)]
			[string] $PfxPassword
	)
	
	# Ignore self signed certificate warnings 
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
	# Set transport to TLS 1.2
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	$sPassword = ConvertTo-SecureString -String $KempPassword -AsPlainText -Force
	$CredentialObject = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $KempUsername,$sPassword
	try {
		Invoke-RestMethod -Method 'POST' -Uri "https://$KempAddress/access/addcert?cert=$KempCertId&password=$PfxPassword&replace=1" -ContentType "application/octet-stream" -InFile $PfxFilePath -Credential $CredentialObject
	}
	catch {
	}
}


### Main Script Body ###
If (Get-LatestPfxFile -PfxUrl $PfxUrl -PfxFilePath $PfxFilePath) {
	$Thumbprint = Get-PfXThumbprint -PfxFilePath $PfxFilePath -PfxPassword $PfxPassword

	switch ($Role) {
		'SfbEdgeExternal' {
			Enable-SfbEdgeExternalCertificate -PfxFilePath $PfxFilePath -PfxPassword $PfxPassword -Thumbprint $Thumbprint
			Set-CertificateFriendlyName -Thumbprint $Thumbprint -CertFriendlyName $CertFriendlyName
			Remove-ExpiredCertificates -ExpirationDate '12/13/2017'
		}
		'RdGateway' {
			Import-PfxToMachineCertStore -PfxFilePath $PfxFilePath -PfxPassword $PfxPassword
			Set-CertificateFriendlyName -Thumbprint $Thumbprint -CertFriendlyName $CertFriendlyName
			Enable-RdGwCertificate -Thumbprint $Thumbprint
			Remove-ExpiredCertificates -ExpirationDate '12/13/2017'
		}
		'Adfs' {
			Import-PfxToMachineCertStore -PfxFilePath $PfxFilePath -PfxPassword $PfxPassword
			Set-CertificateFriendlyName -Thumbprint $Thumbprint -CertFriendlyName $CertFriendlyName
			Enable-AdfsCertificate -Thumbprint $Thumbprint
			Remove-ExpiredCertificates -ExpirationDate '12/13/2017'
		}
		'AdfsProxy' {
			Import-PfxToMachineCertStore -PfxFilePath $PfxFilePath -PfxPassword $PfxPassword
			Set-CertificateFriendlyName -Thumbprint $Thumbprint -CertFriendlyName $CertFriendlyName
			Enable-AdfsProxyCertificate -Thumbprint $Thumbprint
			Remove-ExpiredCertificates -ExpirationDate '12/13/2017'
		}
		'Kemp' {
			Enable-KempCertificate -KempUsername $KempUsername -KempPassword $KempPassword -KempAddress $KempAddress -KempCertId $KempCertId -PfxFilePath $PfxFilePath -PfxPassword $PfxPassword
		}
		'Generic' {
			Import-PfxToMachineCertStore -PfxFilePath $PfxFilePath -PfxPassword $PfxPassword
			Set-CertificateFriendlyName -Thumbprint $Thumbprint -CertFriendlyName $CertFriendlyName
			Remove-ExpiredCertificates -ExpirationDate '12/13/2017'
		}
	}
}
