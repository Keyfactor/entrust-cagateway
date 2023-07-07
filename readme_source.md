# Introduction
This AnyGateway plug-in enables issuance, revocation, and synchronization of certificates from Entrust's Managed SSL/TLS offering.  

# Entrust Authentication
Entrust API now supports two methods of authentication:  
1. Basic Auth only  
2. Basic Auth + Certificate Auth

When creating your API user name and password in the Entrust portal, you will be given the option to select a certificate to go with it. If you do select a certificate, then the gateway will require that certificate information to connect. Otherwise, do not provide ClientCertificate information to the gateway.

# Prerequisites

## AnyGateway Platform Minimum Version
The Entrust AnyGateway requires the Keyfactor AnyGateway v21.5.1 or newer

## Migrating to the Entrust AnyGateway plugin from a previous version of the standalone Entrust Gateway.

## Migration From 20.1.x or Earlier
If you are upgrading from an older version of the Entrust gateway that still used the GUI configuration wizard (20.1.x or earlier), you first have to do an upgrade to EntrustCAProxy version 21.x to migrate your database to SQL.
After doing that upgrade, follow the below steps to migrate from 21.x to the current version.

## Migration from 21.9 or Earlier

* IMPORTANT CONFIG CHANGE: 21.9 and earlier pulled certificate EKU information from the templates. That information is now provided in the config file. See the below section on Templates, and make sure to add the CertificateUsage parameter to any public SSL types in your config.

* Before doing any upgrade, run the following PowerShell command:
    reg export "HKLM\Software\Keyfactor\Keyfactor CA Gateway" C:\EntrustGatewayBackup.reg
* After backing up the registry key, completely uninstall the old version of the Entrust CA Gateway
* Follow the instructions to install the AnyGateway product and update the CAProxyServer.config file, but do not do any further configuration yet
* Run the following PowerShell command:
    reg import C:\EntrustGatewayBackup.reg
* Continue with the gateway configuration, but do NOT run the Set-KeyfactorGatewayEncryptionCert or the Set-KeyfactorGatewayDatabaseConnection cmdlets, as those values were the ones persisted in the registry backup.

This is a one-time process as the Entrust gateway moves fully to the Keyfactor AnyGateway model. Future upgrades will not require this process.

## Certificate Chain

In order to enroll for certificates the Keyfactor Command server must trust the trust chain. Once you create your Root and/or Subordinate CA, make sure to import the certificate chain into the AnyGateway and Command Server certificate store


# Install
* Download latest successful build from [GitHub Releases](../../releases/latest)

* Copy EntrustCAProxy.dll to the Program Files\Keyfactor\Keyfactor AnyGateway directory

* Update the CAProxyServer.config file
  * Update the CAConnection section to point at the EntrustCAProxy class
  ```xml
  <alias alias="CAConnector" type="Keyfactor.Extensions.AnyGateway.Entrust.EntrustCAConnector, EntrustCAProxy"/>
  ```

# Configuration
The following sections will breakdown the required configurations for the AnyGatewayConfig.json file that will be imported to configure the AnyGateway.

## Templates
The Template section will map the CA's products to an AD template.
Available ProductIDs will depend on your Entrust account's inventory
The Lifetime parameter is optional and represents the certificate duration in months. If not provided, default is 12 months.
The CertificateUsage parameter is REQUIRED for public SSL certificate types, and represents the key usage for the certificates enrolled against this template. Valid values are "server", "client", or "serverclient". Do not provide this value for cert types that are not public SSL.
 ```json
  "Templates": {
	"WebServer": {
      "ProductID": "STANDARD_SSL",
      "Parameters": {
		"Lifetime":"12",
        "CertificateUsage":"server"
      }
   }
}
 ```
 The following product codes are supported:
 * STANDARD_SSL
 * ADVANTAGE_SSL
 * UC_SSL
 * EV_SSL
 * QWAC_SSL
 * PSD2_SSL
 * WILDCARD_SSL
 * PRIVATE_SSL
 * PD_SSL
 * CODE_SIGNING
 * EV_CODE_SIGNING
 * CDS_INDIVIDUAL
 * CDS_GROUP
 * CDS_ENT_LITE
 * CDS_ENT_PRO
 * SMIME_ENT
 
 
## Security
The security section does not change specifically for the Entrust Gateway.  Refer to the AnyGateway Documentation for more detail.
```json
  /*Grant permissions on the CA to users or groups in the local domain.
	READ: Enumerate and read contents of certificates.
	ENROLL: Request certificates from the CA.
	OFFICER: Perform certificate functions such as issuance and revocation. This is equivalent to "Issue and Manage" permission on the Microsoft CA.
	ADMINISTRATOR: Configure/reconfigure the gateway.
	Valid permission settings are "Allow", "None", and "Deny".*/
    "Security": {
        "Keyfactor\\Administrator": {
            "READ": "Allow",
            "ENROLL": "Allow",
            "OFFICER": "Allow",
            "ADMINISTRATOR": "Allow"
        },
        "Keyfactor\\gateway_test": {
            "READ": "Allow",
            "ENROLL": "Allow",
            "OFFICER": "Allow",
            "ADMINISTRATOR": "Allow"
        },		
        "Keyfactor\\SVC_TimerService": {
            "READ": "Allow",
            "ENROLL": "Allow",
            "OFFICER": "Allow",
            "ADMINISTRATOR": "None"
        },
        "Keyfactor\\SVC_AppPool": {
            "READ": "Allow",
            "ENROLL": "Allow",
            "OFFICER": "Allow",
            "ADMINISTRATOR": "Allow"
        }
    }
```
## CerificateManagers
The Certificate Managers section is optional.
	If configured, all users or groups granted OFFICER permissions under the Security section
	must be configured for at least one Template and one Requester. 
	Uses "<All>" to specify all templates. Uses "Everyone" to specify all requesters.
	Valid permission values are "Allow" and "Deny".
```json
  "CertificateManagers":{
		"DOMAIN\\Username":{
			"Templates":{
				"MyTemplateShortName":{
					"Requesters":{
						"Everyone":"Allow",
						"DOMAIN\\Groupname":"Deny"
					}
				},
				"<All>":{
					"Requesters":{
						"Everyone":"Allow"
					}
				}
			}
		}
	}
```
## CAConnection
The CA Connection section will determine the API endpoint and configuration data used to connect to Entrust CA Gateway. 
* ```AuthUsername```
This is the username for the gateway to use to authenticate to Entrust  
* ```AuthPassword```
This is the password for the account the gateway should use to authenticate to Entrust
* ```ClientCertificate```
(OPTIONAL) The location and thumbprint of the client authentication certificate to use to connect to Entrust 
* ```Name```
The default requester name.
* ```Email```
The default requester email address.
* ```PhoneNumber```
The default requester phone number
* ```IgnoreExpired```
(OPTIONAL) If set to true, will not sync expired certs from the Entrust account.

```json
  "CAConnection": {
	"AuthUsername":"exampleUser",
    "AuthPassword":"samplePassword",
	"ClientCertificate": {
        "StoreName": "My",
        "StoreLocation": "LocalMachine",
        "Thumbprint": "0123456789abcdef"
    },
    "Name": "TestUser",
    "Email": "email@email.invalid",
    "PhoneNumber": "0000000000",
	"IgnoreExpired": "false"
  },
```
## GatewayRegistration
There are no specific Changes for the GatewayRegistration section. Refer to the AnyGateway Documentation for more detail.
```json
  "GatewayRegistration": {
    "LogicalName": "EntrustCASandbox",
    "GatewayCertificate": {
      "StoreName": "CA",
      "StoreLocation": "LocalMachine",
      "Thumbprint": "0123456789abcdef"
    }
  }
```

## ServiceSettings
There are no specific Changes for the ServiceSettings section. Refer to the AnyGateway Documentation for more detail.
```json
  "ServiceSettings": {
    "ViewIdleMinutes": 8,
    "FullScanPeriodHours": 24,
	"PartialScanPeriodMinutes": 240 
  }
```
