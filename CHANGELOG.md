1.0.4  
-Inital Release.  Support for Enroll, Sync, and Revocation. 

1.0.5  
-Fixes for Renewal Due To Api Validation Issues (Renewals can't send validation flag into Api)  
-Added Trace Logging for troubleshooting

1.0.6  
-Sync fix - certs pending in Entrust now return External Validation status

1.0.7  
-Add configuration option to skip expired certs on sync

1.0.8  
-Fixed logging bug when no SANs were present in request

1.1.0  
-Added support for basic auth (no client certificate)  
-Fixed an issue with cert lookups when the serial number has leading 0s