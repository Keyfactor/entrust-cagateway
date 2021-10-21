// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using Newtonsoft.Json;


namespace Keyfactor.Extensions.AnyGateway.Entrust.APIProxy
{
    /// <summary>
    /// ReissueCertificateRequest
    /// </summary>
    public class ReissueCertificateRequest : EntrustBaseRequest
    {

        public ReissueCertificateRequest(int trackingId)
        {
            this.Resource = $"certificates/{trackingId.ToString()}/reissues";
            this.Method = "POST";

        }
    }

    public class ReissueCertificateRequestBody { 

        /// <summary>
        /// Signing algorithm of certificate (SHA-1 or SHA-2).  The account default is used if not specified.  - This parameter is only applicable when the account preference is set to \&quot;Select signing algorithm at certificate generation time.\&quot; - As of January 1, 2016 any certificates except Private SSL (PRIVATE_SSL) certificates being issued, reissued, or renewed will use SHA2, even if the SHA1 algorithm is specified in the request. Private SSL certificates can continue to use SHA-1. 
        /// </summary>
        /// <value>Signing algorithm of certificate (SHA-1 or SHA-2).  The account default is used if not specified.  - This parameter is only applicable when the account preference is set to \&quot;Select signing algorithm at certificate generation time.\&quot; - As of January 1, 2016 any certificates except Private SSL (PRIVATE_SSL) certificates being issued, reissued, or renewed will use SHA2, even if the SHA1 algorithm is specified in the request. Private SSL certificates can continue to use SHA-1. </value>
        [JsonProperty("signingAlg")]
        public string SigningAlg { get; set; }


        /// <summary>
        /// Extended Key Usage - applicable to all public SSL certificate types
        /// </summary>
        /// <value>Extended Key Usage - applicable to all public SSL certificate types (SERVER_AUTH, CLIENT_AUTH, SERVER_AND_CLIENT_AUTH)</value>
        [JsonProperty("eku")]
        public string Eku { get; set; }
        
        /// <summary>
        /// Base-64 encoded Certificate Signing Request (CSR). CSR is accepted with or without PEM formatting around the Base-64 string.
        /// </summary>
        /// <value>Base-64 encoded Certificate Signing Request (CSR). CSR is accepted with or without PEM formatting around the Base-64 string.</value>
        [JsonProperty("csr")]
        public string Csr { get; set; }

        /// <summary>
        /// The subjectAltName identifier, as an array of values (applies to STANDARD_SSL, ADVANTAGE_SSL, UC_SSL, EV_SSL, QWAC_SSL, QWACPSD2_SSL, WILDCARD_SSL, PRIVATE_SSL, and PD_SSL certificate types).   * If you are requesting a new SSL certificate, and you pass a subjectAltName parameter, any SAN names in the CSR are ignored. If no subjectAltName parameter is passed, the SAN names in the CSR are used.    * See the requesttype parameter (further in this table) to understand more about SANs during reissues and renewals.   * In the case of Standard certificates, if the CN of the certificate is &lt;domain&gt;.&lt;tld&gt; only the www.&lt;domain&gt;.&lt;tld&gt; value is accepted. If the CN of the certificate is www.&lt;domain&gt;.&lt;tld&gt; only the &lt;domain&gt;.&lt;tld&gt; value is accepted. 
        /// </summary>
        /// <value>The subjectAltName identifier, as an array of values (applies to STANDARD_SSL, ADVANTAGE_SSL, UC_SSL, EV_SSL, QWAC_SSL, QWACPSD2_SSL, WILDCARD_SSL, PRIVATE_SSL, and PD_SSL certificate types).   * If you are requesting a new SSL certificate, and you pass a subjectAltName parameter, any SAN names in the CSR are ignored. If no subjectAltName parameter is passed, the SAN names in the CSR are used.    * See the requesttype parameter (further in this table) to understand more about SANs during reissues and renewals.   * In the case of Standard certificates, if the CN of the certificate is &lt;domain&gt;.&lt;tld&gt; only the www.&lt;domain&gt;.&lt;tld&gt; value is accepted. If the CN of the certificate is www.&lt;domain&gt;.&lt;tld&gt; only the &lt;domain&gt;.&lt;tld&gt; value is accepted. </value>
        [JsonProperty("subjectAltName")]
        public List<string> SubjectAltName { get; set; }



        /// <summary>
        /// In compliance with browser requirements, this certificate may be posted to the Certificate Transparency (CT) logs. This is a best practice technique that helps domain owners monitor certificates issued to their domains. Note that not all certificates are eligible for CT logging. * If ctLog is not specified, the certificate uses the account default. * If ctLog is specified and the account settings allow it, ctLog overrides the account default. * If ctLog is set to *false*, but the account settings is set to \&quot;always log\&quot;, the certificate generation will fail. 
        /// </summary>
        /// <value>In compliance with browser requirements, this certificate may be posted to the Certificate Transparency (CT) logs. This is a best practice technique that helps domain owners monitor certificates issued to their domains. Note that not all certificates are eligible for CT logging. * If ctLog is not specified, the certificate uses the account default. * If ctLog is specified and the account settings allow it, ctLog overrides the account default. * If ctLog is set to *false*, but the account settings is set to \&quot;always log\&quot;, the certificate generation will fail. </value>
        [JsonProperty("ctLog")]
        public bool? CtLog { get; set; }

        /// <summary>
        /// Common Name (CN) attribute in the DN.  Applicable to S/MIME and Document Signing only. 
        /// </summary>
        /// <value>Common Name (CN) attribute in the DN.  Applicable to S/MIME and Document Signing only. </value>
        [JsonProperty("cn")]
        public string Cn { get; set; }

        /// <summary>
        /// email attribute in the DN.  Applicable to S/MIME and Document Signing only. 
        /// </summary>
        /// <value>email attribute in the DN.  Applicable to S/MIME and Document Signing only. </value>
        [JsonProperty("certEmail")]
        public string CertEmail { get; set; }

        /// <summary>
        /// User Principal Name. Applicable to the SMIME_ENT certificate types only. If specified, it must be a valid email address and its domain must be the approved domain for that client. 
        /// </summary>
        /// <value>User Principal Name. Applicable to the SMIME_ENT certificate types only. If specified, it must be a valid email address and its domain must be the approved domain for that client. </value>
        [JsonProperty("upn")]
        public string Upn { get; set; }

        /// <summary>
        /// The client ID. The ID of the primary client is 1. If the clientId is not specified, 1 is used. 
        /// </summary>
        /// <value>The client ID. The ID of the primary client is 1. If the clientId is not specified, 1 is used. </value>
        [JsonProperty("clientId")]
        public int? ClientId { get; set; }

        /// <summary>
        /// When there is an org parameter specified in the request, it is used in the certificate created, even if there is already an Org in the CSR (O&#x3D;). When there is no org parameter specified in the request, the organization from the Client is used when creating all certificate types except for Private Dedicated SSL (PDSSL). In the case of PDSSL certificates only: if there is no org parameter in the request, the organization in the CSR is used, when it is available. If there is no org value in the CSR, then the client organization is used. Note that the org parameter is valid for use only with clientId&#x3D;1, for all certificate types except for PDSSL. When requesting PDSSL certificates, the org parameter can be used in requests for any clientId. 
        /// </summary>
        /// <value>When there is an org parameter specified in the request, it is used in the certificate created, even if there is already an Org in the CSR (O&#x3D;). When there is no org parameter specified in the request, the organization from the Client is used when creating all certificate types except for Private Dedicated SSL (PDSSL). In the case of PDSSL certificates only: if there is no org parameter in the request, the organization in the CSR is used, when it is available. If there is no org value in the CSR, then the client organization is used. Note that the org parameter is valid for use only with clientId&#x3D;1, for all certificate types except for PDSSL. When requesting PDSSL certificates, the org parameter can be used in requests for any clientId. </value>
        [JsonProperty("org")]
        public string Org { get; set; }

        /// <summary>
        /// The organizational unit. This parameter can be set to the name of the &#39;ou&#39; or &#39;&#39; (i.e. ignore CSR ou and do not set the OU). See the behavior below. This parameter is valid for SSL and S/MIME certificate types. &#39;ou&#39; behavior is dependent on whether organizational units are enabled for your account.   If ou is disabled for your account: * New certificates- OUs from CSRs or the &#39;ou&#39; input parameters are ignored. * Reissued certificates- OUs from CSRs, or the &#39;ou&#39; input parameters are ignored. * Renewed certificates- OUs from CSRs, or the &#39;ou&#39; input parameters are ignored.  If OUs are enabled for your account: * New certificates- Valid OUs from CSRs are used. Invalid OUs from CSRs are ignored. The OU in the CSR is overridden by a valid \&quot;ou\&quot; from the input parameter, however if the OU is invalid, an \&quot;Unapproved OU\&quot; error is generated. * Reissued certificates-  If the CSR is not specified when reissuing, then the OU from the CSR of the original certificate is used as the default OU. The OU is ignored if it is invalid. If a new CSR is used when the certificate is reissued, the OU from the CSR is used as the default OU.   If a new CSR with no OU is used, the certificate is reissued without an OU. The original OU in the CSRis overridden by a valid &#39;ou&#39; or &#39;&#39; from the input parameter, however if the OU is invalid, an \&quot;Unapproved OU\&quot; error is generated. * Renewed certificates- If no CSR is specified when the certificate is renewed, the OU of the CSR from the original certificate is used. The OU is ignored if it is invalid. If a new CSR is used and contains a valid OU, the OU from the CSR is used. If the CSR is replaced and contains no OU, the certificate is renewed without an OU. The original OU in the certificate is overridden by a valid &#39;ou&#39; or &#39;&#39; (i.e. no OU) from the input parameter, or by the OU in a replacement CSR, however if the OU is invalid an \&quot;Unapproved OU\&quot; error is generated.  Multiple OUs are reserved for future products. A maximum of one OU may be specified for current products. 
        /// </summary>
        /// <value>The organizational unit. This parameter can be set to the name of the &#39;ou&#39; or &#39;&#39; (i.e. ignore CSR ou and do not set the OU). See the behavior below. This parameter is valid for SSL and S/MIME certificate types. &#39;ou&#39; behavior is dependent on whether organizational units are enabled for your account.   If ou is disabled for your account: * New certificates- OUs from CSRs or the &#39;ou&#39; input parameters are ignored. * Reissued certificates- OUs from CSRs, or the &#39;ou&#39; input parameters are ignored. * Renewed certificates- OUs from CSRs, or the &#39;ou&#39; input parameters are ignored.  If OUs are enabled for your account: * New certificates- Valid OUs from CSRs are used. Invalid OUs from CSRs are ignored. The OU in the CSR is overridden by a valid \&quot;ou\&quot; from the input parameter, however if the OU is invalid, an \&quot;Unapproved OU\&quot; error is generated. * Reissued certificates-  If the CSR is not specified when reissuing, then the OU from the CSR of the original certificate is used as the default OU. The OU is ignored if it is invalid. If a new CSR is used when the certificate is reissued, the OU from the CSR is used as the default OU.   If a new CSR with no OU is used, the certificate is reissued without an OU. The original OU in the CSRis overridden by a valid &#39;ou&#39; or &#39;&#39; from the input parameter, however if the OU is invalid, an \&quot;Unapproved OU\&quot; error is generated. * Renewed certificates- If no CSR is specified when the certificate is renewed, the OU of the CSR from the original certificate is used. The OU is ignored if it is invalid. If a new CSR is used and contains a valid OU, the OU from the CSR is used. If the CSR is replaced and contains no OU, the certificate is renewed without an OU. The original OU in the certificate is overridden by a valid &#39;ou&#39; or &#39;&#39; (i.e. no OU) from the input parameter, or by the OU in a replacement CSR, however if the OU is invalid an \&quot;Unapproved OU\&quot; error is generated.  Multiple OUs are reserved for future products. A maximum of one OU may be specified for current products. </value>
        [JsonProperty("ou")]
        public List<string> Ou { get; set; }

        /// <summary>
        /// The certificate pickup password. * A password must be used if it is set to \&quot;required\&quot; in the account under Options &gt; Certificate Pickup Password. A password is used to protect SMIME_ENT certificates without CSRs. The password protects the returned PKCS12 containing the private key and certificate. * If a password and CSR are provided in an SMIME_ENT certificate request, the CSR will be used, and the password will be ignored. 
        /// </summary>
        /// <value>The certificate pickup password. * A password must be used if it is set to \&quot;required\&quot; in the account under Options &gt; Certificate Pickup Password. A password is used to protect SMIME_ENT certificates without CSRs. The password protects the returned PKCS12 containing the private key and certificate. * If a password and CSR are provided in an SMIME_ENT certificate request, the CSR will be used, and the password will be ignored. </value>
        [JsonProperty("password")]
        public string Password { get; set; }

        /// <summary>
        /// Gets or Sets Tracking
        /// </summary>
        [JsonProperty("tracking")]
        public Tracking Tracking { get; set; }

        /// <summary>
        /// The end user of the Code Signing certificate must generate and store the private key for this request on cryptographically secure hardware to be compliant with the Entrust CSP and Subscription agreement.  You must set the endUserKeyStorageAgreement flag to true, to acknowledge that you will inform the user of this requirement. Applicable to Code Signing certificate types only. 
        /// </summary>
        /// <value>The end user of the Code Signing certificate must generate and store the private key for this request on cryptographically secure hardware to be compliant with the Entrust CSP and Subscription agreement.  You must set the endUserKeyStorageAgreement flag to true, to acknowledge that you will inform the user of this requirement. Applicable to Code Signing certificate types only. </value>
        [JsonProperty("endUserKeyStorageAgreement")]
        public bool? EndUserKeyStorageAgreement { get; set; }

 
    }

}
