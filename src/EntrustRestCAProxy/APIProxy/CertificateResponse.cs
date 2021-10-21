// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.AnyGateway.Entrust.APIProxy
{
    /// <summary>
    /// CertificateResponse
    /// </summary>
    public class CertificateResponse
    {
        
        /// <summary>
        /// Gets or Sets TrackingId
        /// </summary>
        [JsonProperty("trackingId")]
        public int TrackingId { get; set; }

        /// <summary>
        /// PEM-encoded certificate 
        /// </summary>
        /// <value>PEM-encoded certificate </value>
        [JsonProperty("endEntityCert")]
        public string EndEntityCert { get; set; }

        /// <summary>
        /// Gets or Sets ChainCerts
        /// </summary>
        [JsonProperty("chainCerts")]
        public List<string> ChainCerts { get; set; }

        /// <summary>
        /// Serial number in hexadecimal format 
        /// </summary>
        /// <value>Serial number in hexadecimal format </value>
        [JsonProperty("serialNumber")]
        public string SerialNumber { get; set; }

        /// <summary>
        /// The date and time, in RFC3339 format, after which the certificate is no longer valid.
        /// </summary>
        /// <value>The date and time, in RFC3339 format, after which the certificate is no longer valid.</value>
        [JsonProperty("expiresAfter")]
        public DateTime? ExpiresAfter { get; set; }

        /// <summary>
        /// Gets or Sets PickupUrl
        /// </summary>
        [JsonProperty("pickupUrl")]
        public string PickupUrl { get; set; }

        /// <summary>
        /// S/MIME certificate and private key in PKCS12 format protected by the provided password. Only returned for SMIME_ENT certtype and only if no CSR is supplied. 
        /// </summary>
        /// <value>S/MIME certificate and private key in PKCS12 format protected by the provided password. Only returned for SMIME_ENT certtype and only if no CSR is supplied. </value>
        [JsonProperty("pkcs12")]
        public string Pkcs12 { get; set; }

       
    }

}
