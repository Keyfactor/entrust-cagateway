// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Newtonsoft.Json;

namespace Keyfactor.Extensions.AnyGateway.Entrust.APIProxy
{

    public class NewCertificateCall : EntrustBaseRequest
    {
        public NewCertificateCall()
        {
            this.Resource = "certificates";
            this.Method = "POST";
        }
    }

    /// <summary>
    /// NewCertificateRequest
    /// </summary>
    public partial class NewCertificateRequest : RenewCertificateRequestBody
    {
        /// <summary>
        /// Certificate type to request Supported types are:   * STANDARD_SSL   * ADVANTAGE_SSL   * UC_SSL   * EV_SSL   * QWAC_SSL   * QWACPSD2_SSL   * WILDCARD_SSL   * PRIVATE_SSL   * PD_SSL   * CODE_SIGNING   * EV_CODE_SIGNING   * CDS_INDIVIDUAL   * CDS_GROUP   * CDS_ENT_LITE   * CDS_ENT_PRO   * SMIME_ENT 
        /// </summary>
        /// <value>Certificate type to request Supported types are:   * STANDARD_SSL   * ADVANTAGE_SSL   * UC_SSL   * EV_SSL   * QWAC_SSL   * QWACPSD2_SSL   * WILDCARD_SSL   * PRIVATE_SSL   * PD_SSL   * CODE_SIGNING   * EV_CODE_SIGNING   * CDS_INDIVIDUAL   * CDS_GROUP   * CDS_ENT_LITE   * CDS_ENT_PRO   * SMIME_ENT </value>
        [JsonProperty("certType")]
        public string CertType { get; set; }

        /// <summary>
        /// For all SSL and Document Signing certificate types&amp;#58;   * If set to true, certificate request is queued for approval by an administrator.    * If set to false (default), the certificate is generated immediately.          
        /// </summary>
        /// <value>For all SSL and Document Signing certificate types&amp;#58;   * If set to true, certificate request is queued for approval by an administrator.    * If set to false (default), the certificate is generated immediately.          </value>
        [JsonProperty("queueForApproval")]
        public bool? QueueForApproval { get; set; }

    }

}
