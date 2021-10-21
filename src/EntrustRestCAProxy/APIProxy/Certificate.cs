// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace Keyfactor.Extensions.AnyGateway.Entrust.APIProxy
{

    public class PatchCertificateRequest : EntrustBaseRequest
    {
        public PatchCertificateRequest(int trackingId)
        {
            this.Resource = $"certificates/{trackingId.ToString()}";
            this.Method = "PATCH";
        }
    }

    public class PatchCertificateRequestBody
    {
        [JsonProperty("operation")]
        public string Operation { get; set; }

        [JsonProperty("declineReason")]
        public string DeclineReason { get; set; }
    }

    public class GetCertificatesRequest : EntrustBaseRequest
    {
        private int limit, offset;
        private string serialNumber;
        private Dictionary<string, string> queryParams;

        public GetCertificatesRequest(int limit, int offset) : this(limit, offset, new Dictionary<string, string>())
        {
        }

        public GetCertificatesRequest(int limit, int offset, Dictionary<string, string> queryParams)
        {
            this.limit = limit;
            this.offset = offset;
            this.Resource = "certificates";
            this.Method = "GET";
            this.queryParams = queryParams;
        }

        public new string BuildParameters()
        {
            StringBuilder sbParamters = new StringBuilder();
            sbParamters.Append("limit=").Append(this.limit.ToString());
            sbParamters.Append("&offset=").Append(this.offset.ToString());
            
            foreach (KeyValuePair<string, string> k in queryParams)
            {
                sbParamters.Append("&" + k.Key + "=").Append(k.Value);
            }
            return sbParamters.ToString();
        }
    }

    public class GetCertificateByThumbprintRequest : EntrustBaseRequest
    {
        public GetCertificateByThumbprintRequest(string thumbprint)
        {
            this.Resource = "certificates/thumbprints/" + thumbprint;
            this.Method = "GET";
        }
    }

    public class GetCertificateByTrackingIdRequest : EntrustBaseRequest
    {
        public GetCertificateByTrackingIdRequest(int trackingId)
        {
            this.Resource = "certificates/" + trackingId;
            this.Method = "GET";
        }
    }

    public class GetCertificatesResponse {
        [JsonProperty("summary")]
        public Summary summary { get; set; }

        [JsonProperty("certificates")]
        public List<Certificate> certificates { get; set; }
    }

    /// <summary>
    /// Certificate
    /// </summary>
    public class Certificate
    {
        /// <summary>
        /// Gets or Sets Status
        /// </summary>
        [JsonProperty("status")]
        public string Status { get; set; }

        /// <summary>
        /// Gets or Sets TrackingId
        /// </summary>
        [JsonProperty("trackingId")]
        public int TrackingId { get; set; }

        /// <summary>
        /// The URI of the certificate.
        /// </summary>
        [JsonProperty("uri")]
        public string URI { get; set; }

        /// <summary>
        /// Distinguished name
        /// </summary>
        /// <value>Distinguished name</value>
        [JsonProperty("dn")]
        public string Dn { get; set; }

        /// <summary>
        /// Serial number in hexadecimal format. 
        /// </summary>
        /// <value>Serial number in hexadecimal format. </value>
        [JsonProperty("serialNumber")]
        public string SerialNumber { get; set; }

        /// <summary>
        /// The date and time, in RFC3339 format, for when the certificate was issued
        /// </summary>
        /// <value>The date and time, in RFC3339 format, for when the certificate was issued</value>
        [JsonProperty("issueDateTime")]
        public DateTime? IssueDateTime { get; set; }

        /// <summary>
        /// The date and time, in RFC3339 format, after which the certificate is no longer valid
        /// </summary>
        /// <value>The date and time, in RFC3339 format, after which the certificate is no longer valid</value>
        [JsonProperty("expiresAfter")]
        public DateTime? ExpiresAfter { get; set; }

        /// <summary>
        /// Signing algorithm
        /// </summary>
        /// <value>Signing algorithm</value>
        [JsonProperty("signingAlg")]
        public string SigningAlg { get; set; }

        /// <summary>
        /// Extended Key Usage - applicable to all public SSL certificate types
        /// </summary>
        /// <value>Extended Key Usage - applicable to all public SSL certificate types</value>
        [JsonProperty("eku")]
        public string Eku { get; set; }

        /// <summary>
        /// Key size
        /// </summary>
        /// <value>Key size</value>
        [JsonProperty("keySize")]
        public int? KeySize { get; set; }

        /// <summary>
        /// Organization in DN
        /// </summary>
        /// <value>Organization in DN</value>
        [JsonProperty("org")]
        public string Org { get; set; }

        /// <summary>
        /// Organizational unit.
        /// </summary>
        /// <value>Organizational unit.</value>
        [JsonProperty("ou")]
        public List<string> Ou { get; set; }

        /// <summary>
        /// Certificate type, for example:   * STANDARD_SSL   * ADVANTAGE_SSL   * UC_SSL   * EV_SSL   * WILDCARD_SSL   * PRIVATE_SSL   * SMIME_ENT 
        /// </summary>
        /// <value>Certificate type, for example:   * STANDARD_SSL   * ADVANTAGE_SSL   * UC_SSL   * EV_SSL   * WILDCARD_SSL   * PRIVATE_SSL   * SMIME_ENT </value>
        [JsonProperty("certType")]
        public string CertType { get; set; }

        /// <summary>
        /// Domain used
        /// </summary>
        /// <value>Domain used</value>
        [JsonProperty("domainUsed")]
        public string DomainUsed { get; set; }

        /// <summary>
        /// Whether this is a third-party certificate
        /// </summary>
        /// <value>Whether this is a third-party certificate</value>
        [JsonProperty("isThirdParty")]
        public bool? IsThirdParty { get; set; }

    }

    public class Summary
    {
        /// <summary>
        /// The date and time instance, in RFC3339 format, for when we received the request.
        /// </summary>
        /// <value>The date and time instance, in RFC3339 format, for when we received the request.</value>
        [JsonProperty("timestamp")]
        public DateTime? Timestamp { get; set; }

        /// <summary>
        /// Elapsed time it took to process the request, in milliseconds
        /// </summary>
        /// <value>Elapsed time it took to process the request, in milliseconds</value>
        [JsonProperty("elapsed")]
        public int? Elapsed { get; set; }

        /// <summary>
        /// Offset of the result set
        /// </summary>
        /// <value>Offset of the result set</value>
        [JsonProperty("offset")]
        public int? Offset { get; set; }

        /// <summary>
        /// Maximum number of items to return
        /// </summary>
        /// <value>Maximum number of items to return</value>
        [JsonProperty("limit")]
        public int? Limit { get; set; }

        /// <summary>
        /// Count of total number of items
        /// </summary>
        /// <value>Count of total number of items</value>
        [JsonProperty("total")]
        public int? Total { get; set; }

        /// <summary>
        /// Ordering of the results
        /// </summary>
        /// <value>Ordering of the results</value>
        [JsonProperty("sort")]
        public string Sort { get; set; }
    }

    public class SubjectAltName
    {
        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("value")]
        public string Value { get; set; }
    }

    public class Tracking
    {
        [JsonProperty("trackingInfo")]
        public string TrackingInfo { get; set; }

        [JsonProperty("requesterName")]
        public string RequesterName { get; set; }

        [JsonProperty("requesterEmail")]
        public string RequesterEmail { get; set; }

        [JsonProperty("requesterPhone")]
        public string RequesterPhone { get; set; }

        [JsonProperty("deactivated")]
        public bool Deactivated { get; set; }

        /// <summary>
        /// The date and time the certificate was last deactivated.  This is a read-only field and is returned only if deactivated&#x3D;true. 
        /// </summary>
        /// <value>The date and time the certificate was last deactivated.  This is a read-only field and is returned only if deactivated&#x3D;true. </value>
        [JsonProperty("deactivatedOn")]
        public DateTime? DeactivatedOn { get; set; }
    }

    public class CertificateExt : Certificate {

        public CertificateExt(Certificate c) {
            Status = c.Status;
            TrackingId = c.TrackingId;
            Dn = c.Dn;
            SerialNumber = c.SerialNumber;
            IssueDateTime = c.IssueDateTime;
            ExpiresAfter = c.ExpiresAfter;
            SigningAlg = c.SigningAlg;
            Eku = c.Eku;
            KeySize = c.KeySize;
            Org = c.Org;
            Ou = c.Ou;
            CertType = c.CertType;
            DomainUsed = c.DomainUsed;
            IsThirdParty = c.IsThirdParty;
        }

        public CertificateExt() { }

        [JsonProperty("subjectAltName")]
        public List<SubjectAltName> SubjectAltName{ get; set; }

        [JsonProperty("tracking")]
        public Tracking Tracking { get; set; }

        [JsonProperty("endEntityCert")]
        public string EndEntityCert { get; set; }

        [JsonProperty("csr")]
        public string Csr { get; set; }

        [JsonProperty("chainCerts")]
        public string[] ChainCerts{ get; set; }

        [JsonProperty("creatorName")]
        public string CreatorName { get; set; }

        [JsonIgnore]
        public string CertificateTemplate { get; set; }
    }
}
