// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace Keyfactor.Extensions.AnyGateway.Entrust.APIProxy
{

    public class GetDomainsByClientRequest : EntrustBaseRequest
    {
        public GetDomainsByClientRequest(int clientId, int offset, int limit, bool onlyApproved)
        {
            List<string> parameters = new List<string>()
            {
                $"offset={offset}",
                $"limit={limit}"
            };

            if (onlyApproved)
            {
                parameters.Add("verificationStatus=APPROVED");
            }

            Resource = $"clients/{clientId}/domains?{string.Join("&", parameters)}";
            Method = "GET";
        }
    }

    public class GetDomainsByClientResponse 
    {
        [JsonProperty("summary")]
        public Summary Summary { get; set; }

        [JsonProperty("domains")]
        public List<Domain> Domains { get; set; }
    } 

    public class Domain
    {
        /// <summary>
        /// Gets or Sets VerificationMethod
        /// </summary>
        [JsonProperty("verificationMethod")]
        public string VerificationMethod { get; set; }

        /// <summary>
        /// Gets or Sets Status
        /// </summary>
        [JsonProperty("verificationStatus")]
        public string Status { get; set; }

        /// <summary>
        /// Domain name
        /// </summary>
        /// <value>Domain name</value>
        [JsonProperty("domainName")]
        public string DomainName { get; set; }

        /// <summary>
        /// Whether this domain can be used for OV certificates
        /// </summary>
        /// <value>Whether this domain can be used for OV certificates</value>
        [JsonProperty("ovEligible")]
        public bool? OvEligible { get; set; }

        /// <summary>
        /// Expiry time of verified OV information
        /// </summary>
        /// <value>Expiry time of verified OV information</value>
        [JsonProperty("ovExpiry")]
        public DateTime? OvExpiry { get; set; }

        /// <summary>
        /// Whether this domain can be used for EV certificates
        /// </summary>
        /// <value>Whether this domain can be used for EV certificates</value>
        [JsonProperty("evEligible")]
        public bool? EvEligible { get; set; }

        /// <summary>
        /// Expiry time of verified EV information.
        /// </summary>
        /// <value>Expiry time of verified EV information.</value>
        [JsonProperty("evExpiry")]
        public DateTime? EvExpiry { get; set; }

        /// <summary>
        /// Client id of the client to which the domain belongs to.
        /// </summary>
        /// <value>Client id of the client to which the domain belongs to.</value>
        [JsonProperty("clientId")]
        public int? ClientId { get; set; }
    }
}
