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
    public class GetClientsRequest : EntrustBaseRequest
    {
        public GetClientsRequest() {
            this.Resource = "clients";
            this.Method = "GET";
        }
    }

    public class ClientInfo
    {
       /// <summary>
        /// Gets or Sets VerificationStatus
        /// </summary>
        [JsonProperty("evVerificationStatus")]
        public string EVVerificationStatus { get; set; }

        /// <summary>
        /// Gets or Sets VerificationStatus
        /// </summary>
        [JsonProperty("verificationStatus")]
        public string VerificationStatus { get; set; }

        /// <summary>
        /// Client ID of client. For the primary client, this is 1. 
        /// </summary>
        /// <value>Client ID of client. For the primary client, this is 1. </value>
        [JsonProperty("clientId")]
        public int ClientId { get; set; }

        /// <summary>
        /// The company name of the client
        /// </summary>
        /// <value>The company name of the client</value>
        [JsonProperty("clientName")]
        public string ClientName { get; set; }

        /// <summary>
        /// Gets or Sets FriendlyClientName
        /// </summary>
        [JsonProperty("friendlyClientName")]
        public string FriendlyClientName { get; set; }

        /// <summary>
        /// OV information expiry date - - only present if client has been APPROVED
        /// </summary>
        /// <value>OV information expiry date - - only present if client has been APPROVED</value>
        [JsonProperty("ovExpiryDate")]
        public DateTime? OvExpiryDate { get; set; }

        [JsonProperty("evExpiryDate")]
        public DateTime? EvExpiryDate { get; set; }
    }

    public class GetClientsResponse 
    {
        [JsonProperty("clients")]
        public List<ClientInfo> Clients{ get; set; }
    }

}
