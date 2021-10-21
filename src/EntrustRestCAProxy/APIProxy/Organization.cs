﻿// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Newtonsoft.Json;
using System.Collections.Generic;

namespace Keyfactor.Extensions.AnyGateway.Entrust.APIProxy
{
    /// <summary>
    /// Request to get the organizations from Entrust.
    /// </summary>
    public class GetOrganizationsRequest : EntrustBaseRequest
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        public GetOrganizationsRequest()
        {
            Resource = "organizations";
            Method = "GET";
        }
    }

    /// <summary>
    /// Response containing Entrust's organizations.
    /// </summary>
    public class GetOrganizationsResponse : EntrustBaseResponse
    {
        /// <summary>
        /// The collection of organizations returned by Entrust.
        /// </summary>
        [JsonProperty("organizations")]
        public List<Organization> Organizations { get; set; }
    }

    /// <summary>
    /// Class representing an organization returned from the Entrust API.
    /// </summary>
    public class Organization
    {
        /// <summary>
        /// The organization's name.
        /// </summary>
        [JsonProperty("name")]
        public string Name { get; set; }

        /// <summary>
        /// The status of the organization.
        /// </summary>
        [JsonProperty("verificationStatus")]
        public string VerificationStatus { get; set; }

        /// <summary>
        /// The ID of the client associated with this organization.
        /// </summary>
        [JsonProperty("clientId")]
        public int ClientId { get; set; }
    }
}
