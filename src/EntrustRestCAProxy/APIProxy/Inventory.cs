// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Newtonsoft.Json;
using System.Collections.Generic;

namespace Keyfactor.Extensions.AnyGateway.Entrust.APIProxy
{
    public class GetInventoryRequest : EntrustBaseRequest{
        public GetInventoryRequest()
        {
            this.Resource = "inventories";
            this.Method = "GET";
        }
    }

    public class InventoryItem {

        /// <summary>
        /// Gets or Sets ProductType
        /// </summary>
        [JsonProperty("productType")]
        public string ProductType { get; set; }

        /// <summary>
        /// Total inventory for this product type ever added to the account
        /// </summary>
        /// <value>Total inventory for this product type ever added to the account</value>
        [JsonProperty("totalCount")]
        public int? TotalCount { get; set; }

        /// <summary>
        /// Inventory for this product type that has not been used, and has not expired
        /// </summary>
        /// <value>Inventory for this product type that has not been used, and has not expired</value>
        [JsonProperty("remainingCount")]
        public int? RemainingCount { get; set; }

        /// <summary>
        /// Count of consumed inventory for this product type. This count does not include expired inventory
        /// </summary>
        /// <value>Count of consumed inventory for this product type. This count does not include expired inventory</value>
        [JsonProperty("usedCount")]
        public int? UsedCount { get; set; }
     }

    public class GetInventoryResponse {
        [JsonProperty("inventories")]
        public List<InventoryItem> Inventories { get; set; }
    }
}
