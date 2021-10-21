// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Extensions.AnyGateway.Entrust.APIProxy;
using Keyfactor.Extensions.AnyGateway.Entrust.Client;
using CAProxy.Models;

namespace Keyfactor.Extensions.AnyGateway.Entrust
{
    public class EntrustCertType : CABaseCertType
    {
        #region Product Types

        public static EntrustCertType Standard = new EntrustCertType() { ShortName = "STANDARD_SSL", ProductCode = "STANDARD_SSL", DisplayName = "Standard SSL" };
        public static EntrustCertType Advantage = new EntrustCertType() { ShortName = "ADVANTAGE_SSL", ProductCode = "ADVANTAGE_SSL", DisplayName = "Advantage SSL" };
        public static EntrustCertType UC = new EntrustCertType() { ShortName = "UC_SSL", ProductCode = "UC_SSL", DisplayName = "UC SSL" };

        public static EntrustCertType EV = new EntrustCertType() { ShortName = "EV_SSL", ProductCode = "EV_SSL", DisplayName = "EV SSL" };
        public static EntrustCertType QWAC = new EntrustCertType() { ShortName = "QWAC_SSL", ProductCode = "QWAC_SSL", DisplayName = "QWAC SSL" };
        public static EntrustCertType PSD2 = new EntrustCertType() { ShortName = "PSD2_SSL", ProductCode = "PSD2_SSL", DisplayName = "PSD2 SSL" };

        public static EntrustCertType Wildcard = new EntrustCertType() { ShortName = "WILDCARD_SSL", ProductCode = "WILDCARD_SSL", DisplayName = "Wildcard SSL" };
        public static EntrustCertType Private = new EntrustCertType() { ShortName = "PRIVATE_SSL", ProductCode = "PRIVATE_SSL", DisplayName = "Private SSL" };
        public static EntrustCertType PD = new EntrustCertType() { ShortName = "PD_SSL", ProductCode = "PD_SSL", DisplayName = "PD SSL" };
        public static EntrustCertType CodeSigning = new EntrustCertType() { ShortName = "CODE_SIGNING", ProductCode = "CODE_SIGNING", DisplayName = "Code Signing" };
        public static EntrustCertType EVCodeSigning = new EntrustCertType() { ShortName = "EV_CODE_SIGNING", ProductCode = "EV_CODE_SIGNING", DisplayName = "EV Code Signing" };
        public static EntrustCertType CDSIndividual = new EntrustCertType() { ShortName = "CDS_INDIVIDUAL", ProductCode = "CDS_INDIVIDUAL", DisplayName = "CDS Individual" };
        public static EntrustCertType CDSGroup = new EntrustCertType() { ShortName = "CDS_GROUP", ProductCode = "CDS_GROUP", DisplayName = "CDS Group" };
        public static EntrustCertType CDSEntLite = new EntrustCertType() { ShortName = "CDS_ENT_LITE", ProductCode = "CDS_ENT_LITE", DisplayName = "CDS Ent Lite" };
        public static EntrustCertType CDSEntPro = new EntrustCertType() { ShortName = "CDS_ENT_PRO", ProductCode = "CDS_ENT_PRO", DisplayName = "CDS Ent Pro" };
        public static EntrustCertType SMIMEEnt = new EntrustCertType() { ShortName = "SMIME_ENT", ProductCode = "SMIME_ENT", DisplayName = "SMIME Ent" };

        /// <summary>
        /// Master list of all product types.
        /// </summary>
        public static new List<CABaseCertType> AllTypes = new List<CABaseCertType>() { Standard, Advantage, UC, EV, QWAC, PSD2, Wildcard, Private, PD, CodeSigning, EVCodeSigning, CDSIndividual, CDSGroup, CDSEntLite, CDSEntPro, SMIMEEnt };

        /// <summary>
        /// The certificate types that are available through FLEX inventory.
        /// </summary>
        private static List<CABaseCertType> FlexTypes => AllTypes.Where(x => x.ShortName.Contains("SSL") && x.ShortName != "PD_SSL").ToList();

        #endregion Product Types

        #region Methods

        /// <summary>
        /// Checks if inventory exists for the product type provided.
        /// </summary>
        /// <param name="client">The <see cref="EntrustClient"/> is used to call out to the Entrust API.</param>
        /// <param name="productType">The product type we seek to check the inventory of.</param>
        /// <returns></returns>
        public static bool InventoryExists(EntrustClient client, string productType)
        {
            // Gets an inventory with all of the product types.
            List<InventoryItem> inventoryItems = client.GetInventories();

            InventoryItem inventory = inventoryItems.FirstOrDefault(x => x.ProductType.Equals(productType, StringComparison.CurrentCultureIgnoreCase));
            if (inventory == null)
            {
                inventory = inventoryItems.FirstOrDefault(x => x.ProductType.Equals("FLEX", StringComparison.CurrentCultureIgnoreCase));
            }

            return inventory != null && inventory.RemainingCount > 0;
        }

        /// <summary>
        /// Checks if the product ID exists in Entrust.
        /// </summary>
        /// <param name="client">The <see cref="EntrustClient"/> is used to call out to the Entrust API.</param>
        /// <param name="productType">The product type we seek to check the inventory of.</param>
        /// <returns></returns>
        public static bool ProductIDValid(EntrustClient client, string productType)
        {
            // Client should always be valid, but sanity check it anyway.
            if (client == null)
            {
                return false;
            }

            // Try to find the product they asked for.
            CABaseCertType inventory = GetCustomerAccountTypes(client)
                    ?.FirstOrDefault(x => x.ProductCode.Equals(productType, StringComparison.CurrentCultureIgnoreCase));

            return inventory != null;
        }

        /// <summary>
        /// Gets a complete list of product types for a customer's account, including both the base types and the FLEX product types.
        /// </summary>
        /// <param name="client">The <see cref="EntrustClient"/> making the API call to get the product types.</param>
        /// <returns></returns>
        public static List<CABaseCertType> GetCustomerAccountTypes(EntrustClient client)
        {
            if (client == null)
            {
                throw new Exception("The client does not have a value, and therefore the customer account types cannot be retrieved.");
            }

            // Gets an inventory with all of the product types.
            List<InventoryItem> inventoryItems = client.GetInventories();

            // Add the base types.
            List<CABaseCertType> customerTypes = AllTypes
                .Where(x => inventoryItems.Any(y => y.ProductType == x.ProductCode))
                .ToList();

            // Add any types we get through FLEX inventory.
            if (inventoryItems.Any(x => x.ProductType == "FLEX"))
            {
                customerTypes.AddRange(FlexTypes.Where(x => !customerTypes.Any(y => y.ShortName == x.ShortName)));
            }

            return customerTypes;
        }

        #endregion Methods
    }
}
