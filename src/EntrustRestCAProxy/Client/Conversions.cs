// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using System;
using System.Globalization;
using System.Text.RegularExpressions;
using CAProxyConstants = CAProxy.Common.Constants;

namespace Keyfactor.Extensions.AnyGateway.Entrust.Client
{
    public class Conversions
    {
        private static ILogger logger = LogHandler.GetClassLogger<Conversions>();

        public static string RevokeReasonToString(UInt32 revokeType)
        {
            switch(revokeType)
            {
                case 1:
                case 2:  // Entrust doesn't accept CA Compromised, since they get to decide that, not us
                    return "keyCompromise";
                case 3:
                    return "affiliationChanged";
                case 4:
                    return "superseded";
                case 5:
                case 6: // Entrust doesn't accept Certificate Hold
                    return "cessationOfOperation";
                default:
                    return "affiliationChanged";
            }
        }

        public static byte[] PemToDer(string pem)
        {
            if (pem == null) { return null; }

            string noHeaders = Regex.Replace(pem, @"-----[^-]+-----", "").Trim();
            return Convert.FromBase64String(noHeaders);
        }

        //this is the error maaping routine
        public static int HResultForErrorCode(string errorCode)
        {
            try
            {
                string prefix = errorCode.Substring(0, 3);
                int category = CategoryNumberForPrefix(prefix);
                string subCode = errorCode.Substring(3);
                int subCodeInt = int.Parse(subCode, NumberStyles.HexNumber);
                // a means customer defined error 8 (below) means microsoft
                // HResult of form A000CSSS, where C is the category, and SSS is the subcode
                return unchecked((int)0xA0010000 | (category << 12) | subCodeInt);
            }
            catch(Exception ex)
            {
                logger.LogWarning($"Unable to convert error code '{errorCode}' to HResult: {LogHandler.FlattenException(ex)}");
                return unchecked((int)0x80004005); // E_FAIL
            }
        }
        //this is off and on errors for microsoft event viewer on box
        public static int EventIDForErrorCode(string errorCode)
        {
            try
            {
                string prefix = errorCode.Substring(0, 3);
                int category = CategoryNumberForPrefix(prefix);
                string subCode = errorCode.Substring(3);
                int subCodeInt = int.Parse(subCode, NumberStyles.Integer);

                // Event ID of form CSSS, where C is the category, and SSS is the subcode
                return category * 1000 + subCodeInt;
            }
            catch (Exception ex)
            {
                logger.LogWarning($"Unable to convert error code '{errorCode}' to Event ID: {LogHandler.FlattenException(ex)}");
                return 0;
            }
        }

        private static int CategoryNumberForPrefix(string prefix)
        {
            switch(prefix.ToUpper())
            {
                case "ACC":
                    return CAProxyConstants.EventCategories.ACCOUNT;
                case "SUS":
                    return CAProxyConstants.EventCategories.SUSPENSION;
                case "CSR":
                    return CAProxyConstants.EventCategories.CSR;
                case "SQL":
                    return CAProxyConstants.EventCategories.DATABASE;
                case "E2G":
                    return CAProxyConstants.EventCategories.E2G;
                case "GEN":
                    return CAProxyConstants.EventCategories.GENERAL;
                case "INP":
                    return CAProxyConstants.EventCategories.INPUT;
                case "LIS":
                    return CAProxyConstants.EventCategories.LISTS;
                case "PUP":
                    return CAProxyConstants.EventCategories.PICKUP;
                case "REV":
                    return CAProxyConstants.EventCategories.REVOCATION;
                case "SVR":
                    return CAProxyConstants.EventCategories.SERVER;
                default:
                    return CAProxyConstants.EventCategories.UNKNOWN;
            }
        }
    }
}