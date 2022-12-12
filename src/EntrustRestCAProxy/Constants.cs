// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

namespace Keyfactor.Extensions.AnyGateway.Entrust
{
	public class Constants
	{
		public const string USERNAME = "AuthUsername";
		public const string PASSWORD = "AuthPassword";
		public const string CLIENT_CERTIFICATE = "ClientCertificate";
		public const string STORE_NAME = "StoreName";
		public const string STORE_LOCATION = "StoreLocation";
		public const string THUMBPRINT = "Thumbprint";
		public const string IGNORE_EXPIRED = "IgnoreExpired";

		public const string CLIENT = "EntrustClient";
		public const string DOMAINS = "EntrustDomains";
		public const string ENROLL_NUMBER = "Phone Number";
		public const string CONFIG_NUMBER = "PhoneNumber";
		public const string NAME = "Name";
		public const string EMAIL = "Email";
		public const string ORGANIZATION = "Organization";

		public const string SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
		public const string CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

		public const string REQUEST_TIMEOUT_SECONDS = "RequestTimeoutSeconds";
	}
}