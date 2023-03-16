// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.AnyGateway.Entrust.APIProxy;
using Keyfactor.Logging;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Keyfactor.Extensions.AnyGateway.Entrust.Client
{
	public class EntrustClient
	{
		private static ILogger Logger => LogHandler.GetClassLogger<EntrustClient>();
		private string UserName { get; set; }
		private string Password { get; set; }
		private string BaseUrl { get; set; }
		private HttpClient client { get; set; }
		private X509Certificate2 AuthCert { get; set; }

		private class EntrustResponse
		{
			public EntrustResponse()
			{
				Success = true;
				Response = "";
			}

			public bool Success { get; set; }
			public string Response { get; set; }
		}

		public EntrustClient(string username, string password, X509Certificate2 authCert, string baseUrl)
		{
			UserName = username;
			Password = password;
			BaseUrl = baseUrl;
			AuthCert = authCert;
		}

		public EntrustClient(string username, string password, X509Certificate2 authCert)
			: this(username, password, authCert, "https://api.entrust.net/enterprise/v2/")
		{
		}

		private EntrustResponse Request(EntrustBaseRequest request, string parameters)
		{
			return Request(request, parameters, true);
		}

		private EntrustResponse Request(EntrustBaseRequest request, string parameters, bool adminuser)
		{
			EntrustResponse oCertCertResponse = new EntrustResponse();
			bool rateLimited = true;
			int retryAfter = 0;

			while (rateLimited)
			{
				System.Threading.Thread.Sleep(retryAfter * 1000);
				try
				{
					string targetURI;
					if (request.Method == "POST" || request.Method == "PUT" || request.Method == "PATCH")
					{
						targetURI = BaseUrl + request.Resource;
					}
					else
					{
						if (String.IsNullOrEmpty(parameters))
						{
							targetURI = BaseUrl + request.Resource;
						}
						else
						{
							targetURI = BaseUrl + request.Resource + "?" + parameters;
						}
					}

					Logger.LogTrace($"Entered Entrust Request Method: {request.Method} - URL: {targetURI}");

					HttpWebRequest objRequest = (HttpWebRequest)WebRequest.Create(targetURI);
					objRequest.Method = request.Method;
					objRequest.ContentType = "application/json";
					objRequest.Headers["Authorization"] = "Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes(UserName + ":" + Password));
					if (AuthCert != null)
					{
						objRequest.ClientCertificates.Add(AuthCert);
					}

					if (int.TryParse(ConfigurationManager.AppSettings[Constants.REQUEST_TIMEOUT_SECONDS], out int timeout))
					{
						Logger.LogTrace($"Setting request timeout to {timeout} seconds.");
						objRequest.Timeout = timeout * 1000;
					}
					else
					{
						Logger.LogWarning("Could not retrieve RequestTimeoutSeconds application setting. Using default value of 100 seconds.");
					}

					if (!String.IsNullOrEmpty(parameters) && (objRequest.Method == "POST" || objRequest.Method == "PUT" || objRequest.Method == "PATCH"))
					{
						byte[] postBytes = Encoding.UTF8.GetBytes(parameters);
						objRequest.ContentLength = postBytes.Length;
						Stream requestStream = objRequest.GetRequestStream();
						requestStream.Write(postBytes, 0, postBytes.Length);
						requestStream.Close();
					}

					Stopwatch watch = new Stopwatch();
					watch.Start();

					using (HttpWebResponse objResponse = (HttpWebResponse)objRequest.GetResponse())
					{
						oCertCertResponse.Response = new StreamReader(objResponse.GetResponseStream()).ReadToEnd();

						Logger.LogTrace($"Entrust API returned response {objResponse.StatusCode} ({oCertCertResponse.Response.Length} characters) in {watch.ElapsedMilliseconds}ms");
					}

					Logger.LogTrace("Full Response Body: " + oCertCertResponse.Response);
					rateLimited = false;
				}
				catch (WebException wex)
				{
					if (wex.Response != null)
					{
						using (HttpWebResponse errorResponse = (HttpWebResponse)wex.Response)
						{
							using (StreamReader reader = new StreamReader(errorResponse.GetResponseStream()))
							{
								oCertCertResponse.Response = reader.ReadToEnd();
								string retrySeconds = errorResponse.Headers["Retry-After"];

								if (!Int32.TryParse(retrySeconds, out retryAfter))
								{
									rateLimited = false;
								}
								else
								{
									retryAfter += 1; // Add one second to ensure we're not losing a decimal place.
									Logger.LogTrace("Rate Limit exceeded. Resubmitting request after {0} seconds.", retryAfter);
								}
							}
						}
					}
					else
					{
						Logger.LogError($"Entrust Response Error: {wex.Message}");
						throw new Exception($"Unable to establish connection to Entrust web service: {wex.Message}", wex);
					}
				}
				catch (Exception ex)
				{
					Logger.LogError($"Entrust Response Error: {ex.Message}");
					throw new Exception($"Unable to establish connection to Entrust web service: {ex.Message}", ex);
				}
			}

			return oCertCertResponse;
		}

		private bool IsError(string response)
		{
			return response.Contains("errors");
		}

		public VersionResponse GetApplicationVersion()
		{
			VersionRequest oRequest = new VersionRequest();
			EntrustResponse oResponse = Request(oRequest, oRequest.BuildParameters());
			VersionResponse response;

			if (IsError(oResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				Logger.LogError($"Error occurred requesting application version from the Entrust REST API - {e.errors.First().message}");
				throw new Exception(e.errors.First<Error>().message);
			}
			else
			{
				response = JsonConvert.DeserializeObject<VersionResponse>(oResponse.Response);
			}

			return response;
		}

		public List<Organization> GetOrganizations()
		{
			GetOrganizationsRequest request = new GetOrganizationsRequest();
			EntrustResponse apiResponse = Request(request, string.Empty);

			if (IsError(apiResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(apiResponse.Response);

				Logger.LogError($"Error occurred requesting organizations from the Entrust REST API: {e.errors.First().message}");

				throw new Exception(e.errors.First().message);
			}
			else
			{
				GetOrganizationsResponse response = JsonConvert.DeserializeObject<GetOrganizationsResponse>(apiResponse.Response);
				return response.Organizations;
			}
		}

		public List<APIProxy.ClientInfo> GetClients()
		{
			GetClientsRequest oRequest = new GetClientsRequest();
			EntrustResponse oResponse = Request(oRequest, oRequest.BuildParameters());
			GetClientsResponse response;

			if (IsError(oResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);

				Logger.LogError($"Error occurred requesting client list from the Entrust REST API - {e.errors.First().message}");

				throw new Exception(e.errors.First().message);
			}
			else
			{
				response = JsonConvert.DeserializeObject<GetClientsResponse>(oResponse.Response);
			}

			return response.Clients;
		}

		public IEnumerable<Domain> GetApprovedDomainsByClient(int clientId)
		{
			int total = 0;
			int offset = 0;
			int limit = 1000;
			while (true)
			{
				GetDomainsByClientResponse domainsResponse;
				try
				{
					domainsResponse = GetDomainsByClient(clientId, offset, limit, true);
				}
				catch (Exception e)
				{
					if (limit == 100)
					{
						Logger.LogError($"Getting domains failed with error: {e.Message}. Not re-trying.");
						throw;
					}
					else
					{
						Logger.LogWarning($"Getting domains failed with error: {e.Message}. Trying again with limit of 100.");
						limit = 100;
						continue;
					}
				}

				if (total == 0)
				{
					total = domainsResponse.Summary.Total ?? 0;
				}

				foreach (Domain domain in domainsResponse.Domains)
				{
					yield return domain;
				}

				offset += domainsResponse.Domains.Count;

				if (domainsResponse.Domains.Count == 0 || total == offset)
				{
					break;
				}
			}
		}

		private GetDomainsByClientResponse GetDomainsByClient(int clientId, int offset, int limit, bool onlyApproved)
		{
			GetDomainsByClientRequest request = new GetDomainsByClientRequest(clientId, offset, limit, onlyApproved);
			EntrustResponse response = Request(request, request.BuildParameters());
			GetDomainsByClientResponse domainsResponse;

			if (IsError(response.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(response.Response);
				Logger.LogError($"Error occurred requesting domain list for clientId {clientId} from the Entrust REST API - {e.errors.First().message}");
				throw new Exception(e.errors.First().message);
			}
			else
			{
				domainsResponse = JsonConvert.DeserializeObject<GetDomainsByClientResponse>(response.Response);
			}

			return domainsResponse;
		}

		public List<Certificate> GetAllCertificates()
		{
			List<Certificate> result = new List<Certificate>();
			int limit = 1000;
			int received = 0;
			int? total = 0;
			bool requestStarted = false;

			while (!requestStarted || received != total)
			{
				GetCertificatesRequest oRequest = new GetCertificatesRequest(limit, received);
				EntrustResponse oResponse = Request(oRequest, oRequest.BuildParameters());
				GetCertificatesResponse response;

				if (IsError(oResponse.Response))
				{
					ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
					Logger.LogError($"Error occurred requesting certificate list from Entrust REST API - {e.errors.First().message}");
					throw new Exception(e.errors.First().message);
				}
				else
				{
					response = JsonConvert.DeserializeObject<GetCertificatesResponse>(oResponse.Response);
					total = response.summary.Total;
					received += response.certificates.Count;
					result.AddRange(response.certificates);
				}
				requestStarted = true;
			}

			return result;
		}

		public CertificateExt GetCertificateByTrackingId(int trackingId)
		{
			GetCertificateByTrackingIdRequest oRequest = new GetCertificateByTrackingIdRequest(trackingId);
			EntrustResponse oResponse = Request(oRequest, oRequest.BuildParameters());
			CertificateExt response;

			if (IsError(oResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				Logger.LogError($"Error occurred requesting certificate for trackingId {trackingId} from the Entrust REST API - Error status code {e.status} : {e.errors.First().message}");
				throw new Exception(e.errors.First().message);
			}
			else
			{
				response = JsonConvert.DeserializeObject<CertificateExt>(oResponse.Response);
			}

			return response;
		}

		public CertificateExt GetCertificateByThumbprint(string thumbprint)
		{
			GetCertificateByThumbprintRequest oRequest = new GetCertificateByThumbprintRequest(thumbprint);
			EntrustResponse oResponse = Request(oRequest, oRequest.BuildParameters());
			CertificateExt response;

			if (IsError(oResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				Logger.LogError("Error occurred requesting certificate for thumbprint {0} from the Entrust REST API - Error status code {1} : {2}", thumbprint, e.status, e.errors.First().message);
				throw new Exception(e.errors.First().message);
			}
			else
			{
				response = JsonConvert.DeserializeObject<CertificateExt>(oResponse.Response);
			}

			return response;
		}

		public CertificateResponse RequestNewCertificate(NewCertificateRequest request)
		{
			NewCertificateCall call = new NewCertificateCall();
			EntrustResponse oResponse = Request(call, JsonConvert.SerializeObject(request, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }));
			CertificateResponse response;

			if (IsError(oResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				Logger.LogError($"Error occurred requesting new certificate from Entrust REST API - {e.errors.First().message}");
				throw new Exception(e.errors.First().message);
			}
			else
			{
				response = JsonConvert.DeserializeObject<CertificateResponse>(oResponse.Response);
			}

			return response;
		}

		public CertificateResponse ReissueCertificate(ReissueCertificateRequestBody request, int trackingId)
		{
			EntrustResponse oResponse = Request(new ReissueCertificateRequest(trackingId), JsonConvert.SerializeObject(request, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }));
			CertificateResponse response;

			if (IsError(oResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				Logger.LogError($"Error occurred reissuing certificate with trackingId {trackingId} from Entrust REST API - {e.errors.First().message}");
				throw new Exception(e.errors.First().message);
			}
			else
			{
				response = JsonConvert.DeserializeObject<CertificateResponse>(oResponse.Response);
			}

			return response;
		}

		public CertificateResponse RenewCertificate(RenewCertificateRequestBody request, int trackingId)
		{
			EntrustResponse oResponse = Request(new RenewCertificateRequest(trackingId), JsonConvert.SerializeObject(request, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }));
			CertificateResponse response;

			if (IsError(oResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				Logger.LogError($"Error occurred renewing certificate with trackingId {trackingId} from Entrust REST API - {e.errors.First().message}");
				throw new Exception(e.errors.First().message);
			}
			else
			{
				response = JsonConvert.DeserializeObject<CertificateResponse>(oResponse.Response);
			}

			return response;
		}

		public ValueTuple<bool, string> ValidateRenewCertificate(RenewCertificateRequestBody request, int trackingId)
		{
			// We switch the value here so that callers don't have to create a new request.
			bool? originalValue = request.ValidateOnly;
			request.ValidateOnly = true;
			EntrustResponse oResponse = Request(new RenewCertificateRequest(trackingId), JsonConvert.SerializeObject(request, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }));
			request.ValidateOnly = originalValue;

			if (IsError(oResponse.Response))
			{
				ErrorResponse response = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				Error requestError = response.errors[0];
				return (false, requestError.message);
			}
			return (true, oResponse.Response);
		}

		public ValueTuple<bool, string> ValidateRequestNewCertificate(NewCertificateRequest request)
		{
			// We switch the value here so that callers don't have to create a new request.
			bool? originalValue = request.ValidateOnly;
			request.ValidateOnly = true;
			EntrustResponse oResponse = Request(new NewCertificateCall(), JsonConvert.SerializeObject(request, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }));
			request.ValidateOnly = originalValue;

			if (IsError(oResponse.Response))
			{
				ErrorResponse response = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				Error requestError = response.errors[0];
				return (false, requestError.message);
			}
			return (true, oResponse.Response);
		}

		public Certificate GetCertificateBySerialNumber(string serialNumber)
		{
			string trimmedSerialNumber = serialNumber.StartsWith("00") ? serialNumber.Substring(2) : serialNumber;
			List<Certificate> result = new List<Certificate>();

			Dictionary<string, string> qParams = new Dictionary<string, string>();
			qParams.Add("serialNumber", trimmedSerialNumber);
			GetCertificatesRequest oRequest = new GetCertificatesRequest(1, 0, qParams);
			EntrustResponse oResponse = Request(oRequest, oRequest.BuildParameters());
			GetCertificatesResponse response;

			if (IsError(oResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				if (e.status == 404)
				{
					return null;
				}
				Logger.LogError($"Error occurred requesting certificate with serial number {trimmedSerialNumber} from Entrust REST API - {e.errors.First().message}");
				throw new Exception(e.errors.First().message);
			}
			else
			{
				response = JsonConvert.DeserializeObject<GetCertificatesResponse>(oResponse.Response);
			}

			if (response.certificates.Count > 0)
			{
				return response.certificates[0];
			}
			else
			{
				return null;
			}
		}

		public void RevokeCertificate(int trackingId, string reason, string comment)
		{
			RevokeCertificateCall oRequest = new RevokeCertificateCall(trackingId);
			RevokeCertificateRequest request = new RevokeCertificateRequest()
			{
				CrlReason = reason,
				RevocationComment = comment
			};

			EntrustResponse oResponse = Request(oRequest, JsonConvert.SerializeObject(request, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }));

			if (IsError(oResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				Logger.LogError($"Error occurred revoking certificate with trackingId {trackingId} from Entrust REST API - {e.errors.First().message}");
				throw new Exception(e.errors.First().message);
			}
		}

		public List<InventoryItem> GetInventories()
		{
			GetInventoryRequest oRequest = new GetInventoryRequest();
			EntrustResponse oResponse = Request(oRequest, oRequest.BuildParameters());
			GetInventoryResponse response;

			if (IsError(oResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				Logger.LogError($"Error occurred requesting inventory from Entrust REST API - {e.errors.First().message}");
				throw new Exception(e.errors.First().message);
			}
			else
			{
				response = JsonConvert.DeserializeObject<GetInventoryResponse>(oResponse.Response);
			}

			return response.Inventories;
		}

		public CertificateResponse ApproveCertificate(int trackingId)
		{
			PatchCertificateRequest oRequest = new PatchCertificateRequest(trackingId);
			PatchCertificateRequestBody body = new PatchCertificateRequestBody()
			{
				Operation = CertificateOperation.APPROVE
			};
			EntrustResponse oResponse = Request(oRequest, JsonConvert.SerializeObject(body, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }));
			CertificateResponse response;

			if (IsError(oResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				Logger.LogError($"Error occurred approving certificate with trackingId {trackingId} from Entrust REST API - {e.errors.First().message}");
				throw new Exception(e.errors.First().message);
			}
			else
			{
				response = JsonConvert.DeserializeObject<CertificateResponse>(oResponse.Response);
			}

			return response;
		}

		public void DeclineCertificate(int trackingId, string declineReason)
		{
			var oRequest = new PatchCertificateRequest(trackingId);
			var body = new PatchCertificateRequestBody()
			{
				Operation = CertificateOperation.DECLINE,
				DeclineReason = declineReason
			};
			EntrustResponse oResponse = Request(oRequest, JsonConvert.SerializeObject(body, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }));

			if (IsError(oResponse.Response))
			{
				ErrorResponse e = JsonConvert.DeserializeObject<ErrorResponse>(oResponse.Response);
				Logger.LogError($"Error occurred denying certificate with trackingId {trackingId} from Entrust REST API - {e.errors.First().message}");
				throw new Exception(e.errors.First().message);
			}
		}
	}
}