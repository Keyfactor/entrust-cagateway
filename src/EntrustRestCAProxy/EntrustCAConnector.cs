// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using CAProxy.AnyGateway;
using CAProxy.AnyGateway.Configuration;
using CAProxy.AnyGateway.Interfaces;
using CAProxy.AnyGateway.Models;
using CAProxy.AnyGateway.Models.Configuration;
using CAProxy.Common;
using CAProxy.Common.Config;
using Keyfactor.Extensions.AnyGateway.Entrust.APIProxy;
using Keyfactor.Extensions.AnyGateway.Entrust.Client;
using CAProxy.Models;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

using static CAProxy.Common.RequestUtilities;
using static CSS.PKI.PKIConstants.Microsoft;

using EntrustConstants = Keyfactor.Extensions.AnyGateway.Entrust.Constants;

namespace Keyfactor.Extensions.AnyGateway.Entrust
{
    public partial class EntrustCAConnector : BaseCAConnector, ICAConnectorConfigInfoProvider
    {
        #region Fields and Constructors

        /// <summary>
        /// Provides configuration information for the <see cref="EntrustCAConnector"/>.
        /// </summary>
        private ICAConnectorConfigProvider ConfigProvider { get; set; }

        #endregion Fields and Constructors

        #region ICAConnector Methods

        /// <summary>
        /// Initializes the <see cref="EntrustCAConnector"/>.
        /// </summary>
        /// <param name="configProvider">The config provider contains information required to connect to the CA.</param>
        public override void Initialize(ICAConnectorConfigProvider configProvider)
        {
            ConfigProvider = configProvider;
        }

        /// <summary>
        /// Enrolls for a certificate.
        /// </summary>
        /// <param name="csr">The CSR being used to enroll</param>
        /// <param name="subject">The subject of the certificate.</param>
        /// <param name="san">The collection of SANs associated with the request as attributes.</param>
        /// <param name="productInfo">Information about the product being enrolled for.</param>
        /// <param name="requestFormat">The format the CSR is in.</param>
        /// <param name="enrollmentType">The type of enrollment being performed, i.e. new, renew, or reissue.</param>
        /// <returns></returns>
        [Obsolete]
        public override EnrollmentResult Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, CSS.PKI.PKIConstants.X509.RequestFormat requestFormat, EnrollmentType enrollmentType)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Enrolls for a certificate through the Entrust API.
        /// </summary>
        /// <param name="certificateDataReader">Reads certificate data from the database.</param>
        /// <param name="csr">The certificate CSR in PEM format.</param>
        /// <param name="subject">The subject of the certificate request.</param>
        /// <param name="san">Any sans added to the request.</param>
        /// <param name="productInfo">Information about the CA product type.</param>
        /// <param name="requestFormat">The format of the request.</param>
        /// <param name="enrollmentType">The type of the enrollment, i.e. new, renew, or reissue.</param>
        /// <returns></returns>
        public override EnrollmentResult Enroll(ICertificateDataReader certificateDataReader, string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, CSS.PKI.PKIConstants.X509.RequestFormat requestFormat, EnrollmentType enrollmentType)
        {
            Dictionary<string, object> connectionInfo = ConfigProvider.CAConnectionData;
            EntrustClient client = CreateEntrustClient(connectionInfo);
            X509Name subjectParsed = new X509Name(subject);

            string underscoreErrorMessage = "Underscore is not allowed in DNSName.";
            string requestEmail;
            string requestNumber;
            string requestName;
            string commonName = "";
            string organization = "";
            string checkingSanVariable = "";
            int trackingId = 0;
            int clientId = -1;

            // Check tracking ID if we're doing a renewal or reissuance.
            if (enrollmentType == EnrollmentType.Reissue || enrollmentType == EnrollmentType.Renew)
            {
                trackingId = GetTrackingId(client, productInfo);

                // Check now if the trackingId is 0 to fail early.
                if (trackingId == 0)
                {
                    throw new Exception("The tracking ID of the certificate requested for renewal or reissue is 0. This certificate must be renewed or reissued through the Entrust portal.");
                }
            }

            try
            {
                checkingSanVariable = "Common Name";
                string cn = subjectParsed.GetValueList(X509Name.CN).Cast<string>().LastOrDefault();
                if (!string.IsNullOrEmpty(cn))
                {
                    if (cn.Contains("_"))
                    {
                        throw new Exception(underscoreErrorMessage);
                    }
                    commonName = cn;
                }

                checkingSanVariable = "Organization";
                string org = subjectParsed.GetValueList(X509Name.O).Cast<string>().LastOrDefault();
                if (productInfo.ProductParameters.ContainsKey(EntrustConstants.ORGANIZATION) && !string.IsNullOrEmpty(productInfo.ProductParameters[EntrustConstants.ORGANIZATION]))
                {
                    organization = productInfo.ProductParameters[EntrustConstants.ORGANIZATION];
                }
                else if (!string.IsNullOrEmpty(org))
                {
                    organization = org;
                }

                checkingSanVariable = "Email";
                string subjectEmail = subjectParsed.GetValueList(X509Name.EmailAddress).Cast<string>().LastOrDefault();
                if (productInfo.ProductParameters.ContainsKey(EntrustConstants.EMAIL) && !string.IsNullOrEmpty(productInfo.ProductParameters[EntrustConstants.EMAIL]))
                {
                    requestEmail = productInfo.ProductParameters[EntrustConstants.EMAIL];
                }
                else if (!string.IsNullOrEmpty(subjectEmail))
                {
                    requestEmail = subjectEmail;
                }
                else if (connectionInfo.ContainsKey(EntrustConstants.EMAIL) && !string.IsNullOrEmpty((string)connectionInfo[EntrustConstants.EMAIL]))
                {
                    requestEmail = (string)connectionInfo[EntrustConstants.EMAIL];
                }
                else
                {
                    requestEmail = "email@email.invalid";
                }

                checkingSanVariable = "Telephone Number";
                if (productInfo.ProductParameters.ContainsKey(EntrustConstants.ENROLL_NUMBER) && !string.IsNullOrEmpty(productInfo.ProductParameters[EntrustConstants.ENROLL_NUMBER]))
                {
                    requestNumber = productInfo.ProductParameters[EntrustConstants.ENROLL_NUMBER];
                }
                else if (!string.IsNullOrEmpty((string)connectionInfo[EntrustConstants.CONFIG_NUMBER]))
                {
                    requestNumber = (string)connectionInfo[EntrustConstants.CONFIG_NUMBER];
                }
                else
                {
                    requestNumber = "0000000000";
                }

                checkingSanVariable = "Name";
                if (productInfo.ProductParameters.ContainsKey(EntrustConstants.NAME) && !string.IsNullOrEmpty(productInfo.ProductParameters[EntrustConstants.NAME]))
                {
                    requestName = productInfo.ProductParameters[EntrustConstants.NAME];
                }
                else if (!string.IsNullOrEmpty((string)connectionInfo[EntrustConstants.NAME]))
                {
                    requestName = (string)connectionInfo[EntrustConstants.NAME];
                }
                else
                {
                    requestName = "TestUser";
                }
            }
            catch (Exception ex)
            {
                if (ex.Message == underscoreErrorMessage)
                {
                    Logger.Error($"Error occurred trying to validate the SAN information. {ex.Message}");
                    throw new UnsuccessfulRequestException(ex.Message, unchecked((uint)HRESULTs.INVALID_DATA));
                }
                else
                {
                    Logger.Error($"Error occurred trying to validate the request information. Required attributes {checkingSanVariable} may be missing.");
                    throw new UnsuccessfulRequestException("Error occurred trying to validate the request information. Required attributes " + checkingSanVariable + " may be missing.",
                        unchecked((uint)HRESULTs.INVALID_DATA));
                }
            }


            List<string> dnsNames = new List<string>();
            if (san.ContainsKey("Dns"))
            {
                dnsNames = new List<string>(san["Dns"]);
            }

            if (!commonName.Contains('.'))
            {
                throw new Exception($"Domain cannot be determined from Common Name.");
            }

            IEnumerable<Organization> approvedOrgs = client.GetOrganizations().Where(x => x.VerificationStatus.Equals("APPROVED", StringComparison.OrdinalIgnoreCase));
            if (string.IsNullOrEmpty(organization)) // If the organization is empty, use the default client.
            {
                clientId = 1;
            }
            else
            {
                Organization org = approvedOrgs.FirstOrDefault(x => x.Name.Equals(organization, StringComparison.OrdinalIgnoreCase));
                if (org != null)
                {
                    clientId = org.ClientId;
                }
            }

            if (clientId == -1)
            {
                throw new Exception($"Organization {organization} is not a valid Entrust organization for this account. The following organizations are approved: {string.Join(", ", approvedOrgs.Select(x => x.Name))}.");
            }

            string usageType = (productInfo.ProductParameters.ContainsKey("CertificateUsage")) ? productInfo.ProductParameters["CertificateUsage"] : "";
            string eku = "";
            if (usageType.Equals("SERVERCLIENT", StringComparison.OrdinalIgnoreCase))
            {
                eku = "SERVER_AND_CLIENT_AUTH";
            }
            else if (usageType.Equals("SERVER", StringComparison.OrdinalIgnoreCase))
            {
                eku = "SERVER_AUTH";
            }
            else if (usageType.Equals("CLIENT", StringComparison.OrdinalIgnoreCase))
            {
                eku = "CLIENT_AUTH";
            }
            else
			{
                eku = "";
			}
            Tracking trackingInfo = new Tracking()
            {
                TrackingInfo = "",
                RequesterEmail = requestEmail,
                RequesterName = requestName,
                RequesterPhone = requestNumber,
                Deactivated = false
            };

            if (!EntrustCertType.InventoryExists(client, productInfo.ProductID))
            {
                Logger.Error($"Inventory for certificate type '{productInfo.ProductID}' has been used up. To perform the operation, revoke existing certificates or contact Entrust to acquire new inventory.");
                throw new Exception($"Inventory for certificate type '{productInfo.ProductID}' has been used up. To perform the operation, revoke existing certificates or contact Entrust to acquire new inventory.");
            }

            var months = (productInfo.ProductParameters.ContainsKey("Lifetime")) ? int.Parse(productInfo.ProductParameters["Lifetime"]) : 12;
            

            CertificateResponse response;
            switch (enrollmentType)
            {
                case EnrollmentType.New:
                    NewCertificateRequest request = new NewCertificateRequest()
                    {
                        Csr = csr,
                        ClientId = clientId,
                        Org = organization,
                        CertType = productInfo.ProductID.ToUpper(),
                        CertExpiryDate = DateTime.Now.AddMonths(months),
                        CertLifetime = "P" + Math.Round(months / 12.0).ToString() + "Y",
                        Tracking = trackingInfo,
                        QueueForApproval = false,
                        CertEmail = requestEmail,
                        SubjectAltName = dnsNames,
                        Password = "",
                        SigningAlg = "SHA-2",
                        Eku = eku,
                        Cn = commonName,
                        //email from userInfo
                        Upn = requestEmail,
                        Ou = new List<string>(),
                        EndUserKeyStorageAgreement = true,
                        //When true, this causes the api to only validate the submitted info and not actually register a cert.
                        ValidateOnly = false
                    };
                    (bool validResponse, string messageResponse) = client.ValidateRequestNewCertificate(request);
                    if (!validResponse) {
                        Logger.Error($"Request validation failed. {messageResponse}");
                        throw new Exception($"Request validation failed. {messageResponse}");
                    }

                    response = client.RequestNewCertificate(request);
                    break;
                case EnrollmentType.Reissue:
                    ReissueCertificateRequestBody reissueRequest = new ReissueCertificateRequestBody()
                    {
                        Csr = csr,
                        ClientId = clientId,
                        Org = string.Empty,
                        Tracking = trackingInfo,
                        CertEmail = requestEmail,
                        SubjectAltName = dnsNames,
                        Password = string.Empty,
                        SigningAlg = "SHA-2",
                        Eku = eku,
                        Cn = commonName,
                        //email from userInfo
                        Upn = requestEmail,
                        Ou = new List<string>(),
                        EndUserKeyStorageAgreement = true,
                    };

                    response = client.ReissueCertificate(reissueRequest, trackingId);
                    break;
                case EnrollmentType.Renew:
                    RenewCertificateRequestBody renewRequest = new RenewCertificateRequestBody()
                    {
                        Csr = csr,
                        ClientId = clientId,
                        Org = "",
                        CertExpiryDate = DateTime.Now.AddMonths(months),
                        CertLifetime = "P" + Math.Round(months / 12.0).ToString() + "Y",
                        Tracking = trackingInfo,
                        CertEmail = requestEmail,
                        SubjectAltName = dnsNames,
                        Password = "",
                        SigningAlg = "SHA-2",
                        Eku = eku,
                        Cn = commonName,
                        //email from userInfo
                        Upn = requestEmail,
                        Ou = new List<string>(),
                        EndUserKeyStorageAgreement = true,
                    };

                    (bool validRenewResponse, string messageRenewResponse) = client.ValidateRenewCertificate(renewRequest, GetTrackingId(client, productInfo));
                    if (!validRenewResponse)
                    {
                        Logger.Error($"Request validation failed. {messageRenewResponse}");
                        throw new Exception($"Request validation failed. {messageRenewResponse}");
                    }

                    response = client.RenewCertificate(renewRequest, trackingId);
                    break;
                default:
                    throw new Exception($"The enrollment type {enrollmentType} is not recognized.");
            }

            CertificateExt enrolledCert = client.GetCertificateByTrackingId(response.TrackingId);
            int status = ConvertStatus(enrolledCert.Status);
            string statusMessage;
            switch (status)
            {
                case (int)RequestDisposition.ISSUED:
                    statusMessage = $"Certificate with trackingId {enrolledCert.TrackingId} issued successfully";
                    break;
                case (int)RequestDisposition.PENDING:
                    // Attempt to approve the cert. If still pending, return External validation
                    (int statusPending, string statusPendingMessage) statusTuple = ApproveCert(response.TrackingId, client);
                    status = statusTuple.statusPending;
                    statusMessage = statusTuple.statusPendingMessage;
                    break;
                case (int)RequestDisposition.DENIED:
                    statusMessage = $"Certificate with trackingId {enrolledCert.TrackingId} is denied";
                    break;
                default:
                    statusMessage = $"Certificate with trackingId {enrolledCert.TrackingId} has an unknown status";
                    break;
            }

            return new EnrollmentResult
            {
                CARequestID = response.TrackingId.ToString(),
                Certificate = ConfigurationUtils.OnlyBase64CertContent(response.EndEntityCert),
                Status = status,
                StatusMessage = statusMessage
            };
        }

        /// <summary>
        /// Returns a single certificate record by its serial number.
        /// </summary>
        /// <param name="caRequestID">The CA request ID for the certificate.</param>
        /// <returns></returns>
        public override CAConnectorCertificate GetSingleRecord(string caRequestId)
        {
            // Get status of cert and the cert itself from Digicert
            EntrustClient client = CreateEntrustClient(ConfigProvider.CAConnectionData);

            // Split string to see what kind of ID we have.
            string[] parts = caRequestId.Split('-');

            // Get the cert by tracking ID or thumbprint.
            CertificateExt entrustCert = parts.Length == 1 ? client.GetCertificateByTrackingId(Int32.Parse(caRequestId)) : client.GetCertificateByThumbprint(parts[1]);
            int status = ConvertStatus(entrustCert.Status);
            return new CAConnectorCertificate
            {
                CARequestID = caRequestId,
                Certificate = !string.IsNullOrEmpty(entrustCert.EndEntityCert) ? ConfigurationUtils.OnlyBase64CertContent(entrustCert.EndEntityCert) : null,
                Status = status,
                ProductID = entrustCert.CertType,
                SubmissionDate = entrustCert.IssueDateTime
            };
        }

        /// <summary>
        /// Attempts to reach the CA over the network.
        /// </summary>
        public override void Ping()
        {
            try
            {
                EntrustClient client = CreateEntrustClient(ConfigProvider.CAConnectionData);

                Logger.Debug("Attempting to ping Entrust API.");

                _ = client.GetClients();

                Logger.Debug("Successfully pinged Entrust API.");
            }
            catch (Exception e)
            {
                Logger.Error($"There was an error contacting Entrust: {e.Message}.");
                throw new Exception($"Error attempting to ping Entrust: {e.Message}.", e);
            }
        }

        /// <summary>
        /// Revokes a certificate by its serial number.
        /// </summary>
        /// <param name="caRequestID">The CA request ID (presently the serial number).</param>
        /// <param name="hexSerialNumber">The hex-encoded serial number.</param>
        /// <param name="revocationReason">The revocation reason.</param>
        public override int Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
        {
            Logger.Trace("Entered Entrust Revoke method");
            Dictionary<string, object> connectionInfo = ConfigProvider.CAConnectionData;
            EntrustClient client = CreateEntrustClient(connectionInfo);
            string reason = Conversions.RevokeReasonToString(revocationReason);
            string comment = "Revoked by Entrust Gateway";
            CAConnectorCertificate cert = GetSingleRecord(caRequestID);
            if (!(cert.Status == (int)RequestDisposition.ISSUED))
            {
                string errorMessage = String.Format("Request {0} was not found in Entrust database or is not in a valid state to perform a revocation", caRequestID);
                Logger.Info(errorMessage);
                throw new COMException(errorMessage, HRESULTs.PROP_NOT_FOUND);
            }
            client.RevokeCertificate(Int32.Parse(caRequestID), reason, comment);
            CAConnectorCertificate revokedCert = GetSingleRecord(caRequestID);
            return revokedCert.Status;


        }

        /// <summary>
        /// Synchronizes the CA with the external CA.
        /// </summary>
        /// <param name="certificateDataReader">Provides information about the gateway's certificates.</param>
        /// <param name="blockingBuffer">Buffer into which certificates are placed from the CA.</param>
        /// <param name="certificateAuthoritySyncInfo">Information about the last CA sync.</param>
        /// <param name="cancelToken">The cancellation token.</param>
        [Obsolete]
        public override void Synchronize(ICertificateDataReader certificateDataReader, BlockingCollection<CertificateRecord> blockingBuffer, CertificateAuthoritySyncInfo certificateAuthoritySyncInfo, CancellationToken cancelToken, string reservedUnused)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Synchronizes the gateway with the external CA.
        /// </summary>
        /// <param name="certificateDataReader">Provides information about the gateway's certificates.</param>
        /// <param name="blockingBuffer">Buffer into which certificates are placed from the CA.</param>
        /// <param name="certificateAuthoritySyncInfo">Information about the last CA sync.</param>
        /// <param name="cancelToken">The cancellation token.</param>
        public override void Synchronize(ICertificateDataReader certificateDataReader, BlockingCollection<CAConnectorCertificate> blockingBuffer, CertificateAuthoritySyncInfo certificateAuthoritySyncInfo, CancellationToken cancelToken)
        {
            if (!int.TryParse(ConfigurationManager.AppSettings["MaxAllowedErrors"], out int maxErrors))
            {
                Logger.Warn($"MaxAllowedErrors application setting is missing. Value defaulting to five.");
                maxErrors = 5;
            }

            int deniedCerts = 0;
            int totalSkipped = 0;
            EntrustClient client = CreateEntrustClient(ConfigProvider.CAConnectionData);
            List<Certificate> allCerts = client.GetAllCertificates();
            foreach (Certificate entrustCert in allCerts)
            {
                cancelToken.ThrowIfCancellationRequested();

                if (totalSkipped > maxErrors)
                {
                    Logger.Error($"The maximum number of errors {maxErrors} has been exceeded. The sync is being cancelled.");
                    throw new Exception($"The maximum number of errors {maxErrors} has been exceeded. The sync is being cancelled.");
                }

                // Set up request ID.
                string caRequestId = entrustCert.TrackingId.ToString();

                // If the tracking ID is 0, log it and modify the request ID.
                if (entrustCert.TrackingId == 0)
                {
                    Logger.Warn($"The certificate with serial number '{entrustCert.SerialNumber}' has a tracking ID of 0. Will attempt to sync using thumbprint.");

                    string thumbprint = GetThumbprint(entrustCert);
                    if (string.IsNullOrEmpty(thumbprint))
                    {
                        Logger.Warn("The thumbprint could not be found. Skipping certificate.");
                        ++totalSkipped;
                        continue;
                    }

                    caRequestId = $"0-{thumbprint}";
                }

                try
                {
                    // Find cert within the database
                    CAConnectorCertificate dbCert = certificateDataReader.GetCertificateRecord(caRequestId, string.Empty);

                    // Get status and check to see if we need to skip it.
                    int entrustStatus = ConvertStatus(entrustCert.Status);
                    if (entrustStatus == (int)RequestDisposition.DENIED)
                    {
                        Logger.Warn($"Certificate with tracking ID '{entrustCert.TrackingId}' has a status of DECLINED and will be skipped, as it has no certificate record.");
                        ++deniedCerts;
                        continue;
                    }

                    // If the cert exists, check the status and see if it's different from the cert from Entrust
                    if (dbCert != null)
                    {
                        int dbStatus = dbCert.Status;
                        if (dbStatus != entrustStatus)
                        {
                            CAConnectorCertificate newCert = entrustCert.TrackingId != 0 ? GetSingleRecord(client, entrustCert.TrackingId) : GetSingleRecord(client, GetThumbprint(entrustCert));
                            blockingBuffer.Add(newCert);
                        }
                    }
                    else
                    {
                        CAConnectorCertificate newCert = entrustCert.TrackingId != 0 ? GetSingleRecord(client, entrustCert.TrackingId) : GetSingleRecord(client, GetThumbprint(entrustCert));
                        blockingBuffer.Add(newCert);
                    }
                }
                catch (Exception e)
                {
                    Logger.Error($"An error occurred while processing certificate with tracking ID '{entrustCert.TrackingId}', skipping.", e);
                    ++totalSkipped;
                }
            }

            Logger.Debug($"Synchronization skipped a total of {deniedCerts} certificates with the 'DECLINED' status.");
        }

        /// <summary>
        /// Validates that the CA connection info is correct.
        /// </summary>
        /// <param name="connectionInfo">The information used to connect to the CA.</param>
        public override void ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            Logger.Trace("Entered 'ValidateCAConnectionInfo' method.");
            List<string> errors = new List<string>();

            Logger.Trace("Checking the Username");
            string username = connectionInfo.ContainsKey(EntrustConstants.USERNAME) ? (string)connectionInfo[EntrustConstants.USERNAME] : string.Empty;
            if (string.IsNullOrWhiteSpace(username))
            {
                errors.Add("The username is required");
            }

            Logger.Trace("Checking the Password");
            string password = connectionInfo.ContainsKey(EntrustConstants.PASSWORD) ? (string)connectionInfo[EntrustConstants.PASSWORD] : string.Empty;
            if (string.IsNullOrWhiteSpace(password))
            {
                errors.Add("The password is required");
            }

            Logger.Trace("Checking the user information");
            string name = connectionInfo.ContainsKey(EntrustConstants.NAME) ? (string)connectionInfo[EntrustConstants.NAME] : string.Empty;
            if (string.IsNullOrWhiteSpace(name))
            {
                errors.Add("The name is required");
            }

            string email = connectionInfo.ContainsKey(EntrustConstants.EMAIL) ? (string)connectionInfo[EntrustConstants.EMAIL] : string.Empty;
            if (string.IsNullOrWhiteSpace(email))
            {
                errors.Add("The email is required");
            }

            string number = connectionInfo.ContainsKey(EntrustConstants.CONFIG_NUMBER) ? (string)connectionInfo[EntrustConstants.CONFIG_NUMBER] : string.Empty;
            if (string.IsNullOrWhiteSpace(number))
            {
                errors.Add("The phone number is required");
            }

            Logger.Trace("Checking the certificate information.");
            Dictionary<string, object> clientCertificate;
            X509Certificate2 authCert = null;
            if (!connectionInfo.ContainsKey(EntrustConstants.CLIENT_CERTIFICATE))
            {
                errors.Add("The client certificate is required.");
            }
            else
            {
                clientCertificate = (Dictionary<string, object>)connectionInfo[EntrustConstants.CLIENT_CERTIFICATE];
                if (!clientCertificate.ContainsKey(EntrustConstants.STORE_LOCATION)
                    || !clientCertificate.ContainsKey(EntrustConstants.STORE_NAME)
                    || !clientCertificate.ContainsKey(EntrustConstants.THUMBPRINT))
                {
                    errors.Add("The store location, store name, and thumbprint of the client certificate are required.");
                }
                else
                {
                    Logger.Trace("Checking for authentication certificate.");
                    StoreLocation storeLocation = (StoreLocation)Enum.Parse(typeof(StoreLocation), (string)clientCertificate[EntrustConstants.STORE_LOCATION]);
                    GatewayCertificate finder = new GatewayCertificate();
                    try
                    {
                        authCert = finder.FindGatewayCertificate((string)clientCertificate[EntrustConstants.STORE_NAME], storeLocation, (string)clientCertificate[EntrustConstants.THUMBPRINT]);
                    }
                    catch (Exception e)
                    {
                        errors.Add(e.Message);
                    }

                    Logger.Trace("Checking for private key permissions.");
                    try
                    {
                        //https://www.pkisolutions.com/accessing-and-using-certificate-private-keys-in-net-framework-net-core/
                        _ = authCert.GetRSAPrivateKey();
                        _ = authCert.GetDSAPrivateKey();
                        _ = authCert.GetECDsaPrivateKey();
                    }
                    catch
                    {
                        errors.Add("The service user cannot access the authentication certificate's private key.");
                    }
                }
            }

            EntrustClient client = new EntrustClient(username, password, authCert);
            try
            {
                List<ClientInfo> clients = client.GetClients();
                if (clients.Count <= 0)
                {
                    errors.Add($"Checking clients to determine Entrust connection failed.");
                }
            }
            catch (Exception e)
            {
                errors.Add($"An error occured when trying to connect to Entrust. {e.Message}");
            }
            Logger.Trace("Leaving 'ValidateCAConnectionInfo' method.");

            // We cannot proceed if there are any errors.
            if (errors.Any())
            {
                ThrowValidationException(errors);
            }
        }

        /// <summary>
        /// Validates that the product information for the CA is correct.
        /// </summary>
        /// <param name="productInfo">The product information.</param>
        public override void ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            string productId = productInfo.ProductID;
            EntrustClient client = CreateEntrustClient(connectionInfo);
            Logger.Trace("Checking inventory");

            bool inventory = EntrustCertType.ProductIDValid(client, productId);
            if (!inventory)
            {
                throw new Exception($"The product ID '{productId}' could not be validated.");
            }
            else
            {
                Logger.Trace($"Validation for product ID '{productId}' successful");
            }
        }

        #endregion ICAConnector Methods

        #region ICAConnectorConfigInfoProvider Methods

        /// <summary>
        /// Returns the default CA connector section of the config file.
        /// </summary>
        public Dictionary<string, object> GetDefaultCAConnectorConfig()
        {
            Dictionary<string, string> clientCert = new Dictionary<string, string>()
            {
                { EntrustConstants.STORE_NAME, "" },
                { EntrustConstants.STORE_LOCATION, "" },
                { EntrustConstants.THUMBPRINT, "" }
            };
            return new Dictionary<string, object>()
            {
                { EntrustConstants.USERNAME, "" },
                { EntrustConstants.PASSWORD, "" },
                { EntrustConstants.CLIENT_CERTIFICATE, clientCert },
                { EntrustConstants.NAME, "TestUser" },
                { EntrustConstants.EMAIL, "email@email.invalid" },
                { EntrustConstants.CONFIG_NUMBER, "0000000000" }
            };
        }

        /// <summary>
        /// Gets the default comment on the default product type.
        /// </summary>
        /// <returns></returns>
        public string GetProductIDComment()
        {
            try
            {
                if (ConfigProvider == null)
                {
                    Logger.Info($"No configuration provided. Returning all product types, which are: {string.Join(", ", EntrustCertType.AllTypes.Select(x => x.ShortName))}");
                    return $"Available Entrust product types are: {string.Join(", ", EntrustCertType.AllTypes.Select(x => x.ShortName))}.\nNote: some of these product types may not be available to your account.";
                }

                EntrustClient client = CreateEntrustClient(ConfigProvider.CAConnectionData);

                List<CABaseCertType> certTypes = EntrustCertType.GetCustomerAccountTypes(client);
                if (certTypes == null || !certTypes.Any())
                {
                    throw new Exception("No product types were received from Entrust.");
                }

                Logger.Info($"Returning available product types, which are: {string.Join(", ", certTypes.Select(x => x.ShortName))}.");
                return $"Available Entrust product types are: {string.Join(", ", certTypes.Select(x => x.ShortName))}.";
            }
            catch (Exception e)
            {
                Logger.Info($"There was an error getting the product ID comment: {e.Message}");
                return $"Available Entrust product types are: {string.Join(", ", EntrustCertType.AllTypes.Select(x => x.ShortName))}.\nNote: some of these product types may not be available to your account.";
            }
        }

        /// <summary>
        /// Gets annotations for the CA connector properties.
        /// </summary>
        /// <returns></returns>
        public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>()
            {
                [EntrustConstants.PASSWORD] = new PropertyConfigInfo()
                {
                    Comments = "Account Password",
                    Hidden = true,
                    DefaultValue = ""
                }
            };
        }

        /// <summary>
        /// Gets annotations for the template mapping parameters.
        /// </summary>
        /// <returns></returns>
        public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets default template map parameters for Entrust product types.
        /// </summary>
        /// <returns></returns>
        public Dictionary<string, string> GetDefaultTemplateParametersConfig()
        {
            throw new NotImplementedException();
        }

        #endregion ICAConnectorConfigInfoProvider Methods

        #region Helpers

        /// <summary>
        /// Throws an exception with the concatenated errors.
        /// </summary>
        /// <param name="errors">The errors we want to see in the exception.</param>
        private void ThrowValidationException(List<string> errors)
        {
            throw new Exception(string.Join("\n", errors));
        }

        /// <summary>
        /// Creates a REST client for the Entrust API.
        /// </summary>
        /// <param name="connectionInfo">The information we need to create the client.</param>
        /// <returns></returns>
        private EntrustClient CreateEntrustClient(Dictionary<string, object> connectionInfo)
        {
            string username = connectionInfo.ContainsKey(EntrustConstants.USERNAME) ? (string)connectionInfo[EntrustConstants.USERNAME] : string.Empty;

            string password = connectionInfo.ContainsKey(EntrustConstants.PASSWORD) ? (string)connectionInfo[EntrustConstants.PASSWORD] : string.Empty;

            Dictionary<string, object> clientCertificate = (Dictionary<string, object>)connectionInfo[EntrustConstants.CLIENT_CERTIFICATE];

            Logger.Trace("Checking for authentication certificate.");
            StoreLocation storeLocation = (StoreLocation)Enum.Parse(typeof(StoreLocation), (string)clientCertificate[EntrustConstants.STORE_LOCATION]);
            GatewayCertificate finder = new GatewayCertificate();
            X509Certificate2 authCert = finder.FindGatewayCertificate((string)clientCertificate[EntrustConstants.STORE_NAME], storeLocation, (string)clientCertificate[EntrustConstants.THUMBPRINT]);
            EntrustClient client = new EntrustClient(username, password, authCert);
            return client;
        }

        /// <summary>
        /// Converts the Entrust string status into a RequestDisposition integer.
        /// </summary>
        /// <param name="status">The string status received from Entrust.</param>
        /// <returns></returns>
        private int ConvertStatus(string status)
        {
            switch (status.ToLower())
            {
                case "active":
                case "ready":
                case "reissued":
                case "renewed":
                case "expired":
                    return (int)RequestDisposition.ISSUED;
                case "pending":
                    return (int)RequestDisposition.PENDING;
                case "deactivated":
                case "suspended":
                case "revoked":
                    return (int)RequestDisposition.REVOKED;
                case "declined":
                    return (int)RequestDisposition.DENIED;
                default:
                    return (int)RequestDisposition.UNKNOWN;
            }
        }

        /// <summary>
        /// Gets a single record by its tracking ID.
        /// </summary>
        /// <param name="client">The Entrust REST API client.</param>
        /// <param name="trackingId">The tracking ID of the cert we want.</param>
        /// <returns></returns>
        private CAConnectorCertificate GetSingleRecord(EntrustClient client, int trackingId)
        {
            CertificateExt entrustCertDetail = client.GetCertificateByTrackingId(trackingId);
            string noHeaders = !string.IsNullOrEmpty(entrustCertDetail.EndEntityCert) ? ConfigurationUtils.OnlyBase64CertContent(entrustCertDetail.EndEntityCert) : null;
            CAConnectorCertificate newCert = new CAConnectorCertificate
            {
                CARequestID = trackingId.ToString(),
                Certificate = noHeaders,
                Status = ConvertStatus(entrustCertDetail.Status),
                SubmissionDate = entrustCertDetail.IssueDateTime,
                CSR = !string.IsNullOrEmpty(entrustCertDetail.Csr) ? ConfigurationUtils.OnlyBase64CertContent(entrustCertDetail.Csr) : null,
                Requester = entrustCertDetail.Tracking.RequesterName,
                RevocationDate = entrustCertDetail.Tracking.Deactivated ? entrustCertDetail.Tracking.DeactivatedOn ?? DateTime.UtcNow : (DateTime?)null
            };
            return newCert;
        }

        /// <summary>
        /// Gets a single record by its thumbprint.
        /// </summary>
        /// <param name="client">The Entrust REST API client.</param>
        /// <param name="thumbprint">The thumbprint of the cert we want.</param>
        /// <returns></returns>
        private CAConnectorCertificate GetSingleRecord(EntrustClient client, string thumbprint)
        {
            CertificateExt entrustCertDetail = client.GetCertificateByThumbprint(thumbprint);
            string noHeaders = !string.IsNullOrEmpty(entrustCertDetail.EndEntityCert) ? ConfigurationUtils.OnlyBase64CertContent(entrustCertDetail.EndEntityCert) : null;
            CAConnectorCertificate newCert = new CAConnectorCertificate
            {
                CARequestID = $"0-{thumbprint}",
                Certificate = noHeaders,
                Status = entrustCertDetail.Status.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase) ? (int)RequestDisposition.FOREIGN_CERT : ConvertStatus(entrustCertDetail.Status),
                SubmissionDate = entrustCertDetail.IssueDateTime,
                CSR = !string.IsNullOrEmpty(entrustCertDetail.Csr) ? ConfigurationUtils.OnlyBase64CertContent(entrustCertDetail.Csr) : null,
                Requester = entrustCertDetail.Tracking.RequesterName,
                RevocationDate = entrustCertDetail.Tracking.Deactivated ? entrustCertDetail.Tracking.DeactivatedOn ?? DateTime.UtcNow : (DateTime?)null
            };
            return newCert;
        }

        /// <summary>
        /// Returns the tracking ID of the prior certificate.
        /// </summary>
        /// <param name="client">The <see cref="EntrustClient"/> contacts the Entrust API.</param>
        /// <param name="enrollmentProductInfo">Contains information required to retrieve the tracking ID.</param>
        /// <returns></returns>
        private int GetTrackingId(EntrustClient client, EnrollmentProductInfo enrollmentProductInfo)
        {
            if (enrollmentProductInfo.ProductParameters.ContainsKey("priorcertsn"))
            {
                //get prior cert serial number
                string attrPriorCertSN = enrollmentProductInfo.ProductParameters["priorcertsn"];

                //requesting certificate by serial number  
                Certificate priorCertTemp = client.GetCertificateBySerialNumber(attrPriorCertSN);
                if (priorCertTemp != null)
                {
                    return priorCertTemp.TrackingId;
                }
                else
                {
                    Logger.Trace($"No certificate found with serial number {enrollmentProductInfo.ProductParameters["priorcertsn"]}.");
                }
            }

            throw new Exception($"Reissue requested, but certificate with serial number {enrollmentProductInfo.ProductParameters["priodcertsn"]} not found.");
        }

        /// <summary>
        /// Return the thumbprint of a certificate we received from Entrust.
        /// </summary>
        /// <param name="entrustCert">The Entrust certificate we want to get the thumbprint of.</param>
        /// <returns></returns>
        private string GetThumbprint(Certificate entrustCert)
        {
            // It seems as if this URL is the only place we can actually get the thumbprint.
            if (entrustCert.URI.Contains("/thumbprints/"))
            {
                string[] parts = entrustCert.URI.Split(new string[] { "/thumbprints/" }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 1)
                {
                    // Trim just in case some URIs come back with trailing slash.
                    return parts.Last().Trim('/').ToUpper();
                }
            }

            // If the URL doesn't contain thumbprint, we return nothing.
            return null;
        }

        /// <summary>
        /// Approves a pending cert and returns the status and status message .
        /// </summary>
        /// <param name="client">The <see cref="EntrustClient"/> contacts the Entrust API.</param>
        /// <param name="trackingId">Tracking ID of certificate being approved.</param>
        /// <returns></returns>
        private ValueTuple<int, string> ApproveCert(int trackingId, EntrustClient client)
        {
            CertificateResponse approveResult = client.ApproveCertificate(trackingId);
            CertificateExt changedCert = client.GetCertificateByTrackingId(trackingId);
            int newStatus = ConvertStatus(changedCert.Status);

            if (newStatus == (int)RequestDisposition.PENDING)
            {
                return ((int)RequestDisposition.EXTERNAL_VALIDATION, $"Certificate with trackingId {trackingId} is still pending after approval attempt. External validation is required.");
            }
            else if (newStatus == (int)RequestDisposition.ISSUED)
            {
                return (newStatus, $"Certificate with trackingId {trackingId} has been issued after Entrust returned it with a pending status.");
            }

            return ((int)RequestDisposition.UNKNOWN, $"Attempted to approve certificate with trackingId {trackingId}. Status is neither issued or pending. ");
        }

        #endregion Helpers
    }
}
