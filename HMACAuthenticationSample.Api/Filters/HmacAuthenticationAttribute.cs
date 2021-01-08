using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Caching;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Filters;
using System.Web.Http.Results;

namespace HMACAuthenticationSample.Api.Filters
{
    public class HmacAuthenticationAttribute : Attribute, IAuthenticationFilter
    {
        public bool AllowMultiple => false;

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            //try to get identity principle
            GenericPrincipal principal = TryGetIdentityPrincipal(context.Request);
            //if authenticated and principle is returned
            if (principal != null)
            {
                context.Principal = principal;
            }
            else
            {
                //no identity principle is created, unauthorized request
                context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
            }
            return Task.FromResult(0);

        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            context.Result = new ResultWithChallenge(context.Result);
            return Task.FromResult(0);
        }

        #region Private Methds

        /// <summary>
        /// Gets identity principle.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns>identity principle if request is authenticated, null otherwise</returns>
        private GenericPrincipal TryGetIdentityPrincipal(HttpRequestMessage request)
        {

            GenericPrincipal principal = null;
            string authenticationScheme = ConfigurationManager.AppSettings["authenticationScheme"];

            //check if authrization header is available and authorization scheme is the expected value
            if (request.Headers.Authorization != null && request.Headers.Authorization.Scheme.Equals(authenticationScheme, StringComparison.OrdinalIgnoreCase))
            {
                //extract the values from authorization header
                var autherizationHeaderArray = ExtractAutherizationHeaderValues(request.Headers.Authorization.Parameter);
                //if authorization header has four distinct values
                //assign the values to variables
                if (autherizationHeaderArray != null)
                {
                    var appId = autherizationHeaderArray[0];
                    var signature = autherizationHeaderArray[1];
                    var nonce = autherizationHeaderArray[2];
                    var requestTimeStamp = autherizationHeaderArray[3];
                    //check if the request is authenticated
                    if (IsAuthenticated(request, appId, signature, nonce, requestTimeStamp))
                    {
                        //create a identity principle for app id
                        principal = new GenericPrincipal(new GenericIdentity(appId), null);
                    }
                }
            }
            return principal;
        }

        /// <summary>
        /// Extracts the autherization header values.
        /// </summary>
        /// <param name="authorizationHeader">The authorization header.</param>
        /// <returns>4 authorization header values. If the header contains more or less number of values it will return null</returns>
        private string[] ExtractAutherizationHeaderValues(string authorizationHeader)
        {
            var credentialArray = authorizationHeader.Split(':');

            if (credentialArray.Length == 4)
            {
                return credentialArray;
            }
            return null;
        }

        private bool IsAuthenticated(HttpRequestMessage request, string appId, string requestSignature, string nonce, string requestTimeStamp)
        {
            bool isAuthenticated = false;
            //check if  request is not a replay attack
            if (!IsReplayRequest(appId, nonce, requestTimeStamp))
            {
                //compute signature to match with request signature
                //hash  request content
                string contentJson = request.Content.ReadAsStringAsync().Result;
                byte[] contentHash = GetSHA256Hash(contentJson);
                //get Base64 string from the content if hash is not null.
                string requestContent = contentHash != null ? Convert.ToBase64String(contentHash) : string.Empty;
                //get the request uri in lower case
                string requestUri = request.RequestUri.AbsoluteUri.ToLower();
                //get the request method (GET/POST etc..)
                string requestHttpMethod = request.Method.Method.ToUpper();
                //populate the string to be converted to signature
                //should contain appId, requestHttpMethod, requestUri, requestTimeStamp, nonce and request content in the given order
                string signatureData = $"{appId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContent}";
                //get the signature data in bytes
                byte[] signatureDataBytes = Encoding.UTF8.GetBytes(signatureData);
                //get the secret key
                string secretKey = ConfigurationManager.AppSettings["appSecret"];
                //get the secret key in bytes
                byte[] secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);
                //compute hmac hash using the secret key
                using (HMACSHA256 hmac = new HMACSHA256(secretKeyBytes))
                {
                    byte[] computedSignatureHash = hmac.ComputeHash(signatureDataBytes);
                    string serverSignatire = Convert.ToBase64String(computedSignatureHash);
                    //check computed signature hash and request signature are equal
                    if (serverSignatire.Equals(requestSignature, StringComparison.OrdinalIgnoreCase))
                    {
                        //hases are matching
                        isAuthenticated = true;
                    }
                }
            }
            return isAuthenticated;
        }

        /// <summary>
        /// Determines whether the request is a replay request.
        /// </summary>
        /// <param name="nonce">The nonce.</param>
        /// <param name="requestTimeStamp">The request time stamp.</param>
        /// <param name="appId">The appId given to the app.</param>
        /// <returns>
        ///   <c>true</c> if [is replay request] [the specified nonce]; otherwise, <c>false</c>.
        /// </returns>
        private bool IsReplayRequest(string appId, string nonce, string requestTimeStamp)
        {
            bool isReplayRequest = false;

            string cacheNonce = $"{appId}{nonce}";

            //get server Unix time stamp
            DateTime epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            int serverTimeStamp = Convert.ToInt32((DateTime.UtcNow - epochStart).TotalSeconds);
            //convert client time stamp into int
            int clientTimeStamp = Convert.ToInt32(requestTimeStamp);
            //get the time stamp difference
            int timeStampDifference = serverTimeStamp - clientTimeStamp;
            //get the configured request expiration time
            int requestExpirationTime = Convert.ToInt32(ConfigurationManager.AppSettings["requestExpirationTime"]);
            bool nonceInCache = MemoryCache.Default.Contains(cacheNonce);
            //check if nonce already available in memory cache and time stamp is valid
            if (!nonceInCache && timeStampDifference <= requestExpirationTime)
            {
                //if nonce is not available
                MemoryCache.Default.Add(cacheNonce, requestTimeStamp, DateTimeOffset.UtcNow.AddSeconds(requestExpirationTime));
            }
            else
            {
                //replay request
                isReplayRequest = true;
            }
            return isReplayRequest;
        }

        /// <summary>
        /// Gets the sha256 hash.
        /// </summary>
        /// <param name="httpContent">httpContent.</param>
        /// <returns>sha256 hash value in bytes</returns>
        private byte[] GetSHA256Hash(string contentJson)
        {
            using (SHA256 sha256hash = SHA256.Create())
            {
                byte[] hash = null;
                //get the content as byte array
                var content = Encoding.UTF8.GetBytes(contentJson);
                //if content is available
                if (content.Length != 0)
                {
                    //compute the hash
                    hash = sha256hash.ComputeHash(content);
                }
                return hash;
            }
        }

        #endregion Private Methds
    }
}