using HMACAuthenticationSample.Api.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HMACAuthenticationSample.Client
{
    class Program
    {
        static void Main(string[] args)
        {

            HttpClient client = new HttpClient();

            client.BaseAddress = new Uri("http://localhost:58479/");

            //GET Request
            var header = GetHeader("GET", "http://localhost:58479/api/item/get", null);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("TestAuthScheme", header);
            var response = client.GetAsync("api/item/get").Result.Content.ReadAsStringAsync().Result;
            Console.WriteLine($"GET Response : {response}");

            //POST Request
            var item = new Item() { Id = 2, Name = "TestPostItem" };
            var json = JsonConvert.SerializeObject(item);
            header = GetHeader("POST", "http://localhost:58479/api/item/post", json);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("TestAuthScheme", header);
            var stringContent = new StringContent(json, Encoding.UTF8, "application/json");
            response = client.PostAsync("api/item/post", stringContent).Result.Content.ReadAsStringAsync().Result;
            Console.WriteLine($"POST Response : {response}");

            Console.ReadLine();

        }

        private static string GetHeader(string requestHttpMethod, string requestUri, string content)
        {

            string appId = "ec77a717328c411899deee01735bf90f";

            DateTime epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            int requestTimeStamp = Convert.ToInt32((DateTime.UtcNow - epochStart).TotalSeconds);

            string nonce = Guid.NewGuid().ToString();
            byte[] contentHash = GetSHA256Hash(content);
            //get Base64 string from the content if hash is not null.
            string requestContent = contentHash != null ? Convert.ToBase64String(contentHash) : string.Empty;

            string signatureData = $"{appId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContent}";
            //get the signature data in bytes
            byte[] signatureDataBytes = Encoding.UTF8.GetBytes(signatureData);

            string secretKey = "n9waAyo4xDsdVKi1i1kjXlHguo3/+qKwEUnRiJYMFA3d8A0Uj+/cVq89kCbjBeyhZ0fQ1084kZCyp3WxQ9Xxpg==";
            //get the secret key in bytes
            byte[] secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);

            string signature;
            using (HMACSHA256 hmac = new HMACSHA256(secretKeyBytes))
            {
                byte[] computedSignatureHash = hmac.ComputeHash(signatureDataBytes);
                signature = $"{appId}:{Convert.ToBase64String(computedSignatureHash)}:{nonce}:{requestTimeStamp}";
            }
            return signature;
        }


        private static byte[] GetSHA256Hash(string contentString)
        {
            if (string.IsNullOrEmpty(contentString))
            {
                return null;
            }

            using (SHA256 sha256hash = SHA256.Create())
            {
                byte[] hash = null;
                //get the content as byte array
                var content = Encoding.UTF8.GetBytes(contentString);
                //if content is available
                if (content.Length != 0)
                {
                    //compute the hash
                    hash = sha256hash.ComputeHash(content);
                }
                return hash;
            }
        }
    }
}
