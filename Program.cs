using System;
using Azure.Core;
using Azure.Identity;
using Microsoft.Azure.Services.AppAuthentication;
using System.Threading;
using System.IO;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Microsoft.Data.SqlClient;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;

namespace MSITokenTest
{
    class Program
    {
        private const string expiry = "expires_on";
        private const string azureSqlResourceId = "https://database.windows.net/";

        static void Main(string[] args)
        {
            string connectionString = Environment.GetEnvironmentVariable("MSI_TEST_CONN_STRING");
            string[] accessTokens = new string[3];

            while (true)
            {
                accessTokens[0] = GetAccessTokenFromIMDS();
                accessTokens[1] = GetAccessTokenFromAppAuth();
                accessTokens[2] = GetAccessTokenFromAzureIdentity();

                for (int i = 0; i < accessTokens.Length; i++)
                {
                    try
                    {
                        using (SqlConnection conn = new SqlConnection(connectionString))
                        {
                            conn.AccessToken = accessTokens[i];
                            conn.Open();
                            Console.WriteLine(DateTime.UtcNow + $" Connected with Access token from {GetProvider(i)}");
                            using (SqlCommand cmd = conn.CreateCommand())
                            {
                                cmd.CommandText = "SELECT @@VERSION";
                                using (var reader = cmd.ExecuteReader())
                                {
                                    while (reader.Read())
                                    {
                                        Console.WriteLine(DateTime.UtcNow + " " + reader.GetValue(0));
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(DateTime.UtcNow + " " + e.ToString());
                        Console.WriteLine(DateTime.UtcNow + $" ACCESS TOKEN PROVIDER: {GetProvider(i)}");
                        Console.WriteLine(DateTime.UtcNow + " " + accessTokens[i]);
                        PrintAccessTokenExpiry(accessTokens[i]);
                    }
                }
                Thread.Sleep(5 * 60 * 1000);
            }
        }

        private static string GetProvider(int i)
        {
            switch (i)
            {
                case 0: return "IMDS Service";
                case 1: return "App Auth Library";
                case 2: return "Azure Identity";
            }
            return null;
        }

        private static string GetAccessTokenFromIMDS()
        {
            // Build request to acquire managed identities for Azure resources token
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://database.windows.net/");
            request.Headers["Metadata"] = "true";
            request.Method = "GET";

            try
            {
                // Call /token endpoint
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();

                // Pipe response Stream to a StreamReader, and extract access token
                StreamReader streamResponse = new StreamReader(response.GetResponseStream());
                string stringResponse = streamResponse.ReadToEnd();
                var imdsAccessToken = stringResponse.Substring(17, stringResponse.IndexOf('"', 17) - 17);
                var expiresin = stringResponse.Substring(stringResponse.IndexOf(expiry) + expiry.Length + 3, 10);
                var expiryTime = DateTime.UnixEpoch.AddSeconds(long.Parse(expiresin));
                Console.WriteLine(DateTime.UtcNow + $" ******** IMDS ********");
                PrintAccessTokenExpiry(imdsAccessToken);
                Console.WriteLine(DateTime.UtcNow + $" IMDS Expires On: " + expiryTime);
                Console.WriteLine(DateTime.UtcNow + $" ********************");
                return imdsAccessToken;
            }
            catch (Exception e)
            {
                string errorText = String.Format("{0} \n\n{1}", e.Message, e.InnerException != null ? e.InnerException.Message : "Acquire token failed");
                Console.WriteLine(DateTime.UtcNow + " " + e.Message);
                return null;
            }
        }

        private static string GetAccessTokenFromAppAuth()
        {
            var token = new AzureServiceTokenProvider().GetAccessTokenAsync(azureSqlResourceId).GetAwaiter().GetResult();

            Console.WriteLine(DateTime.UtcNow + $" ******** App Auth Library ********");
            PrintAccessTokenExpiry(token);
            Console.WriteLine(DateTime.UtcNow + $" ********************");

            return token;
        }

        private static string GetAccessTokenFromAzureIdentity()
        {
            var tokenCredential = new DefaultAzureCredential();
            var context = new TokenRequestContext(new string[] { azureSqlResourceId });
            var token = tokenCredential.GetTokenAsync(context).GetAwaiter().GetResult();

            Console.WriteLine(DateTime.UtcNow + $" ******** Azure Identity Library ********");
            PrintAccessTokenExpiry(token.Token);
                Console.WriteLine(DateTime.UtcNow + $" Azure Identity Expires On: " + token.ExpiresOn);
            Console.WriteLine(DateTime.UtcNow + $" ********************");

            return token.Token;
        }

        private static void PrintAccessTokenExpiry(string accessToken)
        {
            var payload = JObject.Parse(ReadToken(accessToken)).GetValue("Payload");
            Console.Out.WriteLine(DateTime.UtcNow + $" JWT Token Expires On:  " + DateTime.UnixEpoch.AddSeconds((long)payload[4]["Value"]));
        }
        public static string ReadToken(string jwtInput)
        {
            var jwtHandler = new JwtSecurityTokenHandler();
            var jwtOutput = string.Empty;

            // Check Token Format
            if (!jwtHandler.CanReadToken(jwtInput)) throw new Exception("The token doesn't seem to be in a proper JWT format.");

            var token = jwtHandler.ReadJwtToken(jwtInput);

            // Re-serialize the Token Headers to just Key and Values
            var jwtHeader = JsonConvert.SerializeObject(token.Header.Select(h => new { h.Key, h.Value }));
            jwtOutput = $"{{\r\n\"Header\":\r\n{JToken.Parse(jwtHeader)},";

            // Re-serialize the Token Claims to just Type and Values
            var jwtPayload = JsonConvert.SerializeObject(token.Claims.Select(c => new { c.Type, c.Value }));
            jwtOutput += $"\r\n\"Payload\":\r\n{JToken.Parse(jwtPayload)}\r\n}}";

            // Output the whole thing to pretty Json object formatted.
            return JToken.Parse(jwtOutput).ToString(Formatting.Indented);
        }
    }
}
