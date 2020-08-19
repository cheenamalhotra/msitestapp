using System;
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
        /// <summary>
        /// Runs test application with connection string in argument.
        /// </summary>
        /// <param name="args">args[0] Connection string</param>
        static void Main(string[] args)
        {
            if(args.Length < 1)
            {
                throw new ArgumentException("Please provide connection string in argument.")
            }

            string accessToken = null;
            string expiry = "expires_on";

            while (true)
            {
                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                var tempAccessToken = azureServiceTokenProvider.GetAccessTokenAsync("https://database.windows.net/").GetAwaiter().GetResult();
                if (accessToken != tempAccessToken)
                {
                    Console.WriteLine(DateTime.UtcNow + " | NEW ACCESS TOKEN RECEIVED BY AZURE APP AUTH");
                    PrintAccessTokenExpiry(tempAccessToken);
                    accessToken = tempAccessToken;
                }

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
                    if (accessToken != imdsAccessToken)
                    {
                        Console.WriteLine("ATTENTION! DIFFERENT ACCESS TOKEN RECEIVED FROM IMDS");
                        Console.WriteLine("Azure Identity Access Token:");
                        PrintAccessTokenExpiry(accessToken);
                        Console.WriteLine("IMDS Access Token:");
                        PrintAccessTokenExpiry(imdsAccessToken);
                    }
                    var expiresin = stringResponse.Substring(stringResponse.IndexOf(expiry) + expiry.Length + 3, 10);
                    var expiryTime = DateTime.UnixEpoch.AddSeconds(long.Parse(expiresin));
                    Console.WriteLine("********IMDS********");
                    PrintAccessTokenExpiry(imdsAccessToken);
                    Console.WriteLine("IMDS Expires On: " + expiryTime);
                    Console.WriteLine("********************");
                }
                catch (Exception e)
                {
                    string errorText = String.Format("{0} \n\n{1}", e.Message, e.InnerException != null ? e.InnerException.Message : "Acquire token failed");
                    Console.WriteLine(e.Message);
                }

                using (SqlConnection conn = new SqlConnection(args[0]))
                {
                    conn.AccessToken = accessToken;
                    conn.Open();
                    Console.WriteLine(DateTime.UtcNow + " | Pooling: no | " + "Connected");
                    using (SqlCommand cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = "SELECT @@VERSION";
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                Console.WriteLine(reader.GetValue(0));
                            }
                        }
                    }
                }
                Thread.Sleep(5 * 60 * 1000);
            }
        }

        private static void PrintAccessTokenExpiry(string accessToken)
        {
            var payload = JObject.Parse(ReadToken(accessToken)).GetValue("Payload");
            Console.Out.WriteLine($"JWT Expires On:  " + DateTime.UnixEpoch.AddSeconds((long)payload[4]["Value"]));
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
