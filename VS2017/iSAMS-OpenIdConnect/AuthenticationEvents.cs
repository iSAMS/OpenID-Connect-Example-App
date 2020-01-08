using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json.Linq;

namespace iSAMS_OpenIdConnect
{
    public class AuthenticationEvents : OpenIdConnectEvents
    {
        public override Task RedirectToIdentityProvider(RedirectContext context)
        {
            // When redirecting to the identity provider, give the id_token as an identity hint.
            // This helps the iSAMS Authentication Server know which user it is dealing with.
            if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
            {
                var idTokenHint = context.HttpContext.User.FindFirst("id_token");
                if (idTokenHint != null) context.ProtocolMessage.IdTokenHint = idTokenHint.Value;
            }

            return base.RedirectToIdentityProvider(context);
        }

        public override Task TokenValidated(TokenValidatedContext context)
        {
            DecodeAndWrite(context.ProtocolMessage.IdToken);
            DecodeAndWrite(context.ProtocolMessage.AccessToken);

            return base.TokenValidated(context);
        }

        /// <summary>
        ///     Decodes a token and writes it into the debug window.
        /// </summary>
        /// <param name="token">The JWT Token</param>
        private static void DecodeAndWrite(string token)
        {
            try
            {
                var parts = token.Split('.');

                var partToConvert = parts[1];
                partToConvert = partToConvert.Replace('-', '+');
                partToConvert = partToConvert.Replace('_', '/');
                switch (partToConvert.Length % 4)
                {
                    case 0:
                        break;
                    case 2:
                        partToConvert += "==";
                        break;
                    case 3:
                        partToConvert += "=";
                        break;
                }

                var partAsBytes = Convert.FromBase64String(partToConvert);
                var partAsUtf8String = Encoding.UTF8.GetString(partAsBytes, 0, partAsBytes.Count());

                // Json .NET
                var jwt = JObject.Parse(partAsUtf8String);

                // Write to output
                Debug.Write(jwt.ToString());
            }
            catch (Exception ex)
            {
                // something went wrong
                Debug.Write(ex.Message);
            }
        }
    }
}