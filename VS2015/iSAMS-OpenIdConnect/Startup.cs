using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(iSAMS_OpenIdConnect.Startup))]

namespace iSAMS_OpenIdConnect
{
    public class Startup
    {
        private const string Authority = Domain + "/auth";

        private const string Domain = "https://developerdemo.isams.cloud"; // <= your_host_here (without a trailing /)

        private const string ClientId = "isams.oidc.demo"; // <= your_client_id_here

        private const string ClientSecret = "40019D7D-7641-4A54-9F8C-9FF08AEC0614"; // <= your_client_secret_here

        // Set required response type(s), see https://developer.isams.com/docs/getting-started-single-sign-on#section-single-sign-on
        private const string ResponseType = "code id_token token";

        // Add required scopes, see https://developer.isams.com/docs/scopes
        private const string ScopesCsv = "openid,email,profile";

        public void Configuration(IAppBuilder app)
        {
            var redirectUri = "http://localhost:52102/signin-oidc";
            var postLogoutRedirectUri = "http://localhost:52102/signout-callback-oidc";

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = Authority,
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                PostLogoutRedirectUri = postLogoutRedirectUri,
                RedirectUri = redirectUri,
                RequireHttpsMetadata = false,
                ResponseType = ResponseType,
                // Add required scopes, see https://developer-beta.isams.com/docs/scopes
                Scope = ScopesCsv.Replace(",", " "),
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name"
                },

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = async n =>
                    {
                        // Exchange code for access and ID tokens
                        var tokenClient = new TokenClient(Authority + "/connect/token", ClientId, ClientSecret);
                        var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(n.Code, redirectUri);

                        if (tokenResponse.IsError)
                        {
                            throw new Exception(tokenResponse.Error);
                        }

                        var userInfoClient = new UserInfoClient(Authority + "/connect/userinfo");
                        var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);
                        var claims = new List<Claim>();
                        claims.AddRange(userInfoResponse.Claims);
                        claims.Add(new Claim("id_token", tokenResponse.IdentityToken));
                        claims.Add(new Claim("access_token", tokenResponse.AccessToken));

                        if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
                        {
                            claims.Add(new Claim("refresh_token", tokenResponse.RefreshToken));
                        }

                        n.AuthenticationTicket.Identity.AddClaims(claims);
                    },

                    RedirectToIdentityProvider = n =>
                    {
                        // If signing out, add the id_token_hint
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var idTokenClaim = n.OwinContext.Authentication.User.FindFirst("id_token");

                            if (idTokenClaim != null)
                            {
                                n.ProtocolMessage.IdTokenHint = idTokenClaim.Value;
                            }
                        }

                        return Task.CompletedTask;
                    }
                }
            });
        }
    }
}