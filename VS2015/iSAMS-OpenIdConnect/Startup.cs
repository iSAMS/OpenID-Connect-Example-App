using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(iSAMS_OpenIdConnect.Startup))]

namespace iSAMS_OpenIdConnect
{
    public class Startup
    {
        public const string IsamsDomain = "https://isams.local"; // <= your_host_here (without a trailing /)

        public const string ThisDomain = "http://localhost:52102"; // <= this_host_here (without a trailing /)

        private const string Authority = IsamsDomain + "/auth";

        private const string ClientId = "isams.oidc.demo"; // <= your_client_id_here

        private const string ClientSecret = "40019D7D-7641-4A54-9F8C-9FF08AEC0614"; // <= your_client_secret_here (not recommended to hard-code your secret)

        // Set required response type(s), see https://developer.isams.com/docs/getting-started-single-sign-on#section-single-sign-on
        private const string ResponseType = OpenIdConnectResponseType.CodeIdTokenToken;

        // Add required scopes, see https://developer.isams.com/docs/scopes
        private const string ScopesCsv = OpenIdConnectScope.OpenIdProfile + "," + OpenIdConnectScope.Email;

        public void Configuration(IAppBuilder app)
        {
            var redirectUri = $"{ThisDomain}/signin-oidc";
            var postLogoutRedirectUri = $"{ThisDomain}/";

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                CookieSecure = CookieSecureOption.Never, // <= Not recommended to use in Production code because you should enforce secure cookies.
                CookieManager = new SystemWebChunkingCookieManager()
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = Authority,
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                PostLogoutRedirectUri = postLogoutRedirectUri,
                RedirectUri = redirectUri,
                RequireHttpsMetadata = false,
                ResponseType = ResponseType,
                // Add required scopes, see https://developer.isams.com/docs/scopes
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
                        claims.Add(new Claim(OidcConstants.TokenTypes.IdentityToken, tokenResponse.IdentityToken));
                        claims.Add(new Claim(OidcConstants.TokenTypes.AccessToken, tokenResponse.AccessToken));

                        if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
                        {
                            claims.Add(new Claim(OidcConstants.TokenTypes.RefreshToken, tokenResponse.RefreshToken));
                        }

                        n.AuthenticationTicket.Identity.AddClaims(claims);
                    },

                    RedirectToIdentityProvider = n =>
                    {
                        // If signing out, add the id_token_hint
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var idTokenClaim =
                                n.OwinContext.Authentication.User.FindFirst(OidcConstants.TokenTypes.IdentityToken);

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