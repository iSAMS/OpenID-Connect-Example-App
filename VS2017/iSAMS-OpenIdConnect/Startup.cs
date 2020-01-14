using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

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

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            // OpenIDConnect authentication event handling.
            services.AddTransient<AuthenticationEvents, AuthenticationEvents>();

            // Allow claims to pass through without being changed by Microsoft.
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            // Add cookie authentication under the default authentication scheme.
            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                })
                .AddCookie()
                .AddOpenIdConnect(options =>
                {
                    options.Authority = Authority;
                    options.ClientId = ClientId;
                    options.ClientSecret = ClientSecret;
                    options.RequireHttpsMetadata = false;
                    options.ResponseType = ResponseType;

                    // Add required scopes, see https://developer.isams.com/docs/scopes
                    options.Scope.Clear();
                    foreach (var scope in ScopesCsv.Split(',', StringSplitOptions.RemoveEmptyEntries))
                    {
                        options.Scope.Add(scope);
                    }

                    // Save tokens for future use.
                    options.SaveTokens = true;

                    // Have the authentication provider gather claims for us
                    options.GetClaimsFromUserInfoEndpoint = true;

                    options.EventsType = typeof(AuthenticationEvents);
                });
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            // Standard configuration.
            app.UseDeveloperExceptionPage();
            app.UseBrowserLink();

            // Authentication MUST be added before MVC or the user context will not be created
            // before the request reaches the application.
            app.UseAuthentication();

            app.UseStaticFiles();
            app.UseMvc(routes => { routes.MapRoute("default", "{controller=Home}/{action=Index}/{id?}"); });
        }
    }
}