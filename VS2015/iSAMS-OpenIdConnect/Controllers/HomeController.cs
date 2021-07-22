using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using IdentityModel;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;

namespace iSAMS_OpenIdConnect.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View("Index");
        }

        [Authorize]
        public ActionResult Claims()
        {
            return View("Claims");
        }

        public ActionResult Logout()
        {
            HttpContext.GetOwinContext().Authentication.SignOut(OpenIdConnectAuthenticationDefaults.AuthenticationType,
                CookieAuthenticationDefaults.AuthenticationType);
            return Index();
        }

        [Authorize]
        public async Task<ActionResult> MakeApiCall()
        {
            using (var httpClient = new HttpClient())
            {
                httpClient.BaseAddress = new Uri(Startup.IsamsDomain);

                httpClient.DefaultRequestHeaders.Accept.Clear();
                httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var identityClaims = ClaimsPrincipal.Current.Identities.First().Claims;
                var accessToken = identityClaims.First(x => x.Type == OidcConstants.TokenTypes.AccessToken).Value;
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                var httpRequest = new HttpRequestMessage(HttpMethod.Get, "api/estates/buildings");

                var response = await httpClient.SendAsync(httpRequest, CancellationToken.None);
                var result = await response.Content.ReadAsStringAsync();

                return View("MakeApiCall", (object) result);
            }
        }
    }
}