using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Mvc;

//https://developer.okta.com/quickstart/#/okta-sign-in-page/dotnet/aspnet4
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
            //return new SignOutResult(new[]
            //    {OpenIdConnectDefaults.AuthenticationScheme, CookieAuthenticationDefaults.AuthenticationScheme});
            return null;
        }

        [Authorize]
        public async Task<ActionResult> MakeApiCall()
        {
            using (var httpClient = new HttpClient())
            {
                var accessToken = (string) null; //await HttpContext.GetTokenAsync("access_token");

                httpClient.BaseAddress = new Uri("https://developerdemo.isams.cloud");
                httpClient.DefaultRequestHeaders.Accept.Clear();
                httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                var httpRequest = new HttpRequestMessage(HttpMethod.Get, "api/estates/buildings");

                var response = await httpClient.SendAsync(httpRequest, CancellationToken.None);
                var result = await response.Content.ReadAsStringAsync();

                return View("MakeApiCall", result);
            }
        }
    }
}