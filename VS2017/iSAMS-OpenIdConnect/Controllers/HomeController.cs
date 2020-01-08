using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace iSAMS_OpenIdConnect.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View("Index");
        }

        [Authorize]
        public IActionResult Claims()
        {
            return View("Claims");
        }

        public IActionResult Logout()
        {
            return new SignOutResult(new[]
                {OpenIdConnectDefaults.AuthenticationScheme, CookieAuthenticationDefaults.AuthenticationScheme});
        }

        [Authorize]
        public async Task<ActionResult> MakeApiCall()
        {
            using (var httpClient = new HttpClient())
            {
                var accessToken = await HttpContext.GetTokenAsync("access_token");

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