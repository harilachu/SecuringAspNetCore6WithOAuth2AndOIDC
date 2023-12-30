using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace ImageGallery.Client.Controllers
{
    public class AuthenticationController : Controller
    {
        private readonly IHttpClientFactory httpClientFactory;

        public AuthenticationController(IHttpClientFactory httpClientFactory)
        {
            this.httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        }

        [Authorize]
        public async Task Logout()
        {
            var client = httpClientFactory.CreateClient("IDPClient");
            var discoverydocumentResponse = await client.GetDiscoveryDocumentAsync();
            if(discoverydocumentResponse.IsError)
            {
                throw new Exception(discoverydocumentResponse.Error);
            }

            var accessTokenRevocationResponse = await client.RevokeTokenAsync(
                new TokenRevocationRequest()
                {
                    Address = discoverydocumentResponse.RevocationEndpoint,
                    ClientId = "imagegalleryclient",
                    ClientSecret = "secret",
                    Token = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken)
                });

            if(accessTokenRevocationResponse.IsError)
            {
                throw new Exception($"{accessTokenRevocationResponse.Error}");
            }

            var refreshTokenRevocationResponse = await client.RevokeTokenAsync(
                new TokenRevocationRequest()
                {
                    Address = discoverydocumentResponse.RevocationEndpoint,
                    ClientId = "imagegalleryclient",
                    ClientSecret = "secret",
                    Token = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken)
                });

            if (refreshTokenRevocationResponse.IsError)
            {
                throw new Exception($"{refreshTokenRevocationResponse.Error}");
            }

            //clears the local cookie;
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            //Redirects to IDP linked to scheme, so it can clear its own session/cookie
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);

        }

        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
