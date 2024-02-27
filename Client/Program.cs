using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(opts =>
    {
        opts.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        opts.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(opts =>
    {
        opts.Authority = "https://localhost:5001";
        opts.ClientId = "web";
        opts.ClientSecret = "secret";
        opts.Scope.Add(OpenIdConnectScope.Email);
        opts.Scope.Add("offline_access");
        opts.Scope.Add("api1");
        opts.SaveTokens = true;
        opts.GetClaimsFromUserInfoEndpoint = true;
        opts.ResponseType = OpenIdConnectResponseType.Code;
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.MapGet("/", async (IAuthenticationSchemeProvider schemeProvider) =>
{
    var externalSchemes = (await schemeProvider.GetAllSchemesAsync())
        .Where(scheme => scheme.DisplayName is not null)
        .Select(scheme => scheme.DisplayName)
        .ToArray();

    return TypedResults.Ok(externalSchemes);
});

app.MapGet("/challenge/{scheme}", (string scheme) => TypedResults.Challenge(new AuthenticationProperties
{
    RedirectUri = "/challenge/callback"
}, [scheme]));

app.MapGet("/challenge/callback", async (HttpContext httpContext) =>
{
    var authResult = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    if (!authResult.Succeeded)
        throw new InvalidOperationException($"External authentication error: {authResult.Failure}");
    var externalUser = authResult.Principal;
    var claims = externalUser.Claims.Select(c => new { c.Type, c.Value });
    return TypedResults.Ok(claims);
});

app.MapGet("/signout", () => TypedResults.SignOut(authenticationSchemes:
    [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));

app.Run();