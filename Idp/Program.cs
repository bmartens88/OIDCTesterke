using System.Security.Claims;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Services;
using IdentityModel;
using Idp;
using Idp.Data;
using Idp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(opts =>
    opts.UseInMemoryDatabase(":inMemory:"));

builder.Services.AddIdentityCore<AppUser>(opts => opts.SignIn.RequireConfirmedAccount = false)
    .AddEntityFrameworkStores<AppDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

builder.Services.AddIdentityServer()
    .AddInMemoryIdentityResources(Config.ApiResources)
    .AddInMemoryApiScopes(Config.ApiScopes)
    .AddInMemoryClients(Config.Clients)
    .AddAspNetIdentity<AppUser>();

builder.Services.AddAuthentication(opts =>
    {
        opts.DefaultScheme = IdentityConstants.ApplicationScheme;
        opts.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddOpenIdConnect(opts =>
    {
        opts.Authority = "https://demo.duendesoftware.com";
        opts.ClientId = "interactive.confidential";
        opts.ClientSecret = "secret";
        opts.UsePkce = true;
        opts.Scope.Add(IdentityServerConstants.StandardScopes.Email);
        opts.Scope.Add("api");
        opts.Scope.Add("offline_access");
        opts.SaveTokens = true;
        opts.GetClaimsFromUserInfoEndpoint = true;
        opts.ResponseType = OpenIdConnectResponseType.Code;
        opts.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
    })
    .AddIdentityCookies();

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseIdentityServer();
app.UseAuthorization();

app.MapGet("/", async (IAuthenticationSchemeProvider schemeProvider) =>
{
    var externalSchemes = (await schemeProvider.GetAllSchemesAsync())
        .Where(scheme => scheme.DisplayName is not null)
        .Select(scheme => scheme.DisplayName)
        .ToArray();

    return TypedResults.Ok(externalSchemes);
});

app.MapGet("/account/login", (string? returnUrl) => TypedResults.Challenge(new AuthenticationProperties
{
    RedirectUri = "/challenge/callback",
    Items =
    {
        { "returnUrl", returnUrl }
    }
}, [OpenIdConnectDefaults.AuthenticationScheme]));

app.MapGet("/challenge/callback", async (HttpContext httpContext, UserManager<AppUser> userManager,
    SignInManager<AppUser> signInManager) =>
{
    var result = await httpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
    if (!result.Succeeded)
        throw new InvalidOperationException($"External authentication error: {result.Failure}");

    var externalUser = result.Principal ??
                       throw new InvalidOperationException("External authentication produced a null Principal");

    var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                      externalUser.FindFirst(ClaimTypes.NameIdentifier)
                      ?? throw new InvalidOperationException("Unknown userid");
    var providerUserId = userIdClaim.Value;

    var user = await userManager.FindByLoginAsync(OpenIdConnectDefaults.DisplayName, providerUserId) ??
               await AutoProvisionUserAsync(OpenIdConnectDefaults.DisplayName, providerUserId, externalUser.Claims,
                   userManager);

    var additionalLocalClaims = new List<Claim>();
    var localSigninProps = new AuthenticationProperties();
    CaptureExternalLoginContext(result, additionalLocalClaims, localSigninProps);

    await signInManager.SignInWithClaimsAsync(user, localSigninProps, additionalLocalClaims);

    await httpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

    var returnUrl = result.Properties?.Items["returnUrl"] ?? "~/";

    return TypedResults.Redirect(returnUrl);
});

app.MapGet("/account/logout", async Task<IResult> (
    string? logoutId,
    HttpContext httpContext,
    ClaimsPrincipal user,
    SignInManager<AppUser> signinManager,
    IIdentityServerInteractionService interactionService,
    IEventService events,
    LinkGenerator linkGenerator) =>
{
    if (user.Identity?.IsAuthenticated is true)
    {
        logoutId ??= await interactionService.CreateLogoutContextAsync();

        var logout = await interactionService.GetLogoutContextAsync(logoutId);
        var postLogoutUrl = logout?.PostLogoutRedirectUri;

        await signinManager.SignOutAsync();

        var idp = user.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
        await events.RaiseAsync(new UserLogoutSuccessEvent(user.GetSubjectId(), user.GetDisplayName()));

        if (idp is not null and not IdentityServerConstants.LocalIdentityProvider)
            if (await httpContext.GetSchemeSupportsSignOutAsync(idp))
            {
                var url = linkGenerator.GetPathByName("LoggedOut", new { logoutId });
                return TypedResults.SignOut(new AuthenticationProperties
                {
                    RedirectUri = url
                }, [idp]);
            }
    }

    var redirectUrl = linkGenerator.GetPathByName("LoggedOut", new { logoutId });
    return TypedResults.Redirect(redirectUrl);
});

app.MapGet("/account/logout/loggedout", () => { })
    .WithName("LoggedOut");

app.Run();
return;

async Task<AppUser> AutoProvisionUserAsync(string provider, string providerUserId, IEnumerable<Claim> claims,
    UserManager<AppUser> userManager)
{
    var sub = Guid.NewGuid().ToString();

    var user = new AppUser
    {
        Id = sub,
        UserName = sub
    };

    var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ??
                claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
    if (email is not null)
        user.Email = email;

    var filtered = new List<Claim>();

    var name = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name)?.Value ??
               claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
    if (name is not null)
    {
        filtered.Add(new Claim(JwtClaimTypes.Name, name));
    }
    else
    {
        var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ??
                    claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value;
        var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ??
                   claims.FirstOrDefault(x => x.Type == ClaimTypes.Surname)?.Value;
        if (first != null && last != null)
            filtered.Add(new Claim(JwtClaimTypes.Name, first + " " + last));
        else if (first != null)
            filtered.Add(new Claim(JwtClaimTypes.Name, first));
        else if (last != null) filtered.Add(new Claim(JwtClaimTypes.Name, last));
    }

    var identityResult = await userManager.CreateAsync(user);
    if (!identityResult.Succeeded) throw new InvalidOperationException(identityResult.Errors.First().Description);

    if (filtered.Count != 0)
    {
        identityResult = await userManager.AddClaimsAsync(user, filtered);
        if (!identityResult.Succeeded) throw new InvalidOperationException(identityResult.Errors.First().Description);
    }

    identityResult = await userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerUserId, provider));
    if (!identityResult.Succeeded) throw new InvalidOperationException(identityResult.Errors.First().Description);

    return user;
}

static void CaptureExternalLoginContext(AuthenticateResult externalResult, ICollection<Claim> localClaims,
    AuthenticationProperties localSigninProps)
{
    localClaims.Add(new Claim(JwtClaimTypes.IdentityProvider, OpenIdConnectDefaults.DisplayName));
    var idToken = externalResult.Properties?.GetTokenValue("id_token");
    if (idToken is not null)
        localSigninProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = idToken } });
}

internal static class Extensions
{
    public static async Task<bool> GetSchemeSupportsSignOutAsync(this HttpContext httpContext, string scheme)
    {
        var provider = httpContext.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
        var handler = await provider.GetHandlerAsync(httpContext, scheme);
        return handler is IAuthenticationSignOutHandler;
    }
}