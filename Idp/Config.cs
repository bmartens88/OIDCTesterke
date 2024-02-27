using Duende.IdentityServer;
using Duende.IdentityServer.Models;

namespace Idp;

public static class Config
{
    public static IEnumerable<IdentityResource> ApiResources =>
    [
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
        new IdentityResources.Email()
    ];

    public static IEnumerable<ApiScope> ApiScopes =>
    [
        new ApiScope("api1", "My API")
    ];

    public static IEnumerable<Client> Clients =>
    [
        new Client
        {
            ClientId = "web",
            ClientSecrets = [new Secret("secret".Sha256())],
            Enabled = true,
            AllowedScopes =
            [
                IdentityServerConstants.StandardScopes.OpenId,
                IdentityServerConstants.StandardScopes.Profile,
                IdentityServerConstants.StandardScopes.Email,
                "api1"
            ],
            RedirectUris = ["https://localhost:5003/signin-oidc"],
            RequirePkce = true,
            AllowedGrantTypes = GrantTypes.Code,
            AllowOfflineAccess = true,
            PostLogoutRedirectUris = ["https://localhost:5003/signout-callback-oidc"]
        }
    ];
}