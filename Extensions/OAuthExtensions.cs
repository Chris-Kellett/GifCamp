using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;

namespace GifCamp.Extensions;

public static class OAuthExtensions
{
    public static IServiceCollection AddOAuthAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        // Add AuthenticationStateProvider for Blazor
        services.AddScoped<Microsoft.AspNetCore.Components.Authorization.AuthenticationStateProvider,
            Microsoft.AspNetCore.Components.Server.ServerAuthenticationStateProvider>();

        // Configure Authentication
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = "OAuth";
        })
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.LoginPath = "/login";
            options.LogoutPath = "/logout";
            options.ExpireTimeSpan = TimeSpan.FromDays(7);
            options.SlidingExpiration = true;
        })
        .AddOAuth("OAuth", options =>
        {
            // Get OAuth settings from configuration (user secrets)
            var clientId = configuration["OAuth:ClientId"];
            var clientSecret = configuration["OAuth:ClientSecret"];
            var authorizationEndpoint = configuration["OAuth:AuthorizationEndpoint"];
            var tokenEndpoint = configuration["OAuth:TokenEndpoint"];
            var userInformationEndpoint = configuration["OAuth:UserInformationEndpoint"];
            var callbackPath = configuration["OAuth:CallbackPath"] ?? "/signin-oauth";

            // Validate required configuration
            var missingConfig = new List<string>();
            if (string.IsNullOrEmpty(clientId))
                missingConfig.Add("OAuth:ClientId");
            if (string.IsNullOrEmpty(clientSecret))
                missingConfig.Add("OAuth:ClientSecret");
            if (string.IsNullOrEmpty(authorizationEndpoint))
                missingConfig.Add("OAuth:AuthorizationEndpoint");
            if (string.IsNullOrEmpty(tokenEndpoint))
                missingConfig.Add("OAuth:TokenEndpoint");
            if (string.IsNullOrEmpty(userInformationEndpoint))
                missingConfig.Add("OAuth:UserInformationEndpoint");

            if (missingConfig.Any())
            {
                throw new InvalidOperationException(
                    $"OAuth configuration is missing the following required settings in user secrets:\n" +
                    string.Join("\n", missingConfig.Select(c => $"  - {c}")) +
                    "\n\nPlease configure these using: dotnet user-secrets set \"<key>\" \"<value>\"");
            }

            options.ClientId = clientId;
            options.ClientSecret = clientSecret;
            options.CallbackPath = callbackPath;
            options.AuthorizationEndpoint = authorizationEndpoint;
            options.TokenEndpoint = tokenEndpoint;
            options.UserInformationEndpoint = userInformationEndpoint;

            // Configure scopes
            var scopes = configuration["OAuth:Scopes"]?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                         ?? new[] { "openid", "profile", "email" };
            foreach (var scope in scopes)
            {
                options.Scope.Add(scope);
            }

            // Save tokens
            options.SaveTokens = true;

            options.Events = new OAuthEvents
            {
                OnCreatingTicket = async context =>
                {
                    // Create a request with the access token in the Authorization header
                    var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", context.AccessToken);
                    
                    // Extract user information from the response
                    var userInfoResponse = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
                    userInfoResponse.EnsureSuccessStatusCode();
                    var userInfoJson = await userInfoResponse.Content.ReadAsStringAsync();
                    var userInfo = System.Text.Json.JsonDocument.Parse(userInfoJson);

                    // Map common claims
                    var claims = new List<Claim>();

                    // Try to extract common OAuth claim names
                    if (userInfo.RootElement.TryGetProperty("sub", out var sub))
                        claims.Add(new Claim(ClaimTypes.NameIdentifier, sub.GetString() ?? ""));

                    if (userInfo.RootElement.TryGetProperty("name", out var name))
                        claims.Add(new Claim(ClaimTypes.Name, name.GetString() ?? ""));
                    else if (userInfo.RootElement.TryGetProperty("preferred_username", out var username))
                        claims.Add(new Claim(ClaimTypes.Name, username.GetString() ?? ""));

                    if (userInfo.RootElement.TryGetProperty("email", out var email))
                        claims.Add(new Claim(ClaimTypes.Email, email.GetString() ?? ""));

                    // Add all claims from user info
                    foreach (var claim in userInfo.RootElement.EnumerateObject())
                    {
                        if (claim.Value.ValueKind == System.Text.Json.JsonValueKind.String)
                        {
                            claims.Add(new Claim(claim.Name, claim.Value.GetString() ?? ""));
                        }
                    }

                    context.Identity?.AddClaims(claims);
                },
                OnTicketReceived = context =>
                {
                    // The redirect is handled by the RedirectUri in the ChallengeAsync call
                    return Task.CompletedTask;
                }
            };
        });

        return services;
    }
}

