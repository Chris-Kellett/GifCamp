using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace GifCamp.Extensions;

public static class AuthenticationEndpoints
{
    public static WebApplication MapAuthenticationEndpoints(this WebApplication app)
    {
        // Map login endpoint
        app.MapGet("/login", async (HttpContext context) =>
        {
            var returnUrl = context.Request.Query["returnUrl"].ToString();
            if (string.IsNullOrEmpty(returnUrl))
                returnUrl = "/";

            await context.ChallengeAsync("OAuth", new AuthenticationProperties
            {
                RedirectUri = returnUrl
            });
        });

        // Map logout endpoint
        app.MapGet("/logout", async (HttpContext context) =>
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            context.Response.Redirect("/");
        });

        return app;
    }
}

