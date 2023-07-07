using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Text.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Auth0.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication(authOption =>
{    
    authOption.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    authOption.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
    //if use auth0, comment these 4 below lines because it already use cookie, if not uncomment
    //.AddCookie(cookieOption =>
    //{
    //    cookieOption.Cookie.Name = "ThinhCookie";
    //})
    .AddOAuth("github", githubOption =>
    {
        githubOption.ClientId = builder.Configuration.GetSection("Authentication:Github:ClientId").Value;
        githubOption.ClientSecret = builder.Configuration.GetSection("Authentication:Github:ClientSecret").Value;
        githubOption.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme; //for set ctx.User
        

        githubOption.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
        githubOption.TokenEndpoint = "https://github.com/login/oauth/access_token";

        githubOption.CallbackPath = "/oauth/github-cb";
        githubOption.SaveTokens = true; // for user identity
        githubOption.UserInformationEndpoint = "https://api.github.com/user";//required to get user info to create claim principle


        githubOption.ClaimActions.MapJsonKey("sub", "id");
        githubOption.ClaimActions.MapJsonKey(ClaimTypes.Name, "login");  //create claim actions create claims ò c1st param with key in json element (user data)
        //claims actions will be run in ctx.RunClaimActions(user);

        githubOption.Events.OnCreatingTicket = async (ctx) =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", ctx.AccessToken);
            using var result = await ctx.Backchannel.SendAsync(request);
            var user = await result.Content.ReadFromJsonAsync<JsonElement>();
            ctx.RunClaimActions(user);
        };
    })
    .AddFacebook("facebook",facebookOptions =>
    {        
        facebookOptions.AppId = builder.Configuration.GetSection("Authentication:Facebook:AppId").Value;
        facebookOptions.AppSecret = builder.Configuration.GetSection("Authentication:Facebook:AppSecret").Value;
        facebookOptions.AccessDeniedPath = "/AccessDeniedPathInfo";
        facebookOptions.SignInScheme =  CookieAuthenticationDefaults.AuthenticationScheme; //for set ctx.User but may be already in addAuthentication
    })
    .AddGoogle("google", googleOption =>
    {
        googleOption.ClientId = builder.Configuration.GetSection("Authentication:Google:ClientId").Value;
        googleOption.ClientSecret = builder.Configuration.GetSection("Authentication:Google:ClientSecret").Value;
        googleOption.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddAuth0WebAppAuthentication(auth0Option =>
    {
        auth0Option.Domain = builder.Configuration["Authentication:Auth0:Domain"];
        auth0Option.ClientId = builder.Configuration["Authentication:Auth0:ClientId"];
        //auth0Option.ClientSecret = builder.Configuration["Authentication:Auth:ClientSecret"];
    });

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/user", (HttpContext ctx) => { 
    return ctx.User.Claims.Select(x => new { x.Type, x.Value }).ToList();
});
app.MapGet("/", (HttpContext ctx, IDataProtectionProvider idp) =>
{
    var cookie = ctx.Request.Cookies.Where(x => x.Key == "ThinhCookie").FirstOrDefault();
    var accessToken = ctx.GetTokenAsync("access_token"); 
    return ctx.User.Identity.IsAuthenticated.ToString();
});

app.MapGet("/login/facebook", () =>
{
    return Results.Challenge(
        new Microsoft.AspNetCore.Authentication.AuthenticationProperties()
        {
            RedirectUri = "https://localhost:5005/"
        },
        authenticationSchemes: new List<string>() { "facebook" });
});

app.MapGet("/login/github", (HttpContext ctx) =>
{   
    return  Results.Challenge(
        new Microsoft.AspNetCore.Authentication.AuthenticationProperties()
        {
            RedirectUri = "https://localhost:5005/"
        },
        authenticationSchemes: new List<string>() { "github" });
});
app.MapGet("/login/google", (HttpContext ctx) =>
{
    return Results.Challenge(
        new Microsoft.AspNetCore.Authentication.AuthenticationProperties()
        {
            RedirectUri = "https://localhost:5005/"
        },
        authenticationSchemes: new List<string>() { "google" });
});
app.MapGet("/login/auth0",async (HttpContext ctx) =>
{
    var authenticationProperties = new LoginAuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
    // Indicate here where Auth0 should redirect the user after a login.
    // Note that the resulting absolute Uri must be added to the
    // **Allowed Callback URLs** settings for the app.

    await ctx.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
});

app.MapGet("/logout", async (HttpContext ctx) => {
    await ctx.SignOutAsync();
    return "signeout";
});
//ko can vi phuong thuc o tren login google da create cookie va extract cookie vao ctx.User
//app.MapGet("signed-in", (HttpContext ctx) => {
//    var claims = new List<Claim>()
//    {
//        new Claim("google", "google"),
//        new Claim("isAuthenticated", true.ToString())
//    };
//    var claimIdentity = new ClaimsIdentity(claims);
//    var claimPrinciple = new ClaimsPrincipal(claimIdentity);
//    var result = ctx.SignInAsync(claimPrinciple);
//    return ctx.User.Identity.IsAuthenticated.ToString();
    
//});



app.Run();


