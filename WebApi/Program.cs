using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using ZeroBounceSDK;
using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddLogging();

var apiKey = builder.Configuration["ZeroBounce:Key"];

if (string.IsNullOrWhiteSpace(apiKey))
{
    throw new Exception("Invalid API key");
}

builder.Services.AddCors();

builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter(policyName: "minute", opt =>
    {
        opt.PermitLimit = 20;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = 5;
    });

    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            await context.HttpContext.Response.WriteAsync(
                $"Too many requests. Please try again after {retryAfter.TotalSeconds} second(s).",
                cancellationToken: token);
        }
        else
        {
            await context.HttpContext.Response.WriteAsync(
                "Too many requests. Please try again later.",
                cancellationToken: token);
        }
    };
});

ZeroBounce.Instance.Initialize(apiKey);

var app = builder.Build();

app.UseHttpsRedirection();

app.UseRateLimiter();

app.Use(async (context, next) =>
{
    if (!context.Request.Headers.ContainsKey("Origin"))
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        await context.Response.WriteAsync("Direct server requests are not allowed.");
        return;
    }

    // Origin header exists, proceed to CORS validation
    await next(context);
});

app.UseCors(policy =>
    policy.WithOrigins(builder.Configuration["AllowedOrigin"]!).WithMethods(HttpMethods.Post).AllowAnyHeader());

app.MapPost("validate-email", (EmailValidationRequest request, HttpContext httpContext, ILogger<Program> logger) =>
{
    if (string.IsNullOrWhiteSpace(request.Email))
    {
        return Results.BadRequest("Email is not valid");
    }

    // Basic email format check using regex
    var emailRegex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$");
    if (!emailRegex.IsMatch(request.Email))
    {
        return Results.BadRequest("Email format is not valid");
    }

    ZBValidateResponse? response = null;
    ZeroBounce.Instance.Validate(
        request.Email,
        httpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
        success =>
        {
            response = success;
        },
        failure =>
        {
            logger.LogError("Error occured: {Message}", failure);
        });

    return Results.Ok(new
    {
        isValid = response is { Status: ZBValidateStatus.Valid }
    });
}).RequireRateLimiting("minute");

app.Run();

internal sealed record EmailValidationRequest(string? Email);