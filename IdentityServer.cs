using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Security.Principal;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Server.IISIntegration;
using System.DirectoryServices;
using System.Threading;
using System.Threading.Tasks;
using ActiveDirectory;

namespace IdentityServer
{
    /// <summary>
    /// Configures the OpenIddict server and validation stack.
    /// Runs in degraded mode (no user store) with custom event handlers that resolve
    /// identity claims from Windows Authentication and Active Directory.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Supported flows: Authorization Code, Implicit, and Hybrid.
    /// Supported scopes: <c>openid</c>, <c>email</c>, <c>profile</c>, <c>roles</c>.
    /// </para>
    /// <para>
    /// When <c>IdentityServer:PersistKeys</c> is <see langword="true"/>, signing and encryption keys
    /// are persisted to disk (under <c>IdentityServer:DataPath</c>), protected at rest with Windows
    /// DPAPI, so the same key material survives app pool recycles and avoids JWKS cache mismatches
    /// in OIDC clients. When <see langword="false"/> (default), ephemeral keys are generated on
    /// every startup.
    /// </para>
    /// </remarks>
    public class IdentityServer
    {
        private sealed class ClientConfig
        {
            public string ClientId { get; init; } = "";
            public string? ClientSecret { get; init; }
        }

        /// <summary>
        /// Finds a matching client from <c>IdentityServer:Clients</c> by exact <paramref name="clientId"/>
        /// or by the <c>*</c> wildcard entry. Returns <see langword="null"/> if the list is configured
        /// but contains no match, or a wildcard <c>ClientConfig</c> if the list is absent (open access).
        /// </summary>
        private static ClientConfig? FindClient(string? clientId)
        {
            var clients = Program.Configuration.GetSection("IdentityServer:Clients").Get<ClientConfig[]>();
            if (clients == null || clients.Length == 0)
                return new ClientConfig { ClientId = "*" }; // no list configured: accept any client

            return clients.FirstOrDefault(c => c.ClientId.Equals(clientId ?? "", StringComparison.OrdinalIgnoreCase))
                ?? clients.FirstOrDefault(c => c.ClientId == "*");
        }

        /// <summary>
        /// Returns a logger for this class, resolved from the request's DI container when available,
        /// falling back to <see cref="Program.LoggerFactory"/> or a null logger.
        /// </summary>
        private static ILogger GetLogger(HttpContext? httpContext) =>
            (httpContext?.RequestServices.GetService<ILoggerFactory>()
             ?? Program.LoggerFactory
             ?? NullLoggerFactory.Instance)
            .CreateLogger<IdentityServer>();

        private static Regex[]? _validGroupPatterns;
        private static Regex[] ValidGroupPatterns => _validGroupPatterns ??=
            Program.Configuration.GetSection("IdentityServer:Groups").Get<string[]>()!
                .Select(g => new Regex(g, RegexOptions.IgnoreCase | RegexOptions.Compiled))
                .ToArray();

        /// <summary>
        /// Loads an <see cref="ADUser"/> from Active Directory with a bounded timeout and retries.
        /// After a long idle, the underlying ADSI/LDAP connection can go stale and the lookup fails
        /// immediately (e.g. "The server is not operational") or hangs. Retries alone are not enough:
        /// firing them back-to-back all lands in the same broken window, so a short delay between
        /// attempts lets the OS re-establish the domain-controller connection. The first real login
        /// therefore self-heals on the very first click instead of rejecting and forcing a retry.
        /// </summary>
        private static async Task<ADUser> LoadAdUserAsync(string winAccountName, ILogger logger, CancellationToken ct)
        {
            int attempts = Math.Max(1, Program.Configuration.GetValue("IdentityServer:AdLookupAttempts", 5));
            var timeout = TimeSpan.FromSeconds(
                Math.Max(1, Program.Configuration.GetValue("IdentityServer:AdLookupTimeoutSeconds", 15)));
            var retryDelay = TimeSpan.FromSeconds(
                Math.Max(0, Program.Configuration.GetValue("IdentityServer:AdLookupRetryDelaySeconds", 2)));

            Exception? lastError = null;
            for (int attempt = 1; attempt <= attempts; attempt++)
            {
                bool isFinal = attempt == attempts;
                try
                {
                    // On the final attempt, await without the timeout wrapper so a genuine error surfaces.
                    Task<ADUser> lookup = Task.Run(() => new ADUser(winAccountName), ct);
                    if (isFinal)
                    {
                        return await lookup;
                    }

                    Task completed = await Task.WhenAny(lookup, Task.Delay(timeout, ct));
                    if (ReferenceEquals(completed, lookup))
                    {
                        return await lookup; // observe any exception thrown by the constructor
                    }

                    // Timed out: dispose the orphaned entry on a best-effort basis and retry after a delay.
                    logger.LogWarning(
                        "AD lookup for '{User}' timed out after {Timeout}s (attempt {Attempt}/{Attempts}); retrying after {Delay}s.",
                        winAccountName, timeout.TotalSeconds, attempt, attempts, retryDelay.TotalSeconds);
                    _ = lookup.ContinueWith(t =>
                    {
                        try { t.GetAwaiter().GetResult()?.Dispose(); } catch { /* ignore */ }
                    }, TaskScheduler.Default);
                }
                catch (Exception ex) when (!isFinal)
                {
                    lastError = ex;
                    logger.LogWarning(ex,
                        "AD lookup for '{User}' failed (attempt {Attempt}/{Attempts}); retrying after {Delay}s.",
                        winAccountName, attempt, attempts, retryDelay.TotalSeconds);
                }

                // Give the OS/ADSI connection time to recover before the next attempt.
                if (!isFinal && retryDelay > TimeSpan.Zero)
                {
                    await Task.Delay(retryDelay, ct);
                }
            }

            // All attempts failed: surface the last error rather than swallowing it.
            throw new InvalidOperationException(
                $"Active Directory lookup for '{winAccountName}' failed after {attempts} attempts.", lastError);
        }

        /// <summary>
        /// Loads a persistent RSA key from <paramref name="filename"/> under <c>IdentityServer:DataPath</c>
        /// (defaulting to a <c>keys</c> subfolder of the app base directory), generating and saving a new
        /// 2048-bit key if the file does not yet exist.
        /// </summary>
        /// <remarks>
        /// Private key material is encrypted at rest with Windows DPAPI
        /// (<see cref="DataProtectionScope.LocalMachine"/>); the raw key bytes are never written to disk
        /// in plaintext. Only processes running on the same machine can decrypt the file.
        /// </remarks>
        private static RsaSecurityKey LoadOrCreateRsaKey(string filename)
        {
            var dataPath = Program.Configuration.GetValue<string>("IdentityServer:DataPath")
                           ?? Path.Combine(AppContext.BaseDirectory, "keys");
            Directory.CreateDirectory(dataPath);
            var keyPath = Path.Combine(dataPath, filename);

            var rsa = RSA.Create(2048);
            if (File.Exists(keyPath))
            {
                byte[] decrypted = ProtectedData.Unprotect(
                    File.ReadAllBytes(keyPath), null, DataProtectionScope.LocalMachine);
                rsa.ImportFromPem(Encoding.UTF8.GetString(decrypted));
            }
            else
            {
                byte[] pem = Encoding.UTF8.GetBytes(rsa.ExportPkcs8PrivateKeyPem());
                File.WriteAllBytes(keyPath, ProtectedData.Protect(pem, null, DataProtectionScope.LocalMachine));
            }

            return new RsaSecurityKey(rsa);
        }

        /// <summary>
        /// Registers OpenIddict server and validation services in the DI container.
        /// Reads <c>IdentityServer:ServerUri</c>, <c>IdentityServer:Hosts</c>, and
        /// <c>IdentityServer:Groups</c> from <see cref="Program.Configuration"/>.
        /// </summary>
        /// <param name="services">The application service collection.</param>
        public static void Add(IServiceCollection services)
        {
            services.AddOpenIddict().AddServer(options =>
            {
                // When PersistKeys is true, keys survive app pool recycles (preventing JWKS cache
                // mismatches) and are protected at rest with Windows DPAPI. When false (default),
                // ephemeral keys are generated on every startup.
                if (Program.Configuration.GetValue<bool>("IdentityServer:PersistKeys"))
                    options.AddSigningKey(LoadOrCreateRsaKey("signing-key.bin"))
                           .AddEncryptionKey(LoadOrCreateRsaKey("encryption-key.bin"));
                else
                    options.AddSigningKey(new RsaSecurityKey(RSA.Create(2048)))
                           .AddEncryptionKey(new RsaSecurityKey(RSA.Create(2048)));
                options.AllowAuthorizationCodeFlow();
                options.AllowHybridFlow();
                options.AllowImplicitFlow();

                var accessTokenLifetime = Program.Configuration.GetValue<TimeSpan?>("IdentityServer:AccessTokenLifetime");
                if (accessTokenLifetime.HasValue) options.SetAccessTokenLifetime(accessTokenLifetime.Value);

                var identityTokenLifetime = Program.Configuration.GetValue<TimeSpan?>("IdentityServer:IdentityTokenLifetime");
                if (identityTokenLifetime.HasValue) options.SetIdentityTokenLifetime(identityTokenLifetime.Value);

                var authCodeLifetime = Program.Configuration.GetValue<TimeSpan?>("IdentityServer:AuthorizationCodeLifetime");
                if (authCodeLifetime.HasValue) options.SetAuthorizationCodeLifetime(authCodeLifetime.Value);
                var serverUri = Program.Configuration.GetSection("IdentityServer:ServerUri").Get<string>();
                if (!string.IsNullOrEmpty(serverUri) && serverUri != "*")
                    options.SetIssuer(new Uri(serverUri));
                options.SetAuthorizationEndpointUris("connect/authorize")
                       .SetTokenEndpointUris("connect/token");
                options.EnableDegradedMode();
                options.UseAspNetCore()
                    .DisableTransportSecurityRequirement();
                options.RegisterScopes(Scopes.OpenId, Scopes.Email, Scopes.Profile, Scopes.Roles);

                // Validate authorization requests: verify client_id against IdentityServer:Clients
                // and redirect_uri host against IdentityServer:Hosts.
                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        var logger = GetLogger(context.Transaction.GetHttpRequest()?.HttpContext);

                        if (FindClient(context.Request.ClientId) == null)
                        {
                            logger.LogWarning("Authorization request rejected: unknown client_id '{ClientId}'",
                                context.Request.ClientId);
                            context.Reject(
                                error: Errors.InvalidClient,
                                description: "The specified client_id is not valid.");
                            return default;
                        }

                        var redirectHost = new Uri(context.RedirectUri!).Host;
                        if (Program.Configuration.GetSection("IdentityServer:Hosts").Get<string[]>()!
                            .Any(s => new Uri(s).Host.Equals(redirectHost, StringComparison.OrdinalIgnoreCase)))
                        {
                            return default;
                        }

                        logger.LogWarning("Authorization request rejected: redirect_uri '{RedirectUri}' host not in allowed list",
                            context.RedirectUri);
                        context.Reject(
                            error: Errors.InvalidClient,
                            description: "The specified redirect_uri is not valid.");
                        return default;
                    }));

                // Validate token requests: verify client_id against IdentityServer:Clients, and
                // client_secret if one is configured for the matched client.
                // Use ClientSecret: "*" to accept any secret without validating it.
                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        var logger = GetLogger(context.Transaction.GetHttpRequest()?.HttpContext);

                        var client = FindClient(context.Request.ClientId);
                        if (client == null)
                        {
                            logger.LogWarning("Token request rejected: unknown client_id '{ClientId}'",
                                context.Request.ClientId);
                            context.Reject(
                                error: Errors.InvalidClient,
                                description: "The specified client_id is not valid.");
                            return default;
                        }

                        if (client.ClientSecret != null && client.ClientSecret != "*" &&
                            !string.Equals(client.ClientSecret, context.Request.ClientSecret, StringComparison.Ordinal))
                        {
                            logger.LogWarning("Token request rejected: invalid client_secret for client '{ClientId}'",
                                context.Request.ClientId);
                            context.Reject(
                                error: Errors.InvalidClient,
                                description: "The specified client_secret is not valid.");
                            return default;
                        }

                        return default;
                    }));

                // Handle authorization requests: build claims from Windows identity and AD
                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(async context =>
                    {
                        var logger = GetLogger(context.Transaction.GetHttpRequest()?.HttpContext);
                        string? winAccountName = null;
                        try
                        {
                            HttpRequest request = context.Transaction.GetHttpRequest()
                                ?? throw new InvalidOperationException("The ASP.NET Core request cannot be retrieved.");

                            AuthenticateResult result = await request.HttpContext.AuthenticateAsync(IISDefaults.AuthenticationScheme);
                            if (!result.Succeeded)
                            {
                                logger.LogWarning("Windows authentication failed for authorization request from {RemoteIp}: {Failure}",
                                    request.HttpContext.Connection.RemoteIpAddress,
                                    result.Failure?.Message ?? "(no details)");
                                context.Reject(error: Errors.AccessDenied, description: "Windows authentication failed.");
                                return;
                            }

                            ClaimsIdentity identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
                            WindowsIdentity wi = (WindowsIdentity)request.HttpContext.User.Identity!;

                            // S-1-2-0 is the "Local" well-known SID; its presence means the user
                            // is logged on locally and Active Directory may not be reachable
                            bool isLocal = wi.FindAll(ClaimTypes.GroupSid).Any(g => g.Value == "S-1-2-0");

                            winAccountName = wi.FindFirst(ClaimTypes.Name)!.Value;
                            string primarySid = wi.FindFirst(ClaimTypes.PrimarySid)!.Value;
                            string samName    = winAccountName.Contains('\\') ? winAccountName.Split('\\')[1] : winAccountName;

                            logger.LogDebug("Building claims for {User} (local: {IsLocal}, scopes: {Scopes})",
                                winAccountName, isLocal, string.Join(" ", context.Request.GetScopes()));

                            if (isLocal)
                            {
                                if (context.Request.HasScope(Scopes.OpenId))
                                {
                                    identity.AddClaim(Claims.Subject, primarySid);
                                    identity.AddClaim(ClaimTypes.Name, samName);
                                    identity.AddClaim(Claims.PreferredUsername, samName);
                                    identity.AddClaim(Claims.Name, samName); // Full Name
                                }

                                if (context.Request.HasScope(Scopes.Profile))
                                {
                                    identity.AddClaim(ClaimTypes.WindowsAccountName, winAccountName);
                                }

                                if (context.Request.HasScope(Scopes.Email))
                                {
                                    string localEmail = samName + "@localhost";
                                    identity.AddClaim(ClaimTypes.Email, localEmail);
                                    identity.AddClaim(Claims.Email, localEmail); // OIDC "email" claim
                                }
                            }
                            else
                            {
                                // Fetch user attributes from Active Directory
                                ADUser? user = null;
                                try
                                {
                                    user = await LoadAdUserAsync(winAccountName, logger, CancellationToken.None);
                                }
                                catch (Exception ex)
                                {
                                    logger.LogError(ex, "Active Directory lookup for '{User}' failed after retries; rejecting authorization request.", winAccountName);
                                    context.Reject(error: Errors.ServerError, description: "Unable to contact Active Directory. Please try again.");
                                    return;
                                }
                                using (user)
                                {
                                if (context.Request.HasScope(Scopes.OpenId))
                                {
                                    identity.AddClaim(Claims.Subject, primarySid);
                                    identity.AddClaim(ClaimTypes.Name, user.DisplayName);
                                    identity.AddClaim(Claims.PreferredUsername, samName);
                                    identity.AddClaim(Claims.Name, user.DisplayName); // Full Name
                                }

                                if (context.Request.HasScope(Scopes.Email))
                                {
                                    // user.Email reads the AD "mail" attribute; fall back to a synthetic
                                    // address when mail is not populated in AD.
                                    string email = !string.IsNullOrEmpty(user.Email) ? user.Email : user.Username + "@localhost";
                                    identity.AddClaim(ClaimTypes.Email, email);
                                    identity.AddClaim(Claims.Email, email); // OIDC "email" claim
                                }

                                if (context.Request.HasScope(Scopes.Profile))
                                {
                                    identity.AddClaim(ClaimTypes.WindowsAccountName, winAccountName);
                                    if (!string.IsNullOrEmpty(user.GivenName)) { identity.AddClaim(ClaimTypes.GivenName, user.GivenName); identity.AddClaim(Claims.GivenName, user.GivenName); }
                                    if (!string.IsNullOrEmpty(user.Surname)) { identity.AddClaim(ClaimTypes.Surname, user.Surname); identity.AddClaim(Claims.FamilyName, user.Surname); }
                                    // Work phone (AD telephoneNumber) -> standard OIDC "phone_number" claim
                                    if (!string.IsNullOrEmpty(user.TelephoneNumber)) { identity.AddClaim(Claims.PhoneNumber, user.TelephoneNumber); }
                                    // Mobile phone (AD mobile) -> emitted only when present
                                    if (!string.IsNullOrEmpty(user.MobilePhone)) { identity.AddClaim(ClaimTypes.MobilePhone, user.MobilePhone); }
                                }

                                if (context.Request.HasScope(Scopes.Roles))
                                {
                                    // Filter AD groups against the regex patterns in IdentityServer:Groups
                                    var groups = user.GroupsCommonName;
                                    foreach (string group in groups)
                                    {
                                        if (ValidGroupPatterns.Any(rx => rx.IsMatch(group)))
                                        {
                                            identity.AddClaim(Claims.Role, group);
                                        }
                                    }
                                    var matchedRoles = identity.FindAll(Claims.Role).ToList();
                                    int roleCharCount = matchedRoles.Sum(c => c.Value.Length);
                                    logger.LogDebug("User {User} has {Total} AD groups; {Matched} matched configured patterns ({Chars} chars)",
                                        winAccountName, groups.Count, matchedRoles.Count, roleCharCount);
                                    if (roleCharCount > 4096)
                                        logger.LogWarning("User {User} has {Chars} characters of role claims — token may be large enough to trigger HTTP 431 errors. Consider tightening IdentityServer:Groups patterns.",
                                            winAccountName, roleCharCount);
                                }
                                }
                            }

                            // Include all claims in both the access token and the identity token
                            identity.SetDestinations(claim => new[]
                            {
                                Destinations.AccessToken,
                                Destinations.IdentityToken
                            });

                            context.Principal = new ClaimsPrincipal(identity);
                            logger.LogInformation("Authorization granted for {User} via {AuthType}", winAccountName, wi.AuthenticationType);
                        }
                        catch (Exception ex)
                        {
                            logger.LogError(ex, "Error building authorization claims for user '{User}'", winAccountName ?? "(unknown)");
                            context.Reject(error: Errors.ServerError, description: "An internal error occurred while processing the authorization request.");
                        }
                    }));

                // Log the serialized token sizes so oversized tokens are caught before they
                // cause HTTP 431 errors on downstream services using them as Bearer headers.
                options.AddEventHandler<ApplyTokenResponseContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        var logger = GetLogger(context.Transaction.GetHttpRequest()?.HttpContext);
                        int accessTokenLength = context.Response.AccessToken?.Length ?? 0;
                        int idTokenLength     = context.Response.IdToken?.Length     ?? 0;
                        logger.LogDebug("Token response sizes — access_token: {AccessLen} chars, id_token: {IdLen} chars",
                            accessTokenLength, idTokenLength);
                        if (accessTokenLength > 8192)
                            logger.LogWarning("access_token is {AccessLen} chars — downstream services using it as a Bearer header may receive HTTP 431 errors.",
                                accessTokenLength);
                        return default;
                    }));
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });
        }
    }
}
