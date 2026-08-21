using ActiveDirectory;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.DirectoryServices;
using System.Linq;

namespace IdentityServer.Controllers
{
    public class ValidateAdUserRequest
    {
        public string UserName { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class ValidateAdUserResponse
    {
        public bool Succeed { get; set; }
        public string? Message { get; set; }
        public AdUserData? Data { get; set; }
    }

    public class AdUserData
    {
        public string UserName { get; set; } = string.Empty;
        public string? DisplayName { get; set; }
        public string? Email { get; set; }
        public string? TelephoneNumber { get; set; }
        public string? MobilePhone { get; set; }
    }

    /// <summary>
    /// Provides Active Directory credential verification and user attribute lookup.
    /// </summary>
    [ApiController]
    [Route("api/ad")]
    [AllowAnonymous]
    public class AdAuthController : ControllerBase
    {
        private readonly ILogger<AdAuthController> _logger;

        public AdAuthController(ILogger<AdAuthController> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Validates Active Directory credentials and returns user details.
        /// </summary>
        [HttpPost("validate")]
        public IActionResult Validate([FromBody] ValidateAdUserRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.UserName) || string.IsNullOrWhiteSpace(request.Password))
            {
                return Ok(new ValidateAdUserResponse
                {
                    Succeed = false,
                    Message = "Username and password cannot be empty."
                });
            }

            var userName = request.UserName.Trim();
            if (userName.Contains('\\') || userName.Contains('@') || userName.All(char.IsDigit) || userName.Any(char.IsUpper))
            {
                return Ok(new ValidateAdUserResponse
                {
                    Succeed = false,
                    Message = "Invalid domain username or password."
                });
            }

            try
            {
                // Authenticate against Active Directory using LDAP bind
                using (var entry = new DirectoryEntry("LDAP://rootDSE", request.UserName, request.Password, AuthenticationTypes.Secure))
                {
                    var nativeObject = entry.NativeObject; // Force authentication
                }

                string? displayName = null;
                string? email = null;
                string? telephone = null;
                string? mobile = null;

                try
                {
                    using var adUser = new ADUser(request.UserName);
                    displayName = adUser.DisplayName ?? request.UserName;
                    email = adUser.Email;
                    telephone = adUser.TelephoneNumber;
                    mobile = adUser.MobilePhone;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to retrieve AD user attributes for {User}", request.UserName);
                }

                _logger.LogInformation("Active Directory authentication succeeded for {User} ({DisplayName})", request.UserName, displayName);
                return Ok(new ValidateAdUserResponse
                {
                    Succeed = true,
                    Data = new AdUserData
                    {
                        UserName = request.UserName,
                        DisplayName = displayName ?? request.UserName,
                        Email = email,
                        TelephoneNumber = telephone,
                        MobilePhone = mobile
                    }
                });
            }
            catch (DirectoryServicesCOMException ex)
            {
                _logger.LogWarning("Active Directory authentication failed for {User}: {Message}", request.UserName, ex.Message);
                return Ok(new ValidateAdUserResponse
                {
                    Succeed = false,
                    Message = "Invalid domain username or password."
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during Active Directory authentication for {User}", request.UserName);
                return Ok(new ValidateAdUserResponse
                {
                    Succeed = false,
                    Message = "Invalid domain username or password."
                });
            }
        }
    }
}
