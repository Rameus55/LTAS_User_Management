using LTAS_User_Management.Logging;
using LTAS_User_Management.Models;
using LTAS_User_Management.Utilities;
using Relativity.API;
using Relativity.Identity.V1.Services;
using Relativity.Identity.V1.Shared;
using Relativity.Identity.V1.UserModels;
using Relativity.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static LTAS_User_Management.Handlers.MessageHandler;

namespace LTAS_User_Management.Handlers
{
    public class UserHandler
    {
        private readonly IUserManager _userManager;
        private readonly ILTASLogger _ltasLogger;
        private readonly LTASUMHelper _ltasHelper;
        private readonly IHelper _helper;

        public UserHandler(
            IUserManager userManager,
            IDBContext eddsDbContext,
            IHelper helper,
            IAPILog logger)
        {
            _userManager = userManager;
            _helper = helper;
            _ltasHelper = new LTASUMHelper(helper, logger.ForContext<UserHandler>());
            _ltasLogger = LoggerFactory.CreateLogger<UserHandler>(eddsDbContext, helper, _ltasHelper.Logger);
        }

        public async Task DisableUserAsync(int userArtifactId)
        {
            try
            {
                _ltasLogger.LogInformation($"Starting to disable user: {userArtifactId}");                

                UserResponse userResponse = await _userManager.ReadAsync(userArtifactId);
                UserRequest userRequest = new UserRequest(userResponse)
                {
                    Notes = "user had no active groups",
                    Keywords = "disabled by LTAS User Management system",
                    RelativityAccess = false,                  
                };

                await _userManager.UpdateAsync(userArtifactId, userRequest);                
            }
            catch (Exception ex)
            {
                _ltasLogger.LogError(ex, $"Failed to disable user: {userArtifactId}");
                _ltasHelper.Logger.LogError(ex, $"Failed to disable user: {userArtifactId}");
            }
        }

        public async Task UpdateItemListUserAsync(int userArtifactId)
        {
            try
            {                
                UserResponse userResponse = await _userManager.ReadAsync(userArtifactId);
                UserRequest userRequest = new UserRequest(userResponse)
                {
                    ItemListPageLength = 200
                };

                await _userManager.UpdateAsync(userArtifactId, userRequest);
                _ltasLogger.LogInformation($"Updated ItemListPage for user: {userArtifactId}");

            }
            catch (Exception ex)
            {
                _ltasLogger.LogError(ex, $"Failed to update ItemListPage for user: {userArtifactId}");
                _ltasHelper.Logger.LogError(ex, $"Failed to update ItemListPage for user: {userArtifactId}");
            }
        }

        public async Task<QueryResultSlim> RetrieveGroupsForUser(int userArtifactId)
        {
            try
            {
                _ltasLogger.LogInformation($"Retrieving groups for user: {userArtifactId}");                

                QueryRequest queryRequest = new QueryRequest
                {
                    Fields = new FieldRef[]
                    {
                        new FieldRef { Name = "ArtifactID" }
                    }
                };

                var result = await _userManager.QueryGroupsByUserAsync(queryRequest, 0, 10000, userArtifactId);

                _ltasLogger.LogInformation($"Successfully retrieved groups for user: {userArtifactId}");                

                return result;
            }
            catch (Exception ex)
            {
                _ltasLogger.LogError(ex, $"Failed to retrieve groups for user: {userArtifactId}");
                _ltasHelper.Logger.LogError(ex, $"Failed to retrieve groups for user: {userArtifactId}");
                return null;
            }
        }

        public async Task<List<LoginProfileValidation>> ValidateUsersLoginProfilesAsync(List<Users> users, IInstanceSettingsBundle _instanceSettingsBundle)
        {
            var results = new List<LoginProfileValidation>();
            foreach (var user in users)
            {
                try
                {
                    var result = new LoginProfileValidation
                    {
                        UserArtifactId = user.ArtifactId,
                        EmailAddress = user.EmailAddress,
                        FirstName = user.FirstName,
                        LastName = user.LastName,
                        InvalidProviderTypes = new List<string>()
                    };

                    // Check if user is in admin groups to determine if they need OktaAdmin
                    bool isAdmin = false;
                    var userGroups = await RetrieveGroupsForUser(user.ArtifactId);
                    if (userGroups != null && userGroups.Objects != null)
                    {
                        // Check if user belongs to admin groups
                        foreach (var group in userGroups.Objects)
                        {
                            // Access group name based on how QueryResultSlim returns data
                            // Adjust this according to how your data structure actually looks
                            string groupName = null;

                            // Try to get group name through dictionary access if available
                            if (group is IDictionary<string, object> dict && dict.ContainsKey("Name"))
                            {
                                groupName = dict["Name"]?.ToString();
                            }
                            // Alternative approach if objects have a different structure
                            else if (group.GetType().GetProperty("Name") != null)
                            {
                                groupName = group.GetType().GetProperty("Name").GetValue(group)?.ToString();
                            }

                            if (groupName != null &&
                                (groupName.Equals("System Administrators", StringComparison.OrdinalIgnoreCase) ||
                                 groupName.Equals("QE_LTAS_ADMIN", StringComparison.OrdinalIgnoreCase)))
                            {
                                isAdmin = true;
                                break;
                            }
                        }
                    }

                    var servicesManager = _helper.GetServicesManager();
                    using (var loginProfileManager = servicesManager.CreateProxy<ILoginProfileManager>(ExecutionIdentity.System))
                    {
                        var profile = await loginProfileManager.GetLoginProfileAsync(user.ArtifactId);

                        // Track all non-Okta authentication methods as invalid
                        if (profile.Password != null)
                            result.InvalidProviderTypes.Add("Password");
                        if (profile.IntegratedAuthentication != null)
                            result.InvalidProviderTypes.Add("IntegratedAuthentication");
                        if (profile.ActiveDirectory != null)
                            result.InvalidProviderTypes.Add("ActiveDirectory");
                        if (profile.ClientCertificate != null)
                            result.InvalidProviderTypes.Add("ClientCertificate");
                        if (profile.RSA != null)
                            result.InvalidProviderTypes.Add("RSA");

                        // Check for valid authentication methods based on user type
                        bool hasOkta = false;
                        bool hasOktaAdmin = false;

                        // Check OpenID providers
                        if (profile.OpenIDConnectMethods != null)
                        {
                            foreach (var method in profile.OpenIDConnectMethods)
                            {
                                if (!method.IsEnabled) continue;

                                if (method.ProviderName.IndexOf("okta", StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    // Check if this is specifically OktaAdmin
                                    if (method.ProviderName.IndexOf("oktaadmin", StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        hasOktaAdmin = true;
                                    }
                                    else
                                    {
                                        hasOkta = true;
                                    }
                                }
                                else
                                {
                                    result.InvalidProviderTypes.Add($"OpenIDConnect: {method.ProviderName}");
                                }
                            }
                        }

                        // Check SAML2 providers
                        if (profile.SAML2Methods != null)
                        {
                            foreach (var method in profile.SAML2Methods)
                            {
                                if (!method.IsEnabled) continue;

                                if (method.ProviderName.IndexOf("okta", StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    // Check if this is specifically OktaAdmin
                                    if (method.ProviderName.IndexOf("oktaadmin", StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        hasOktaAdmin = true;
                                    }
                                    else
                                    {
                                        hasOkta = true;
                                    }
                                }
                                else
                                {
                                    result.InvalidProviderTypes.Add($"SAML2: {method.ProviderName}");
                                }
                            }
                        }

                        // Set validation flags based on requirements
                        if (isAdmin)
                        {
                            // Admin users must use OktaAdmin
                            result.IsValid = hasOktaAdmin && !hasOkta && result.InvalidProviderTypes.Count == 0;
                            result.HasNoValidProvider = !hasOktaAdmin;

                            if (!hasOktaAdmin)
                            {
                                result.ValidationMessage = "System Administrator or QE_LTAS_ADMIN user must use OktaAdmin provider";
                            }
                            else if (hasOkta || result.InvalidProviderTypes.Count > 0)
                            {
                                result.HasMultipleProviders = true;
                                result.ValidationMessage = $"Admin user has additional providers: {string.Join(", ", result.InvalidProviderTypes.Concat(hasOkta ? new[] { "Okta (standard)" } : new string[0]))}";
                            }
                        }
                        else
                        {
                            // Regular Quinn users must use standard Okta
                            result.IsValid = hasOkta && !hasOktaAdmin && result.InvalidProviderTypes.Count == 0;
                            result.HasNoValidProvider = !hasOkta;

                            if (!hasOkta)
                            {
                                result.ValidationMessage = "Quinn user must use Okta provider";
                            }
                            else if (hasOktaAdmin || result.InvalidProviderTypes.Count > 0)
                            {
                                result.HasMultipleProviders = true;
                                result.ValidationMessage = $"User has additional providers: {string.Join(", ", result.InvalidProviderTypes.Concat(hasOktaAdmin ? new[] { "OktaAdmin" } : new string[0]))}";
                            }
                        }

                        // Log findings
                        _ltasLogger.LogInformation($"User {user.ArtifactId} validation results:");
                        _ltasLogger.LogInformation($"- Is Admin: {isAdmin}");
                        _ltasLogger.LogInformation($"- Has Okta: {hasOkta}");
                        _ltasLogger.LogInformation($"- Has OktaAdmin: {hasOktaAdmin}");
                        _ltasLogger.LogInformation($"- Has multiple providers: {result.HasMultipleProviders}");
                        _ltasLogger.LogInformation($"- Has no valid provider: {result.HasNoValidProvider}");
                        _ltasLogger.LogInformation($"- Is valid: {result.IsValid}");

                        // Only add to results if there are issues
                        if (!result.IsValid)
                        {
                            results.Add(result);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _ltasLogger.LogError(ex, $"Failed to check login profile for user: {user.ArtifactId}");
                    _ltasHelper.Logger.LogError(ex, $"Failed to check login profile for user: {user.ArtifactId}");
                }
            }
            _ltasLogger.LogInformation($"Found {results?.Count ?? 0} quinn users with login method issues");

            if (results?.Count > 0)
            {
                string message = "The following quinn users have some form of problem with the login method on their accounts, these need to reviewed and resolved.";
                var emailbody = MessageHandler.EmailBody.LoginValidationEmailBody(results, message).ToString();
                await MessageHandler.Email.SendInternalNotificationAsync(
                    _instanceSettingsBundle,
                    emailbody,
                    "Quinn Users With Invalid Login Method");
            }
            return results;
        }

        
        public async Task<List<PasswordAuthValidation>> ValidatePasswordAndTwoFactorAsync(List<Users> users)
        {
            var results = new List<PasswordAuthValidation>();

            foreach (var user in users)
            {
                try
                {
                    //_ltasLogger.LogInformation($"Checking password auth and 2FA for user: {user.ArtifactId} ({user.EmailAddress})");

                    var result = new PasswordAuthValidation
                    {
                        UserArtifactId = user.ArtifactId,
                        EmailAddress = user.EmailAddress,
                        FirstName = user.FirstName,
                        LastName = user.LastName
                    };

                    var servicesManager = _helper.GetServicesManager();
                    using (var loginProfileManager = servicesManager.CreateProxy<ILoginProfileManager>(ExecutionIdentity.System))
                    {
                        var profile = await loginProfileManager.GetLoginProfileAsync(user.ArtifactId);

                        // Check if user is using password authentication
                        result.IsUsingPasswordAuth = profile.Password != null && profile.Password.IsEnabled;

                        if (result.IsUsingPasswordAuth)
                        {
                            //_ltasLogger.LogInformation($"User {user.ArtifactId} has password authentication enabled");

                            // Check if 2FA is enabled by verifying TwoFactorProtocol has a value
                            result.Has2FAEnabled = profile.Password.TwoFactorProtocol.HasValue.Equals(true);

                            if (!result.Has2FAEnabled)
                            {
                               // _ltasLogger.LogInformation($"User {user.ArtifactId} does not have 2FA enabled");
                                result.ValidationMessage = "User has password authentication enabled but 2FA is not configured";
                                results.Add(result);
                            }
                            else
                            {
                                //_ltasLogger.LogInformation($"User {user.ArtifactId} has 2FA enabled ({profile.Password.TwoFactorProtocol})");
                            }
                        }
                        else
                        {
                            //_ltasLogger.LogInformation($"User {user.ArtifactId} is not using password authentication");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _ltasLogger.LogError(ex, $"Failed to check password auth and 2FA for user: {user.ArtifactId}");
                    _ltasHelper.Logger.LogError(ex, $"Failed to check password auth and 2FA for user: {user.ArtifactId}");

                    // Create validation result for errored user
                    results.Add(new PasswordAuthValidation
                    {
                        UserArtifactId = user.ArtifactId,
                        EmailAddress = user.EmailAddress,
                        FirstName = user.FirstName,
                        LastName = user.LastName,
                        ValidationMessage = $"Error checking authentication settings: {ex.Message}"
                    });
                }
            }

            // Log summary
            _ltasLogger.LogInformation($"Completed password and 2FA validation for {users.Count} users");
            _ltasLogger.LogInformation($"Found {results.Count} users with password auth enabled but no 2FA");

            return results;
        }

        public async Task<List<UserClientValidation>> ValidateUsersClientAsync(List<Users> users, IInstanceSettingsBundle instanceSettingsBundle)
        {
            var singleSettingValueEnvironment = instanceSettingsBundle.GetStringAsync("Relativity.Core", "RelativityInstanceURL");
            string environmentValue = singleSettingValueEnvironment.Result.Split('-')[1].Split('.')[0].ToUpper();
            
            var results = new List<UserClientValidation>();
            int targetClientId = 0;
            //finds the environment that the user is in and their client ID
            switch (environmentValue)
            {
                case ("US"):
                    targetClientId = 1348948;                    
                    break;

                case ("EU"):
                    targetClientId = 1067216;
                    break;

                case ("AU"):
                    targetClientId = 1304327;
                    break;
            }
                foreach (var user in users)
            {
                try
                {                   
                    var result = new UserClientValidation
                    {
                        UserArtifactId = user.ArtifactId,
                        ClientArtifactId = targetClientId
                    };

                    var servicesManager = _helper.GetServicesManager();
                    using (var userManager = servicesManager.CreateProxy<IUserManager>(ExecutionIdentity.System))
                    {
                        try
                        {
                            var response = await userManager.ReadAsync(user.ArtifactId);

                            if (response.Client?.Value != null && !response.Client.Secured)
                            {
                                int currentClientId = response.Client.Value.ArtifactID;
                                // Only add users with the target client ID
                                if (currentClientId != targetClientId)
                                {
                                    results.Add(result);                                    
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _ltasLogger.LogError(ex, $"Error reading user data for: {user.ArtifactId}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _ltasLogger.LogError(ex, $"Failed to check client for user: {user.ArtifactId}");
                    _ltasHelper.Logger.LogError(ex, $"Failed to check client for user: {user.ArtifactId}");
                }
            }

            _ltasLogger.LogInformation($"Found {results.Count} users to update to client ID {targetClientId}");

            return results;
        }

        public async Task UpdateUsersToNewClientAsync(List<UserClientValidation> users)
        {
            try
            {               
                foreach (var user in users)
                {                   
                    try
                    {
                        var servicesManager = _helper.GetServicesManager();
                        using (var userManager = servicesManager.CreateProxy<IUserManager>(ExecutionIdentity.System))
                        {
                            var userResponse = await userManager.ReadAsync(user.UserArtifactId);
                            var userRequest = new UserRequest(userResponse)
                            {
                                Client = new Securable<ObjectIdentifier>
                                {
                                    Value = new ObjectIdentifier { ArtifactID = user.ClientArtifactId},
                                    Secured = false
                                }
                            };

                            await userManager.UpdateAsync(user.UserArtifactId, userRequest);
                            _ltasLogger.LogInformation($"Successfully updated client for user: {user.UserArtifactId} ({userResponse.EmailAddress}) to {user.ClientArtifactId}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _ltasLogger.LogError(ex, $"Failed to update client for user: {user.UserArtifactId}");
                        _ltasHelper.Logger.LogError(ex, $"Failed to update client for user: {user.UserArtifactId}");
                    }
                }
                _ltasLogger.LogInformation($"Completed client update process");
            }
            catch (Exception ex)
            {
                _ltasLogger.LogError(ex, "Failed to process client updates");
                _ltasHelper.Logger.LogError(ex, "Failed to process client updates");
                throw;
            }
        }
    }
}
