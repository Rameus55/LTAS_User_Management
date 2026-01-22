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

        public async Task<bool> AdminUpdateAsync(int userArtifactId)
        {
            try
            {
                UserResponse userResponse = await _userManager.ReadAsync(userArtifactId);

                if (userResponse.Keywords != "Do Not Bill")
                {
                    _ltasLogger.LogInformation($"Updating admin user {userArtifactId} keyword to 'Do Not Bill'");
                    UserRequest userRequest = new UserRequest(userResponse)
                    {
                        Keywords = "Do Not Bill"
                    };
                    await _userManager.UpdateAsync(userArtifactId, userRequest);
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                _ltasLogger.LogError(ex, $"Failed to update admin user: {userArtifactId}");
                _ltasHelper.Logger.LogError(ex, $"Failed to update admin user: {userArtifactId}");
                return false;
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
                QueryRequest queryRequest = new QueryRequest
                {
                    Fields = new FieldRef[]
                    {
                        new FieldRef { Name = "ArtifactID" },
                        new FieldRef { Name = "Name" }
                    }
                };
                var result = await _userManager.QueryGroupsByUserAsync(queryRequest, 0, 10000, userArtifactId);
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

                    // Check if user is in admin groups
                    bool isAdmin = false;
                    var userGroups = await RetrieveGroupsForUser(user.ArtifactId);
                    if (userGroups != null && userGroups.Objects != null)
                    {
                        foreach (var group in userGroups.Objects)
                        {
                            string groupName = group.Values?.Count > 1 ? group.Values[1]?.ToString() : null;
                            if (groupName != null &&
                                (groupName.Equals("System Administrators", StringComparison.OrdinalIgnoreCase) ||
                                 groupName.Equals("QE_LTAS_ADMIN", StringComparison.OrdinalIgnoreCase)))
                            {
                                isAdmin = true;
                                await AdminUpdateAsync(user.ArtifactId);
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

                        // Check for valid authentication methods
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
                                    if (method.ProviderName.Replace(" ", "").IndexOf("oktaadmin", StringComparison.OrdinalIgnoreCase) >= 0)
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
                                    if (method.ProviderName.Replace(" ", "").IndexOf("oktaadmin", StringComparison.OrdinalIgnoreCase) >= 0)
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
                            // Admin users must use BOTH Okta AND OktaAdmin
                            result.IsValid = hasOktaAdmin && hasOkta && result.InvalidProviderTypes.Count == 0;
                            result.HasNoValidProvider = !hasOktaAdmin || !hasOkta;

                            if (!hasOktaAdmin && !hasOkta)
                            {
                                result.ValidationMessage = "System Administrator or QE_LTAS_ADMIN user must use both Okta and OktaAdmin providers";
                            }
                            else if (!hasOktaAdmin)
                            {
                                result.ValidationMessage = "System Administrator or QE_LTAS_ADMIN user is missing OktaAdmin provider";
                            }
                            else if (!hasOkta)
                            {
                                result.ValidationMessage = "System Administrator or QE_LTAS_ADMIN user is missing standard Okta provider";
                            }
                            else if (result.InvalidProviderTypes.Count > 0)
                            {
                                result.HasMultipleProviders = true;
                                result.ValidationMessage = $"Admin user has additional invalid providers: {string.Join(", ", result.InvalidProviderTypes)}";
                            }
                        }
                        else
                        {
                            // Regular Quinn users must use standard Okta only
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

                        result.IsUsingPasswordAuth = profile.Password != null && profile.Password.IsEnabled;
                        if (result.IsUsingPasswordAuth)
                        {
                            result.Has2FAEnabled = profile.Password.TwoFactorProtocol.HasValue.Equals(true);
                            if (!result.Has2FAEnabled)
                            {
                                result.ValidationMessage = "User has password authentication enabled but 2FA is not configured";
                                results.Add(result);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _ltasLogger.LogError(ex, $"Failed to check password auth and 2FA for user: {user.ArtifactId}");
                    _ltasHelper.Logger.LogError(ex, $"Failed to check password auth and 2FA for user: {user.ArtifactId}");

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

            _ltasLogger.LogInformation($"Found {results.Count} users with password auth enabled but no 2FA");
            return results;
        }

        public async Task<List<UserClientValidation>> ValidateUsersClientAsync(List<Users> users, IInstanceSettingsBundle instanceSettingsBundle)
        {
            var singleSettingValueEnvironment = instanceSettingsBundle.GetStringAsync("Relativity.Core", "RelativityInstanceURL");
            string environmentValue = singleSettingValueEnvironment.Result.Split('-')[1].Split('.')[0].ToUpper();

            var results = new List<UserClientValidation>();
            int targetClientId = 0;

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
                                    Value = new ObjectIdentifier { ArtifactID = user.ClientArtifactId },
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

        public async Task<List<int>> UpdateAdminGroupUsersAsync(List<Users> users)
        {
            var updatedUserIds = new List<int>();

            _ltasLogger.LogInformation($"Starting admin group user update process for {users.Count} users");

            foreach (var user in users)
            {
                try
                {
                    var userGroups = await RetrieveGroupsForUser(user.ArtifactId);

                    if (userGroups?.Objects != null)
                    {
                        bool isAdminUser = false;

                        foreach (var group in userGroups.Objects)
                        {
                            string groupName = group.Values?.Count > 1 ? group.Values[1]?.ToString() : null;

                            if (groupName != null &&
                                (groupName.Equals("System Administrators", StringComparison.OrdinalIgnoreCase) ||
                                 groupName.Equals("QE_LTAS_ADMIN", StringComparison.OrdinalIgnoreCase)))
                            {
                                isAdminUser = true;
                                break;
                            }
                        }

                        if (isAdminUser)
                        {
                            bool wasUpdated = await AdminUpdateAsync(user.ArtifactId);
                            if (wasUpdated)
                            {
                                updatedUserIds.Add(user.ArtifactId);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _ltasLogger.LogError(ex, $"Failed to process admin update for user: {user.ArtifactId}");
                    _ltasHelper.Logger.LogError(ex, $"Failed to process admin update for user: {user.ArtifactId}");
                }
            }

            _ltasLogger.LogInformation($"Completed admin group user update. Updated {updatedUserIds.Count} users");
            return updatedUserIds;
        }
    }
}