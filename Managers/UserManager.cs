using LTAS_User_Management.Handlers;
using LTAS_User_Management.Logging;
using LTAS_User_Management.Models;
using LTAS_User_Management.Utilities;
using Relativity.API;
using System.Collections.Generic;
using System.Threading.Tasks;
using System;
using Relativity.Identity.V1.Services;
using System.Text;

public class UserManager
{    
    private readonly DataHandler _dataHandler;
    private readonly LTASUMHelper _ltasHelper;
    private readonly IInstanceSettingsBundle _instanceSettingsBundle;
    private readonly ILTASLogger _ltasLogger;    
    private readonly UserHandler _userHandler;

    public UserManager(        
        DataHandler dataHandler,
        IAPILog logger,
        IHelper helper,
        IInstanceSettingsBundle instanceSettingsBundle,
        IDBContext eddsDbContext,
        IUserManager userManager)
    {
        _dataHandler = dataHandler ?? throw new ArgumentNullException(nameof(dataHandler));
        _ltasHelper = new LTASUMHelper(helper, logger.ForContext<UserManager>());
        _instanceSettingsBundle = instanceSettingsBundle ?? throw new ArgumentNullException(nameof(instanceSettingsBundle));
        _ltasLogger = LoggerFactory.CreateLogger<UserManager>(eddsDbContext, helper, _ltasHelper.Logger);       
        _userHandler = new UserHandler(userManager, eddsDbContext, helper, logger);
    }

    public async Task ProcessUserManagementRoutinesAsync()
    {
        try
        {
            _ltasLogger.LogInformation("Starting user management routines");
            var usersWithNoGroups = _dataHandler.UsersWithNoGroups();
            _ltasLogger.LogInformation($"Found {usersWithNoGroups?.Count ?? 0} active users with no groups");

            if (usersWithNoGroups?.Count > 0)
            {
                var disabledUsers = await UsersWithNoGroupsAsync(usersWithNoGroups);


                string message = "The following users have been disabled due to having no active groups:";
                var emailBody = MessageHandler.EmailBody.DisabledUsersEmailBody(disabledUsers, message).ToString();
                await MessageHandler.Email.SendInternalNotificationAsync(
                    _instanceSettingsBundle,
                    emailBody,
                    "Users With No Groups Report");
            }

            var quinnUsers = _dataHandler.QuinnUsers();
            _ltasLogger.LogInformation($"Found {quinnUsers?.Count ?? 0} quinn users to lookup their login method");

            if (quinnUsers?.Count > 0)
            {
                var quinnUsersWithLoginIssues = await _userHandler.ValidateUsersLoginProfilesAsync(quinnUsers, _instanceSettingsBundle);
                //TODO: add in cilent update for QE users and system admin update
            }

            var nonQuinnUsers = _dataHandler.NonQuinnUsers();
            _ltasLogger.LogInformation($"Found {nonQuinnUsers?.Count ?? 0} non quinn users to lookup 2FA authenication");

            if (nonQuinnUsers?.Count > 0)
            {
                var nonQuinnUsersWith2FAIssues = await _userHandler.ValidatePasswordAndTwoFactorAsync(nonQuinnUsers);

                if (nonQuinnUsersWith2FAIssues?.Count > 0)
                {
                    string message = "The following external users need to have 2FA implemented, please enable 2FA on these accounts.";
                    var emailbody = MessageHandler.EmailBody.PasswordAuthEmailBody(nonQuinnUsersWith2FAIssues, message).ToString();
                    await MessageHandler.Email.SendInternalNotificationAsync(
                        _instanceSettingsBundle,
                        emailbody,
                        "Users That Require 2FA setup");
                }
            }

            await UpdateItemListPageAndSendEmailAsync();

            _ltasLogger.LogInformation("User management routines completed");            
        }
        catch (Exception ex)
        {
            _ltasLogger.LogError(ex, "Failed to process user management routines");
            _ltasHelper.Logger.LogError(ex, "Failed to process user management routines");
        }
    }

    private async Task <List<Users>> UsersWithNoGroupsAsync(List<Users> usersWithNoGroups)
    {
        try
        {
            var disabledUsers = new List<Users>();
            _ltasLogger.LogInformation($"Starting to disable {usersWithNoGroups.Count} users with no groups...");
            
            foreach (var user in usersWithNoGroups)
            {
                try
                {
                    await _userHandler.DisableUserAsync(user.ArtifactId);
                    _dataHandler.InsertUserToTrackingTable(user.ArtifactId);
                    disabledUsers.Add(user);
                    
                    _ltasLogger.LogInformation($"Successfully disabled user {user.ArtifactId} ({user.EmailAddress})");              
                }
                catch (Exception userEx)
                {
                    _ltasLogger.LogError(userEx, $"Failed to disable user {user.ArtifactId} ({user.EmailAddress})");
                    _ltasHelper.Logger.LogError(userEx, $"Failed to disable user {user.ArtifactId} ({user.EmailAddress})");
                }
            }

            _ltasLogger.LogInformation($"Completed processing. Disabled {disabledUsers.Count} out of {usersWithNoGroups.Count} users");            

            return disabledUsers;
        }
        catch (Exception ex)
        {
            _ltasLogger.LogError(ex, "Error in UsersWithNoGroupsAsync");
            _ltasHelper.Logger.LogError(ex, "Error in UsersWithNoGroupsAsync");
            throw;
        }
    }


    public async Task UpdateItemListPageAndSendEmailAsync()
    {
        var quinnUsersIncorrectItemListPage = _dataHandler.ItemListUsersToUpdate();
        _ltasLogger.LogInformation($"Found {quinnUsersIncorrectItemListPage?.Count ?? 0} total users that have an item list not set to 200.");

        List<Users> updatedUsers = new List<Users>();

        if (quinnUsersIncorrectItemListPage?.Count > 0)
        {            
            _ltasLogger.LogInformation($"Starting ItemListPage Updates...");
            foreach (var user in quinnUsersIncorrectItemListPage)
            {
                try
                {
                    await _userHandler.UpdateItemListUserAsync(user.ArtifactId);         
                    updatedUsers.Add(user); // Add successfully updated user to our list
                }
                catch (Exception ex)
                {
                    _ltasLogger.LogError(ex, $"Failed to update item list page for user: {user.ArtifactId} ({user.EmailAddress})");
                    _ltasHelper.Logger.LogError(ex, $"Failed to update item list page for user: {user.ArtifactId} ({user.EmailAddress})");
                }
            }

            _ltasLogger.LogInformation($"Updated item list page: {updatedUsers.Count} out of {quinnUsersIncorrectItemListPage.Count} users updated.");
           
            if (updatedUsers.Count > 0)
            {
                try
                {
                    string emailMessage = $"The following users had their Item List Page Length updated to 200:";
                    StringBuilder emailBody = MessageHandler.EmailBody.ItemListUpdateEmailBody(updatedUsers, emailMessage);
                    await MessageHandler.Email.SendInternalNotificationAsync(_instanceSettingsBundle, emailBody.ToString(), $"Item List Page Length Update - {DateTime.Now.ToString("MM/dd/yyyy")}");                 
                    _ltasLogger.LogInformation($"Email notification sent with {updatedUsers.Count} updated users");
                }
                catch (Exception ex)
                {
                    _ltasLogger.LogError(ex, "Failed to send email notification about updated users");
                    _ltasHelper.Logger.LogError(ex, "Failed to send email notification about updated users");
                }
            }
        }
    }

}