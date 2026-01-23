using LTAS_User_Management.Models;
using LTAS_User_Management.Utilities;
using Relativity.API;
using System;
using System.Collections.Generic;
using System.Data;
using static kCura.Vendor.Castle.MicroKernel.ModelBuilder.Descriptors.InterceptorDescriptor;

namespace LTAS_User_Management.Handlers
{
    public class DataHandler
    {
        private readonly IDBContext _eddsDbContext;        
        private readonly LTASUMHelper _ltasHelper;

        public DataHandler(IDBContext eddsDbContext, IHelper helper, IAPILog logger)
        {
            _eddsDbContext = eddsDbContext;            
            _ltasHelper = new LTASUMHelper(helper, logger.ForContext<DataHandler>());
        }

        /// <summary>
        /// Retrieves users who only belong to the 'Everyone' group and have Relativity access,
        /// excluding Relativity/KCura domain users
        /// </summary>
        /// <returns>List of users with no additional group memberships or null if an error occurs</returns>
        public List<Users> UsersWithNoGroups()
        {
            try
            {
                var users = new List<Users>();
                string sql = @"SELECT DISTINCT
                        u.ArtifactID, 
                        u.FirstName, 
                        u.LastName, 
                        u.EmailAddress
                    FROM EDDS.eddsdbo.[User] u WITH (NOLOCK)
                    JOIN EDDS.eddsdbo.GroupUser gu WITH (NOLOCK) 
                        ON gu.UserArtifactID = u.ArtifactID
                    JOIN EDDS.eddsdbo.[Group] g WITH (NOLOCK) 
                        ON g.ArtifactID = gu.GroupArtifactID
                    JOIN
                    (
                        SELECT gu.UserArtifactID, COUNT(gu.GroupArtifactID) AS 'Group Count'
                        FROM EDDS.eddsdbo.GroupUser gu WITH (NOLOCK)
                        GROUP BY gu.UserArtifactID
                        HAVING COUNT(gu.GroupArtifactID) = 1
                    ) gc
                        ON gc.UserArtifactID = u.ArtifactID 
                    WHERE   
                        u.RelativityAccess = 1
                        AND g.[Name] = 'Everyone'
                        AND u.EmailAddress NOT LIKE '%kcura.com%'
                        AND u.EmailAddress NOT LIKE '%relativity.com%';";

                var dt = _eddsDbContext.ExecuteSqlStatementAsDataTable(sql);
                foreach (DataRow row in dt.Rows)
                {
                    users.Add(new Users()
                    {
                        ArtifactId = row.Field<int>("ArtifactID"),
                        FirstName = row["FirstName"]?.ToString(),
                        LastName = row["LastName"]?.ToString(),
                        EmailAddress = row["EmailAddress"]?.ToString()
                    });
                }
                return users;
            }
            catch (Exception ex)
            {
                var errorMessage = ex.InnerException != null ?
                    $"{ex.InnerException.Message}---{ex.StackTrace}" :
                    $"{ex.Message}---{ex.StackTrace}";
                _ltasHelper.Logger.ForContext<DataHandler>().LogError($"{errorMessage}");
                return null;
            }
        }    
        /// <summary>
        /// Retrieves Quinn Emanuel users to user for a looking up login method
        /// </summary>
        /// <returns>List of users (quinn) or null if an error occurs</returns>
        public List<Users> QuinnUsers()
        {           
            try
            {                
                var users = new List<Users>();
                string sql = @"SELECT DISTINCT
                                u.ArtifactID,                                 
                                u.FirstName, 
                                u.LastName, 
                                u.EmailAddress                               
                            FROM EDDS.EDDSDBO.[User] u WITH (NOLOCK)
                            WHERE   
                                    u.EmailAddress LIKE '%@quinnemanuel.com'                                
                                AND u.EmailAddress NOT IN ('ltasrelativity@quinnemanuel.com','ah@quinnemanuel.com')
                                AND u.RelativityAccess = 1";
                
                var dt = _eddsDbContext.ExecuteSqlStatementAsDataTable(sql);                

                foreach (DataRow row in dt.Rows)
                {               
                    users.Add(new Users()
                    {
                        ArtifactId = row.Field<int>("ArtifactID"),
                        FirstName = row["FirstName"]?.ToString(),
                        LastName = row["LastName"]?.ToString(),
                        EmailAddress = row["EmailAddress"]?.ToString()
                    });
                }                
                return users;
            }
            catch (Exception ex)
            {
                var errorMessage = ex.InnerException != null ?
                    $"{ex.InnerException.Message}---{ex.StackTrace}" :
                    $"{ex.Message}---{ex.StackTrace}";
                _ltasHelper.Logger.ForContext<DataHandler>().LogError($"{errorMessage}");
                return null;
            }
        }

        /// <summary>
        /// Retrieves Non Quinn Emanuel users to user for a looking up login method
        /// </summary>
        /// <returns>List of non quinn users or null if an error occurs</returns>hey
        public List<Users> NonQuinnUsers()
        {
            try
            {
                var users = new List<Users>();

                string sql = @"SELECT
                                    u.ArtifactID, 
                                    u.FirstName, 
                                    u.LastName, 
                                    u.EmailAddress
                                FROM EDDS.eddsdbo.[User] u WITH (NOLOCK)
                                WHERE   u.EmailAddress NOT LIKE '%@kcura.com'
                                    AND u.EmailAddress NOT LIKE '%@PreviewUser.com'
                                    AND u.EmailAddress NOT LIKE '%@relativity.com'
                                    AND u.EmailAddress NOT LIKE '%@quinnemanuel.com'
                                    AND u.RelativityAccess = 1";

                var dt = _eddsDbContext.ExecuteSqlStatementAsDataTable(sql);

                foreach (DataRow row in dt.Rows)
                {
                    users.Add(new Users()
                    {
                        ArtifactId = row.Field<int>("ArtifactID"),
                        FirstName = row["FirstName"]?.ToString(),
                        LastName = row["LastName"]?.ToString(),
                        EmailAddress = row["EmailAddress"]?.ToString()
                    });
                }
                return users;
            }
            catch (Exception ex)
            {
                var errorMessage = ex.InnerException != null ?
                    $"{ex.InnerException.Message}---{ex.StackTrace}" :
                    $"{ex.Message}---{ex.StackTrace}";
                _ltasHelper.Logger.ForContext<DataHandler>().LogError($"{errorMessage}");
                return null;
            }
        }

        public List<Users> QuinnUsersWrongClient(int clientArtifactId)
        {
            try
            {
                var users = new List<Users>();

                string sql = $@"SELECT DISTINCT
                                eu.ArtifactID,                                 
                                eu.FirstName, 
                                eu.LastName, 
                                eu.EmailAddress                               
                            FROM EDDS.EDDSDBO.[ExtendedUser] eu WITH (NOLOCK)
                            WHERE   
                                 eu.EmailAddress LIKE '%@quinnemanuel.com'
                             AND eu.ClientArtifactID <> {clientArtifactId}";

                var dt = _eddsDbContext.ExecuteSqlStatementAsDataTable(sql);

                foreach (DataRow row in dt.Rows)
                {
                    users.Add(new Users()
                    {
                        ArtifactId = row.Field<int>("ArtifactID"),
                        FirstName = row["FirstName"]?.ToString(),
                        LastName = row["LastName"]?.ToString(),
                        EmailAddress = row["EmailAddress"]?.ToString()
                    });
                }
                return users;
            }
            catch (Exception ex)
            {
                var errorMessage = ex.InnerException != null ?
                    $"{ex.InnerException.Message}---{ex.StackTrace}" :
                    $"{ex.Message}---{ex.StackTrace}";
                _ltasHelper.Logger.ForContext<DataHandler>().LogError($"{errorMessage}");
                return null;
            }
        }

        public void InsertUserToTrackingTable(int userArtifactID)
        {
            try
            {
                string sql = $"INSERT INTO EDDS.QE.LTASDisabledUsers (UserArtifactID) VALUES ({userArtifactID});";

                _eddsDbContext.ExecuteNonQuerySQLStatement(sql);
            }
            catch (Exception ex) 
            {
                var errorMessage = ex.InnerException != null ?
                    $"{ex.InnerException.Message}---{ex.StackTrace}" :
                    $"{ex.Message}---{ex.StackTrace}";
                _ltasHelper.Logger.ForContext<DataHandler>().LogError($"{errorMessage}");
            }
        }

        /// <summary>
        /// Retrieves extended users with ItemListPageLength not equal to 200
        /// </summary>
        /// <returns>List of extended users or null if an error occurs</returns>
        public List<Users> ItemListUsersToUpdate()
        {
            try
            {
                var users = new List<Users>();
                string sql = @"SELECT
                        eu.ArtifactID, 
                        eu.FirstName, 
                        eu.LastName, 
                        eu.EmailAddress
                    FROM eddsdbo.ExtendedUser eu
                    WHERE eu.ItemListPageLength != 200
                        AND LastName NOT LIKE 'Preview'";

                var dt = _eddsDbContext.ExecuteSqlStatementAsDataTable(sql);
                foreach (DataRow row in dt.Rows)
                {
                    users.Add(new Users()
                    {
                        ArtifactId = row.Field<int>("ArtifactID"),
                        FirstName = row["FirstName"]?.ToString(),
                        LastName = row["LastName"]?.ToString(),
                        EmailAddress = row["EmailAddress"]?.ToString()
                    });
                }
                return users;
            }
            catch (Exception ex)
            {
                var errorMessage = ex.InnerException != null ?
                    $"{ex.InnerException.Message}---{ex.StackTrace}" :
                    $"{ex.Message}---{ex.StackTrace}";
                _ltasHelper.Logger.ForContext<DataHandler>().LogError($"{errorMessage}");
                return null;
            }
        }
        public void AuditHouseKeeping()
        {  
            try
            {
                string sql = @"DELETE FROM qe.ApplicationLog_UserMgmt WHERE LogDateTime < DATEADD(day, -30, GETDATE())";
                _eddsDbContext.ExecuteNonQuerySQLStatement(sql);
            }
            catch (Exception ex)
            {
                var errorMessage = ex.InnerException != null ?
                    $"{ex.InnerException.Message}---{ex.StackTrace}" :
                    $"{ex.Message}---{ex.StackTrace}";
                _ltasHelper.Logger.ForContext<DataHandler>().LogError($"Failed to clean up old audit records: {errorMessage}");
            }
        }
    }
}
