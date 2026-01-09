
using System.Collections.Generic;

namespace LTAS_User_Management.Models
{
    public class Users
    {
        public int ArtifactId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string EmailAddress { get; set; }
    }
    public class LoginProfileValidation
    {
        public bool IsValid { get; set; }
        public List<string> InvalidProviderTypes { get; set; } = new List<string>();
        public int UserArtifactId { get; set; }
        public string EmailAddress { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public bool HasMultipleProviders { get; set; }
        public bool HasNoValidProvider { get; set; }
        public string ValidationMessage { get; set; }
    }

    public class PasswordAuthValidation
    {
        public int UserArtifactId { get; set; }
        public string EmailAddress { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public bool IsUsingPasswordAuth { get; set; }
        public bool Has2FAEnabled { get; set; }
        public string ValidationMessage { get; set; }
    }

    public class UserClientValidation
    {
        public int UserArtifactId { get; set; }
        public int ClientArtifactId { get; set; }  // Added this to store the ID
        //public string ValidationMessage { get; set; }
        //public string EmailAddress { get; set; } // user email
        //public string FirstName { get; set; } // user first name
        //public string LastName { get; set; } // user last name
        //public string ClientName { get; set; }
    }
}
