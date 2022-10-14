package Queries

import (
	"fmt"
	"ldapper/Globals"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

/*var userAccountControlMap = map[string]string{
	"66050": "No",
	"66048": "Yes",
	"514":   "Account Locked",
}*/

var userAccountControlMap = map[int]string{
	0x00000002: "USER_ACCOUNT_DISABLED",
	0x00000008: "USER_HOME_DIRECTORY_REQUIRED",
	0x00000020: "USER_PASSWORD_NOT_REQUIRED",
	0x00000100: "USER_TEMP_DUPLICATE_ACCOUNT",
	0x00000200: "USER_NORMAL_ACCOUNT",
	0x00020000: "USER_MNS_LOGON_ACCOUNT",
	0x00000800: "USER_INTERDOMAIN_TRUST_ACCOUNT",
	0x00001000: "USER_WORKSTATION_TRUST_ACCOUNT",
	0x00002000: "USER_SERVER_TRUST_ACCOUNT",
	0x00010000: "USER_DONT_EXPIRE_PASSWORD",
	0x00000010: "USER_ACCOUNT_AUTO_LOCKED",
	0x00000080: "USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED",
	0x00040000: "USER_SMARTCARD_REQUIRED",
	0x00080000: "USER_TRUSTED_FOR_DELEGATION",
	0x00100000: "USER_NOT_DELEGATED",
	0x00008000: "USER_USE_DES_KEY_ONLY",
	0x00200000: "USER_DONT_REQUIRE_PREAUTH",
	0x00800000: "USER_PASSWORD_EXPIRED",
	0x01000000: "USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION",
	0x02000000: "USER_NO_AUTH_DATA_REQUIRED",
	0x04000000: "USER_PARTIAL_SECRETS_ACCOUNT",
	0x08000000: "USER_USE_AES_KEYS",
}

func NetUserQuery(usernameInput string, baseDN string, conn *ldap.Conn) (queryResult string) {

	query := fmt.Sprintf("(samAccountName=%s)", usernameInput) // Query to search for user
	searchReq := Globals.LdapSearch(baseDN, query)             // Search request
	result, err := conn.Search(searchReq)
	if err != nil {
		fmt.Printf("Query error, %s", err)

	}

	// if LdapSearch returns information
	if len(result.Entries) > 0 {

		//Check if user
		objectClass := result.Entries[0].GetAttributeValues("objectClass")
		isUser := false

		for i := 0; i < len(objectClass); i++ {
			if result.Entries[0].GetAttributeValues("objectClass")[i] == "user" {
				isUser = true
			}
		}

		if isUser {
			queryResult += fmt.Sprintf("\nUser Information - %s:\n-------------------------------------------------------------------------------\n", usernameInput)
			//get username
			username := result.Entries[0].GetAttributeValues("sAMAccountName") // Get username
			if len(username) > 0 {                                             // If username is not empty
				queryResult += fmt.Sprintf("User Name: \t%s\n", username[0])
			}

			//get Full Name
			userCN := result.Entries[0].GetAttributeValues("cn")[0]
			userCNEsc := strings.Replace(userCN, "\\", "", -1)
			userCNEsc = strings.Replace(userCNEsc, "(", ldap.EscapeFilter("("), -1) //Escape parenthesis
			userCNEsc = strings.Replace(userCNEsc, ")", ldap.EscapeFilter(")"), -1)
			queryResult += fmt.Sprintf("Full Name: \t%s\n", userCN)

			//get Comments
			if len(result.Entries[0].GetAttributeValues("description")) > 0 { // If comments is not empty
				description := result.Entries[0].GetAttributeValues("description")[0] // Get comments
				queryResult += fmt.Sprintf("Comment: \t%s\n", description)            // Print comments
			} else {
				queryResult += ("Comment: \t\n")
			}

			//get Account Active
			userAccountControlQuery := fmt.Sprintf("(cn=%s)", userCNEsc)                    // Query to search for user
			userAccountControlSearch := Globals.LdapSearch(baseDN, userAccountControlQuery) // Search request

			userAccountControlResult, err := conn.Search(userAccountControlSearch)
			if err != nil {
				fmt.Printf("User Account Control query error, %s", err)

			}

			// Get userAccountControl and convert to int for bitwise operations
			userAccountControl, err := strconv.Atoi(userAccountControlResult.Entries[0].GetAttributeValues("userAccountControl")[0])
			if err != nil {
				fmt.Printf("User Account Control conversion error, %s", err)

			}

			// Get all the user account attributes
			queryResult += fmt.Sprintf("User Account Control: ")
			for code, _ := range userAccountControlMap {
				if (code & userAccountControl) > 0 {
					queryResult += fmt.Sprintf("\t%s\n", userAccountControlMap[code])
				}

			}
			queryResult += fmt.Sprintf("\t(If Enabled, Check Last Lockout Time)\n")

			if len(userAccountControlResult.Entries[0].GetAttributeValues("lockoutTime")) > 0 {
				lockoutTime := userAccountControlResult.Entries[0].GetAttributeValues("lockoutTime")[0]
				if lockoutTime != "0" {
					lockoutTime, err := strconv.Atoi(lockoutTime)
					if err != nil {
						fmt.Printf("Error converting timestamp\n")

					}
					humanTime := Globals.ConvertLDAPTime(lockoutTime).Format("01/02/2006 03:04:05 PM") // Convert timestamp to human readable format
					queryResult += fmt.Sprintf("Last Lockout Time: \t%s\n", humanTime)                 // Print human readable timestamp
				}
			} else {
				queryResult += ("Last Lockout Time: \t\n")
			}

			// get user expiration date
			accountExpires := result.Entries[0].GetAttributeValues("accountExpires")[0] // Get accountExpires
			if accountExpires == "9223372036854775807" || accountExpires == "0" {       // If accountExpires never expires
				queryResult += ("Account Expires: \tNever\n")
			} else {
				ldapTimeInt, err := strconv.Atoi(accountExpires) // Convert string to int
				if err != nil {
					fmt.Printf("Error converting timestamp\n") // if error, print error

				} else {
					humanTime := Globals.ConvertLDAPTime(ldapTimeInt).Format("01/02/2006 03:04:05 PM") // Convert timestamp to human readable format
					queryResult += fmt.Sprintf("Account Expires: \t%s\n", humanTime)
				}
			}

			// get user last password set date
			pwdLastSet := result.Entries[0].GetAttributeValues("pwdLastSet")[0] // Get pwdLastSet
			ldapTimeInt, err := strconv.Atoi(pwdLastSet)                        // Convert string to int
			if err != nil {
				fmt.Printf("Error converting timestamp\n")

			} else {
				humanTime := Globals.ConvertLDAPTime(ldapTimeInt).Format("01/02/2006 03:04:05 PM") // Convert timestamp to human readable format
				queryResult += fmt.Sprintf("Password Last Set: \t%s\n", humanTime)
			}

			//get user homeDirectory
			if len(userAccountControlResult.Entries[0].GetAttributeValues("homeDirectory")) > 0 { // If homeDirectory is not empty
				homeDirectory := result.Entries[0].GetAttributeValues("homeDirectory")[0] // Get homeDirectory
				queryResult += fmt.Sprintf("Home Directory: \t%s\n", homeDirectory)       // Print homeDirectory
			} else {
				queryResult += ("Home Directory: \t\n")
			}

			// Get user last logon date
			if len(userAccountControlResult.Entries[0].GetAttributeValues("lastLogon")) > 0 { // If lastLogon is not empty
				lastLogon := result.Entries[0].GetAttributeValues("lastLogon")[0] // Get lastLogon
				ldapTimeInt, err = strconv.Atoi(lastLogon)                        // Convert string to int
				if err != nil {
					fmt.Printf("Error converting timestamp\n") // if error, print error

				} else {
					humanTime := Globals.ConvertLDAPTime(ldapTimeInt).Format("01/02/2006 03:04:05 PM") // Convert timestamp to human readable format
					if strings.Contains(humanTime, "12/31/1600") {
						humanTime = "Never"
					}
					queryResult += fmt.Sprintf("Last Logon: \t%s\n", humanTime)
				}
			} else {
				queryResult += ("Last Logon: \t\n")
			}

			//Get logon count
			if len(userAccountControlResult.Entries[0].GetAttributeValues("logonCount")) > 0 { // If not empty
				lastLogon := result.Entries[0].GetAttributeValues("logonCount")[0] //
				queryResult += fmt.Sprintf("Logon Count: \t%s\n", lastLogon)
			}

			//Get Email Address
			if len(userAccountControlResult.Entries[0].GetAttributeValues("mail")) > 0 {
				email := result.Entries[0].GetAttributeValues("mail")[0]
				queryResult += fmt.Sprintf("Mail: \t%s\n", email)
			} else {
				queryResult += ("Mail: \t\n")
			}

			//Get SPNs
			spnResults := userAccountControlResult.Entries[0].GetAttributeValues("servicePrincipalName")
			if len(spnResults) > 0 {
				queryResult += "SPN(s): "
				for i := 0; i < len(spnResults); i++ {
					if i == 0 {
						queryResult += fmt.Sprintf("\t%s\n", spnResults[i])
					} else {
						queryResult += fmt.Sprintf("\t%s\n", spnResults[i])
					}
				}
			} else {
				queryResult += ("SPN(s): \t\n")
			}

		} else {
			fmt.Println("Object class is of not of type \"user\".")
		} // end if result.Entries[0].GetAttributeValues("objectClass")[0] == "user"
	} else {
		fmt.Printf("No results for \"%s\", check query.", usernameInput)
	} // End of if result != 0
	return
}
