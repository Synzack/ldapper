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

var userAccountControlMap = map[string]string{
	"1":        "SCRIPT",
	"2":        "ACCOUNTDISABLE",
	"8":        "HOMEDIR_REQUIRED",
	"16":       "LOCKOUT",
	"32":       "PASSWD_NOTREQD",
	"64":       "PASSWD_CANT_CHANGE",
	"128":      "ENCRYPTED_TEXT_PWD_ALLOWED",
	"256":      "TEMP_DUPLICATE_ACCOUNT",
	"512":      "NORMAL_ACCOUNT",
	"514":      "Disabled Account",
	"544":      "Enabled, Password Not Required",
	"546":      "Disabled, Password Not Required",
	"2048":     "INTERDOMAIN_TRUST_ACCOUNT",
	"4096":     "WORKSTATION_TRUST_ACCOUNT",
	"8192":     "SERVER_TRUST_ACCOUNT",
	"65536":    "DONT_EXPIRE_PASSWORD",
	"66048":    "Enabled, Password Doesn't Expire",
	"66050":    "Disabled, Password Doesn't Expire",
	"66082":    "Disabled, Password Doesn't Expire & Not Required",
	"131072":   "MNS_LOGON_ACCOUNT",
	"262144":   "SMARTCARD_REQUIRED",
	"262656":   "Enabled, Smartcard Required",
	"262658":   "Disabled, Smartcard Required",
	"262690":   "Disabled, Smartcard Required, Password Not Required",
	"328194":   "Disabled, Smartcard Required, Password Doesn't Expire",
	"328226":   "Disabled, Smartcard Required, Password Doesn't Expire & Not Required",
	"524288":   "TRUSTED_FOR_DELEGATION",
	"532480":   "Domain controller",
	"1048576":  "NOT_DELEGATED",
	"2097152":  "USE_DES_KEY_ONLY",
	"4194304":  "DONT_REQ_PREAUTH",
	"8388608":  "PASSWORD_EXPIRED",
	"16777216": "TRUSTED_TO_AUTH_FOR_DELEGATION",
	"67108864": "PARTIAL_SECRETS_ACCOUNT",
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
				queryResult += fmt.Sprintf("User Name: \t\t%s\n", username[0])
			}

			//get Full Name
			userCN := result.Entries[0].GetAttributeValues("cn")[0]
			queryResult += fmt.Sprintf("Full Name: \t\t%s\n", userCN)

			//get Comments
			if len(result.Entries[0].GetAttributeValues("description")) > 0 { // If comments is not empty
				description := result.Entries[0].GetAttributeValues("description")[0] // Get comments
				queryResult += fmt.Sprintf("Comment: \t\t%s\n", description)          // Print comments
			} else {
				queryResult += ("Comment: \n")
			}

			//get Account Active
			userAccountControlQuery := fmt.Sprintf("(cn=%s)", userCN)                       // Query to search for user
			userAccountControlSearch := Globals.LdapSearch(baseDN, userAccountControlQuery) // Search request

			userAccountControlResult, err := conn.Search(userAccountControlSearch)
			if err != nil {
				fmt.Printf("User Account Control query error, %s", err)

			}

			userAccountControl := userAccountControlResult.Entries[0].GetAttributeValues("userAccountControl")[0] // Get userAccountControl
			queryResult += fmt.Sprintf("User Account Control: \t%s\n\t\t\t(If Enabled, Check Last Lockout Time)\n\n", userAccountControlMap[userAccountControl])

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
				queryResult += ("Last Lockout Time: \n")
				//fmt.Printf("Acount Enabled: \t%s\n", userAccountControlMap[userAccountControl])
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
				queryResult += ("Home Directory: \n")
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
					queryResult += fmt.Sprintf("Last logon: \t\t%s\n", humanTime)
				}
			} else {
				queryResult += ("Last logon: \n")
			}

		} else {
			fmt.Println("Object class is of not of type \"user\".")
		} // end if result.Entries[0].GetAttributeValues("objectClass")[0] == "user"
	} else {
		fmt.Printf("No results for \"%s\", check query.", usernameInput)
	} // End of if result != 0
	return
}
