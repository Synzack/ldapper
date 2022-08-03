package Queries

import (
	"fmt"
	"ldapper/Globals"
        "strconv"

	"github.com/go-ldap/ldap/v3"
)

func GetUserSPNs(baseDN string, conn *ldap.Conn) (queryResult string) {
	query := "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"
	searchReq := Globals.LdapSearch(baseDN, query)
	result, err := conn.SearchWithPaging(searchReq, 10)

	if err != nil {
		fmt.Printf("Query error, %s", err)
	}
       
        // Build output header Row 
        queryResult = fmt.Sprintf("SPN\tUsername\tPasswordLastSet\tLastLogon\tDelegation\n")

        // check if LDAPSearch returned any entries
        if len(result.Entries) > 0 {
            for ldapResult := range result.Entries{

                username := result.Entries[ldapResult].GetAttributeValues("sAMAccountName")[0]
                
                // Get Delegation Information
                userAccountControl, _ := strconv.Atoi(result.Entries[ldapResult].GetAttributeValue("userAccountControl"))
                delegationInfo := ""
                if userAccountControl & 0x00080000 > 0 {
                delegationInfo = "unconstrained"
                } else if userAccountControl& 0x01000000 > 0 {
                delegationInfo = "constrained"
                }

                //convert LDAP time for pwdLastSet
                pwdLastSet, _ := strconv.Atoi(result.Entries[ldapResult].GetAttributeValue("pwdLastSet"))
                pwdLastSetString := Globals.ConvertLDAPTime(pwdLastSet).String() 
                
                //Assume the account has never logged in
                lastLogonString := "<never>"
                // If the account has logged in convert the LDAP Time
                lastLogon, _ := strconv.Atoi(result.Entries[ldapResult].GetAttributeValue("lastLogon"))
                if lastLogon != 0 {
                    lastLogonString = Globals.ConvertLDAPTime(lastLogon).String()
                }

                // Get each SPN for the account
                for spnResult := range result.Entries[ldapResult].GetAttributeValues("servicePrincipalName"){
                    spn := result.Entries[ldapResult].GetAttributeValues("servicePrincipalName")[spnResult]
                    queryResult += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", spn, username, pwdLastSetString, lastLogonString, delegationInfo)
                }   

            }        
        }
        
    return queryResult
}
