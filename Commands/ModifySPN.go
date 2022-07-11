package Commands

import (
	"fmt"
	"ldapper/Globals"

	"github.com/go-ldap/ldap/v3"
)

func AddSPN(targetUser string, spn string, baseDN string, conn *ldap.Conn) (spnResult string) {

	query := fmt.Sprintf("(sAMAccountName=%s)", targetUser) // Build the query
	searchReq := Globals.LdapSearch(baseDN, query)          // Search the baseDN
	result, err := conn.Search(searchReq)                   // Execute the search
	if err != nil {
		fmt.Printf("Query error, %s", err)
	}
	if len(result.Entries) > 0 {
		targetDN := result.Entries[0].DN
		modSPN := ldap.NewModifyRequest(targetDN, []ldap.Control{})
		modSPN.Add("servicePrincipalName", []string{spn})
		err = conn.Modify(modSPN)
		if err != nil {
			spnResult = fmt.Sprintf("Error: %s", err)
			return
		}
		spnResult = fmt.Sprintf("Successfully added SPN: \"%s\" for user \"%s\"\n", spn, targetUser)
	} else {
		spnResult = fmt.Sprintf("Error: User \"%s\" not found", targetUser)
	}
	return
}

func DeleteSPN(targetUser string, spn string, baseDN string, conn *ldap.Conn) (spnResult string) {

	query := fmt.Sprintf("(sAMAccountName=%s)", targetUser) // Build the query
	searchReq := Globals.LdapSearch(baseDN, query)          // Search the baseDN
	result, err := conn.Search(searchReq)                   // Execute the search
	if err != nil {
		fmt.Printf("Query error, %s", err)
	}
	if len(result.Entries) > 0 {
		targetDN := result.Entries[0].DN
		modSPN := ldap.NewModifyRequest(targetDN, []ldap.Control{})
		modSPN.Delete("servicePrincipalName", []string{spn})
		err = conn.Modify(modSPN)
		if err != nil {
			spnResult = fmt.Sprintf("Error: %s", err)
			return
		}
		spnResult = fmt.Sprintf("Successfully deleted SPN: \"%s\" for user \"%s\"\n", spn, targetUser)
	} else {
		spnResult = fmt.Sprintf("Error: User \"%s\" not found", targetUser)
	}
	return
}
