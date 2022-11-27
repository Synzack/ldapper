package Queries

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func BruteUserQuery(groupInput string, baseDN string, conn *ldap.Conn, userList string) (queryResult string) {

	// if userList is empty, return an error and exit the function
	if userList == "" {
		queryResult = "[-] No users provided"
		return
	}
	// else read the userList and for each user, run the query
	users := strings.Split(userList, ",")
	for _, user := range users {

		searchReq := ldap.NewSearchRequest(
			baseDN, // The base dn to search
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(&(NtVer=\x06\x00\x00\x00)(AAC=\x10\x00\x00\x00)(User="+user+"))"), // The filter to apply
			[]string{"NetLogon"}, // A list attributes to retrieve
			nil)

		// searchReq := Globals.LdapSearch(baseDN, query)
		result, err := conn.Search(searchReq)
		if err != nil {
			fmt.Printf("Query error, %s", err)
			queryResult = "[-] Query error"
			return
		}

		// if LdapSearch returns information
		if len(result.Entries) > 0 {
			queryResult += "[+] User found: " + user + "\n"
		} 
	}
	return
}
