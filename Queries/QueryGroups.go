package Queries

import (
	"fmt"
	"ldapper/Globals"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func GroupsQuery(groupInput string, baseDN string, conn *ldap.Conn) (queryResult string) {

	query := fmt.Sprintf("(samaccountname=%s)", groupInput)
	searchReq := Globals.LdapSearch(baseDN, query)

	result, err := conn.Search(searchReq)
	if err != nil {
		fmt.Printf("Query error, %s", err)
	}
	//fmt.Printf("\nUser: %s\n", groupInput)

	if len(result.Entries) > 0 {
		queryResult += fmt.Sprintf("\nGroup Memberships - %s:\n-------------------------------------------------------------------------------\n", groupInput)
		for i, cn := range result.Entries[0].GetAttributeValues("memberOf") {
			s := strings.Split(cn, ",")
			cn := strings.Replace(s[0], "CN=", "", -1)
			if strings.Contains(cn, " ") {
				cn = ("'" + cn + "' ")
			}

			queryResult += fmt.Sprintf("%s\t", cn)
			i++
			if i%3 == 0 {
				queryResult += ("\n")
			}
		}
		queryResult += ("\n")
	} else {
		fmt.Printf("No results for \"%s\", check query.", groupInput)
	}
	return
}
