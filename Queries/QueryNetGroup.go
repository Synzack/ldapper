package Queries

import (
	"fmt"
	"ldapper/Globals"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func NetGroupQuery(groupInput string, baseDN string, conn *ldap.Conn) ([]string, string) {

	var queryResult []string
	var description string

	query := fmt.Sprintf("(&(objectClass=group)(cn=%s))", groupInput) // Build the query
	searchReq := Globals.LdapSearch(baseDN, query)                    // Search the baseDN
	result, err := conn.Search(searchReq)                             // Execute the search
	if err != nil {
		fmt.Printf("Query error, %s", err)
	}

	// if LdapSearch returns information
	if len(result.Entries) > 0 {
		if len(result.Entries[0].GetAttributeValues("description")) > 0 {
			description = result.Entries[0].GetAttributeValues("description")[0]
		}

		for _, dn := range result.Entries[0].GetAttributeValues("member") {
			regexCN := regexp.MustCompile(`CN=(.*?),[A-Z]{2}=`)
			match := regexCN.FindAllStringSubmatch(dn, -1)
			cn := match[0][1]

			cn = strings.Replace(cn, "\\", "", -1)
			cn = strings.Replace(cn, "(", ldap.EscapeFilter("("), -1) //Escape parenthesis
			cn = strings.Replace(cn, ")", ldap.EscapeFilter(")"), -1)

			query = fmt.Sprintf("(cn=%s)", cn)              // build the query
			searchReq2 := Globals.LdapSearch(baseDN, query) // search for username

			result2, err := conn.Search(searchReq2) // get results
			if err != nil {
				fmt.Printf("Query error, %s", err)
			}

			if len(result2.Entries[0].GetAttributeValues("sAMAccountName")) > 0 {
				samAccountName := result2.Entries[0].GetAttributeValues("sAMAccountName")[0] // get sAMAccountName
				username := strings.Replace(samAccountName, "sAMAccountNAme: ", "", -1)      // remove all sAMAccountName: from string

				//Check if group
				objectClass := result2.Entries[0].GetAttributeValues("objectClass")
				isGroup := false

				for i := 0; i < len(objectClass); i++ {
					if result2.Entries[0].GetAttributeValues("objectClass")[i] == "group" {
						isGroup = true
					}
				}
				if isGroup {
					username = fmt.Sprintf("%s (Group)", username)
				}

				//Append Result Array
				queryResult = append(queryResult, username)
			}
		}
	}

	return queryResult, description
} // end NetGroupQuery

func ReturnGroupQuery(groupInput string, baseDN string, conn *ldap.Conn) (queryResult string) {
	primaryGroupMembers, description := NetGroupQuery(groupInput, baseDN, conn) // Get primary group members
	queryResult += fmt.Sprintf("Comment: %s\n", description)

	if len(primaryGroupMembers) > 0 {
		queryResult += ("\nPrimary Group Members\n-------------------------------------------------------------------------------\n")
		for i, username := range primaryGroupMembers {
			queryResult += fmt.Sprintf("%s\t", username)
			i++
			if i%3 == 0 {
				queryResult += ("\n") // new line every 3 entries
			}
		}
		queryResult += "\n"
	} else {
		queryResult = fmt.Sprintf("No results for \"%s\", check query.\n", groupInput)
	}

	return
} // end ReturnGroupQuery
