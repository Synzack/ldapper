package Queries

import (
	"fmt"
	"ldapper/Globals"

	"github.com/go-ldap/ldap/v3"
)

func NetNestedGroupQuery(groupInput string, baseDN string, conn *ldap.Conn) []string {

	var queryResult []string

	nestedQuery := fmt.Sprintf("(memberof:1.2.840.113556.1.4.1941:=CN=%s,OU=Groups,%s)", groupInput, baseDN)
	searchReq := Globals.LdapSearch(baseDN, nestedQuery) // Search the baseDN
	result, err := conn.Search(searchReq)                // Execute the search
	if err != nil {
		fmt.Printf("Query error, %s", err)
	}

	// if LdapSearch returns information
	if len(result.Entries) > 0 {
		for i := 1; i < len(result.Entries); i++ {
			queryResult = append(queryResult, result.Entries[i].GetAttributeValues("sAMAccountName")[0])
		}
	}

	//For each result, check if group
	for i := 0; i < len(queryResult); i++ {
		query := fmt.Sprintf("(sAMAccountName=%s)", queryResult[i]) // build the query
		searchReq3 := Globals.LdapSearch(baseDN, query)

		result3, err := conn.Search(searchReq3) // get results
		if err != nil {
			fmt.Printf("Query error, %s", err)
		}

		objectClass := result3.Entries[0].GetAttributeValues("objectClass")
		isGroup := false

		for i := 0; i < len(objectClass); i++ {
			if result3.Entries[0].GetAttributeValues("objectClass")[i] == "group" {
				isGroup = true
			}
		}
		//If result is a group, append (Group) to result
		if isGroup {
			queryResult[i] = fmt.Sprintf("%s (Group)", queryResult[i])
		}

	}

	return queryResult
} // end NetNestedGroupQuery

func ReturnNestedGroupQuery(groupInput string, baseDN string, conn *ldap.Conn) (queryResult string) {
	var nestedGroupMembers []string = NetNestedGroupQuery(groupInput, baseDN, conn) // Get nested group members
	primaryGroupMembers, description := NetGroupQuery(groupInput, baseDN, conn)     // Get primary group members
	queryResult += fmt.Sprintf("Comment: %s\n", description)

	if len(primaryGroupMembers) > 0 {
		queryResult += ("\nPrimary Group Members\n-------------------------------------------------------------------------------\n")
		for i, username := range primaryGroupMembers {
			queryResult += fmt.Sprintf("%-25s", username)
			i++
			if i%3 == 0 {
				queryResult += ("\n") // new line every 3 entries
			}
		}

		differenceReturn := Globals.GetArrayDifference(nestedGroupMembers, primaryGroupMembers)
		if len(differenceReturn) > 0 {
			queryResult += ("\n\nNested Group Members\n-------------------------------------------------------------------------------\n")
			for i, username := range differenceReturn {
				queryResult += fmt.Sprintf("%s\t", username)
				i++
				if i%3 == 0 {
					queryResult += ("\n") // new line every 3 entries
				}
			}
		}

	} else {
		fmt.Printf("No results for \"%s\", check query.", groupInput)
		queryResult = ("")
	}

	return
} // end ReturnGroupQuery
