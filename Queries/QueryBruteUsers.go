package Queries

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func BruteUserQuery(userList string, baseDN string, conn *ldap.Conn) (queryResult string) {

	// if userList is empty, return an error and exit the function
	if userList == "" {
		queryResult = "[-] No users provided"
		return
	}

	// open the userList file
	userListFile, err := os.Open(userList)
	if err != nil {
		fmt.Printf("[-] Error opening userList file: %s", err)
		return
	}
	defer userListFile.Close()

	// read the userList file
	userListBytes := make([]byte, 1024) // 1kb buffer size
	_, err = userListFile.Read(userListBytes)
	if err != nil {
		fmt.Printf("[-] Error reading userList file: %s", err)
		return
	}

	// split the userList file into a slice of users
	userListSlice := strings.Split(string(userListBytes), "\n")

	// for each user in the userList, run the query
	for _, user := range userListSlice {

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
