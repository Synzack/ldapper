package Queries

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func BruteUserQuery(userList string, baseDN string, conn *ldap.Conn) (queryResult string) {

	// open the userList file
	userListFile, err := os.Open(userList)
	if err != nil {
		fmt.Printf("[-] Error opening userList file: %s", err)
		return
	}
	defer userListFile.Close()

	// read the userList file
	userListBytes := make([]byte, 5242880) // 5MB buffer size
	_, err = userListFile.Read(userListBytes)
	if err != nil {
		fmt.Printf("[-] Error reading userList file: %s", err)
		return
	}

	// split the userList file into a slice of users
	userListSlice := strings.Split(string(userListBytes), "\n")

	// remove any null bytes (prevents empty user found)
	for i, user := range userListSlice {
		userListSlice[i] = strings.Trim(user, "\x00")
	}

	// for each user in the userList, run the query
	for _, user := range userListSlice {
		// if read a blank line, skip it
		if user == "" || user == "\r" || user == "\n" {
			continue
		}

		searchReq := ldap.NewSearchRequest(
			"", // The base dn to search
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(&(NtVer=\x06\x00\x00\x00)(AAC=\x10\x00\x00\x00)(User="+user+"))"), // The filter to apply
			[]string{"NetLogon"}, // A list attributes to retrieve
			nil,
		)

		result, err := conn.Search(searchReq)
		if err != nil {
			fmt.Printf("Query error, %s", err)
			queryResult = "[-] Query error"
			return
		}

		res := result.Entries[0].Attributes[0].ByteValues[0]
		if len(res) > 2 && res[0] == 0x17 && res[1] == 00 {
			fmt.Println("[+] User found: " + user)
		}

	}
	return
}
