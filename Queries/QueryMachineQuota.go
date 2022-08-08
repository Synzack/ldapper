package Queries

import (
	"fmt"
	"ldapper/Globals"

	"github.com/go-ldap/ldap/v3"
)

func GetMachineQuota(baseDN string, conn *ldap.Conn) (queryResult string) {
	query := ("(objectClass=domain)")
	searchReq := Globals.LdapSearch(baseDN, query)

	result, err := conn.Search(searchReq)
	if err != nil {
		fmt.Printf("Query error, %s", err)
	}

	if len(result.Entries[0].GetAttributeValues("ms-DS-MachineAccountQuota")) > 0 {
		machineQuota := result.Entries[0].GetAttributeValues("ms-DS-MachineAccountQuota")[0]
		queryResult = fmt.Sprintf("Machine Account Quota: %s\n", machineQuota)
		return
	} else {
		queryResult = "No results for ms-DS-MachineAccountQuota.\n"
	}

	return
}
