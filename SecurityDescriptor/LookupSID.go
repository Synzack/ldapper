package SecurityDescriptor

import (
	"fmt"
	"ldapper/Globals"

	"github.com/go-ldap/ldap/v3"
)

func LookupSID(baseDN string, conn *ldap.Conn, SID string) (resolvedSID string) {
	for entry, _ := range wellKnownSIDsMap {
		if SID == entry {
			resolvedSID = wellKnownSIDsMap[entry]
			return
		}
	}

	query := fmt.Sprintf("(objectSID=%s)", SID)
	searchReq := Globals.LdapSearch(baseDN, query)
	result, err := conn.Search(searchReq)
	if err != nil {
		fmt.Printf("Query error, %s", err)

	}

	if len(result.Entries) > 0 {
		resolvedSID = result.Entries[0].GetAttributeValues("sAMAccountName")[0]
	}

	return
}
