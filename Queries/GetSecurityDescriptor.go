package Queries

import (
	"encoding/hex"
	"fmt"
	"ldapper/Globals"
	SD "ldapper/SecurityDescriptor"

	"github.com/go-ldap/ldap/v3"
)

func GetSecurityDescriptor(input string, baseDN string, conn *ldap.Conn) (queryResult string) {
	query := fmt.Sprintf("(samaccountname=%s)", input)
	searchReq := Globals.LdapSearchSD(baseDN, query)
	result, err := conn.Search(searchReq)
	if err != nil {
		fmt.Printf("Query error, %s", err)

	}

	// if LdapSearch returns information
	if len(result.Entries) > 0 {
		sd := result.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
		hexSD := hex.EncodeToString(sd)

		abusableAces := SD.ParseSD(hexSD, baseDN, conn)

		queryResult += "\nGENERIC_ALL:\n"
		for _, entry := range abusableAces {
			if entry.GENERIC_ALL {
				queryResult += fmt.Sprintf("\t%s\n", entry.SamAccountName)
			}
		}

		queryResult += "\nGENERIC_WRITE:\n"
		for _, entry := range abusableAces {
			if entry.GENERIC_WRITE {
				queryResult += fmt.Sprintf("\t%s\n", entry.SamAccountName)
			}
		}

		queryResult += "\nWRITE_OWNER:\n"
		for _, entry := range abusableAces {
			if entry.WRITE_OWNER {
				queryResult += fmt.Sprintf("\t%s\n", entry.SamAccountName)
			}
		}

		queryResult += "\nWRITE_DACL:\n"
		for _, entry := range abusableAces {
			if entry.WRITE_DACL {
				queryResult += fmt.Sprintf("\t%s\n", entry.SamAccountName)
			}
		}

		queryResult += "\nFORCE_CHANGE_PASSWORD:\n"
		for _, entry := range abusableAces {
			if entry.FORCE_CHANGE_PASSWORD {
				queryResult += fmt.Sprintf("\t%s\n", entry.SamAccountName)
			}
		}

		queryResult += "\nADD_MEMBER:\n"
		for _, entry := range abusableAces {
			if entry.ADD_MEMBER {
				queryResult += fmt.Sprintf("\t%s\n", entry.SamAccountName)
			}
		}
	} else {
		queryResult = "No results for input object.\n"
	}
	return
}
