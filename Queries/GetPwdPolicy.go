package Queries

import (
	"fmt"
	"ldapper/Globals"
	"strconv"

	"github.com/go-ldap/ldap/v3"
)

func GetPwdPolicy(baseDN string, conn *ldap.Conn) (queryResult string) {
	query := ("(objectClass=domainDNS)")
	searchReq := Globals.LdapSearch(baseDN, query)

	result, err := conn.Search(searchReq)
	if err != nil {
		fmt.Printf("Query error, %s", err)
	}

	if len(result.Entries) > 0 {
		for domainDNSResult := range result.Entries {
			minPwdLength := result.Entries[domainDNSResult].GetAttributeValue("minPwdLength")
			pwdHistoryLength := result.Entries[domainDNSResult].GetAttributeValue("pwdHistoryLength")
			maxPwdAge := result.Entries[domainDNSResult].GetAttributeValue("maxPwdAge")
			minPwdAge := result.Entries[domainDNSResult].GetAttributeValue("minPwdAge")
			lockoutThreshold := result.Entries[domainDNSResult].GetAttributeValue("lockoutThreshold")
			lockoutDuration := result.Entries[domainDNSResult].GetAttributeValue("lockoutDuration")
			pwdProperties := result.Entries[domainDNSResult].GetAttributeValue("pwdProperties")
			pwdPropertiesResolved := getPwdProperties(pwdProperties)
			//https://ldapwiki.com/wiki/PwdProperties#:~:text=PwdProperties%20attribute%20specifies%20an%20unsigned,Account%20Policies%5CPassword%20Policy%20folder.

			queryResult = fmt.Sprintf("\nMinimum Password Length: \t%s\n", minPwdLength)
			queryResult += fmt.Sprintf("Password History Length: \t%s\n", pwdHistoryLength)
			queryResult += fmt.Sprintf("Lockout Threshold: \t%s\n", lockoutThreshold)
			queryResult += fmt.Sprintf("Lockout Duration: \t%.0f\tminutes\n", Globals.ConvertToMinutes(lockoutDuration))
			queryResult += fmt.Sprintf("Minimum Password Age: \t%.0f\tday(s)\n", Globals.ConvertToMinutes(minPwdAge)/60/24)
			queryResult += fmt.Sprintf("Maximum Password Age: \t%.0f\tday(s)\n", Globals.ConvertToMinutes(maxPwdAge)/60/24)
			queryResult += fmt.Sprintf("\t\nPassword Complexity: \t%s", pwdPropertiesResolved)
		}
	}
	return
}

func getPwdProperties(pwdProperties string) (result string) {
	pwdPropertiesInt, _ := strconv.Atoi(pwdProperties)
	binary := fmt.Sprintf("%06b", pwdPropertiesInt)

	if string(binary[0]) == "1" {
		result += "DOMAIN_REFUSE_PASSWORD_CHANGE\n\t"
	}
	if string(binary[1]) == "1" {
		result += "DOMAIN_PASSWORD_STORE_CLEARTEXT\n\t"
	}
	if string(binary[2]) == "1" {
		result += "DOMAIN_LOCKOUT_ADMINS\n\t"
	}
	if string(binary[3]) == "1" {
		result += "DOMAIN_PASSWORD_NO_CLEAR_CHANGE\n\t"
	}
	if string(binary[4]) == "1" {
		result += "DOMAIN_PASSWORD_NO_ANON_CHANGE\n\t"
	}
	if string(binary[5]) == "1" {
		result += "DOMAIN_PASSWORD_COMPLEX\n\t"
	}

	return
}
