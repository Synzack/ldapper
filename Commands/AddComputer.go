package Commands

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/mazen160/go-random"
	"golang.org/x/text/encoding/unicode"
)

func AddComputerAccount(username string, baseDN string, conn *ldap.Conn) string {
	password, err := random.String(15)
	if err != nil {
		fmt.Println(err)
	}

	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	pwdEncoded, err := utf16.NewEncoder().String(fmt.Sprintf("%q", password))
	if err != nil {
		log.Fatal(err)
	}

	WORKSTATION_TRUST_ACCOUNT := fmt.Sprintf("%d", 0x1000)

	//set vars for request
	usernameMinusDollar := username[:len(username)-1]

	dn := fmt.Sprintf("CN=%s,CN=Computers,%s", username, baseDN)
	spn1 := fmt.Sprintf("HOST/%s", usernameMinusDollar)
	spn2 := fmt.Sprintf("RestrictedKrbHost/%s", usernameMinusDollar)
	domain := baseDN
	domain = strings.Replace(domain, "DC=", "", -1)
	domain = strings.Replace(domain, ",", ".", -1)
	domain = strings.ToLower(domain)
	dnsHostName := fmt.Sprintf("%s.%s", usernameMinusDollar, domain)

	//create add computer request
	addReq := ldap.NewAddRequest(dn, []ldap.Control{})
	addReq.Attribute("objectClass", []string{"top", "organizationalPerson", "user", "computer"})
	addReq.Attribute("sAMAccountName", []string{username})
	addReq.Attribute("userAccountControl", []string{WORKSTATION_TRUST_ACCOUNT})
	addReq.Attribute("unicodePwd", []string{pwdEncoded})
	addReq.Attribute("servicePrincipalName", []string{spn1, spn2})
	addReq.Attribute("dnsHostName", []string{dnsHostName})

	//send request
	if err := conn.Add(addReq); err != nil {
		log.Fatal("Error Adding service: ", err)
		return ""
	}

	return fmt.Sprintf("Successfully created computer account \"%s\" with password \"%s\"\n", username, password)
}
