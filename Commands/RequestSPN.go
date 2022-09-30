package Commands

import (
	"encoding/hex"
	"fmt"
	"ldapper/Globals"
	"log"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
)

// dont really like this string for the config
// would rather just create a new config and make changes via functions
// would be easier to read
// cant seem to figure out how to add a [realm] though

func RequestSPN(targetUser string, username string, password string, ntlm string, domain string, dc string, socksServer string, socksType int) (spnResult string) {

	var cl *client.Client
	var ticket string

	// Need domain in uppercase for GOKRB5 Config
	domain = strings.ToUpper(domain)

	l := log.New(os.Stderr, "GOKRB5 Client: ", log.Ldate|log.Ltime|log.Lshortfile)

	c, err := config.NewFromString(fmt.Sprintf(Globals.Libdefault, domain, domain, dc, domain))

	if err != nil {
		l.Fatalf("Error Loading Config: %v\n", err)
	}

	// Create a Kerberos client with either password or hash
	if password != "" {
		cl = client.NewWithPassword(username, domain, password, c, client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
	} else if ntlm != "" {
		cl = client.NewWithHash(username, domain, ntlm, c, client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
	} else {
		ccache, _ := credentials.LoadCCache(os.Getenv("KRB5CCNAME"))
		cl, _ = client.NewFromCCache(ccache, c)
	}

	// Add socks info to client config if enabled
	if socksServer != "" {
		cl.Config.Socks.Enabled = true
		cl.Config.Socks.Version = socksType
		cl.Config.Socks.Server = socksServer
	}

	err = cl.Login()
	if err != nil {
		l.Fatalf("Erron on AS_REQ: %v\n", err)
	}

	tgt, _, err := cl.GetMSPrincipalTicket(targetUser)

	// only printing out RC4 encrypted tickets currently
	if err != nil {
		l.Printf("Error getting service ticket: %v\n", err)
	} else if tgt.EncPart.EType == etypeID.RC4_HMAC {
		checksumHex := make([]byte, hex.EncodedLen(len(tgt.EncPart.Cipher[:16])))
		hex.Encode(checksumHex, tgt.EncPart.Cipher[:16])

		cipherHex := make([]byte, hex.EncodedLen(len(tgt.EncPart.Cipher[16:])))
		hex.Encode(cipherHex, tgt.EncPart.Cipher[16:])
		ticket = fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s\n", tgt.EncPart.EType, tgt.SName.NameString[0], tgt.Realm, tgt.SName.NameString[0], checksumHex, cipherHex)
	} else if tgt.EncPart.EType != etypeID.RC4_HMAC {
		// Don't belive this would happen becuase we only offer rc4 encrpytion based on our config
		l.Printf("Invalid encryption type")
	}
	return ticket
}
