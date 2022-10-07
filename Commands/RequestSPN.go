package Commands

import (
	"encoding/hex"
	"fmt"
	"ldapper/Globals"
	"log"
	"os"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
)

func RequestSPN(targetUser string, username string, password string, ntlm string, domain string, dc string, ccache bool, socksServer string, socksType int) (spnResult string) {

	var cl *client.Client
	var ticket string
	var err error

	cl = Globals.GetKerberosClient(domain, dc, username, password, ntlm, ccache, socksServer, socksType)

	l := log.New(os.Stderr, "GOKRB5 Client: ", log.Ldate|log.Ltime|log.Lshortfile)

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
