package Globals

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/LeakIX/go-smb2"
	"github.com/LeakIX/ntlmssp"
	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"

	"github.com/jcmturner/gofork/encoding/asn1"
)

func LdapSearch(baseDN string, query string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, 0, 0, 0, false,
		query,
		[]string{},
		nil,
	)
}

func LdapSearchSD(baseDN string, query string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, 0, 0, 0, false,
		query,
		[]string{"nTSecurityDescriptor"},
		[]ldap.Control{&ldap.ControlMicrosoftSDFlags{ControlValue: 7}},
	)
}

func OutputAndLog(fileName string, data string, minWidth int, tabWidth int, padding int, noStdOut bool) {
	outputWriter := new(tabwriter.Writer)
	var multiOut io.Writer
	if fileName != "" {
		f, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		defer f.Close()
		if noStdOut {
			multiOut = io.MultiWriter(f)
		} else {
			multiOut = io.MultiWriter(f, os.Stdout)
		}
	} else {
		multiOut = io.MultiWriter(os.Stdout)
	}

	outputWriter.Init(multiOut, minWidth, tabWidth, padding, '\t', 0)
	fmt.Fprintln(outputWriter, data)

	outputWriter.Flush()
}

func ConvertLDAPTime(t int) time.Time {
	LDAPtime := t
	winSecs := LDAPtime / 10000000
	timeStamp := winSecs - 11644473600
	return time.Unix(int64(timeStamp), 0)
}

func ConvertToMinutes(t string) (minutes float64) {
	removeMinus := strings.Trim(t, "-")
	first5 := removeMinus[:5]
	trailing := removeMinus[5:]
	number, _ := strconv.ParseFloat(first5, 64)
	decimal := float64(number / 10000)
	seconds := (decimal * (math.Pow(10, float64(len(trailing))) / 1000))
	minutes = seconds / 60

	return
}

func GetBaseDN(dc string, conn *ldap.Conn) string {

	//search Scope of Base for defaultNamingContext (baseDN)
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) > 0 {
		return sr.Entries[0].GetAttributeValue("defaultNamingContext")
	} else {
		log.Fatal("Couldn't fetch BaseDN. Cannot run querires.")
	}
	return ""
}

func GetArrayDifference(a, b []string) (diff []string) {
	m := make(map[string]bool)

	for _, item := range b {
		m[item] = true
	}

	for _, item := range a {
		if _, ok := m[item]; !ok {
			diff = append(diff, item)
		}
	}

	return
}

func GetMachineHostname(dc string, proxyDial func(string, string) (net.Conn, error)) string {
	var conn net.Conn
	var err error

	if proxyDial != nil {
		conn, err = proxyDial("tcp", fmt.Sprintf("%s:445", dc))
		if err != nil {
			panic(err)
		}
	} else {
		conn, err = net.Dial("tcp", fmt.Sprintf("%s:445", dc))
		if err != nil {
			panic(err)
		}
	}

	defer conn.Close()

	ntlmsspClient, err := ntlmssp.NewClient(
		ntlmssp.SetCompatibilityLevel(3),
		ntlmssp.SetUserInfo("", ""),
		ntlmssp.SetDomain(""))
	if err != nil {
		panic(err)
	}
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMSSPInitiator{
			NTLMSSPClient: ntlmsspClient,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		log.Println(ntlmsspClient.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvDNSComputerName))
		panic(err)
	}
	dnsComputerName, _ := ntlmsspClient.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvDNSComputerName)
	defer s.Logoff()

	dnsComputerNameString := string(dnsComputerName)
	dnsComputerNameString = strings.Replace(dnsComputerNameString, "\x00", "", -1)

	return dnsComputerNameString

}

func GetKerberosClient(domain string, dc string, username string, password string, ntlm string, ccacheAuth bool, etype string, socksAddress string, socksType int) *client.Client {

	var cl *client.Client
	var err error
	var etypeid int32

	switch etype {
	case "rc4":
		etypeid = 23
	case "aes":
		etypeid = 18
	}
	domain = strings.ToUpper(domain)
	c := config.New()
	c.LibDefaults.DefaultRealm = domain
	c.LibDefaults.PermittedEnctypeIDs = []int32{etypeid}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeid}
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeid}
	c.LibDefaults.UDPPreferenceLimit = 1

	tgsopts := asn1.BitString{}
	tgsopts.Bytes, _ = hex.DecodeString("40810010")
	tgsopts.BitLength = len(tgsopts.Bytes) * 8
	c.LibDefaults.KDCTGSDefaultOptions = tgsopts

	asopts := asn1.BitString{}
	asopts.Bytes, _ = hex.DecodeString("10000000")
	asopts.BitLength = len(asopts.Bytes) * 8
	c.LibDefaults.KDCDefaultOptions = asopts

	var realm config.Realm
	realm.Realm = domain
	realm.KDC = []string{fmt.Sprintf("%s:88", dc)}
	realm.DefaultDomain = domain

	c.Realms = []config.Realm{realm}

	if ccacheAuth {
		ccache, _ := credentials.LoadCCache(os.Getenv("KRB5CCNAME"))
		cl, err = client.NewFromCCache(ccache, c)
		if err != nil {
			log.Fatal(err)
		}
	} else if password != "" {
		cl = client.NewWithPassword(username, domain, password, c, client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
	} else if ntlm != "" {
		cl = client.NewWithHash(username, domain, ntlm, c, client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
	}

	if socksAddress != "" {
		cl.Config.Socks.Enabled = true
		cl.Config.Socks.Version = socksType
		cl.Config.Socks.Server = socksAddress
	}

	return cl

}
