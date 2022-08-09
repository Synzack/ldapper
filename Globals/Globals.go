package Globals

import (
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/go-ldap/ldap/v3"
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
