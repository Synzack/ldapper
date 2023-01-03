package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"ldapper/Commands"
	"ldapper/Globals"
	"ldapper/Queries"
	"log"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"h12.io/socks"
)

type FlagOptions struct {
	upn      string
	password string
	ntlm     string
	ccache   bool
	dc       string
	scheme   bool
	logFile  string
	socks4   string
	socks4a  string
	socks5   string
	brute    string
	threads  int
	help     bool
}

func options() *FlagOptions {
	upn := flag.String("u", "", "Username (username@domain)")
	password := flag.String("p", "", "Password")
	ntlm := flag.String("H", "", "Use NTLM authentication")
	ccache := flag.Bool("k", false, "Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME)")
	dc := flag.String("dc", "", "IP address or FQDN of target DC")
	scheme := flag.Bool("s", false, "Bind using LDAPS")
	logFile := flag.String("o", "", "Log file")
	socks4 := flag.String("socks4", "", "SOCKS4 Proxy Address (ip:port)")
	socks4a := flag.String("socks4a", "", "SOCKS4A Proxy Address (ip:port)")
	socks5 := flag.String("socks5", "", "SOCKS5 Proxy Address (ip:port)")
	brute := flag.String("b", "", "Brute force users from a file")
	threads := flag.Int("t", 4, "Number of threads to use (default 4)")
	help := flag.Bool("h", false, "Display help menu")

	flag.Parse()
	return &FlagOptions{
		upn:      *upn,
		password: *password,
		ntlm:     *ntlm,
		ccache:   *ccache,
		dc:       *dc,
		scheme:   *scheme,
		logFile:  *logFile,
		socks4:   *socks4,
		socks4a:  *socks4a,
		socks5:   *socks5,
		brute:    *brute,
		threads:  *threads,
		help:     *help}

}

func main() {
	opt := options() //get options from command line

	const header = " __    ____   __   ____  ____  ____  ____  \n" +
		"(  )  (    \\ / _\\ (  _ \\(  _ \\(  __)(  _ \\ \n" +
		"/ (_/\\ ) D (/    \\ ) __/ ) __/ ) _)  )   / \n" +
		"\\____/(____/\\_/\\_/(__)  (__)  (____)(__\\_) \n" +
		"                          @SpaceManMitch96\n" +
		"                                @Synzack21\n" +
		"                                  @mfdooom\n\n"

	fmt.Print(header)

	var conn *ldap.Conn
	var proxyConn net.Conn
	var err error
	var domain string
	var username string
	var target []string
	var cl *client.Client
	var socksType int
	var socksAddress string
	var proxyDial func(string, string) (net.Conn, error)

	target = strings.Split(opt.upn, "@")

	// Did the user supply the username correctly <user@domain>?
	if len(target) == 1 {
		opt.help = true
	} else {
		username = target[0]
		domain = target[1]
	}

	// if required flags aren't set, print help
	// if opt.brute is set, we don't need a username
	if opt.brute == "" && (username == "" || opt.dc == "" || (opt.password == "" && opt.ntlm == "" && !opt.ccache) || opt.help) {
		flag.Usage()
		fmt.Println("Examples:")
		fmt.Println("\tWith Password: \t./ldapper -u <username@domain> -p <password> -dc <ip/FQDN> -s")
		fmt.Println("\tWith Hash: \t./ldapper -u <username@domain> -H <hash> -dc <ip/FQDN> -s")
		fmt.Println("\tWith Kerberos: \t./ldapper -u <username@domain> -k -dc <ip/FQDN> -s")
		os.Exit(1)
	}

	//Initialize connection with proxy if specified
	if opt.socks4 != "" || opt.socks4a != "" || opt.socks5 != "" {
		var port string
		if opt.scheme {
			port = "636"
		} else {
			port = "389"
		}

		if opt.socks4 != "" {
			//set socks to socks4
			socksType = socks.SOCKS4
			socksAddress = opt.socks4
		} else if opt.socks4a != "" {
			//set socks to socks4a
			socksType = socks.SOCKS4A
			socksAddress = opt.socks4a
		} else if opt.socks5 != "" {
			//set socks to socks5
			socksType = socks.SOCKS5
			socksAddress = opt.socks5
		}

		// check for socks options
		proxyDial = socks.DialSocksProxy(socksType, socksAddress)
		if err != nil {
			log.Fatal("Cannot initialize proxy.")
		}

		proxyConn, err = proxyDial("tcp", fmt.Sprintf("%s:%s", opt.dc, port))
		if err != nil {
			log.Fatal("Cannot connect through proxy.\n", err)
		}

		if opt.scheme {
			proxyTLS := tls.Client(proxyConn, &tls.Config{InsecureSkipVerify: true})
			conn = ldap.NewConn(proxyTLS, opt.scheme)
		} else {
			conn = ldap.NewConn(proxyConn, opt.scheme)
		}

		conn.Start()
		fmt.Printf("Connecting with proxy: %s\n\n", socksAddress)
	} else { //Initialize without proxy
		if opt.scheme {
			ldapsAddress := fmt.Sprintf("%s:%d", opt.dc, 636)
			conn, err = ldap.DialTLS("tcp", ldapsAddress, &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				log.Fatal(err)
			}

		} else {
			conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", opt.dc, 389))
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	defer conn.Close() //Close connection when done

	if opt.brute != "" {
		// send file name to BruteUSerQuery
		Queries.BruteUserQuery(opt.brute, opt.dc, opt.threads, opt.logFile, opt.scheme)
		return
	}

	// if password option set
	if opt.password != "" {
		err = conn.Bind(opt.upn, opt.password)
		if err != nil {
			log.Fatal(err)
		} else {
			fmt.Println("Bind successful, dropping into shell. ")
		}
	}

	// if ntlm hash option set
	if opt.ntlm != "" {
		err = conn.NTLMBindWithHash(domain, username, opt.ntlm)
		if err != nil {
			fmt.Print("test\n")
			log.Fatal(err)
		} else {
			fmt.Println("Bind successful, dropping into shell. ")
		}
	}

	// if kerberos option set
	if opt.ccache {
		cl = Globals.GetKerberosClient(domain, opt.dc, username, opt.password, opt.ntlm, opt.ccache, socksAddress, socksType)
		if err != nil {
			log.Fatal(err)
		}

		machineName := Globals.GetMachineHostname(opt.dc, proxyDial)

		spnTarget := fmt.Sprintf("ldap/%s", machineName)

		_, err = conn.GSSAPICCBindCCache(cl, spnTarget)
		if err != nil {
			log.Fatal(err)
		} else {
			fmt.Println("Kerberos GSSAPI Bind succesful, dropping into shell. ")
		}
	}

	baseDN := Globals.GetBaseDN(opt.dc, conn)

	// Create impromptu shell for input
	reader := bufio.NewReader(os.Stdin)

	for { //Loop forever
		fmt.Print("\n> ")
		userQuery, err := reader.ReadString('\n')            //Read user input
		userQuery = strings.Replace(userQuery, "\n", "", -1) //Remove newline
		userQuery = strings.Replace(userQuery, "\r", "", -1) //Needed to remove newline in Windows

		if err != nil { //Check for errors
			fmt.Fprintln(os.Stderr, err)
		}

		if opt.logFile != "" {
			Globals.OutputAndLog(opt.logFile, "> "+userQuery, 0, 0, 0, true)
		}

		if userQuery != "exit" {
			// parse shell input
			userInput := strings.SplitN(userQuery, " ", 2)
			module := userInput[0]

			switch module {
			case "help":
				const help = "Available commands:\n" +
					"Queries:\n" +
					"\tnet user <username>\n" +
					"\tgroups <user>\n" +
					"\tnet group <group>\n" +
					"\tnet nestedGroups <group> (OPSEC Warning: Expensive LDAP query)\n" +
					"\tdacl <target object> (Get vulnerable aces within the target's DACL)\n" +
					"\tgetspns (Get All User SPNs)\n" +
					"\tmquota (Get Machine Account Quota)\n" +
					"\tpasspol (Get Domain Password Policy)\n" +
					"Commands:\n" +
					"\taddComputer <computerName$>  (Requires LDAPS)\n" +
					"\tspn <add/delete> <targetUser> <spn>\n" +
					"\troast <targetUser>\n" +
					"Exit:\n" +
					"\texit"
				fmt.Println(help)
			case "groups":

				if len(userInput) == 1 {
					fmt.Println("Incorrect number of arguments. Usage: groups <argument>")
					break
				}
				arguments := userInput[1]

				data := Queries.GroupsQuery(arguments, baseDN, conn)
				Globals.OutputAndLog(opt.logFile, data, 12, 8, 4, false)

			case "net":
				if len(userInput) == 1 {
					fmt.Println("Incorrect number of arguments. Usage: net <option> <argument>")
					break
				}
				arguments := userInput[1]

				// if the length of the options does not == 2, break, show error
				netArgs := strings.SplitN(arguments, " ", 2)

				if len(netArgs) != 2 {
					fmt.Println("Incorrect number of arguments. Usage: net <user/group> <input>")
					break
				}

				option, arg := netArgs[0], netArgs[1]

				// Switch case for net search options
				switch option {
				case "group":
					data := Queries.ReturnGroupQuery(arg, baseDN, conn)
					Globals.OutputAndLog(opt.logFile, data, 12, 8, 4, false)

				case "user":
					data := Queries.NetUserQuery(arg, baseDN, conn)
					Globals.OutputAndLog(opt.logFile, data, 0, 8, 0, false)

				case "nestedGroups":
					data := Queries.ReturnNestedGroupQuery(arg, baseDN, conn)
					Globals.OutputAndLog(opt.logFile, data, 12, 8, 4, false)

				default:
					fmt.Println("Invalid search. Please use:")
					fmt.Println("\tnet group <group>")
					fmt.Println("\tnet nestedGroups <group>")
					fmt.Println("\tnet user <user>")
				} // end 'net' module switch
			case "addComputer":
				if len(userInput) == 1 {
					fmt.Println("Incorrect number of arguments. Usage: addComputer <computerName$>")
					break
				}
				arguments := userInput[1]

				if !strings.HasSuffix(arguments, "$") {
					fmt.Println("Error in computerName. Ensure computername ends with '$'")
					break
				}

				result := Commands.AddComputerAccount(arguments, baseDN, conn)
				Globals.OutputAndLog(opt.logFile, result, 0, 0, 0, false)

			case "spn":
				if len(userInput) == 1 {
					fmt.Println("Incorrect number of arguments. Usage: spn <add/delete> <targetUser> <spn>")
					break
				}
				arguments := userInput[1]

				// split arguments into 3
				spnArgs := strings.SplitN(arguments, " ", 3)
				if len(spnArgs) != 3 {
					fmt.Println("Incorrect number of arguments. Usage: spn <add/delete> <targerUser> <spn/string>")
					break
				}
				option, targetUser, spn := spnArgs[0], spnArgs[1], spnArgs[2]
				switch option {
				case "add":
					result := Commands.AddSPN(targetUser, spn, baseDN, conn)
					Globals.OutputAndLog(opt.logFile, result, 0, 0, 0, false)

				case "delete":
					result := Commands.DeleteSPN(targetUser, spn, baseDN, conn)
					Globals.OutputAndLog(opt.logFile, result, 0, 0, 0, false)
				}
			case "getspns":
				var spnOutput string
				var spnLog string
				var f *os.File
				var multiOut io.Writer

				result := Queries.GetUserSPNs(baseDN, conn)
				//i tabwriter to format SPN output table
				spnWriter := new(tabwriter.Writer)

				// write to stdout and SPN Output File
				if opt.logFile != "" {
					spnOutput = fmt.Sprintf("spns-%s.txt", time.Now().Format("01-02-2006-03-04-05"))
					f, err = os.Create(spnOutput)
					if err != nil {
						log.Fatal(err)
					}

					multiOut = io.MultiWriter(f, os.Stdout)
				} else {
					multiOut = io.MultiWriter(os.Stdout)
				}
				spnWriter.Init(multiOut, 0, 8, 0, '\t', 0)
				fmt.Fprintln(spnWriter, result)

				// close writer and file
				spnWriter.Flush()
				f.Close()

				if opt.logFile != "" {
					spnLog = fmt.Sprintf("Output written to %s\n", spnOutput)
				}

				Globals.OutputAndLog(opt.logFile, spnLog, 0, 0, 0, false)

			case "roast":
				if len(userInput) == 1 {
					fmt.Println("Incorrect number of arguments. Usage: roast <targetUser>")
					break
				}
				roastuser := userInput[1]

				if cl == nil {
					cl = Globals.GetKerberosClient(domain, opt.dc, username, opt.password, opt.ntlm, opt.ccache, socksAddress, socksType)
				}

				result := Commands.RequestTicket(roastuser, cl)

				Globals.OutputAndLog(opt.logFile, result, 0, 0, 0, false)
			case "mquota":
				result := Queries.GetMachineQuota(baseDN, conn)
				Globals.OutputAndLog(opt.logFile, result, 0, 0, 0, false)

			case "passpol":
				result := Queries.GetPwdPolicy(baseDN, conn)
				Globals.OutputAndLog(opt.logFile, result, 0, 8, 0, false)

			case "dacl":
				if len(userInput) == 1 {
					fmt.Println("Incorrect number of arguments. Usage: dacl <target object>")
					break
				}
				arguments := userInput[1]

				data := Queries.GetSecurityDescriptor(arguments, baseDN, conn)
				Globals.OutputAndLog(opt.logFile, data, 6, 8, 4, false)
			default:
				fmt.Println("Invalid command. Use command, \"help\" for available options.")
			} // end 'module' switch
		} else {
			fmt.Print("Goodbye")
			break
		}
	}
}
