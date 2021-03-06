package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"ldapper/Commands"
	"ldapper/Globals"
	"ldapper/Queries"
	"log"
	"net"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"h12.io/socks"
)

type FlagOptions struct {
	username string
	password string
	ntlm     string
	domain   string
	dc       string
	scheme   bool
	logFile  string
	socks4   string
	socks4a  string
	socks5   string
	help     bool
}

func options() *FlagOptions {
	username := flag.String("u", "", "Username \nIf using password auth: 'NetBIOSName\\user' (Must be in quotes or use \\\\)\nIf using NTLM auth: 'username'")
	password := flag.String("p", "", "Password")
	ntlm := flag.String("H", "", "Use NTLM authentication")
	domain := flag.String("d", "", "Domain. Only needed if using NTLM authentication.")
	dc := flag.String("dc", "", "IP address or FQDN of target DC")
	scheme := flag.Bool("s", false, "Bind using LDAPS")
	logFile := flag.String("o", "", "Log file")
	socks4 := flag.String("socks4", "", "SOCKS4 Proxy Address (ip:port)")
	socks4a := flag.String("socks4a", "", "SOCKS4A Proxy Address (ip:port)")
	socks5 := flag.String("socks5", "", "SOCKS5 Proxy Address (ip:port)")
	help := flag.Bool("h", false, "Display help menu")

	flag.Parse()
	return &FlagOptions{
		username: *username,
		password: *password,
		ntlm:     *ntlm,
		domain:   *domain,
		dc:       *dc,
		scheme:   *scheme,
		logFile:  *logFile,
		socks4:   *socks4,
		socks4a:  *socks4a,
		socks5:   *socks5,
		help:     *help}

}

func main() {
	opt := options() //get options from command line

	const header = " __    ____   __   ____  ____  ____  ____  \n" +
		"(  )  (    \\ / _\\ (  _ \\(  _ \\(  __)(  _ \\ \n" +
		"/ (_/\\ ) D (/    \\ ) __/ ) __/ ) _)  )   / \n" +
		"\\____/(____/\\_/\\_/(__)  (__)  (____)(__\\_) \n" +
		"                          @SpaceManMitch96\n" +
		"                                @Synzack21\n\n"

	fmt.Print(header)

	// if required flags aren't set, print help
	if opt.username == "" || opt.dc == "" || (opt.password == "" && opt.ntlm == "") || opt.help {
		flag.Usage()
		fmt.Println("Examples:")
		fmt.Println("\tWith Password: \t./ldapper -u '<netbios>\\username' -p <password> -dc <ip/FQDN> -s")
		fmt.Println("\tWith Hash: \t./ldapper -u <username> -H <hash> -d <domain> -dc <ip/FQDN> -s")
		fmt.Println("Tips:\n\tNetBIOS name can be found with 'nmblookup -A dc-ip' (Linux) or 'nbtstat /a dc-ip' (Windows)")
		os.Exit(1)
	}

	var conn *ldap.Conn
	var proxyConn net.Conn
	var err error

	//Initialize connection with proxy if specified
	if opt.socks4 != "" || opt.socks4a != "" || opt.socks5 != "" {
		var port string
		if opt.scheme {
			port = "636"
		} else {
			port = "389"
		}

		var socksType int
		var socksAddress string
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
		proxyDial := socks.DialSocksProxy(socksType, socksAddress)
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

	//Authenticated Bind
	// if password option set
	if opt.password != "" {
		err = conn.Bind(opt.username, opt.password) //NetBios\user, password
		if err != nil {
			log.Fatal(err)
		} else {
			fmt.Println("Bind successful, dropping into shell. ")
		}
	}

	// if ntlm hash option set
	if opt.ntlm != "" {
		if opt.domain == "" {
			log.Fatal("Domain must be set if using NTLM")
		}
		if strings.Contains(opt.username, "\\") {
			log.Fatal("For NTLM, username must not contain '<netbios>\\'")
		}
		err = conn.NTLMBindWithHash(opt.domain, opt.username, opt.ntlm) //NetBios\user, ntlm hash
		if err != nil {
			fmt.Print("test\n")
			log.Fatal(err)
		} else {
			fmt.Println("Bind successful, dropping into shell. ")
		}
	}
	baseDN := Globals.GetBaseDN(opt.dc, conn)

	// Create impromptu shell for input
	reader := bufio.NewReader(os.Stdin)

	for { //Loop forever
		fmt.Print("\n> ")
		userQuery, err := reader.ReadString('\n')       //Read user input
		userQuery = strings.TrimSuffix(userQuery, "\n") //Remove newline
		if err != nil {                                 //Check for errors
			fmt.Fprintln(os.Stderr, err)
		}

		if opt.logFile != "" {
			Globals.LogToFile(opt.logFile, "> "+userQuery)
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
					"Commands:\n" +
					"\taddComputer <computerName$>  (Requires LDAPS)\n" +
					"\tspn <add/delete> <targetUser> <spn>\n" +
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
				fmt.Println(data)

				// if logfile flag is set, write to file
				if opt.logFile != "" {
					if data != "" {
						Globals.LogToFile(opt.logFile, data)
					}
				}

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
					fmt.Println(data)

					// if logfile flag is set, write to file
					if opt.logFile != "" {
						if data != "" {
							Globals.LogToFile(opt.logFile, data)
						}
					}

				case "user":
					data := Queries.NetUserQuery(arg, baseDN, conn)
					fmt.Println(data)

					// if logfile flag is set, write to file
					if opt.logFile != "" {
						if data != "" {
							Globals.LogToFile(opt.logFile, data)
						}
					}

				case "nestedGroups":
					data := Queries.ReturnNestedGroupQuery(arg, baseDN, conn)
					fmt.Println(data)

					// if logfile flag is set, write to file
					if opt.logFile != "" {
						if data != "" {
							Globals.LogToFile(opt.logFile, data)
						}
					}
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
				fmt.Println(result)

				if opt.logFile != "" {
					if result != "" {
						Globals.LogToFile(opt.logFile, result)
					}
				}
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
					fmt.Println(result)
					if opt.logFile != "" {
						if result != "" {
							Globals.LogToFile(opt.logFile, result)
						}
					}
				case "delete":
					result := Commands.DeleteSPN(targetUser, spn, baseDN, conn)
					fmt.Println(result)
					if opt.logFile != "" {
						if result != "" {
							Globals.LogToFile(opt.logFile, result)
						}
					}
				}
			default:
				fmt.Println("Invalid command. Use command, \"help\" for available options.")
			} // end 'module' switch
		} else {
			fmt.Print("Goodbye")
			break
		}
	}
}
