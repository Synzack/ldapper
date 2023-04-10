package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"ldapper/Commands"
	"ldapper/Globals"
	"ldapper/Queries"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/desertbit/grumble"
	"github.com/fatih/color"
	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"h12.io/socks"
)

var App *grumble.App

var Connected bool

var Conn *ldap.Conn
var ProxyConn net.Conn
var Err error
var Port string
var BaseDN string

var Cl *client.Client
var SocksType int
var SocksAddress string
var ProxyDial func(string, string) (net.Conn, error)

var Domain string
var Username string
var Target []string
var DC string
var Password string
var NTLM string
var Ccache bool
var LogFile string
var LDAPS bool
var Timestamping bool

func main() {
	App = grumble.New(&grumble.Config{
		Name:           "Ldapper",
		Description:    "Enumerate and abuse LDAP. Made simple",
		PromptColor:    color.New(color.FgCyan, color.Bold),
		ASCIILogoColor: color.New(color.FgCyan, color.Bold),
		//HelpHeadlineUnderline: true,
		HelpHeadlineColor: color.New(color.FgCyan, color.Bold),
	})

	App.SetPrintASCIILogo(func(a *grumble.App) {
		a.Println(" __    ____   __   ____  ____  ____  ____  ")
		a.Println("(  )  (    \\ / _\\ (  _ \\(  _ \\(  __)(  _ \\ ")
		a.Println("/ (_/\\ ) D (/    \\ ) __/ ) __/ ) _)  )   / ")
		a.Println("\\____/(____/\\_/\\_/(__)  (__)  (____)(__\\_) ")
		a.Println("                          @SpaceManMitch96")
		a.Println("                                @Synzack21")
		a.Println("                                  @mfdooom\n")

	})
	App.SetPrompt("Not Connected » ")

	App.AddCommand(&grumble.Command{
		Name:      "brute",
		Help:      "Brute force users from a file. No authentication needed.",
		HelpGroup: "Ldapper Enumeration:",

		Flags: func(f *grumble.Flags) {
			f.String("d", "dc", "", "IP address or FQDN of target DC")
			f.String("f", "file", "", "Input file of usernames")
			f.Int("t", "threads", 4, "Number of threads")
			f.String("o", "output file", "", "Name of outputfile")
		},

		Run: func(c *grumble.Context) error {
			if c.Flags.String("dc") == "" || c.Flags.String("file") == "" {
				App.Println("Domain controller and input file must be specified. See \"help brute\" for details.\n")
				return nil
			}
			Queries.BruteUserQuery(c.Flags.String("file"), c.Flags.String("dc"), c.Flags.Int("threads"), c.Flags.String("output file"), LDAPS)
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "disconnect",
		Help:      "Close the LDAP connection",
		HelpGroup: "Initialize/Deinitialize:",

		Run: func(c *grumble.Context) error {
			if Connected {
				App.Printf("Disconnecting from LDAP server at %s...\n\n", DC)
				Conn.Close()
				App.SetPrompt("Not Connected » ")
				Connected = false

				return nil
			} else {
				App.Println("No active LDAP connection. Please see the \"connect\" command to initialize.\n")
				return nil
			}
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "dacl",
		Help:      "Query the DACL of a target object",
		HelpGroup: "Ldapper Queries:",

		Args: func(a *grumble.Args) {
			a.String("target", "target object")
		},

		Run: func(c *grumble.Context) error {
			if Connected {
				if LogFile != "" {
					Globals.OutputAndLog(LogFile, "> "+"dacl "+c.Args.String("target")+"\n", 0, 0, 0, true)
				}
				if Timestamping {
					data := time.Now().Format("01/02/2006 03:04:05") + "\n\n"
					data += Queries.GetSecurityDescriptor(c.Args.String("target"), BaseDN, Conn)
					Globals.OutputAndLog(LogFile, data, 6, 8, 4, false)
				} else {
					data := Queries.GetSecurityDescriptor(c.Args.String("target"), BaseDN, Conn)
					Globals.OutputAndLog(LogFile, data, 6, 8, 4, false)
				}

				return nil
			} else {
				App.Println("No active LDAP connection. Please see the \"connect\" command to initialize.\n")
				return nil
			}
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "passpol",
		Help:      "Query the password policy of the domain",
		HelpGroup: "Ldapper Queries:",

		Run: func(c *grumble.Context) error {
			if Connected {
				if LogFile != "" {
					Globals.OutputAndLog(LogFile, "> "+"passpol"+"\n", 0, 0, 0, true)
				}
				if Timestamping {
					result := time.Now().Format("01/02/2006 03:04:05") + "\n"
					result += Queries.GetPwdPolicy(BaseDN, Conn)
					Globals.OutputAndLog(LogFile, result, 0, 8, 0, false)
				} else {
					result := Queries.GetPwdPolicy(BaseDN, Conn)
					Globals.OutputAndLog(LogFile, result, 0, 8, 0, false)
				}

				return nil
			} else {
				App.Println("No active LDAP connection. Please see the \"connect\" command to initialize.\n")
				return nil
			}
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "mquota",
		Help:      "Query the machine account quota of the domain",
		HelpGroup: "Ldapper Queries:",

		Run: func(c *grumble.Context) error {
			if Connected {
				if LogFile != "" {
					Globals.OutputAndLog(LogFile, "> "+"mquota"+"\n", 0, 0, 0, true)
				}
				if Timestamping {
					result := time.Now().Format("01/02/2006 03:04:05") + "\n\n"
					result += Queries.GetMachineQuota(BaseDN, Conn)
					Globals.OutputAndLog(LogFile, result, 0, 0, 0, false)
				} else {
					result := Queries.GetMachineQuota(BaseDN, Conn)
					Globals.OutputAndLog(LogFile, result, 0, 0, 0, false)
				}

				return nil
			} else {
				App.Println("No active LDAP connection. Please see the \"connect\" command to initialize.\n")
				return nil
			}
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "roast",
		Help:      "Kerberoast a user with an SPN",
		HelpGroup: "Ldapper Commands:",

		Args: func(a *grumble.Args) {
			a.String("algorithm", "rc4/aes")
			a.String("target", "target user")
		},

		Run: func(c *grumble.Context) error {
			if Connected {
				if LogFile != "" {
					Globals.OutputAndLog(LogFile, "> "+"roast "+c.Args.String("algorithm")+" "+c.Args.String("target")+"\n", 0, 0, 0, true)
				}

				switch c.Args.String("algorithm") {
				case "rc4", "aes":
					etype, roastuser := c.Args.String("algorithm"), c.Args.String("target")
					Cl = Globals.GetKerberosClient(Domain, DC, Username, Password, NTLM, Ccache, etype, SocksAddress, SocksType)

					if Timestamping {
						result := time.Now().Format("01/02/2006 03:04:05") + "\n\n"
						result += Commands.RequestTicket(roastuser, Cl)
						Globals.OutputAndLog(LogFile, result, 0, 0, 0, false)
					} else {
						result := Commands.RequestTicket(roastuser, Cl)
						Globals.OutputAndLog(LogFile, result, 0, 0, 0, false)
					}
					return nil
				default:
					App.Println("Not a valid algorithm. Please use \"rc4\" or \"aes\".\n")
					return nil
				}
			} else {
				App.Println("No active LDAP connection. Please see the \"connect\" command to initialize.\n")
				return nil
			}
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "getspns",
		Help:      "Query all user accounts with an SPN",
		HelpGroup: "Ldapper Queries:",

		Run: func(c *grumble.Context) error {
			var spnOutput string
			var spnLog string
			var f *os.File
			var multiOut io.Writer

			if Connected {
				var result string
				if Timestamping {
					result = time.Now().Format("01/02/2006 03:04:05") + "\n\n"
					result += Queries.GetUserSPNs(BaseDN, Conn)
				} else {
					result = Queries.GetUserSPNs(BaseDN, Conn)
				}

				spnWriter := new(tabwriter.Writer)

				if LogFile != "" {
					Globals.OutputAndLog(LogFile, "> "+"getspns", 0, 0, 0, true)

					spnOutput = fmt.Sprintf("spns-%s.txt", time.Now().Format("01-02-2006-03-04-05"))
					f, Err = os.Create(spnOutput)
					if Err != nil {
						App.Println(Err)
						return nil
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

				if LogFile != "" {
					spnLog = fmt.Sprintf("Output written to %s\n", spnOutput)
				}

				Globals.OutputAndLog(LogFile, spnLog, 0, 0, 0, false)

				return nil
			} else {
				App.Println("No active LDAP connection. Please see the \"connect\" command to initialize.\n")
				return nil
			}
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "spn",
		Help:      "Add or remove a SPN on a user account",
		HelpGroup: "Ldapper Commands:",

		Args: func(a *grumble.Args) {
			a.String("argument", "add/delete")
			a.String("target", "target user")
			a.String("spn", "SPN to add or delete")
		},

		Run: func(c *grumble.Context) error {
			if Connected {
				switch c.Args.String("argument") {
				case "add":
					if LogFile != "" {
						Globals.OutputAndLog(LogFile, "> "+"spn add "+c.Args.String("target")+" "+c.Args.String("spn")+"\n", 0, 0, 0, true)
					}
					if Timestamping {
						result := time.Now().Format("01/02/2006 03:04:05") + "\n\n"
						result += Commands.AddSPN(c.Args.String("target"), c.Args.String("spn"), BaseDN, Conn)
						Globals.OutputAndLog(LogFile, result, 0, 0, 0, false)
					} else {
						result := Commands.AddSPN(c.Args.String("target"), c.Args.String("spn"), BaseDN, Conn)
						Globals.OutputAndLog(LogFile, result, 0, 0, 0, false)
					}

				case "delete":
					if LogFile != "" {
						Globals.OutputAndLog(LogFile, "> "+"spn delete "+c.Args.String("target")+" "+c.Args.String("spn")+"\n", 0, 0, 0, true)
					}
					if Timestamping {
						result := time.Now().Format("01/02/2006 03:04:05") + "\n\n"
						result += Commands.DeleteSPN(c.Args.String("target"), c.Args.String("spn"), BaseDN, Conn)
						Globals.OutputAndLog(LogFile, result, 0, 0, 0, false)
					} else {
						result := Commands.DeleteSPN(c.Args.String("target"), c.Args.String("spn"), BaseDN, Conn)
						Globals.OutputAndLog(LogFile, result, 0, 0, 0, false)
					}

				default:
					App.Println("Not a valid argument. Please use \"add\" or \"delete\"")
				}
				return nil
			} else {
				App.Println("No active LDAP connection. Please see the \"connect\" command to initialize.\n")
				return nil
			}
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "addComputer",
		Help:      "Add a computer to the domain",
		HelpGroup: "Ldapper Commands:",

		Args: func(a *grumble.Args) {
			a.String("computerName", "machine name to add")
		},

		Run: func(c *grumble.Context) error {
			if Connected {
				if LogFile != "" {
					Globals.OutputAndLog(LogFile, "> "+"addComputer "+c.Args.String("computerName")+"\n", 0, 0, 0, true)
				}
				if !strings.HasSuffix(c.Args.String("computerName"), "$") {
					App.Println("Error in computerName. Ensure computerName ends with '$'")
					return nil
				}
				if Timestamping {
					result := time.Now().Format("01/02/2006 03:04:05") + "\n\n"
					result += Commands.AddComputerAccount(c.Args.String("computerName"), BaseDN, Conn)
					Globals.OutputAndLog(LogFile, result, 0, 0, 0, false)
				} else {
					result := Commands.AddComputerAccount(c.Args.String("computerName"), BaseDN, Conn)
					Globals.OutputAndLog(LogFile, result, 0, 0, 0, false)
				}

				return nil

			} else {
				App.Println("No active LDAP connection. Please see the \"connect\" command to initialize.\n")
				return nil
			}
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "groups",
		Help:      "Query the groups for a target user",
		HelpGroup: "Ldapper Queries:",

		Args: func(a *grumble.Args) {
			a.String("username", "username to query group memberships for")
		},

		Run: func(c *grumble.Context) error {
			if Connected {
				if LogFile != "" {
					Globals.OutputAndLog(LogFile, "> "+"groups "+c.Args.String("username")+"\n", 0, 0, 0, true)
				}
				if len(c.Args.String("username")) == 1 {
					App.Println("Incorrect number of arguments. Usage: groups <username>")
					return nil
				}
				if Timestamping {
					data := time.Now().Format("01/02/2006 03:04:05") + "\n\n"
					data += Queries.GroupsQuery(c.Args.String("username"), BaseDN, Conn)
					Globals.OutputAndLog(LogFile, data, 12, 8, 4, false)
				} else {
					data := Queries.GroupsQuery(c.Args.String("username"), BaseDN, Conn)
					Globals.OutputAndLog(LogFile, data, 12, 8, 4, false)
				}

				return nil
			} else {
				App.Println("No active LDAP connection. Please see the \"connect\" command to initialize.\n")
				return nil
			}
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "net",
		Help:      "Run net commands",
		HelpGroup: "Ldapper Queries:",

		Args: func(a *grumble.Args) {
			a.String("module", "module to use (user, group, or nestedGroups)")
			a.String("query", "object to query (username or group name). Multi-word queries such as 'domain admins' need to be in ticks or quotes.")
		},

		Run: func(c *grumble.Context) error {
			if Connected {

				switch c.Args.String("module") {
				case "group":
					if LogFile != "" {
						Globals.OutputAndLog(LogFile, "> "+"net group "+c.Args.String("query")+"\n", 0, 0, 0, true)
					}
					if Timestamping {
						data := time.Now().Format("01/02/2006 03:04:05") + "\n\n"
						data += Queries.ReturnGroupQuery(c.Args.String("query"), BaseDN, Conn)
						Globals.OutputAndLog(LogFile, data, 12, 8, 4, false)
					} else {
						data := Queries.ReturnGroupQuery(c.Args.String("query"), BaseDN, Conn)
						Globals.OutputAndLog(LogFile, data, 12, 8, 4, false)
					}

				case "user":
					if LogFile != "" {
						Globals.OutputAndLog(LogFile, "> "+"net user "+c.Args.String("query")+"\n", 0, 0, 0, true)
					}
					if Timestamping {
						data := time.Now().Format("01/02/2006 03:04:05") + "\n"
						data += Queries.NetUserQuery(c.Args.String("query"), BaseDN, Conn)
						Globals.OutputAndLog(LogFile, data, 0, 8, 0, false)
					} else {
						data := Queries.NetUserQuery(c.Args.String("query"), BaseDN, Conn)
						Globals.OutputAndLog(LogFile, data, 0, 8, 0, false)
					}

				case "nestedGroups":
					if LogFile != "" {
						Globals.OutputAndLog(LogFile, "> "+"net nestedGroups "+c.Args.String("query")+"\n", 0, 0, 0, true)
					}
					if Timestamping {
						data := time.Now().Format("01/02/2006 03:04:05") + "\n\n"
						data += Queries.ReturnNestedGroupQuery(c.Args.String("query"), BaseDN, Conn)
						Globals.OutputAndLog(LogFile, data, 12, 8, 4, false)
					} else {
						data := Queries.ReturnNestedGroupQuery(c.Args.String("query"), BaseDN, Conn)
						Globals.OutputAndLog(LogFile, data, 12, 8, 4, false)
					}

				default:
					App.Println("Invalid search. Please use:")
					App.Println("\tnet group <group>")
					App.Println("\tnet nestedGroups <group>")
					App.Println("\tnet user <user>")
				}
				return nil
			} else {
				App.Println("No active LDAP connection. Please see the \"connect\" command to initialize.\n")
				return nil
			}
		},
	})

	App.AddCommand(&grumble.Command{
		Name:      "connect",
		Help:      "Connect to a LDAP server",
		HelpGroup: "Initialize/Deinitialize:",

		Flags: func(f *grumble.Flags) {
			f.String("u", "username", "", "Username (username@domain)")
			f.String("p", "password", "", "Password")
			f.String("H", "ntlm", "", "Use NTLM Authentication")
			f.Bool("k", "kerberos", false, "Use Kerberos Authentication. Grabs credentials from ccache file (KRB5CCNAME)")
			f.String("d", "dc", "", "IP address or FQDN of target DC")
			f.Bool("s", "ldaps", false, "Bind using LDAPS")
			f.String("o", "output", "", "Log file")
			f.String("4", "socks4", "", "SOCKS4 Proxy Address (ip:port)")
			f.String("a", "socks4a", "", "SOCKS4A Proxy Address (ip:port)")
			f.String("5", "socks5", "", "SOCKS5 Proxy Address (ip:port)")
			f.Bool("t", "timestamps", false, "Enable timestamping")
		},

		Run: func(c *grumble.Context) error {
			if c.Flags.String("username") == "" || c.Flags.String("dc") == "" || (c.Flags.String("password") == "" && c.Flags.String("ntlm") == "" && !c.Flags.Bool("kerberos")) {
				App.Println("Improper usage. Please see sample usage below. For full list of arguments, see \"help connect\"")
				fmt.Println("Examples:")
				fmt.Println("\tWith Password: \tconnect -u <username@domain> -p <password> -d <ip/FQDN> -s")
				fmt.Println("\tWith Hash: \tconnect -u <username@domain> -H <hash> -d <ip/FQDN> -s")
				fmt.Println("\tWith Kerberos: \tconnect -u <username@domain> -k -d <ip/FQDN> -s\n")
				return nil
			}

			Timestamping = c.Flags.Bool("timestamps")

			Target = strings.Split(c.Flags.String("username"), "@")

			// Did the user supply the username correctly <user@domain>?
			if len(Target) == 1 {
				App.Println("Invalid input. Please use format username@domain.")
				return nil
			} else {
				Username = Target[0]
				Domain = Target[1]
			}

			//Initialize connection with proxy if specified
			if c.Flags.String("socks4") != "" || c.Flags.String("socks4a") != "" || c.Flags.String("socks5") != "" {
				if c.Flags.Bool("ldaps") {
					Port = "636"
				} else {
					Port = "389"
				}

				if c.Flags.String("socks4") != "" {
					//set socks to socks4
					SocksType = socks.SOCKS4
					SocksAddress = c.Flags.String("socks4")
				} else if c.Flags.String("socks4a") != "" {
					//set socks to socks4a
					SocksType = socks.SOCKS4A
					SocksAddress = c.Flags.String("socks4a")
				} else if c.Flags.String("socks5") != "" {
					//set socks to socks5
					SocksType = socks.SOCKS5
					SocksAddress = c.Flags.String("socks5")
				}

				// check for socks options
				ProxyDial = socks.DialSocksProxy(SocksType, SocksAddress)

				ProxyConn, Err = ProxyDial("tcp", fmt.Sprintf("%s:%s", c.Flags.String("dc"), Port))
				if Err != nil {
					//log.Fatal("Cannot connect through proxy.\n", err)
					App.Printf("Cannot connect through proxy: %v\n", Err)
					return nil
				}

				if c.Flags.Bool("ldaps") {
					proxyTLS := tls.Client(ProxyConn, &tls.Config{InsecureSkipVerify: true})
					Conn = ldap.NewConn(proxyTLS, c.Flags.Bool("ldaps"))
				} else {
					Conn = ldap.NewConn(ProxyConn, c.Flags.Bool("ldaps"))
				}

				Conn.Start()
				fmt.Printf("Connecting with proxy: %s\n\n", SocksAddress)
			} else { //Initialize without proxy
				if c.Flags.Bool("ldaps") {
					ldapsAddress := fmt.Sprintf("%s:%d", c.Flags.String("dc"), 636)
					Conn, Err = ldap.DialTLS("tcp", ldapsAddress, &tls.Config{InsecureSkipVerify: true})
					if Err != nil {

					}

				} else {
					Conn, Err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", c.Flags.String("dc"), 389))
					if Err != nil {
						App.Printf("%v\n", Err)
						return nil
					}
				}
			}

			// if password option set
			if c.Flags.String("password") != "" {
				Err = Conn.Bind(c.Flags.String("username"), c.Flags.String("password"))
				if Err != nil {
					App.Printf("%v\n", Err)
					return nil
				} else {
					if Timestamping {
						App.Println(time.Now().Format("01/02/2006 03:04:05") + "\n\nBind successful, opening connection. Timestamping enabled.\n ")
					} else {
						App.Println("Bind successful, opening connection.\n ")
					}
				}
			}
			// if ntlm hash option set
			if c.Flags.String("ntlm") != "" {
				Err = Conn.NTLMBindWithHash(Domain, Username, c.Flags.String("ntlm"))
				if Err != nil {
					App.Printf("%v\n", Err)
					return nil
				} else {
					if Timestamping {
						App.Println(time.Now().Format("01/02/2006 03:04:05") + "\n\nBind successful, opening connection. Timestamping enabled.\n ")
					} else {
						App.Println("Bind successful, opening connection.\n ")
					}
				}
			}

			// if kerberos option set
			if c.Flags.Bool("kerberos") {
				Cl = Globals.GetKerberosClient(Domain, c.Flags.String("dc"), Username, c.Flags.String("password"), c.Flags.String("ntlm"), c.Flags.Bool("kerberos"), "aes", SocksAddress, SocksType)

				if Err != nil {
					App.Printf("%v\n", Err)
					return nil
				}

				machineName := Globals.GetMachineHostname(c.Flags.String("dc"), ProxyDial)

				spnTarget := fmt.Sprintf("ldap/%s", machineName)

				_, Err = Conn.GSSAPICCBindCCache(Cl, spnTarget)
				if Err != nil {
					App.Printf("%v\n", Err)
					return nil
				} else {
					if Timestamping {
						App.Println(time.Now().Format("01/02/2006 03:04:05") + "\n\nKerberos GSSAPI Bind successful, opening connection. Timestamping enabled.\n ")
					} else {
						App.Println("Kerberos GSSAPI Bind succesful, opening connection.\n ")
					}
				}
			}

			//Set Global Variables
			Connected = true
			DC = c.Flags.String("dc")
			Password = c.Flags.String("password")
			NTLM = c.Flags.String("ntlm")
			Ccache = c.Flags.Bool("kerberos")
			BaseDN = Globals.GetBaseDN(c.Flags.String("dc"), Conn)
			LDAPS = c.Flags.Bool("ldaps")

			if c.Flags.String("output") != "" {
				LogFile = c.Flags.String("output")
			}

			if c.Flags.Bool("ldaps") {
				App.SetPrompt(fmt.Sprintf("%s@%s:636(s) » ", Username, c.Flags.String("dc")))
			} else {
				App.SetPrompt(fmt.Sprintf("%s@%s:389 » ", Username, c.Flags.String("dc")))
			}
			return nil
		},
	})

	appErr := App.Run()
	if appErr != nil {
		fmt.Printf("Could not initialize Ldapper: %v", appErr)
	}
	if Connected {
		defer Conn.Close()
	}

}
