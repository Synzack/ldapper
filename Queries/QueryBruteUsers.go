package Queries

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/schollz/progressbar/v3"
)

func BruteUserQuery(inputname string, server string, threads int, outputFile string, secure bool) {

	var err error
	var totalInputLines int

	// Open output file if specified
	output := os.Stdout
	if outputFile != "" {
		output, err = os.Create(outputFile)
		if err != nil {
			log.Printf("Can't open %v: %v\n\n", outputFile, err)
		}
		defer output.Close()
	}

	// Open input file
	input := os.Stdin
	if inputname != "" {
		input, err = os.Open(inputname)
		if err != nil {
			log.Printf("Can't open %v: %v\n\n", inputname, err)
		}
		defer input.Close()

		if outputFile != "" {
			// Count lines
			linescanner := bufio.NewScanner(input)
			linescanner.Split(bufio.ScanLines)
			for linescanner.Scan() {
				totalInputLines++
			}
			input.Seek(0, io.SeekStart)
		}
	}

	// Read users from file
	names := bufio.NewScanner(input)
	names.Split(bufio.ScanLines)

	// Create channels for parallel processing
	inputBuffer := make(chan string, 128)
	outputBuffer := make(chan string, 128)

	// Create mutex for connecting to LDAP
	var connectMutex sync.Mutex
	var connectError error

	// Use waitgroup to wait for all threads to finish
	var jobs sync.WaitGroup

	bar := progressbar.NewOptions(
		int(totalInputLines),
		progressbar.OptionSetDescription(fmt.Sprintf("Querying %v", server)),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionThrottle(100*time.Millisecond),
		progressbar.OptionUseANSICodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
	)

	// Add threads to waitgroup and start them
	jobs.Add(threads)
	for i := 0; i < threads; i++ {
		go func(server string) {
			for {
				connectMutex.Lock() // Lock mutex to prevent multiple threads from connecting at the same time
				if connectError != nil {
					connectMutex.Unlock() // Unlock mutex if there was an error
					jobs.Done()
					return
				}

				var conn *ldap.Conn
				switch secure {
				case false:
					conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", server, 389))
				case true:
					config := &tls.Config{
						ServerName:         server,
						InsecureSkipVerify: true,
					}
					conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", server, 636), config)
				}

				if err != nil {
					log.Printf("Problem connecting to LDAP %v server: %v", server, err)
					connectError = err
					jobs.Done()
					connectMutex.Unlock()
					return
				}

				// Unlock mutex after connection is established
				connectMutex.Unlock()

				// Start processing users from inputBuffer
				for user := range inputBuffer {
					request := ldap.NewSearchRequest(
						"", // we don't care about the base DN
						ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
						fmt.Sprintf("(&(NtVer=\x06\x00\x00\x00)(AAC=\x10\x00\x00\x00)(User="+user+"))"), // The filter to apply
						[]string{"NetLogon"}, // All that we care about is the NetLogon attribute
						nil,
					)
					response, err := conn.Search(request)
					if err != nil {
						if v, ok := err.(*ldap.Error); ok && v.ResultCode == 201 {
							continue
						}
						log.Printf("failed to execute search request: %v", err)
						continue
					}

					res := response.Entries[0].Attributes[0].ByteValues[0]
					if len(res) > 2 && res[0] == 0x17 && res[1] == 00 {
						outputBuffer <- user
					}
					bar.Add(1)
					io.MultiWriter(os.Stdout, bar)
				}
				break
			}

			jobs.Done()
		}(server)
	}

	// Start reading users from outputBuffer and put them in file or console
	go func() {
		for user := range outputBuffer {
			// this if statement is to console output issues when using the -o flag
			if outputFile != "" {
				fmt.Print("\033[2K\r") // clear line before printing
				fmt.Println("[+] Found user: " + user)
			} else {
				fmt.Print("\033[2K\r") // clear line before printing
				fmt.Print("[+] Found user: ")
			}
			fmt.Fprintln(output, user)
		}
	}()

	// Start reading users from file and put them in inputBuffer
	go func() {
		var line int
		for names.Scan() {

			user := names.Text()
			if user != "" {
				if strings.ContainsAny(user, `"/\:;|=,+*?<>`) {
					continue
				}
				inputBuffer <- user
			}
			line++
		}
		close(inputBuffer)
	}()

	jobs.Wait()
	close(outputBuffer)
}
