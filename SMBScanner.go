// Golang tool to scan SMB and identify version used and signing status
// by @xFreed0m

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/akamensky/argparse"
	"github.com/stacktitan/smb/smb"
)

func banner() {
	asciiArt :=
		`
   _____ __  _______ _____                                 
  / ___//  |/  / __ ) ___/_________ _____  ____  ___  _____
  \__ \/ /|_/ / __  \__ \/ ___/ __ '/ __ \/ __ \/ _ \/ ___/
 ___/ / /  / / /_/ /__/ / /__/ /_/ / / / / / / /  __/ /    
/____/_/  /_/_____/____/\___/\__,_/_/ /_/_/ /_/\___/_/   
===========================================================
By @x_Freed0m
`
	fmt.Println(asciiArt)
}

func argparser() (string, string, string, string, int, string) {
	// argparse section
	// Create new parser object
	parser := argparse.NewParser("SMBScanner", "Golang tool to scan hosts to identify SMB version and signing status. by @xFreed0m")
	targets := parser.String("", "targets", &argparse.Options{Required: true, Help: "File with target addresses to scan"})
	domain := parser.String("d", "domain", &argparse.Options{Required: true, Help: "Domain name to authenticate with"})
	username := parser.String("u", "username", &argparse.Options{Required: true, Help: "Username to authenticate with"})
	password := parser.String("p", "password", &argparse.Options{Required: true, Help: "Password to authenticate with"})
	port := parser.Int("", "port", &argparse.Options{Default: 445, Required: false, Help: "SMB Port to use"})
	logFile := parser.String("l", "logfile", &argparse.Options{Default: "SMBScan.log", Required: false, Help: "Log file to save results to"})

	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		log.Fatalln("[!] Missing arguments, please check your command")
		// using os.exit or the code will keep running with missing arguments
		os.Exit(1)
	}

	// returning all the arguments to be used when calling the executioning function
	return *targets, *domain, *username, *password, *port, *logFile
}

func logger(logfile string) {
	loggingfile, err := os.OpenFile(logfile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}

	// defer loggingfile.Close()

	output := io.MultiWriter(os.Stdout, loggingfile)

	log.SetOutput(output)
	// log.Print("Logging to a file in Go!")

}

func targetsReader(targets string) []string {
	targetsLines, err := os.Open(targets)
	if err != nil {
		log.Fatal(err)
	}
	defer targetsLines.Close()

	var lines []string
	scanner := bufio.NewScanner(targetsLines)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func smbScanner(targets []string, port int, username string, domain string, password string) {

	// scan section

	// for _, target := range targets {
	// 	// conversting port int to string
	// 	portStr := strconv.Itoa(port)
	// 	// creating the server + port string
	// 	targetAddr := target + ":" + portStr

	// }

	for _, target := range targets {

		options := smb.Options{
			Host:        target,
			Port:        port,
			User:        username,
			Domain:      domain,
			Workstation: "",
			Password:    password,
		}
		debug := false
		session, err := smb.NewSession(options, debug)

		if err != nil {
			log.Print("[!] ", err)
			continue
		}
		// defer session.Close()

		if session.IsAuthenticated {
			log.Print("[+] Login successful to ", target)
		} else {
			log.Print("[-] Login failed to ", target)
		}

		if session.IsSigningRequired {
			log.Print("[+] Signing is required on ", target)
		} else {
			log.Print("[-] Signing is NOT required on ", target)
		}

	}
}
func main() {

	banner()
	targets, domain, username, password, port, logfile := argparser()
	logger(logfile)
	lines := targetsReader(targets)
	smbScanner(lines, port, username, domain, password)

}

// TODO:
// add subnet support (argument and file)
// check and print the used SMB version

// v0.0.1
