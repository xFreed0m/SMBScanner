// Golang tool to scan SMB and identify version used and signing status
// by @xFreed0m

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"

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
[!] Supports SMBv2 only!
By @x_Freed0m
`
	fmt.Println(asciiArt)
}

func argparser() (string, string, string, string, int, string, bool) {
	// argparse section
	// Create new parser object
	parser := argparse.NewParser("SMBScanner", "Golang tool to scan hosts to identify SMB version and signing status. by @xFreed0m")
	targets := parser.String("", "targets", &argparse.Options{Required: true, Help: "File with target addresses to scan"})
	domain := parser.String("d", "domain", &argparse.Options{Required: true, Help: "Domain name to authenticate with"})
	username := parser.String("u", "username", &argparse.Options{Required: true, Help: "Username to authenticate with"})
	password := parser.String("p", "password", &argparse.Options{Required: true, Help: "Password to authenticate with"})
	port := parser.Int("", "port", &argparse.Options{Default: 445, Required: false, Help: "SMB Port to use"})
	logFile := parser.String("l", "logfile", &argparse.Options{Default: "SMBScan.log", Required: false, Help: "Log file to save results to"})
	debug := parser.Flag("v", "verbose", &argparse.Options{Default: false, Required: false, Help: "debug"})

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
	return *targets, *domain, *username, *password, *port, *logFile, *debug
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

func hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

//  http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func targetsReader(targets string) []string {
	// opening the input file
	targetsLines, err := os.Open(targets)
	if err != nil {
		log.Fatal(err)
	}
	defer targetsLines.Close()

	var lines []string
	// reading the file content into string array
	scanner := bufio.NewScanner(targetsLines)
	for scanner.Scan() {
		// net.ParseCIDR(lines)
		lines = append(lines, scanner.Text())
	}

	var entries []string
	var cidr [][]string
	var singles []string

	// var ips [][]string
	for _, entry := range lines {
		// if entry has / in the line:
		// if strings.Contains(str, sub)
		if strings.Contains(entry, "/") {
			entries, err = hosts(entry)
			cidr = append(cidr, entries)
		} else {
			var ip net.IP
			ip = net.ParseIP(entry)
			singles = append(singles, ip.String())
		}
	}
	cidr = append(cidr, singles)

	var targetList []string
	for _, each := range cidr {
		for _, other := range each {
			targetList = append(targetList, other)
			sort.Strings(targetList)
		}
	}

	return targetList
}

func smbScanner(targets []string, port int, username string, domain string, password string, debug bool) {
	// scan section

	for _, target := range targets {

		options := smb.Options{
			Host:        target,
			Port:        port,
			User:        username,
			Domain:      domain,
			Workstation: "",
			Password:    password,
		}
		debug := debug
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
	targets, domain, username, password, port, logfile, debug := argparser()
	logger(logfile)
	ips := targetsReader(targets)

	smbScanner(ips, port, username, domain, password, debug)

}

// TODO:
// remove duplicates from targets
// pack the tool in docker file
// check and print the used SMB version (supported by library?)

// v0.0.4
