package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	defaultPorts = "80,443,22"
)

func main() {
	config := parseFlags()
	results := &Results{}

	if config.help {
		printHelp()
		os.Exit(0)
	}

	validateInput(config, results)

	setupTempDir(&config)

	convertCIDRtoIPList(&config)

	runScanningTechniques(config, results)

	printText(config.isSilent, "End, good bye:)", "Print")
	removeTempDir(config.tempDir)
}

type Config struct {
	ip              string
	ipList          string
	cidr            string
	cidrList        string
	outputFile      string
	ports           string
	threads         int
	verbose         bool
	isSilent        bool
	help            bool
	pingTimeout     time.Duration
	portscanTimeout time.Duration
	fullMode        bool
	pingMode        bool
	portscanMode    bool
	ptrMode         bool
	tempDir         string
}

type Results struct {
	activeIPs []string
	sync.Mutex
}

func parseFlags() Config {
	config := NewConfig()                            // Create a new Config struct with default values
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine) // Use pflag alongside the standard flag package
	pflag.StringVarP(&config.ip, "ip", "i", "", "single IP")
	pflag.StringVarP(&config.ipList, "ip-list", "I", "", "list of IP")
	pflag.StringVarP(&config.cidr, "cidr", "c", "", "list of CIDR")
	pflag.StringVarP(&config.cidrList, "cidr-list", "C", "", "list of CIDR")
	pflag.StringVarP(&config.outputFile, "output", "o", "", "output file")
	pflag.StringVarP(&config.ports, "ports", "p", defaultPorts, "Comma-separated list of ports. default: 80,443,22")
	pflag.DurationVar(&config.pingTimeout, "ping-timeout", 400*time.Millisecond, "Ping timeout in milliseconds")
	pflag.DurationVar(&config.portscanTimeout, "portscan-timeout", 400*time.Millisecond, "Port-scan timeout in milliseconds")
	pflag.BoolVarP(&config.fullMode, "full", "", false, "Runs full mode")
	pflag.BoolVarP(&config.pingMode, "ping", "", true, "Runs only ping mode")
	pflag.BoolVarP(&config.portscanMode, "portscan", "", false, "Runs only portscan mode")
	pflag.BoolVarP(&config.ptrMode, "ptr", "", false, "Runs PTR scan")
	pflag.IntVarP(&config.threads, "threads", "t", 5, "number of threads")
	pflag.BoolVarP(&config.verbose, "verbose", "v", false, "verbose mode. If set, it shows according to which technique the IP is active.")
	pflag.BoolVarP(&config.isSilent, "silent", "s", false, "silent mode")
	pflag.BoolVarP(&config.help, "help", "h", false, "print this help menu")
	pflag.Parse()
	pflag.Visit(func(f *pflag.Flag) {
		switch f.Name {
		case "ip", "ip-list", "cidr", "cidr-list", "output", "ports":
			// Validate and process flag values as needed
		case "verbose":
			config.verbose = true
		case "silent":
			config.isSilent = true
		case "help":
			config.help = true
		case "full":
			config.fullMode = true
		case "ping":
			config.pingMode = true
		case "portscan":
			config.portscanMode = true
		case "ptr":
			config.ptrMode = true
		}
	})
	return config
}
func NewConfig() Config {
	return Config{
		ports:           defaultPorts,
		threads:         5,
		pingTimeout:     400 * time.Millisecond,
		portscanTimeout: 400 * time.Millisecond,
	}
}

func validateInput(config Config, results *Results) {
	if config.cidr == "" && config.cidrList == "" && config.ip == "" && config.ipList == "" {
		printText(config.isSilent, "You must specify at least one of the following flags: (-c | --cidr), (-i | --ip), (-I | --ip-list), (-C | --cidr-list", "Error")
		printText(config.isSilent, "Use -h or --help for more information", "Info")
		os.Exit(1)
	}

	if (config.ip != "" && config.ipList != "") || (config.ip != "" && config.cidr != "") || (config.ip != "" && config.cidrList != "") || (config.ipList != "" && config.cidr != "") || (config.ipList != "" && config.cidrList != "") || (config.cidr != "" && config.cidrList != "") {
		printText(config.isSilent, "Incompatible flags detected. You can only use one of the following flags: (-i | --ip), (-I | --ip-list), (-c | --cidr), (-C | --cidr-list).", "Error")
		printText(config.isSilent, "Use -h or --help for more information.", "Info")
		os.Exit(1)
	}

	if config.fullMode && (config.pingMode || config.portscanMode || config.ptrMode) {
		printText(config.isSilent, "Incompatible flags detected. When using -full flag, other flags (-ping, -portscan, -ptr) are not allowed.", "Error")
		printText(config.isSilent, "Use -h or --help for more information.", "Info")
		os.Exit(1)
	}

	if (config.cidrList != "" || config.ipList != "") && config.outputFile == "" {
		printText(config.isSilent, "You must specify an output file when using -ip-list or -cidr-list flags.", "Error")
		printText(config.isSilent, "Use -h or --help for more information.", "Info")
		os.Exit(1)
	}

	if config.threads <= 0 {
		printText(config.isSilent, "Number of threads must be greater than 0.", "Error")
		os.Exit(1)
	}

	if config.pingTimeout <= 0 {
		printText(config.isSilent, "Ping timeout must be greater than 0.", "Error")
		os.Exit(1)
	}

	if config.portscanTimeout <= 0 {
		printText(config.isSilent, "Portscan timeout must be greater than 0.", "Error")
		os.Exit(1)
	}

	if config.portscanTimeout < config.pingTimeout {
		printText(config.isSilent, "Portscan timeout cannot be less than ping timeout.", "Error")
		os.Exit(1)
	}
}

func setupTempDir(config *Config) {
	config.tempDir = filepath.Join(os.TempDir(), "goscan-"+strconv.Itoa(rand.Int()))
	if err := os.MkdirAll(config.tempDir, os.ModePerm); err != nil {
		printText(config.isSilent, fmt.Sprintf("Failed to create temporary directory: %v", err), "Error")
		os.Exit(1)
	}
}

func convertCIDRtoIPList(config *Config) {
	if config.cidr != "" {
		ip, ipnet, err := net.ParseCIDR(config.cidr)
		if err != nil {
			printText(config.isSilent, fmt.Sprintf("Failed to parse CIDR: %v", err), "Error")
			os.Exit(1)
		}

		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			config.ipList += ip.String() + "\n"
		}
		config.ipList = strings.TrimSpace(config.ipList)
	}

	if config.cidrList != "" {
		file, err := os.Open(config.cidrList)
		if err != nil {
			printText(config.isSilent, fmt.Sprintf("Failed to open CIDR list file: %v", err), "Error")
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			cidr := scanner.Text()
			ip, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				printText(config.isSilent, fmt.Sprintf("Failed to parse CIDR from list: %v", err), "Error")
				continue
			}

			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
				config.ipList += ip.String() + "\n"
			}
		}
		config.ipList = strings.TrimSpace(config.ipList)
	}
}

func runScanningTechniques(config Config, results *Results) {
	// Use channels to collect results from goroutines.
	var wg sync.WaitGroup
	activeIPChan := make(chan string, config.threads*2)
	defer close(activeIPChan)

	for i := 0; i < config.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range activeIPChan {
				results.Lock()
				results.activeIPs = append(results.activeIPs, ip)
				results.Unlock()
			}
		}()
	}

	if config.pingMode || config.fullMode {
		pingTechnique(config, activeIPChan)
	}

	if config.portscanMode || config.fullMode {
		portScanTechnique(config, activeIPChan)
	}

	wg.Wait()

	if config.ptrMode {
		ptrScanTechnique(config, results)
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func pingTechnique(config Config, activeIPChan chan<- string) {
	if config.verbose {
		printText(config.isSilent, "Starting ping scan", "Info")
	}

	if config.ipList != "" {
		ipList := strings.Split(config.ipList, "\n")
		for _, ip := range ipList {
			pingIP(ip, config, activeIPChan)
		}
	} else if config.ip != "" {
		pingIP(config.ip, config, activeIPChan)
	}
}

func pingIP(ip string, config Config, activeIPChan chan<- string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		printText(config.isSilent, fmt.Sprintf("Invalid IP address: %s", ip), "Error")
		return
	}

	timeout := config.pingTimeout
	if config.verbose {
		printText(config.isSilent, fmt.Sprintf("Pinging %s with a timeout of %s...", ip, timeout), "Info")
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		printText(config.isSilent, fmt.Sprintf("Failed to create ICMP packet listener for %s: %v", ip, err), "Error")
		return
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte(""),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		printText(config.isSilent, fmt.Sprintf("Failed to marshal ICMP message for %s: %v", ip, err), "Error")
		return
	}

	startTime := time.Now()

	_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: parsedIP})
	if err != nil {
		printText(config.isSilent, fmt.Sprintf("Failed to send ICMP packet to %s: %v", ip, err), "Error")
		return
	}

	conn.SetReadDeadline(time.Now().Add(timeout))

	response := make([]byte, 1500)
	_, _, err = conn.ReadFrom(response)
	if err != nil {
		printText(config.isSilent, fmt.Sprintf("No response from %s: %v", ip, err), "Info")
		return
	}

	elapsedTime := time.Since(startTime)
	if config.verbose {
		printText(config.isSilent, fmt.Sprintf("Received ICMP reply from %s in %s", ip, elapsedTime), "Info")
	}

	activeIPChan <- ip
}

func portScanTechnique(config Config, activeIPChan chan<- string) {
	if config.verbose {
		printText(config.isSilent, "Starting port scan", "Info")
	}

	if config.ipList != "" {
		ipList := strings.Split(config.ipList, "\n")
		for _, ip := range ipList {
			portScanIP(ip, config, activeIPChan)
		}
	} else if config.ip != "" {
		portScanIP(config.ip, config, activeIPChan)
	}
}

func portScanIP(ip string, config Config, activeIPChan chan<- string) {
	timeout := config.portscanTimeout

	if config.verbose {
		printText(config.isSilent, fmt.Sprintf("Scanning ports on %s with a timeout of %s...", ip, timeout), "Info")
	}

	for _, portStr := range strings.Split(config.ports, ",") {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			printText(config.isSilent, fmt.Sprintf("Invalid port number: %s", portStr), "Error")
			continue
		}

		target := fmt.Sprintf("%s:%d", ip, port)

		conn, err := net.DialTimeout("tcp", target, timeout)
		if err != nil {
			if config.verbose {
				printText(config.isSilent, fmt.Sprintf("Port %d on %s is closed", port, ip), "Info")
			}
			continue
		}
		conn.Close()

		if config.verbose {
			printText(config.isSilent, fmt.Sprintf("Port %d on %s is open", port, ip), "Info")
		}

		activeIPChan <- ip
	}
}

func ptrScanTechnique(config Config, results *Results) {
	if config.verbose {
		printText(config.isSilent, "Starting PTR scan", "Info")
	}

	for _, ip := range results.activeIPs {
		names, err := net.LookupAddr(ip)
		if err != nil {
			if config.verbose {
				printText(config.isSilent, fmt.Sprintf("Failed to perform PTR lookup for %s: %v", ip, err), "Info")
			}
			continue
		}

		if len(names) > 0 {
			printText(config.isSilent, fmt.Sprintf("PTR scan result for %s: %s", ip, strings.Join(names, ", ")), "Info")
		} else {
			printText(config.isSilent, fmt.Sprintf("PTR scan result for %s: No PTR records found", ip), "Info")
		}
	}
}

func printText(isSilent bool, text string, prefix string) {
	if !isSilent {
		fmt.Printf("[%s] %s\n", prefix, text)
	}
}

func printHelp() {
	helpText := `
    Goscan - A simple network scanner tool in Go
    Usage:
      goscan [flags]
    Flags:
      -c, --cidr string           List of CIDR
      -C, --cidr-list string      List of CIDR
      -i, --ip string             Single IP
      -I, --ip-list string        List of IP
      -o, --output string         Output file
      -p, --ports string           Comma-separated list of ports. default: 80,443,22
          --ping-timeout duration Ping timeout in milliseconds (default 400ms)
          --portscan-timeout duration
                                   Port-scan timeout in milliseconds (default 400ms)
          --full                  Runs full mode
          --ping                  Runs only ping mode
          --portscan              Runs only portscan mode
          --ptr                   Runs PTR scan
      -s, --silent                Silent mode
      -t, --threads int           Number of threads (default 5)
      -v, --verbose               Verbose mode. If set, it shows according to which technique the IP is active.
      -h, --help                  Print this help menu
    `
	fmt.Println(helpText)
}

func removeTempDir(tempDir string) {
	if tempDir != "" {
		os.RemoveAll(tempDir)
	}
}
