package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Scarabel0X/ScarabRecon/internal/runner"

	"github.com/cyinnove/logify"
)

const Version = "v1.0.0"

func main() {
	domainFlag := flag.String("d", "", "Target domain(s) separated by commas (e.g., example.com,test.com)")
	listFlag := flag.String("l", "", "Path to a file containing a list of domains")
	allowedFlag := flag.String("a", "", "Allowed domains separated by commas (e.g., api.target.com)")
	timeoutFlag := flag.Int("timeout", 20, "Timeout in seconds for requests")
	threadsFlag := flag.Int("t", 10, "Number of concurrent threads")
	depthFlag := flag.Int("depth", 3, "Maximum depth for active crawling")
	activeFlag := flag.Bool("active", true, "Enable active crawling (true/false)")
	jsFlag := flag.Bool("js", true, "Enable JavaScript files analysis (true/false)")
	cookieFlag := flag.String("c", "", "Cookies to be sent with requests (e.g., 'session_id=12345')")
	headerFlag := flag.String("H", "", "Custom headers separated by commas (e.g., 'Authorization: Bearer token, X-Custom: value')")
	versionFlag := flag.Bool("v", false, "Print the version of ScarabRecon and exit")

	flag.Usage = func() {
		fmt.Printf("Scarabel URL Enumeration Tool\n\n")
		fmt.Printf("Usage:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	fmt.Println("🚀 Starting Scarabel URL Enumeration Tool (ScarabRecon)...")

	if *versionFlag {
		fmt.Printf("ScarabRecon Version: %s\n", Version)
		os.Exit(0)
	}

	var domains []string
	if *domainFlag != "" {
		splitDomains := strings.Split(*domainFlag, ",")
		for _, d := range splitDomains {
			domains = append(domains, strings.TrimSpace(d))
		}
	}

	if *listFlag != "" {
		data, err := os.ReadFile(*listFlag)
		if err != nil {
			logify.Errorf("Failed to read domains file: %v", err)
			os.Exit(1)
		}
		cleanData := strings.ReplaceAll(string(data), "\r\n", "\n")
		lines := strings.Split(string(cleanData), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				domains = append(domains, trimmed)
			}
		}
	}

	if len(domains) == 0 {
		logify.Errorf("No targets specified! Please use -d to specify a domain or -l for a file.")
		flag.Usage()
		os.Exit(1)
	}

	var allowedDomains []string
	if *allowedFlag != "" {
		splitAllowed := strings.Split(*allowedFlag, ",")
		for _, a := range splitAllowed {
			allowedDomains = append(allowedDomains, strings.TrimSpace(a))
		}
	}
	var headers []string
	if *headerFlag != "" {
		splitHeaders := strings.Split(*headerFlag, ",")
		for _, h := range splitHeaders {
			headers = append(headers, strings.TrimSpace(h))
		}
	}
	_, err := runner.Runn(
		domains,
		allowedDomains,
		*timeoutFlag,
		*threadsFlag,
		*depthFlag,
		*activeFlag,
		*jsFlag,
		*cookieFlag,
		headers,
	)

	if err != nil {
		logify.Errorf("Error during analysis: %v", err)
		os.Exit(1)
	}

	logify.Infof("✅ Scan completed successfully!")
}
