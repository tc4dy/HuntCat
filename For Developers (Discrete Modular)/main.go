package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	clearScreen()
	displayASCIIBanner()

	targetURL := ""
	opts := make([]CrawlerOption, 0)
	showHelp := false
	unknownArgs := make([]string, 0)

	for _, arg := range os.Args[1:] {
		if arg == "--help" || arg == "-h" {
			showHelp = true
			continue
		}
		if strings.HasPrefix(arg, "--cookie=") {
			opts = append(opts, WithAuthCookie(strings.TrimPrefix(arg, "--cookie=")))
		} else if strings.HasPrefix(arg, "--token=") {
			opts = append(opts, WithAuthToken(strings.TrimPrefix(arg, "--token=")))
		} else if strings.HasPrefix(arg, "--header=") {
			kv := strings.TrimPrefix(arg, "--header=")
			parts := strings.SplitN(kv, ":", 2)
			if len(parts) == 2 {
				opts = append(opts, WithCustomHeaders(map[string]string{
					strings.TrimSpace(parts[0]): strings.TrimSpace(parts[1]),
				}))
			} else {
				unknownArgs = append(unknownArgs, fmt.Sprintf("%s (missing ':')", arg))
			}
		} else if strings.HasPrefix(arg, "-") {
			unknownArgs = append(unknownArgs, arg)
		} else if targetURL == "" {
			targetURL = arg
		} else {
			unknownArgs = append(unknownArgs, arg)
		}
	}

	if showHelp {
		printUsage()
		os.Exit(0)
	}

	if targetURL == "" {
		printUsage()
		os.Exit(1)
	}

	for _, arg := range unknownArgs {
		fmt.Printf("%s[!] Ignoring unrecognized argument: %s%s\n", colorYellow, arg, colorReset)
	}

	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		fmt.Printf("%s[-] Invalid URL: %s%s\n", colorRed, targetURL, colorReset)
		os.Exit(1)
	}

	fmt.Printf("%s[*] Target: %s%s\n", colorCyan, targetURL, colorReset)
	fmt.Printf("%s[+] Initializing HuntCat with %d concurrent workers...%s\n", colorGreen, maxConcurrency, colorReset)
	fmt.Printf("%s[*] Fetching robots.txt and sitemap.xml...%s\n", colorMagenta, colorReset)
	fmt.Printf("%s[*] Enforcing rate limiting (%dms/request)...%s\n\n", colorBlue, rateLimitDelay.Milliseconds(), colorReset)

	startTime := time.Now()

	crawler, err := NewCrawler(targetURL, opts...)
	if err != nil {
		fmt.Printf("%s[-] Error initializing crawler: %s%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	fmt.Printf("%s[...] Starting deep crawl with SEO analysis...%s\n\n", colorBoldCyan, colorReset)

	audit := crawler.Start()

	duration := time.Since(startTime)

	displaySummaryReport(audit)

	fmt.Printf("\n%s[*] Crawl completed in: %s%s\n", colorCyan, duration.Round(time.Millisecond), colorReset)

	fmt.Printf("\n%s[*] Generating HTML report...%s\n", colorCyan, colorReset)
	if err := exportHTMLReport(audit, targetURL); err != nil {
		fmt.Printf("%s[-] Error generating HTML report: %s%s\n", colorRed, err, colorReset)
	} else {
		fmt.Printf("%s[+] HTML report saved: huntcat_report.html%s\n", colorGreen, colorReset)
	}

	fmt.Printf("%s[*] Generating CSV report...%s\n", colorCyan, colorReset)
	if err := exportCSVReport(audit); err != nil {
		fmt.Printf("%s[-] Error generating CSV report: %s%s\n", colorRed, err, colorReset)
	} else {
		fmt.Printf("%s[+] CSV report saved: huntcat_report.csv%s\n", colorGreen, colorReset)
	}

	fmt.Println()
	fmt.Printf("%s[+] HuntCat hunt completed! Thank you for using HuntCat.%s\n", colorBoldGreen, colorReset)
	fmt.Println()
}

func printUsage() {
	fmt.Println(colorRed + "Usage: huntcat <website-url> [options]" + colorReset)
	fmt.Println(colorYellow + "Example: huntcat https://example.com" + colorReset)
	fmt.Println(colorYellow + "Options:" + colorReset)
	fmt.Println(colorYellow + "  --cookie=<value>       Set authentication cookie" + colorReset)
	fmt.Println(colorYellow + "  --token=<value>        Set Bearer token" + colorReset)
	fmt.Println(colorYellow + "  --header=<k:v>         Add custom header (repeatable)" + colorReset)
	fmt.Println(colorYellow + "  -h, --help             Show this help message" + colorReset)
}
