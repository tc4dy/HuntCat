package main

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func resolveURL(baseURL, targetURL string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	target, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}

	target.Fragment = ""
	resolved := base.ResolveReference(target)
	scheme := strings.ToLower(resolved.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	resolved.Fragment = ""
	return resolved.String()
}

func logStatus(urlStr string, statusCode int, resourceType, errorMsg string) {
	printMutex.Lock()
	defer printMutex.Unlock()

	var color string
	var symbol string

	if errorMsg != "" {
		color = colorRed
		symbol = "✗"
	} else if statusCode == 404 {
		color = colorRed
		symbol = "✗"
	} else if statusCode >= 500 {
		color = colorBoldRed
		symbol = "✗"
	} else if statusCode >= 300 && statusCode < 400 {
		color = colorYellow
		symbol = "↻"
	} else if statusCode == 200 {
		color = colorGreen
		symbol = "✓"
	} else {
		color = colorWhite
		symbol = "•"
	}

	displayURL := urlStr
	if len(displayURL) > maxURLLength {
		displayURL = displayURL[:truncatedURLLength] + "..."
	}

	if errorMsg != "" {
		fmt.Printf("%s[%s %3d] %s (%s)%s\n", color, symbol, statusCode, displayURL, errorMsg, colorReset)
	} else {
		fmt.Printf("%s[%s %3d] %s%s\n", color, symbol, statusCode, displayURL, colorReset)
	}
}

func logImageStatus(urlStr string, statusCode int, size int64) {
	printMutex.Lock()
	defer printMutex.Unlock()

	var color string
	var symbol string
	var message string

	if statusCode != 200 {
		color = colorRed
		symbol = "✗"
		message = "Failed to load"
	} else if size >= criticalImageThreshold {
		color = colorBoldRed
		symbol = "🛑"
		message = fmt.Sprintf("CRITICAL: %.2f MB - Immediate optimization required!", float64(size)/(1024*1024))
	} else if size >= hugeImageThreshold {
		color = colorOrange
		symbol = "⚠"
		message = fmt.Sprintf("WARNING: %.2f MB - Must be optimized", float64(size)/(1024*1024))
	} else if size >= largeImageThreshold {
		color = colorYellow
		symbol = "💡"
		message = fmt.Sprintf("ADVICE: %.2f KB - Consider optimizing", float64(size)/1024)
	} else {
		color = colorGreen
		symbol = "✓"
		message = fmt.Sprintf("OK: %.2f KB", float64(size)/1024)
	}

	displayURL := urlStr
	if len(displayURL) > shortURLLength {
		displayURL = displayURL[:shortTruncatedLength] + "..."
	}

	fmt.Printf("%s[%s IMG] %s - %s%s\n", color, symbol, displayURL, message, colorReset)
}

func clearScreen() {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	default:
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}
