package main

import (
	"encoding/csv"
	"fmt"
	"html"
	"os"
	"text/tabwriter"
	"time"
)

func displayASCIIBanner() {
	banner := `
  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗ ██████╗ █████╗ ████████╗
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝
  ███████║██║   ██║██╔██╗ ██║   ██║   ██║     ███████║   ██║   
  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██║     ██╔══██║   ██║   
  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ╚██████╗██║  ██║   ██║   
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ╚═╝   
`

	catArt := `
                     /\_/\  
                    ( o.o ) 
                     > ^ 
`

	fmt.Print(colorBoldCyan)
	fmt.Println(banner)
	fmt.Print(colorGreen)
	fmt.Println(catArt)
	fmt.Print(colorCyan)
	fmt.Println("                           Enterprise Web Audit & SEO Crawler")
	fmt.Println("                                    Dev: @tc4dy")
	fmt.Print(colorYellow)
	fmt.Println("                      \"Sniffing every corner of the web, one paw at a time.\"")
	fmt.Print(colorReset)
	fmt.Println()
	fmt.Println(colorCyan + "═══════════════════════════════════════════════════════════════════════════════" + colorReset)
	fmt.Println()
}

func displaySummaryReport(audit *AuditResult) {
	fmt.Println()
	fmt.Println(colorBoldCyan + "╔═══════════════════════════════════════════════════════════════════════════════╗" + colorReset)
	fmt.Println(colorBoldCyan + "║                            HUNTCAT AUDIT REPORT                               ║" + colorReset)
	fmt.Println(colorBoldCyan + "╚═══════════════════════════════════════════════════════════════════════════════╝" + colorReset)
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	fmt.Fprintln(w, colorBoldGreen+"METRIC\tVALUE\tSTATUS"+colorReset)
	fmt.Fprintln(w, "────────────────────────────\t────────\t────────────────")

	fmt.Fprintf(w, "Total Resources Scanned\t%d\t%s✓ Complete%s\n", audit.TotalScanned, colorGreen, colorReset)

	if len(audit.BrokenLinks) > 0 {
		fmt.Fprintf(w, "Broken Links (404)\t%d\t%s✗ Critical%s\n", len(audit.BrokenLinks), colorRed, colorReset)
	} else {
		fmt.Fprintf(w, "Broken Links (404)\t%d\t%s✓ Excellent%s\n", len(audit.BrokenLinks), colorGreen, colorReset)
	}

	if len(audit.ServerErrors) > 0 {
		fmt.Fprintf(w, "Server Errors (5xx)\t%d\t%s✗ Critical%s\n", len(audit.ServerErrors), colorBoldRed, colorReset)
	} else {
		fmt.Fprintf(w, "Server Errors (5xx)\t%d\t%s✓ Excellent%s\n", len(audit.ServerErrors), colorGreen, colorReset)
	}

	if len(audit.RedirectChains) > 0 {
		fmt.Fprintf(w, "Redirect Chains\t%d\t%s⚠ Warning%s\n", len(audit.RedirectChains), colorYellow, colorReset)
	} else {
		fmt.Fprintf(w, "Redirect Chains\t%d\t%s✓ Good%s\n", len(audit.RedirectChains), colorGreen, colorReset)
	}

	if len(audit.CriticalAssets) > 0 {
		fmt.Fprintf(w, "Critical Images (>2MB)\t%d\t%s🛑 URGENT%s\n", len(audit.CriticalAssets), colorBoldRed, colorReset)
	} else {
		fmt.Fprintf(w, "Critical Images (>2MB)\t%d\t%s✓ Excellent%s\n", len(audit.CriticalAssets), colorGreen, colorReset)
	}

	if len(audit.WarningAssets) > 0 {
		fmt.Fprintf(w, "Large Images (>1MB)\t%d\t%s⚠ Optimize%s\n", len(audit.WarningAssets), colorOrange, colorReset)
	} else {
		fmt.Fprintf(w, "Large Images (>1MB)\t%d\t%s✓ Good%s\n", len(audit.WarningAssets), colorGreen, colorReset)
	}

	if len(audit.AdviceAssets) > 0 {
		fmt.Fprintf(w, "Medium Images (>700KB)\t%d\t%s💡 Consider%s\n", len(audit.AdviceAssets), colorYellow, colorReset)
	} else {
		fmt.Fprintf(w, "Medium Images (>700KB)\t%d\t%s✓ Good%s\n", len(audit.AdviceAssets), colorGreen, colorReset)
	}

	if len(audit.DuplicateContent) > 0 {
		fmt.Fprintf(w, "Duplicate Content\t%d\t%s⚠ SEO Issue%s\n", len(audit.DuplicateContent), colorYellow, colorReset)
	} else {
		fmt.Fprintf(w, "Duplicate Content\t%d\t%s✓ Excellent%s\n", len(audit.DuplicateContent), colorGreen, colorReset)
	}

	if len(audit.NonHTTPS) > 0 {
		fmt.Fprintf(w, "Non-HTTPS Pages\t%d\t%s⚠ Security Risk%s\n", len(audit.NonHTTPS), colorOrange, colorReset)
	} else {
		fmt.Fprintf(w, "Non-HTTPS Pages\t%d\t%s✓ Secure%s\n", len(audit.NonHTTPS), colorGreen, colorReset)
	}

	if len(audit.MissingMetaTags) > 0 {
		fmt.Fprintf(w, "Missing/Poor Meta Tags\t%d\t%s⚠ SEO Issue%s\n", len(audit.MissingMetaTags), colorYellow, colorReset)
	} else {
		fmt.Fprintf(w, "Missing/Poor Meta Tags\t%d\t%s✓ Good%s\n", len(audit.MissingMetaTags), colorGreen, colorReset)
	}

	if len(audit.SitemapURLs) > 0 {
		fmt.Fprintf(w, "Sitemap URLs Found\t%d\t%s✓ Detected%s\n", len(audit.SitemapURLs), colorGreen, colorReset)
	} else {
		fmt.Fprintf(w, "Sitemap URLs Found\t%d\t%s⚠ Not Found%s\n", len(audit.SitemapURLs), colorYellow, colorReset)
	}

	if audit.RobotsAllowed {
		fmt.Fprintf(w, "Robots.txt Status\t-\t%s✓ Compliant%s\n", colorGreen, colorReset)
	} else {
		fmt.Fprintf(w, "Robots.txt Status\t-\t%s⚠ Issues%s\n", colorYellow, colorReset)
	}

	fmt.Fprintln(w, "────────────────────────────\t────────\t────────────────")

	healthColor := colorGreen
	healthStatus := "Excellent"
	if audit.HealthScore < 50 {
		healthColor = colorRed
		healthStatus = "Poor"
	} else if audit.HealthScore < 70 {
		healthColor = colorOrange
		healthStatus = "Fair"
	} else if audit.HealthScore < 90 {
		healthColor = colorYellow
		healthStatus = "Good"
	}
	fmt.Fprintf(w, "Site Health Score\t%.1f%%\t%s%s%s\n", audit.HealthScore, healthColor, healthStatus, colorReset)

	seoColor := colorGreen
	seoStatus := "Excellent"
	if audit.SEOScore < 50 {
		seoColor = colorRed
		seoStatus = "Poor"
	} else if audit.SEOScore < 70 {
		seoColor = colorOrange
		seoStatus = "Needs Work"
	} else if audit.SEOScore < 90 {
		seoColor = colorYellow
		seoStatus = "Good"
	}
	fmt.Fprintf(w, "SEO Score\t%.1f%%\t%s%s%s\n", audit.SEOScore, seoColor, seoStatus, colorReset)

	perfColor := colorGreen
	perfStatus := "Excellent"
	if audit.PerformanceScore < 50 {
		perfColor = colorRed
		perfStatus = "Poor"
	} else if audit.PerformanceScore < 70 {
		perfColor = colorOrange
		perfStatus = "Needs Work"
	} else if audit.PerformanceScore < 90 {
		perfColor = colorYellow
		perfStatus = "Good"
	}
	fmt.Fprintf(w, "Performance Score\t%.1f%%\t%s%s%s\n", audit.PerformanceScore, perfColor, perfStatus, colorReset)

	secColor := colorGreen
	secStatus := "Secure"
	if audit.SecurityScore < 50 {
		secColor = colorRed
		secStatus = "Vulnerable"
	} else if audit.SecurityScore < 70 {
		secColor = colorOrange
		secStatus = "At Risk"
	} else if audit.SecurityScore < 90 {
		secColor = colorYellow
		secStatus = "Fair"
	}
	fmt.Fprintf(w, "Security Score\t%.1f%%\t%s%s%s\n", audit.SecurityScore, secColor, secStatus, colorReset)

	w.Flush()

	fmt.Println()
	fmt.Println(colorCyan + "═══════════════════════════════════════════════════════════════════════════════" + colorReset)
}

func exportHTMLReport(audit *AuditResult, targetURL string) error {
	htmlContent := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HuntCat Audit Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 5px;
        }
        .header .dev {
            font-size: 0.9em;
            opacity: 0.7;
            font-style: italic;
        }
        .score-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f7fafc;
        }
        .score-card {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
        }
        .score-card h3 {
            font-size: 0.9em;
            color: #718096;
            margin-bottom: 15px;
            text-transform: uppercase;
        }
        .score-circle {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            margin: 0 auto 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2em;
            font-weight: bold;
            color: white;
        }
        .score-excellent { background: linear-gradient(135deg, #48bb78, #38a169); }
        .score-good { background: linear-gradient(135deg, #ecc94b, #d69e2e); }
        .score-fair { background: linear-gradient(135deg, #ed8936, #dd6b20); }
        .score-poor { background: linear-gradient(135deg, #f56565, #e53e3e); }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: white;
        }
        .stat-card {
            background: #f7fafc;
            padding: 25px;
            border-radius: 12px;
            border-left: 4px solid #667eea;
        }
        .stat-card.critical { border-left-color: #f56565; }
        .stat-card.warning { border-left-color: #ed8936; }
        .stat-card.success { border-left-color: #48bb78; }
        .stat-card h3 {
            font-size: 0.9em;
            color: #718096;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2d3748;
        }
        .table-container {
            padding: 40px;
        }
        .table-container h2 {
            color: #2d3748;
            font-size: 1.8em;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        thead {
            background: #2d3748;
            color: white;
        }
        th, td {
            padding: 16px;
            text-align: left;
        }
        th {
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
        }
        tbody tr {
            border-bottom: 1px solid #e2e8f0;
        }
        tbody tr:hover {
            background: #f7fafc;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .status-ok { background: #c6f6d5; color: #22543d; }
        .status-error { background: #fed7d7; color: #742a2a; }
        .status-warning { background: #feebc8; color: #7c2d12; }
        .status-critical { background: #feb2b2; color: #742a2a; font-weight: bold; }
        .url-cell {
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: #4299e1;
        }
        .footer {
            text-align: center;
            padding: 30px;
            background: #f7fafc;
            color: #718096;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🐱 HuntCat</h1>
            <div class="subtitle">Enterprise Web Audit & SEO Crawler Report</div>
            <div class="dev">Dev: @tc4dy</div>
        </div>
        <div class="score-grid">
            <div class="score-card">
                <h3>Health Score</h3>
                <div class="score-circle ` + getScoreClass(audit.HealthScore) + `">
                    ` + fmt.Sprintf("%.0f%%", audit.HealthScore) + `
                </div>
            </div>
            <div class="score-card">
                <h3>SEO Score</h3>
                <div class="score-circle ` + getScoreClass(audit.SEOScore) + `">
                    ` + fmt.Sprintf("%.0f%%", audit.SEOScore) + `
                </div>
            </div>
            <div class="score-card">
                <h3>Performance</h3>
                <div class="score-circle ` + getScoreClass(audit.PerformanceScore) + `">
                    ` + fmt.Sprintf("%.0f%%", audit.PerformanceScore) + `
                </div>
            </div>
            <div class="score-card">
                <h3>Security</h3>
                <div class="score-circle ` + getScoreClass(audit.SecurityScore) + `">
                    ` + fmt.Sprintf("%.0f%%", audit.SecurityScore) + `
                </div>
            </div>
        </div>
        <div class="stats">
            <div class="stat-card success">
                <h3>Total Scanned</h3>
                <div class="value">` + fmt.Sprintf("%d", audit.TotalScanned) + `</div>
            </div>
            <div class="stat-card ` + getStatClass(len(audit.BrokenLinks), audit.TotalScanned) + `">
                <h3>Broken Links</h3>
                <div class="value">` + fmt.Sprintf("%d", len(audit.BrokenLinks)) + `</div>
            </div>
            <div class="stat-card ` + getStatClass(len(audit.ServerErrors), audit.TotalScanned) + `">
                <h3>Server Errors</h3>
                <div class="value">` + fmt.Sprintf("%d", len(audit.ServerErrors)) + `</div>
            </div>
            <div class="stat-card ` + getStatClass(len(audit.CriticalAssets), audit.TotalScanned) + `">
                <h3>Critical Images</h3>
                <div class="value">` + fmt.Sprintf("%d", len(audit.CriticalAssets)) + `</div>
            </div>
            <div class="stat-card ` + getStatClass(len(audit.DuplicateContent), audit.TotalScanned) + `">
                <h3>Duplicate Content</h3>
                <div class="value">` + fmt.Sprintf("%d", len(audit.DuplicateContent)) + `</div>
            </div>
            <div class="stat-card ` + getStatClass(len(audit.NonHTTPS), audit.TotalScanned) + `">
                <h3>Non-HTTPS Pages</h3>
                <div class="value">` + fmt.Sprintf("%d", len(audit.NonHTTPS)) + `</div>
            </div>
        </div>
        <div class="table-container">
            <h2>Critical Issues</h2>
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Issue</th>
                        <th>Priority</th>
                    </tr>
                </thead>
                <tbody>`

	allIssues := make([]PageStatus, 0)
	allIssues = append(allIssues, audit.BrokenLinks...)
	allIssues = append(allIssues, audit.ServerErrors...)
	allIssues = append(allIssues, audit.CriticalAssets...)
	allIssues = append(allIssues, audit.DuplicateContent...)
	allIssues = append(allIssues, audit.NonHTTPS...)

	for _, issue := range allIssues {
		statusClass := "status-ok"
		statusText := fmt.Sprintf("%d", issue.StatusCode)
		message := "OK"
		priority := "Low"

		if issue.StatusCode == 404 {
			statusClass = "status-error"
			message = "Broken Link"
			priority = "High"
		} else if issue.StatusCode >= 500 {
			statusClass = "status-critical"
			message = "Server Error"
			priority = "Critical"
		} else if issue.ResourceType == "image" && issue.Size >= criticalImageThreshold {
			statusClass = "status-critical"
			message = fmt.Sprintf("Critical: %.2f MB", float64(issue.Size)/(1024*1024))
			priority = "Critical"
		} else if issue.ContentHash != "" {
			statusClass = "status-warning"
			message = "Duplicate of: " + html.EscapeString(issue.ContentHash)
			priority = "Medium"
		} else if !issue.IsHTTPS {
			statusClass = "status-warning"
			message = "Not using HTTPS"
			priority = "High"
		}

		escapedURL := html.EscapeString(issue.URL)
		escapedMessage := html.EscapeString(message)
		escapedPriority := html.EscapeString(priority)

		htmlContent += fmt.Sprintf(`
                    <tr>
                        <td class="url-cell" title="%s">%s</td>
                        <td>%s</td>
                        <td><span class="status-badge %s">%s</span></td>
                        <td>%s</td>
                        <td><span class="status-badge %s">%s</span></td>
                    </tr>`,
			escapedURL, escapedURL, html.EscapeString(issue.ResourceType), statusClass, statusText, escapedMessage, statusClass, escapedPriority)
	}

	htmlContent += `
                </tbody>
            </table>
        </div>
        <div class="footer">
            Generated by HuntCat on ` + html.EscapeString(time.Now().Format("January 2, 2006 at 15:04:05")) + `<br>
            Target: ` + html.EscapeString(targetURL) + `<br>
            Sitemap URLs Found: ` + fmt.Sprintf("%d", len(audit.SitemapURLs)) + `<br>
            Robots.txt: ` + func() string {
		if audit.RobotsAllowed {
			return "Compliant"
		}
		return "Issues Detected"
	}() + `<br>
            "Sniffing every corner of the web, one paw at a time."
        </div>
    </div>
</body>
</html>`

	return os.WriteFile("huntcat_report.html", []byte(htmlContent), 0644)
}

func getScoreClass(score float64) string {
	if score >= 90 {
		return "score-excellent"
	} else if score >= 70 {
		return "score-good"
	} else if score >= 50 {
		return "score-fair"
	}
	return "score-poor"
}

func getStatClass(count int, total int) string {
	if count == 0 {
		return "success"
	}
	if total == 0 {
		return "critical"
	}
	ratio := float64(count) / float64(total) * 100
	if ratio < 2.0 {
		return "warning"
	}
	return "critical"
}

func exportCSVReport(audit *AuditResult) error {
	file, err := os.Create("huntcat_report.csv")
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"URL", "Type", "Status Code", "Size (bytes)", "HTTPS", "HTTP Version", "Title", "Description", "H1 Count", "Has Canonical", "Load Time (ms)", "Issue"})

	for _, page := range audit.Pages {
		issue := "OK"
		if page.StatusCode == 404 {
			issue = "Broken Link"
		} else if page.StatusCode >= 500 {
			issue = "Server Error"
		} else if page.ResourceType == "image" && page.Size >= criticalImageThreshold {
			issue = "Critical Image Size"
		} else if page.ContentHash != "" {
			issue = "Duplicate Content"
		} else if !page.IsHTTPS {
			issue = "Not HTTPS"
		} else if page.Title == "" {
			issue = "Missing Title"
		} else if page.Description == "" {
			issue = "Missing Description"
		}

		writer.Write([]string{
			page.URL,
			page.ResourceType,
			fmt.Sprintf("%d", page.StatusCode),
			fmt.Sprintf("%d", page.Size),
			fmt.Sprintf("%t", page.IsHTTPS),
			page.HTTPVersion,
			page.Title,
			page.Description,
			fmt.Sprintf("%d", page.H1Count),
			fmt.Sprintf("%t", page.HasCanonical),
			fmt.Sprintf("%d", page.LoadTime.Milliseconds()),
			issue,
		})
	}

	return nil
}
