![HuntCat Banner](huntcat-banner.svg)

# HuntCat [![Awesome Go](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/avelino/awesome-go)
**Enterprise-Grade Web Audit & SEO Crawler**

## **Warning!**
**(With Modular & Standalone Mods for developers and users.)**
**huntcat.go** is intended for regular users. If you're a developer and want to explore the code more thoroughly, you can access the main file structure 💾 **(main.go, crawler.go, constants.go, colors.go, page_status.go, http_client.go, parsers.go, reports.go, utils.go, go.mod)** in the **"For Developers (Discrete Modular)"** folder. 🔨

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)](https://github.com)
[![Made with Go](https://img.shields.io/badge/Made%20with-Go-1E90BE?style=for-the-badge&logo=go)](https://go.dev/)
[![Open Source Love](https://img.shields.io/badge/Open%20Source-%E2%9D%A4-red?style=for-the-badge)](https://github.com/tc4dy/HuntCat)
[![GitHub Stars](https://img.shields.io/github/stars/tc4dy/HuntCat?style=for-the-badge&logo=github)](https://github.com/tc4dy/HuntCat/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/tc4dy/HuntCat?style=for-the-badge&logo=github)](https://github.com/tc4dy/HuntCat/network/members)

*"Leave your cats in the area and enjoy!"*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Reports](#-reports) • [Structure](#-repository-structure)

---

## 🎯 **Overview**

**HuntCat** is a blazing-fast, enterprise-grade web crawler and SEO auditor built in pure Go. Designed for technical SEO professionals, web developers, and DevOps teams who demand **speed**, **accuracy**, and **actionable insights**.

### Why HuntCat?

- ⚡ **Ultra-Fast**: Concurrent crawling with 50+ workers
- 🎨 **Beautiful Reports**: Professional HTML + CSV exports
- 🔒 **Security-First**: TLS 1.2+, HTTP/2 support, HTTPS validation
- 🤖 **SEO Intelligence**: Meta tags, canonicals, structured data detection
- 🚦 **Polite Crawling**: robots.txt compliance, rate limiting
- 🧠 **Smart Detection**: Duplicate content via SHA-256 hashing
- 📊 **4D Scoring System**: Health, SEO, Performance, Security

---

## ✨ **Features**

### 🕷️ **Advanced Crawling**
- Recursive link discovery with intelligent depth control
- Concurrent processing (up to 100 workers)
- Automatic sitemap.xml parsing
- External link validation (HEAD requests)
- Image asset optimization analysis

### 🩺 **Health Monitoring**
- **404 Detection**: Broken link identification
- **5xx Errors**: Server-side issue tracking
- **Redirect Chains**: 301/302 loop detection
- **Asset Analysis**: Image size optimization (700KB/1MB/2MB thresholds)
- **Load Time Tracking**: Per-resource performance metrics

### 🔍 **SEO Audit Engine**
- Title tag validation (optimal: 50-60 chars)
- Meta description analysis (optimal: 120-160 chars)
- H1 tag counting (best practice: exactly 1)
- Canonical URL detection
- Open Graph meta tags extraction
- Structured Data (JSON-LD) detection
- Meta robots tag inspection

### 🛡️ **Security Checks**
- HTTPS enforcement validation
- HTTP/2 protocol detection
- TLS version verification (>= 1.2)
- Non-secure page flagging

### 📈 **Intelligent Scoring**
```
Health Score      = (100 - error_rate)
SEO Score         = Meta tag compliance + structural quality
Performance Score = Asset optimization + load times
Security Score    = HTTPS coverage + TLS compliance
```

---

## 🚀 **Installation**

### **Prerequisites**
- [Go 1.22+](https://go.dev/dl/) installed
- Terminal/Command Prompt access

### **Quick Install**
```bash
# Clone the repository
git clone https://github.com/tc4dy/HuntCat.git
cd HuntCat

# Initialize Go module
go mod download

# Run directly
go run huntcat.go https://example.com

# Or build binary
go build -o huntcat huntcat.go
./huntcat https://example.com
```

### **One-Liner Install (Unix/Linux/macOS)**
```bash
curl -sSL https://raw.githubusercontent.com/tc4dy/HuntCat/main/huntcat.go -o huntcat.go
```

---

## 📖 **Usage**

HuntCat ships in two forms: a **Standalone** single file for end users, and a **Discrete Modular** structure for developers. Both are functionally identical — the same Go code, just organized differently.

---

### **Standalone (End Users)**

The `huntcat.go` file contains the entire application in one place. No need to navigate folders or understand the project structure — just download and run.

```bash
# Basic scan
go run huntcat.go https://yoursite.com

# Build a binary once, use anywhere
go build -ldflags="-s -w" -o huntcat huntcat.go
./huntcat https://example.com
```

**Authentication & Custom Headers:**
```bash
# With authentication cookie
go run huntcat.go https://example.com --cookie="session=abc123"

# With Bearer token
go run huntcat.go https://example.com --token="eyJhbGci..."

# With custom header
go run huntcat.go https://example.com --header="X-API-Key: mykey"

# Multiple custom headers (repeatable)
go run huntcat.go https://example.com --header="X-Foo: bar" --header="X-Baz: qux"
```

---

### **Discrete Modular (Developers)**

The `For Developers (Discrete Modular)/` folder contains the same application split across multiple files by responsibility. This is the recommended structure if you want to contribute, extend, or understand the internals.

```bash
cd "For Developers (Discrete Modular)"

# Download dependencies
go mod download

# Run using all files
go run *.go https://example.com

# Build binary
go build -ldflags="-s -w" -o huntcat .
./huntcat https://example.com
```

**Authentication & Custom Headers work identically:**
```bash
go run *.go https://example.com --cookie="session=abc123"
go run *.go https://example.com --token="eyJhbGci..."
go run *.go https://example.com --header="X-API-Key: mykey"
```

---

### **All Available Options**

| Flag | Description | Example |
|------|-------------|---------|
| `--cookie=<value>` | Set authentication cookie | `--cookie="session=abc123"` |
| `--token=<value>` | Set Bearer token (Authorization header) | `--token="eyJhbGci..."` |
| `--header=<k:v>` | Add a custom HTTP header (repeatable) | `--header="X-Key: val"` |

---

## 📊 **Reports**

HuntCat generates **2 comprehensive reports** after each scan:

### 1. **HTML Report** (`huntcat_report.html`)
- Beautiful gradient design
- Visual score cards (Health, SEO, Performance, Security)
- Interactive issue tables
- Filterable by priority

**Preview:**
```
+------------------------------------------+
|  Health Score:       100%  Excellent      |
|  SEO Score:           45%  Needs Work     |
|  Performance Score:   92%  Good           |
|  Security Score:     100%  Secure         |
+------------------------------------------+
```

### 2. **CSV Export** (`huntcat_report.csv`)
- Import to Excel/Google Sheets
- Raw data for custom analysis
- Columns: URL, Type, Status, Size, HTTPS, HTTP Version, Title, Description, H1 Count, Canonical, Load Time, Issue

---

## 🏗️ **Architecture**

### **Core Components**
```
+----------------------------------------------------------+
|                    HuntCat Engine                        |
+----------------------------------------------------------+
|                                                          |
|  +--------------+  +--------------+  +--------------+   |
|  |   Crawler    |  |   Analyzer   |  |   Reporter   |   |
|  |              |  |              |  |              |   |
|  | - Link Disc. |  | - SEO Check  |  | - HTML Gen   |   |
|  | - Asset Find |  | - Perf Audit |  | - CSV Export |   |
|  | - Robots.txt |  | - Security   |  | - Scoring    |   |
|  +--------------+  +--------------+  +--------------+   |
|                                                          |
|  +------------------------------------------------------+|
|  |  Concurrency Engine (WaitGroup + Semaphore)          ||
|  +------------------------------------------------------+|
+----------------------------------------------------------+
```

### **Tech Stack**
- **Language**: Go 1.22+ (Pure standard library + golang.org/x/net/html)
- **Concurrency**: Goroutines, WaitGroups, Mutexes, Channels
- **HTTP Client**: Custom HTTP/2 client with TLS 1.2+ enforcement
- **Parsing**: golang.org/x/net/html for robust HTML parsing
- **Hashing**: SHA-256 for duplicate content detection

---

## 🎨 **Screenshots**

### Terminal Output
```
  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗ ██████╗ █████╗ ████████╗
  ...

Target: https://example.com
Initializing HuntCat with 50 concurrent workers...
Fetching robots.txt and sitemap.xml...
Enforcing rate limiting (100ms/request)...

Starting deep crawl with SEO analysis...

[✓ 200] https://example.com
[✓ 200] https://example.com/about
[✗ 404] https://example.com/missing-page
[⚠ IMG] https://example.com/huge-image.jpg - WARNING: 2.5 MB

╔═══════════════════════════════════════════════════════╗
║              HUNTCAT AUDIT REPORT                     ║
╚═══════════════════════════════════════════════════════╝

Total Resources Scanned    145      [+] Complete
Broken Links (404)         3        [-] Critical
Critical Images (>2MB)     2        [!] URGENT
Site Health Score          97.9%    Excellent
SEO Score                  68.3%    Good

Crawl completed in: 2.34s
HTML report saved: huntcat_report.html
CSV report saved: huntcat_report.csv
```

## 📁 Repository Structure

- HuntCat/
  - huntcat.go — Standalone version (for end users)
  - For Developers (Discrete Modular)/
    - main.go — Entry point
    - crawler.go — Crawling engine
    - constants.go — Configuration constants
    - colors.go — Terminal color definitions
    - page_status.go — Data structures
    - http_client.go — HTTP client & user agents
    - parsers.go — HTML parsing & SEO analysis
    - reports.go — HTML, CSV & console reports
    - utils.go — Helper functions
    - go.mod — Go module dependencies
    - go.sum — Dependency checksums
    - README.txt — Warning for developers
  - README.md — Main documentation
  - LICENSE — MIT License
  - .gitignore — Git ignore rules
  - huntcat-banner.svg — Project banner

### **File Descriptions**

| File | Description |
|------|-------------|
| `huntcat.go` | **Standalone** - Single file, download and run with `go run huntcat.go <url>` |
| `For Developers (Discrete Modular)/` | **Modular source** - Run with `go run *.go <url>`, for contributors and curious developers |
| `go.mod` | Go module definition and external dependencies |
| `go.sum` | Dependency checksums for reproducible builds |
| `README.md` | Documentation — you're reading it! |
| `LICENSE` | MIT License — open source, free to use |
| `.gitignore` | Keeps the repo clean |
| `huntcat-banner.svg` | Project banner / visual identity |

---

## ⚙️ **Configuration**

Edit constants in `huntcat.go` (or `constants.go` in the modular version) to customize behavior:

```go
const (
    maxConcurrency         = 50                      // Concurrent workers
    requestTimeout         = 30 * time.Second        // HTTP timeout
    rateLimitDelay         = 100 * time.Millisecond  // Delay between requests
    largeImageThreshold    = 700 * 1024              // 700KB
    hugeImageThreshold     = 1024 * 1024             // 1MB
    criticalImageThreshold = 2 * 1024 * 1024         // 2MB
    maxCrawlDepth          = 5                       // Maximum crawl depth
    optimalTitleMin        = 50                      // Minimum title length (SEO)
    optimalTitleMax        = 60                      // Maximum title length (SEO)
    optimalDescMax         = 160                     // Maximum meta description length
)
```

---

## **Known Limitations**

- **No JavaScript rendering**: HuntCat fetches raw HTML. Pages that require JavaScript to render content (SPAs, React/Vue/Angular apps) will return incomplete results.
- **No SPA support**: Single Page Applications that load content dynamically via API calls will not be fully crawled.
- **robots.txt is advisory**: HuntCat respects `robots.txt` rules by default but does not enforce `Crawl-delay` directives — use `rateLimitDelay` in constants instead.

---

## **License**

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
