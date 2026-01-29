# 🐱 HuntCat

**Enterprise-Grade Web Audit & SEO Crawler**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)](https://github.com)

*"Leave your cats in the area and enjoy!"*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Reports](#-reports) • [Architecture](#-architecture)

</div>

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
- ✅ Title tag validation (optimal: 50-60 chars)
- ✅ Meta description analysis (optimal: 120-160 chars)
- ✅ H1 tag counting (best practice: exactly 1)
- ✅ Canonical URL detection
- ✅ Open Graph meta tags extraction
- ✅ Structured Data (JSON-LD) detection
- ✅ Meta robots tag inspection

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
git clone https://github.com/yourusername/huntcat.git
cd huntcat

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
curl -sSL https://raw.githubusercontent.com/yourusername/huntcat/main/install.sh | bash
```

---

## 📖 **Usage**

### **Basic Scan**
```bash
go run huntcat.go https://yoursite.com
```

### **Custom Binary**
```bash
# Build once
go build -ldflags="-s -w" -o huntcat huntcat.go

# Use anywhere
./huntcat https://example.com
./huntcat https://github.com
./huntcat https://stackoverflow.com
```

### **Advanced Options**
```bash
# Scan with custom concurrency (edit maxConcurrency in code)
# Default: 50 workers

# Adjust rate limiting (edit rateLimitDelay in code)
# Default: 100ms per request
```

---

## 📊 **Reports**

HuntCat generates **2 comprehensive reports** after each scan:

### 1. **HTML Report** (`huntcat_report.html`)
- 🎨 Beautiful gradient design
- 📈 Visual score cards (Health, SEO, Performance, Security)
- 📋 Interactive issue tables
- 🔍 Filterable by priority

**Preview:**
```
┌─────────────────────────────────────────┐
│  Health Score:       100%  🟢          │
│  SEO Score:           45%  🔴          │
│  Performance Score:   92%  🟡          │
│  Security Score:     100%  🟢          │
└─────────────────────────────────────────┘
```

### 2. **CSV Export** (`huntcat_report.csv`)
- 📊 Import to Excel/Google Sheets
- 🔢 Raw data for custom analysis
- 📅 Columns: URL, Type, Status, Size, HTTPS, HTTP Version, Title, Description, H1 Count, Canonical, Load Time, Issue

---

## 🏗️ **Architecture**

### **Core Components**
```
┌─────────────────────────────────────────────────────────┐
│                    HuntCat Engine                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Crawler    │  │   Analyzer   │  │   Reporter   │ │
│  │              │  │              │  │              │ │
│  │ • Link Disc. │  │ • SEO Check  │  │ • HTML Gen   │ │
│  │ • Asset Find │  │ • Perf Audit │  │ • CSV Export │ │
│  │ • Robots.txt │  │ • Security   │  │ • Scoring    │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Concurrency Engine (WaitGroup + Semaphore)     │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
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
  
🎯 Target: https://example.com
⚡ Initializing HuntCat with 50 concurrent workers...
🤖 Fetching robots.txt and sitemap.xml...
🔒 Enforcing rate limiting (100ms/request)...

🔍 Starting deep crawl with SEO analysis...

[✓ 200] https://example.com
[✓ 200] https://example.com/about
[✗ 404] https://example.com/missing-page
[⚠ IMG] https://example.com/huge-image.jpg - WARNING: 2.5 MB

╔═══════════════════════════════════════════════════════╗
║              HUNTCAT AUDIT REPORT                     ║
╚═══════════════════════════════════════════════════════╝

Total Resources Scanned    145      ✓ Complete
Broken Links (404)         3        ✗ Critical
Critical Images (>2MB)     2        🛑 URGENT
Site Health Score          97.9%    Excellent
SEO Score                  68.3%    Good

⏱  Crawl completed in: 2.34s
✓ HTML report saved: huntcat_report.html
✓ CSV report saved: huntcat_report.csv
```

---

## ⚙️ **Configuration**

Edit constants in `huntcat.go` to customize behavior:
```go
const (
    maxConcurrency         = 50              // Concurrent workers
    requestTimeout         = 30 * time.Second // HTTP timeout
    rateLimitDelay         = 100 * time.Millisecond // Request delay
    largeImageThreshold    = 700 * 1024      // 700KB
    hugeImageThreshold     = 1024 * 1024     // 1MB
    criticalImageThreshold = 2 * 1024 * 1024 // 2MB
)
```

---

## 🤝 **Contributing**

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 **License**

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 **Author**

**Developer**: [@tc4dy](https://github.com/tc4dy)

---

## 🙏 **Acknowledgments**

- Inspired by enterprise SEO tools like Screaming Frog and Ahrefs
- Built with ❤️ using the Go programming language
- Special thanks to the Go community

---
<div align="center">

**⭐ If you find HuntCat useful, please star this repository! ⭐**

Made with 🐱 and Go

</div>
