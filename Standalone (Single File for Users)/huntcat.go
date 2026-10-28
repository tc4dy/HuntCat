package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	htmlparser "golang.org/x/net/html"
)

const (
	maxConcurrency         = 50
	requestTimeout         = 30 * time.Second
	maxRedirects           = 10
	largeImageThreshold    = 700 * 1024
	hugeImageThreshold     = 1024 * 1024
	criticalImageThreshold = 2 * 1024 * 1024
	userAgentBase          = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	rateLimitDelay         = 100 * time.Millisecond
	optimalTitleMin        = 50
	optimalTitleMax        = 60
	optimalDescMax         = 160
	maxCrawlDepth          = 5
	maxURLLength           = 80
	truncatedURLLength     = 77
	shortURLLength         = 60
	shortTruncatedLength   = 57
	gcInterval             = 100
	memoryPruneInterval    = 5 * time.Minute
)

const (
	colorReset     = "\033[0m"
	colorRed       = "\033[31m"
	colorGreen     = "\033[32m"
	colorYellow    = "\033[33m"
	colorBlue      = "\033[34m"
	colorCyan      = "\033[36m"
	colorWhite     = "\033[37m"
	colorOrange    = "\033[38;5;208m"
	colorBoldRed   = "\033[1;31m"
	colorBoldGreen = "\033[1;32m"
	colorBoldCyan  = "\033[1;36m"
	colorMagenta   = "\033[35m"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

var (
	printMutex sync.Mutex
	userAgents = []string{
		userAgentBase,
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
	}
)

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

type PageStatus struct {
	URL            string
	StatusCode     int
	ContentType    string
	Size           int64
	ErrorMessage   string
	ResourceType   string
	Redirects      int
	Title          string
	Description    string
	H1Count        int
	HasCanonical   bool
	CanonicalURL   string
	IsHTTPS        bool
	HTTPVersion    string
	HasRobotsMeta  bool
	DuplicateOf    string
	LoadTime       time.Duration
	HasSitemap     bool
	MetaRobots     string
	OGTags         map[string]string
	StructuredData bool
}

type AuditResult struct {
	Pages            []PageStatus
	BrokenLinks      []PageStatus
	ServerErrors     []PageStatus
	RedirectChains   []PageStatus
	CriticalAssets   []PageStatus
	WarningAssets    []PageStatus
	AdviceAssets     []PageStatus
	SEOIssues        []PageStatus
	DuplicateContent []PageStatus
	NonHTTPS         []PageStatus
	MissingMetaTags  []PageStatus
	TotalScanned     int
	HealthScore      float64
	SEOScore         float64
	PerformanceScore float64
	SecurityScore    float64
	SitemapURLs      []string
	RobotsAllowed    bool
	RobotsFound      bool
	RobotsTxtContent string
}

type redirectCountKey struct{}

type Crawler struct {
	baseURL          *url.URL
	visited          map[string]bool
	visitedPrev      map[string]bool
	visitedMutex     sync.RWMutex
	results          []PageStatus
	resultsMutex     sync.Mutex
	wg               sync.WaitGroup
	semaphore        chan struct{}
	client           HTTPClient
	domain           string
	rateLimiter      *time.Ticker
	contentHashes    map[string]string
	contentHashMutex sync.RWMutex
	contentCache     map[string]string
	contentCacheMtx  sync.RWMutex
	robotsRules      map[string]bool
	robotsMutex      sync.RWMutex
	sitemapURLs      []string
	sitemapMutex     sync.Mutex
	robotsTxtRaw     string
	robotsFound      bool
	authCookie       string
	authToken        string
	customHeaders    map[string]string
	scannedCount     int64
	lastPruneTime    time.Time
	pruneMutex       sync.Mutex
}

type sitemapURL struct {
	Loc string `xml:"loc"`
}

type sitemapIndex struct {
	Sitemaps []sitemapURL `xml:"sitemap"`
}

type urlset struct {
	URLs []sitemapURL `xml:"url"`
}

type CrawlerOption func(*Crawler)

func WithAuthCookie(cookie string) CrawlerOption {
	return func(c *Crawler) { c.authCookie = cookie }
}

func WithAuthToken(token string) CrawlerOption {
	return func(c *Crawler) { c.authToken = token }
}

func WithCustomHeaders(headers map[string]string) CrawlerOption {
	return func(c *Crawler) {
		for k, v := range headers {
			c.customHeaders[k] = v
		}
	}
}

func WithHTTPClient(client HTTPClient) CrawlerOption {
	return func(c *Crawler) { c.client = client }
}

func NewCrawler(startURL string, opts ...CrawlerOption) (*Crawler, error) {
	parsedURL, err := url.Parse(startURL)
	if err != nil {
		return nil, err
	}

	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}

	client := &http.Client{
		Timeout:   requestTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects")
			}
			if counter, ok := req.Context().Value(redirectCountKey{}).(*int32); ok {
				atomic.StoreInt32(counter, int32(len(via)))
			}
			return nil
		},
	}

	crawler := &Crawler{
		baseURL:       parsedURL,
		visited:       make(map[string]bool),
		visitedPrev:   make(map[string]bool),
		results:       make([]PageStatus, 0),
		semaphore:     make(chan struct{}, maxConcurrency),
		client:        client,
		domain:        parsedURL.Host,
		rateLimiter:   time.NewTicker(rateLimitDelay),
		contentHashes: make(map[string]string),
		contentCache:  make(map[string]string),
		robotsRules:   make(map[string]bool),
		sitemapURLs:   make([]string, 0),
		customHeaders: make(map[string]string),
		lastPruneTime: time.Now(),
	}

	for _, opt := range opts {
		opt(crawler)
	}

	crawler.fetchRobotsTxt()
	crawler.fetchSitemap()

	return crawler, nil
}

func (c *Crawler) setRequestHeaders(req *http.Request) {
	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")

	for k, v := range c.customHeaders {
		req.Header.Set(k, v)
	}

	if c.authCookie != "" {
		req.Header.Set("Cookie", c.authCookie)
	}

	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
}

func (c *Crawler) fetchRobotsTxt() {
	robotsURL := c.baseURL.Scheme + "://" + c.baseURL.Host + "/robots.txt"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if err != nil {
		c.robotsMutex.Lock()
		c.robotsRules["*"] = true
		c.robotsMutex.Unlock()
		return
	}

	c.setRequestHeaders(req)
	resp, err := c.client.Do(req)
	if err != nil {
		c.robotsMutex.Lock()
		c.robotsRules["*"] = true
		c.robotsMutex.Unlock()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		c.robotsMutex.Lock()
		c.robotsRules["*"] = true
		c.robotsMutex.Unlock()
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.robotsMutex.Lock()
		c.robotsRules["*"] = true
		c.robotsMutex.Unlock()
		return
	}

	c.robotsMutex.Lock()
	c.robotsTxtRaw = string(body)
	c.robotsFound = true
	c.robotsMutex.Unlock()

	lines := strings.Split(string(body), "\n")
	userAgentMatch := false
	tempRules := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			agent := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "user-agent:"))
			userAgentMatch = (agent == "*" || strings.Contains(agent, "mozilla") || agent == "huntcat")
			continue
		}

		if !userAgentMatch {
			continue
		}

		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			rulePath := strings.TrimSpace(line[9:])
			if rulePath != "" {
				tempRules[rulePath] = false
			}
		} else if strings.HasPrefix(strings.ToLower(line), "allow:") {
			rulePath := strings.TrimSpace(line[6:])
			if rulePath != "" {
				tempRules[rulePath] = true
			}
		}
	}

	c.robotsMutex.Lock()
	if len(tempRules) == 0 {
		c.robotsRules["*"] = true
	} else {
		for k, v := range tempRules {
			c.robotsRules[k] = v
		}
	}
	c.robotsMutex.Unlock()
}

func matchRobotsRule(pattern, urlPath string) bool {
	if pattern == "" {
		return false
	}
	anchor := false
	if strings.HasSuffix(pattern, "$") {
		anchor = true
		pattern = pattern[:len(pattern)-1]
	}
	if !strings.Contains(pattern, "*") {
		if anchor {
			return urlPath == pattern
		}
		return strings.HasPrefix(urlPath, pattern)
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if i == 0 {
			if !strings.HasPrefix(urlPath, part) {
				return false
			}
			pos = len(part)
		} else if i == len(parts)-1 {
			if anchor {
				if !strings.HasSuffix(urlPath, part) {
					return false
				}
				if len(urlPath)-len(part) < pos {
					return false
				}
			} else {
				idx := strings.Index(urlPath[pos:], part)
				if idx < 0 {
					return false
				}
				pos += idx + len(part)
			}
		} else {
			idx := strings.Index(urlPath[pos:], part)
			if idx < 0 {
				return false
			}
			pos += idx + len(part)
		}
	}
	return true
}

func (c *Crawler) isAllowedByRobots(urlPath string) bool {
	c.robotsMutex.RLock()
	defer c.robotsMutex.RUnlock()

	longestMatch := 0
	allowed := true

	for pattern, rule := range c.robotsRules {
		if pattern == "*" {
			continue
		}
		if matchRobotsRule(pattern, urlPath) {
			if len(pattern) > longestMatch {
				longestMatch = len(pattern)
				allowed = rule
			} else if len(pattern) == longestMatch && rule {
				allowed = true
			}
		}
	}

	return allowed
}

func (c *Crawler) fetchSitemap() {
	visited := make(map[string]bool)
	rootURL := c.baseURL.Scheme + "://" + c.baseURL.Host + "/sitemap.xml"
	c.fetchSitemapRecursive(rootURL, 0, visited)
}

func (c *Crawler) fetchSitemapRecursive(sitemapURL string, depth int, visited map[string]bool) {
	if depth > 2 || visited[sitemapURL] {
		return
	}
	visited[sitemapURL] = true

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", sitemapURL, nil)
	if err != nil {
		return
	}

	c.setRequestHeaders(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var idx sitemapIndex
	if err := xml.Unmarshal(body, &idx); err == nil && len(idx.Sitemaps) > 0 {
		for _, s := range idx.Sitemaps {
			if s.Loc != "" {
				resolved := resolveURL(sitemapURL, s.Loc)
				if resolved != "" {
					c.fetchSitemapRecursive(resolved, depth+1, visited)
				}
			}
		}
		return
	}

	var urls urlset
	if err := xml.Unmarshal(body, &urls); err == nil {
		c.sitemapMutex.Lock()
		for _, u := range urls.URLs {
			if u.Loc != "" {
				resolved := resolveURL(sitemapURL, u.Loc)
				if resolved != "" {
					c.sitemapURLs = append(c.sitemapURLs, resolved)
				}
			}
		}
		c.sitemapMutex.Unlock()
	}
}

func (c *Crawler) markVisited(urlStr string) bool {
	c.visitedMutex.Lock()
	defer c.visitedMutex.Unlock()
	if c.visited[urlStr] || c.visitedPrev[urlStr] {
		return false
	}
	c.visited[urlStr] = true
	return true
}

func (c *Crawler) isVisited(urlStr string) bool {
	c.visitedMutex.RLock()
	defer c.visitedMutex.RUnlock()
	return c.visited[urlStr] || c.visitedPrev[urlStr]
}

func (c *Crawler) addResult(status PageStatus) {
	c.resultsMutex.Lock()
	defer c.resultsMutex.Unlock()
	c.results = append(c.results, status)
}

func (c *Crawler) getCachedContent(body string) string {
	quickHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))[:16]

	c.contentCacheMtx.RLock()
	cached, exists := c.contentCache[quickHash]
	c.contentCacheMtx.RUnlock()

	if exists {
		return cached
	}

	mainContent := extractMainContent(body)

	c.contentCacheMtx.Lock()
	c.contentCache[quickHash] = mainContent
	c.contentCacheMtx.Unlock()

	return mainContent
}

func (c *Crawler) checkDuplicateContent(body string, currentURL string) (bool, string) {
	mainContent := c.getCachedContent(body)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(mainContent)))

	c.contentHashMutex.Lock()
	defer c.contentHashMutex.Unlock()

	if originalURL, exists := c.contentHashes[hash]; exists {
		if originalURL != currentURL {
			return true, originalURL
		}
		return false, ""
	}

	c.contentHashes[hash] = currentURL
	return false, ""
}

func (c *Crawler) shouldCrawl(targetURL *url.URL) bool {
	normalizedHost := strings.ToLower(targetURL.Host)
	if strings.HasPrefix(normalizedHost, "www.") {
		normalizedHost = normalizedHost[4:]
	}
	baseHost := strings.ToLower(c.domain)
	if strings.HasPrefix(baseHost, "www.") {
		baseHost = baseHost[4:]
	}
	if normalizedHost != baseHost {
		return false
	}

	if !c.isAllowedByRobots(targetURL.Path) {
		return false
	}

	lowerPath := strings.ToLower(targetURL.Path)
	excludedExtensions := []string{
		".pdf", ".zip", ".tar", ".gz", ".exe", ".dmg",
		".mp4", ".avi", ".mov", ".mp3", ".wav",
	}

	for _, ext := range excludedExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return false
		}
	}

	return true
}

func (c *Crawler) maybePruneMemory() {
	c.pruneMutex.Lock()
	defer c.pruneMutex.Unlock()

	if time.Since(c.lastPruneTime) < memoryPruneInterval {
		return
	}

	c.visitedMutex.Lock()
	if len(c.visited) >= 10000 {
		c.visitedPrev = c.visited
		c.visited = make(map[string]bool)
	}
	c.visitedMutex.Unlock()

	c.contentCacheMtx.Lock()
	if len(c.contentCache) > 5000 {
		c.contentCache = make(map[string]string)
	}
	c.contentCacheMtx.Unlock()

	c.contentHashMutex.Lock()
	if len(c.contentHashes) > 5000 {
		c.contentHashes = make(map[string]string)
	}
	c.contentHashMutex.Unlock()

	c.lastPruneTime = time.Now()
}

func (c *Crawler) fetchPage(urlStr string) (*PageStatus, string, error) {
	<-c.rateLimiter.C

	var redirectCount int32
	baseCtx := context.WithValue(context.Background(), redirectCountKey{}, &redirectCount)
	ctx, cancel := context.WithTimeout(baseCtx, requestTimeout)
	defer cancel()

	startTime := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return &PageStatus{
			URL:          urlStr,
			StatusCode:   0,
			ErrorMessage: err.Error(),
			ResourceType: "page",
			LoadTime:     time.Since(startTime),
		}, "", err
	}

	c.setRequestHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return &PageStatus{
			URL:          urlStr,
			StatusCode:   0,
			ErrorMessage: err.Error(),
			ResourceType: "page",
			LoadTime:     time.Since(startTime),
		}, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &PageStatus{
			URL:          urlStr,
			StatusCode:   resp.StatusCode,
			ErrorMessage: err.Error(),
			ResourceType: "page",
			LoadTime:     time.Since(startTime),
		}, "", err
	}

	loadTime := time.Since(startTime)
	httpVersion := "HTTP/1.1"
	if resp.ProtoMajor == 2 {
		httpVersion = "HTTP/2"
	}

	isHTTPS := false
	if parsedURL, parseErr := url.Parse(urlStr); parseErr == nil && parsedURL != nil {
		isHTTPS = parsedURL.Scheme == "https"
	}

	status := &PageStatus{
		URL:          urlStr,
		StatusCode:   resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
		Size:         int64(len(body)),
		ResourceType: "page",
		Redirects:    int(atomic.LoadInt32(&redirectCount)),
		IsHTTPS:      isHTTPS,
		HTTPVersion:  httpVersion,
		LoadTime:     loadTime,
		OGTags:       make(map[string]string),
	}

	return status, string(body), nil
}

func (c *Crawler) checkResource(urlStr string, resourceType string) {
	defer c.wg.Done()

	if !c.markVisited(urlStr) {
		return
	}

	c.semaphore <- struct{}{}
	defer func() { <-c.semaphore }()

	<-c.rateLimiter.C

	headStart := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	req, err := http.NewRequestWithContext(ctx, "HEAD", urlStr, nil)
	cancel()
	if err != nil {
		c.addResult(PageStatus{
			URL:          urlStr,
			StatusCode:   0,
			ErrorMessage: err.Error(),
			ResourceType: resourceType,
			LoadTime:     time.Since(headStart),
		})
		logStatus(urlStr, 0, resourceType, err.Error())
		return
	}

	c.setRequestHeaders(req)
	resp, err := c.client.Do(req)

	if err != nil || resp == nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}

		fallbackStart := time.Now()
		ctx2, cancel2 := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel2()

		req2, err2 := http.NewRequestWithContext(ctx2, "GET", urlStr, nil)
		if err2 != nil {
			message := "request build failed"
			if err != nil {
				message = err.Error()
			} else {
				message = err2.Error()
			}
			c.addResult(PageStatus{
				URL:          urlStr,
				StatusCode:   0,
				ErrorMessage: message,
				ResourceType: resourceType,
				LoadTime:     time.Since(headStart),
			})
			logStatus(urlStr, 0, resourceType, message)
			return
		}

		c.setRequestHeaders(req2)
		resp2, err2 := c.client.Do(req2)
		if err2 != nil {
			c.addResult(PageStatus{
				URL:          urlStr,
				StatusCode:   0,
				ErrorMessage: err2.Error(),
				ResourceType: resourceType,
				LoadTime:     time.Since(headStart),
			})
			logStatus(urlStr, 0, resourceType, err2.Error())
			return
		}
		defer resp2.Body.Close()

		contentLength := resp2.ContentLength
		if contentLength < 0 {
			contentLength = 0
		}
		loadTime := time.Since(fallbackStart)
		parsedURL, parseErr := url.Parse(urlStr)
		isHTTPS := parseErr == nil && parsedURL != nil && parsedURL.Scheme == "https"
		status := PageStatus{
			URL:          urlStr,
			StatusCode:   resp2.StatusCode,
			ContentType:  resp2.Header.Get("Content-Type"),
			Size:         contentLength,
			ResourceType: resourceType,
			IsHTTPS:      isHTTPS,
			LoadTime:     loadTime,
		}
		c.addResult(status)
		if resourceType == "image" {
			logImageStatus(urlStr, resp2.StatusCode, contentLength)
		} else {
			logStatus(urlStr, resp2.StatusCode, resourceType, "")
		}
		return
	}

	contentLength := resp.ContentLength
	if contentLength < 0 {
		contentLength = 0
	}
	loadTime := time.Since(headStart)
	parsedURL, parseErr := url.Parse(urlStr)
	isHTTPS := parseErr == nil && parsedURL != nil && parsedURL.Scheme == "https"

	status := PageStatus{
		URL:          urlStr,
		StatusCode:   resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
		Size:         contentLength,
		ResourceType: resourceType,
		IsHTTPS:      isHTTPS,
		LoadTime:     loadTime,
	}

	resp.Body.Close()
	c.addResult(status)

	if resourceType == "image" {
		logImageStatus(urlStr, resp.StatusCode, contentLength)
	} else {
		logStatus(urlStr, resp.StatusCode, resourceType, "")
	}
}

func (c *Crawler) crawlPage(urlStr string, depth int) {
	defer c.wg.Done()

	if !c.markVisited(urlStr) {
		return
	}

	atomic.AddInt64(&c.scannedCount, 1)
	if atomic.LoadInt64(&c.scannedCount)%gcInterval == 0 {
		c.maybePruneMemory()
	}

	c.semaphore <- struct{}{}
	defer func() { <-c.semaphore }()

	status, body, err := c.fetchPage(urlStr)

	if err == nil && status.StatusCode == 200 && strings.Contains(strings.ToLower(status.ContentType), "text/html") {
		c.analyzeSEO(status, body)

		isDuplicate, originalURL := c.checkDuplicateContent(body, urlStr)
		if isDuplicate {
			status.DuplicateOf = originalURL
		}
	}

	c.addResult(*status)

	if err != nil {
		logStatus(urlStr, status.StatusCode, "page", err.Error())
		return
	}

	logStatus(urlStr, status.StatusCode, "page", "")

	if status.StatusCode != 200 || !strings.Contains(strings.ToLower(status.ContentType), "text/html") {
		return
	}

	links, images := extractPageAssets(body, urlStr)

	for _, link := range links {
		parsedLink, err := url.Parse(link)
		if err != nil {
			continue
		}

		if parsedLink.Host == "" {
			parsedLink.Host = c.domain
			parsedLink.Scheme = c.baseURL.Scheme
		}

		parsedLink.Fragment = ""
		fullURL := parsedLink.String()

		if c.shouldCrawl(parsedLink) {
			if depth < maxCrawlDepth {
				c.wg.Add(1)
				go c.crawlPage(fullURL, depth+1)
			}
		} else if parsedLink.Host != c.domain {
			c.wg.Add(1)
			go c.checkResource(fullURL, "external")
		}
	}

	for _, img := range images {
		parsedImg, err := url.Parse(img)
		if err != nil {
			continue
		}

		if parsedImg.Host == "" {
			parsedImg.Host = c.domain
			parsedImg.Scheme = c.baseURL.Scheme
		}

		parsedImg.Fragment = ""
		fullURL := parsedImg.String()

		c.wg.Add(1)
		go c.checkResource(fullURL, "image")
	}
}

func (c *Crawler) Start() *AuditResult {
	startURL := c.baseURL.String()

	c.wg.Add(1)
	go c.crawlPage(startURL, 0)

	c.sitemapMutex.Lock()
	sitemapURLs := append([]string(nil), c.sitemapURLs...)
	c.sitemapMutex.Unlock()

	for _, raw := range sitemapURLs {
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if !c.shouldCrawl(parsed) {
			continue
		}
		parsed.Fragment = ""
		fullURL := parsed.String()
		c.wg.Add(1)
		go c.crawlPage(fullURL, 1)
	}

	c.wg.Wait()

	result := c.analyzeResults()

	c.rateLimiter.Stop()

	return result
}

func (c *Crawler) analyzeResults() *AuditResult {
	audit := &AuditResult{
		Pages:            make([]PageStatus, 0),
		BrokenLinks:      make([]PageStatus, 0),
		ServerErrors:     make([]PageStatus, 0),
		RedirectChains:   make([]PageStatus, 0),
		CriticalAssets:   make([]PageStatus, 0),
		WarningAssets:    make([]PageStatus, 0),
		AdviceAssets:     make([]PageStatus, 0),
		SEOIssues:        make([]PageStatus, 0),
		DuplicateContent: make([]PageStatus, 0),
		NonHTTPS:         make([]PageStatus, 0),
		MissingMetaTags:  make([]PageStatus, 0),
		SitemapURLs:      c.sitemapURLs,
		RobotsAllowed:    len(c.robotsRules) > 0,
		RobotsFound:      c.robotsFound,
		RobotsTxtContent: c.robotsTxtRaw,
	}

	c.resultsMutex.Lock()
	defer c.resultsMutex.Unlock()

	securityIssues := 0
	seoIssues := 0
	performanceIssues := 0
	htmlPages := 0
	imageResources := 0

	for _, result := range c.results {
		audit.Pages = append(audit.Pages, result)

		if result.StatusCode == 404 {
			audit.BrokenLinks = append(audit.BrokenLinks, result)
		}

		if result.StatusCode >= 500 {
			audit.ServerErrors = append(audit.ServerErrors, result)
		}

		if result.Redirects > 0 {
			audit.RedirectChains = append(audit.RedirectChains, result)
		}

		if !result.IsHTTPS && result.ResourceType == "page" {
			audit.NonHTTPS = append(audit.NonHTTPS, result)
			securityIssues++
		}

		if result.ResourceType == "page" && strings.Contains(strings.ToLower(result.ContentType), "text/html") {
			htmlPages++
			titleLen := len(result.Title)
			if result.Title == "" || titleLen < optimalTitleMin || titleLen > optimalTitleMax {
				audit.SEOIssues = append(audit.SEOIssues, result)
				seoIssues++
			}
			if result.Description == "" || len(result.Description) > optimalDescMax {
				audit.MissingMetaTags = append(audit.MissingMetaTags, result)
				seoIssues++
			}
			if result.H1Count != 1 {
				seoIssues++
			}
			if !result.HasCanonical {
				seoIssues++
			} else if result.CanonicalURL == result.URL {
				seoIssues++
			}
		}

		if result.DuplicateOf != "" {
			audit.DuplicateContent = append(audit.DuplicateContent, result)
			seoIssues++
		}

		if result.ResourceType == "image" && result.StatusCode == 200 {
			imageResources++
			if result.Size >= criticalImageThreshold {
				audit.CriticalAssets = append(audit.CriticalAssets, result)
				performanceIssues += 3
			} else if result.Size >= hugeImageThreshold {
				audit.WarningAssets = append(audit.WarningAssets, result)
				performanceIssues += 2
			} else if result.Size >= largeImageThreshold {
				audit.AdviceAssets = append(audit.AdviceAssets, result)
				performanceIssues++
			}
		}

		if result.LoadTime > 3*time.Second {
			performanceIssues++
		}
	}

	audit.TotalScanned = len(c.results)

	totalIssues := len(audit.BrokenLinks) + len(audit.ServerErrors) + len(audit.CriticalAssets)
	if audit.TotalScanned > 0 {
		audit.HealthScore = 100 - (float64(totalIssues) / float64(audit.TotalScanned) * 100)
		if audit.HealthScore < 0 {
			audit.HealthScore = 0
		}
	}

	if htmlPages > 0 {
		maxSEOIssues := htmlPages * 4
		audit.SEOScore = 100 - (float64(seoIssues) / float64(maxSEOIssues) * 100)
		if audit.SEOScore < 0 {
			audit.SEOScore = 0
		}
	} else {
		audit.SEOScore = 100
	}

	perfBase := imageResources + htmlPages
	if perfBase > 0 {
		maxPerfIssues := perfBase * 2
		audit.PerformanceScore = 100 - (float64(performanceIssues) / float64(maxPerfIssues) * 100)
		if audit.PerformanceScore < 0 {
			audit.PerformanceScore = 0
		}
	} else {
		audit.PerformanceScore = 100
	}

	if htmlPages > 0 {
		audit.SecurityScore = 100 - (float64(securityIssues) / float64(htmlPages) * 100)
		if audit.SecurityScore < 0 {
			audit.SecurityScore = 0
		}
	} else {
		audit.SecurityScore = 100
	}

	return audit
}

var contentSkipTags = map[string]bool{
	"nav": true, "header": true, "footer": true, "script": true, "style": true,
}

func extractMainContent(body string) string {
	doc, err := htmlparser.Parse(strings.NewReader(body))
	if err != nil {
		return body
	}
	var content strings.Builder
	var traverse func(*htmlparser.Node)
	traverse = func(n *htmlparser.Node) {
		if n.Type == htmlparser.ElementNode && contentSkipTags[n.Data] {
			return
		}
		if n.Type == htmlparser.TextNode {
			text := strings.TrimSpace(n.Data)
			if text != "" {
				if content.Len() > 0 {
					content.WriteByte(' ')
				}
				content.WriteString(text)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)
	return content.String()
}

func findBaseHref(doc *htmlparser.Node) string {
	var found string
	var walk func(*htmlparser.Node)
	walk = func(n *htmlparser.Node) {
		if found != "" {
			return
		}
		if n.Type == htmlparser.ElementNode && n.Data == "base" {
			for _, attr := range n.Attr {
				if strings.EqualFold(attr.Key, "href") && attr.Val != "" {
					found = attr.Val
					return
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return found
}

func (c *Crawler) analyzeSEO(status *PageStatus, body string) {
	if status == nil {
		return
	}
	if status.OGTags == nil {
		status.OGTags = make(map[string]string)
	}
	doc, err := htmlparser.Parse(strings.NewReader(body))
	if err != nil {
		return
	}

	var traverse func(*htmlparser.Node)
	h1Count := 0

	traverse = func(n *htmlparser.Node) {
		if n.Type == htmlparser.ElementNode {
			switch n.Data {
			case "title":
				var titleText strings.Builder
				for child := n.FirstChild; child != nil; child = child.NextSibling {
					if child.Type == htmlparser.TextNode {
						titleText.WriteString(child.Data)
					}
				}
				status.Title = strings.TrimSpace(titleText.String())
			case "h1":
				var h1Text strings.Builder
				for child := n.FirstChild; child != nil; child = child.NextSibling {
					if child.Type == htmlparser.TextNode {
						h1Text.WriteString(child.Data)
					}
				}
				if trimmed := strings.TrimSpace(h1Text.String()); trimmed != "" {
					h1Count++
				}
			case "link":
				var rel, href string
				for _, attr := range n.Attr {
					if strings.EqualFold(attr.Key, "rel") {
						rel = attr.Val
					}
					if strings.EqualFold(attr.Key, "href") {
						href = attr.Val
					}
				}
				hasCanonical := false
				for _, token := range strings.Fields(strings.ToLower(rel)) {
					if token == "canonical" {
						hasCanonical = true
						break
					}
				}
				if hasCanonical && href != "" {
					status.HasCanonical = true
					status.CanonicalURL = href
				}
			case "meta":
				var name, content, property string
				for _, attr := range n.Attr {
					if strings.EqualFold(attr.Key, "name") {
						name = strings.ToLower(attr.Val)
					}
					if strings.EqualFold(attr.Key, "property") {
						property = strings.ToLower(attr.Val)
					}
					if strings.EqualFold(attr.Key, "content") {
						content = attr.Val
					}
				}

				if name == "description" {
					status.Description = content
				}
				if name == "robots" {
					status.HasRobotsMeta = true
					status.MetaRobots = content
				}
				if strings.HasPrefix(property, "og:") {
					status.OGTags[property] = content
				}
			case "script":
				for _, attr := range n.Attr {
					if strings.EqualFold(attr.Key, "type") &&
						strings.Contains(strings.ToLower(attr.Val), "application/ld+json") {
						status.StructuredData = true
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	status.H1Count = h1Count
}

func extractPageAssets(body, baseURL string) ([]string, []string) {
	doc, err := htmlparser.Parse(strings.NewReader(body))
	if err != nil {
		return nil, nil
	}

	effectiveBase := baseURL
	if baseHref := findBaseHref(doc); baseHref != "" {
		if resolved := resolveURL(baseURL, baseHref); resolved != "" {
			effectiveBase = resolved
		}
	}

	links := make([]string, 0)
	images := make([]string, 0)

	var traverse func(*htmlparser.Node)
	traverse = func(n *htmlparser.Node) {
		if n.Type == htmlparser.ElementNode {
			if n.Data == "a" {
				for _, attr := range n.Attr {
					if strings.EqualFold(attr.Key, "href") {
						link := attr.Val
						if link != "" && !strings.HasPrefix(link, "#") &&
							!strings.HasPrefix(link, "javascript:") &&
							!strings.HasPrefix(link, "mailto:") &&
							!strings.HasPrefix(link, "tel:") {
							absURL := resolveURL(effectiveBase, link)
							if absURL != "" {
								links = append(links, absURL)
							}
						}
					}
				}
			} else if n.Data == "img" {
				for _, attr := range n.Attr {
					if strings.EqualFold(attr.Key, "src") {
						img := attr.Val
						if img != "" && !strings.HasPrefix(img, "data:") {
							absURL := resolveURL(effectiveBase, img)
							if absURL != "" {
								images = append(images, absURL)
							}
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	return links, images
}

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
		symbol = "[-]"
	} else if statusCode == 404 {
		color = colorRed
		symbol = "[-]"
	} else if statusCode >= 500 {
		color = colorBoldRed
		symbol = "[!]"
	} else if statusCode >= 300 && statusCode < 400 {
		color = colorYellow
		symbol = "[~]"
	} else if statusCode == 200 {
		color = colorGreen
		symbol = "[+]"
	} else {
		color = colorWhite
		symbol = "[*]"
	}

	displayURL := urlStr
	if len(displayURL) > maxURLLength {
		displayURL = displayURL[:truncatedURLLength] + "..."
	}

	if errorMsg != "" {
		fmt.Printf("%s%s %3d %s [%s] (%s)%s\n", color, symbol, statusCode, displayURL, resourceType, errorMsg, colorReset)
	} else {
		fmt.Printf("%s%s %3d %s [%s]%s\n", color, symbol, statusCode, displayURL, resourceType, colorReset)
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
		symbol = "[-]"
		message = "Failed to load"
	} else if size >= criticalImageThreshold {
		color = colorBoldRed
		symbol = "[!]"
		message = fmt.Sprintf("CRITICAL: %.2f MB - Immediate optimization required!", float64(size)/(1024*1024))
	} else if size >= hugeImageThreshold {
		color = colorOrange
		symbol = "[!]"
		message = fmt.Sprintf("WARNING: %.2f MB - Must be optimized", float64(size)/(1024*1024))
	} else if size >= largeImageThreshold {
		color = colorYellow
		symbol = "[*]"
		message = fmt.Sprintf("ADVICE: %.2f KB - Consider optimizing", float64(size)/1024)
	} else {
		color = colorGreen
		symbol = "[+]"
		message = fmt.Sprintf("OK: %.2f KB", float64(size)/1024)
	}

	displayURL := urlStr
	if len(displayURL) > shortURLLength {
		displayURL = displayURL[:shortTruncatedLength] + "..."
	}

	fmt.Printf("%s%s IMG %s - %s%s\n", color, symbol, displayURL, message, colorReset)
}

func clearScreen() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls")
	default:
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "clear screen failed: %v\n", err)
	}
}

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

	fmt.Fprintf(w, "Total Resources Scanned\t%d\t%s[+] Complete%s\n", audit.TotalScanned, colorGreen, colorReset)

	if len(audit.BrokenLinks) > 0 {
		fmt.Fprintf(w, "Broken Links (404)\t%d\t%s[-] Critical%s\n", len(audit.BrokenLinks), colorRed, colorReset)
	} else {
		fmt.Fprintf(w, "Broken Links (404)\t%d\t%s[+] Excellent%s\n", len(audit.BrokenLinks), colorGreen, colorReset)
	}

	if len(audit.ServerErrors) > 0 {
		fmt.Fprintf(w, "Server Errors (5xx)\t%d\t%s[-] Critical%s\n", len(audit.ServerErrors), colorBoldRed, colorReset)
	} else {
		fmt.Fprintf(w, "Server Errors (5xx)\t%d\t%s[+] Excellent%s\n", len(audit.ServerErrors), colorGreen, colorReset)
	}

	if len(audit.RedirectChains) > 0 {
		fmt.Fprintf(w, "Redirect Chains\t%d\t%s[!] Warning%s\n", len(audit.RedirectChains), colorYellow, colorReset)
	} else {
		fmt.Fprintf(w, "Redirect Chains\t%d\t%s[+] Good%s\n", len(audit.RedirectChains), colorGreen, colorReset)
	}

	if len(audit.CriticalAssets) > 0 {
		fmt.Fprintf(w, "Critical Images (>2MB)\t%d\t%s[!] URGENT%s\n", len(audit.CriticalAssets), colorBoldRed, colorReset)
	} else {
		fmt.Fprintf(w, "Critical Images (>2MB)\t%d\t%s[+] Excellent%s\n", len(audit.CriticalAssets), colorGreen, colorReset)
	}
[+] Good%s\n", len(audit.WarningAssets), colorGreen, colorReset)
	}

	if len(audit.AdviceAssets) > 0 {
		fmt.Fprintf(w, "Medium Images (>700KB)\t%d\t%s[*] Consider%s\n", len(audit.AdviceAssets), colorYellow, colorReset)
	} else {
		fmt.Fprintf(w, "Medium Images (>700KB)\t%d\t%s[+] Good%s\n", len(audit.AdviceAssets), colorGreen, colorReset)
	}

	if len(audit.DuplicateContent) > 0 {
		fmt.Fprintf(w, "Duplicate Content\t%d\t%s[!] SEO Issue%s\n", len(audit.DuplicateContent), colorYellow, colorReset)
	} else {
		fmt.Fprintf(w, "Duplicate Content\t%d\t%s[+] Excellent%s\n", len(audit.DuplicateContent), colorGreen, colorReset)
	}

	if len(audit.NonHTTPS) > 0 {
		fmt.Fprintf(w, "Non-HTTPS Pages\t%d\t%s[!] Security Risk%s\n", len(audit.NonHTTPS), colorOrange, colorReset)
	} else {
		fmt.Fprintf(w, "Non-HTTPS Pages\t%d\t%s[+] Secure%s\n", len(audit.NonHTTPS), colorGreen, colorReset)
	}

	if len(audit.MissingMetaTags) > 0 {
		fmt.Fprintf(w, "Missing/Poor Meta Tags\t%d\t%s[!] SEO Issue%s\n", len(audit.MissingMetaTags), colorYellow, colorReset)
	} else {
		fmt.Fprintf(w, "Missing/Poor Meta Tags\t%d\t%s[+] Good%s\n", len(audit.MissingMetaTags), colorGreen, colorReset)
	}

	if len(audit.SitemapURLs) > 0 {
		fmt.Fprintf(w, "Sitemap URLs Found\t%d\t%s[+] Detected%s\n", len(audit.SitemapURLs), colorGreen, colorReset)
	} else {
		fmt.Fprintf(w, "Sitemap URLs Found\t%d\t%s[!] Not Found%s\n", len(audit.SitemapURLs), colorYellow, colorReset)
	}

	if audit.RobotsFound {
		fmt.Fprintf(w, "Robots.txt Status\t-\t%s[+] Found%s\n", colorGreen, colorReset)
	} else {
		fmt.Fprintf(w, "Robots.txt Status\t-\t%s[!] Not Found%s\n", colorYellow, colorReset)
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
            <h1>HuntCat</h1>
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
		} else if issue.DuplicateOf != "" {
			statusClass = "status-warning"
			message = "Duplicate of: " + html.EscapeString(issue.DuplicateOf)
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
		if audit.RobotsFound {
			return "Found"
		}
		return "Not Found"
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

	if err := writer.Write([]string{"URL", "Type", "Status Code", "Size (bytes)", "HTTPS", "HTTP Version", "Title", "Description", "H1 Count", "Has Canonical", "Load Time (ms)", "Issue"}); err != nil {
		return err
	}

	for _, page := range audit.Pages {
		issue := "OK"
		if page.StatusCode == 404 {
			issue = "Broken Link"
		} else if page.StatusCode >= 500 {
			issue = "Server Error"
		} else if page.ResourceType == "image" && page.Size >= criticalImageThreshold {
			issue = "Critical Image Size"
		} else if page.DuplicateOf != "" {
			issue = "Duplicate Content"
		} else if !page.IsHTTPS {
			issue = "Not HTTPS"
		} else if page.Title == "" {
			issue = "Missing Title"
		} else if page.Description == "" {
			issue = "Missing Description"
		}

		if err := writer.Write([]string{
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
		}); err != nil {
			return err
		}
	}

	writer.Flush()
	return writer.Error()
}

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
