package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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
