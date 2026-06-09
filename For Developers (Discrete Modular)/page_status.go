package main

import "time"

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
	ContentHash    string
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
	RobotsTxtContent string
}
