package main

import (
	"net/url"
	"testing"
)

func TestMatchRobotsRulePrefix(t *testing.T) {
	if !matchRobotsRule("/private/", "/private/page.html") {
		t.Fatal("expected prefix match")
	}
	if matchRobotsRule("/private/", "/public/page.html") {
		t.Fatal("unexpected match")
	}
}

func TestMatchRobotsRuleWildcard(t *testing.T) {
	if !matchRobotsRule("/private/*", "/private/a/b.html") {
		t.Fatal("wildcard should cross slashes per RFC 9309")
	}
	if !matchRobotsRule("/*.php$", "/index.php") {
		t.Fatal("anchored wildcard should match")
	}
	if matchRobotsRule("/*.php$", "/index.php?x=1") {
		t.Fatal("anchor should reject trailing content")
	}
}

func TestRobotsAllowBeatsDisallowOnTie(t *testing.T) {
	c := &Crawler{robotsRules: map[string]bool{"/api": false, "/api/public": true}}
	if !c.isAllowedByRobots("/api/public/data") {
		t.Fatal("longer allow should win")
	}
	if c.isAllowedByRobots("/api/private") {
		t.Fatal("disallow should still apply")
	}
}

func TestShouldCrawlRejectsExcludedExtension(t *testing.T) {
	c := &Crawler{domain: "example.com", robotsRules: map[string]bool{"*": true}}
	parsed, _ := url.Parse("https://example.com/file.pdf")
	if c.shouldCrawl(parsed) {
		t.Fatal("pdf should be excluded")
	}
}

func TestAnalyzeResultsScoresUseCorrectDenominator(t *testing.T) {
	c := &Crawler{
		results: []PageStatus{
			{ResourceType: "page", StatusCode: 200, ContentType: "text/html", Title: "short", H1Count: 0},
			{ResourceType: "image", StatusCode: 200, Size: 100},
		},
	}
	audit := c.analyzeResults()
	if audit.SEOScore >= 100 {
		t.Fatal("seo score should drop for malformed page")
	}
	if audit.PerformanceScore >= 100 {
		t.Fatal("performance score should drop when only one image and one slow page")
	}
}
