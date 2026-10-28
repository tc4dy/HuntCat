package main

import "testing"

func TestExtractMainContentAddsWordBoundary(t *testing.T) {
	body := `<html><body><p>Hello</p><p>World</p></body></html>`
	got := extractMainContent(body)
	if got != "Hello World" {
		t.Fatalf("expected word boundary, got %q", got)
	}
}

func TestExtractPageAssetsHonorsBaseHref(t *testing.T) {
	body := `<html><head><base href="https://cdn.example.com/assets/"></head><body><img src="logo.png"><a href="/about">About</a></body></html>`
	links, images := extractPageAssets(body, "https://example.com/")
	if len(images) != 1 || images[0] != "https://cdn.example.com/assets/logo.png" {
		t.Fatalf("unexpected images: %v", images)
	}
	if len(links) != 1 || links[0] != "https://cdn.example.com/about" {
		t.Fatalf("unexpected links: %v", links)
	}
}

func TestAnalyzeSEOHandlesCanonicalTokens(t *testing.T) {
	c := &Crawler{}
	status := &PageStatus{OGTags: map[string]string{}}
	body := `<html><head><link rel="canonical alternate" href="https://example.com/a"><meta name="description" content="desc"></head></html>`
	c.analyzeSEO(status, body)
	if !status.HasCanonical {
		t.Fatal("canonical token should be detected")
	}
	if status.Description != "desc" {
		t.Fatal("description should be captured")
	}
}
