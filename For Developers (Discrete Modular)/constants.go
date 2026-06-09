package main

import "time"

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
