package main

import (
	"strings"

	htmlparser "golang.org/x/net/html"
)

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
