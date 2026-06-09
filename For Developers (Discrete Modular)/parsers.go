package main

import (
	"strings"

	htmlparser "golang.org/x/net/html"
)

func extractMainContent(body string) string {
	doc, err := htmlparser.Parse(strings.NewReader(body))
	if err != nil {
		return body
	}
	var content strings.Builder
	var traverse func(*htmlparser.Node)
	traverse = func(n *htmlparser.Node) {
		if n.Type == htmlparser.ElementNode {
			skip := []string{"nav", "header", "footer", "script", "style"}
			for _, tag := range skip {
				if n.Data == tag {
					return
				}
			}
		}
		if n.Type == htmlparser.TextNode {
			text := strings.TrimSpace(n.Data)
			if text != "" {
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

func (c *Crawler) analyzeSEO(status *PageStatus, body string) {
	if status == nil {
		return
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
					if attr.Key == "rel" {
						rel = attr.Val
					}
					if attr.Key == "href" {
						href = attr.Val
					}
				}
				if rel == "canonical" && href != "" {
					status.HasCanonical = true
					status.CanonicalURL = href
				}
			case "meta":
				var name, content, property string
				for _, attr := range n.Attr {
					if attr.Key == "name" {
						name = attr.Val
					}
					if attr.Key == "property" {
						property = attr.Val
					}
					if attr.Key == "content" {
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
					if attr.Key == "type" && strings.Contains(attr.Val, "application/ld+json") {
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

	links := make([]string, 0)
	images := make([]string, 0)

	var traverse func(*htmlparser.Node)
	traverse = func(n *htmlparser.Node) {
		if n.Type == htmlparser.ElementNode {
			if n.Data == "a" {
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						link := attr.Val
						if link != "" && !strings.HasPrefix(link, "#") &&
							!strings.HasPrefix(link, "javascript:") &&
							!strings.HasPrefix(link, "mailto:") &&
							!strings.HasPrefix(link, "tel:") {
							absURL := resolveURL(baseURL, link)
							if absURL != "" {
								links = append(links, absURL)
							}
						}
					}
				}
			} else if n.Data == "img" {
				for _, attr := range n.Attr {
					if attr.Key == "src" {
						img := attr.Val
						if img != "" && !strings.HasPrefix(img, "data:") {
							absURL := resolveURL(baseURL, img)
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
