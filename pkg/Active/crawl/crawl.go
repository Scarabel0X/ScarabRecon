package crawl

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/corpix/uarand"
	"github.com/cyinnove/logify"
	"github.com/gocolly/colly/v2"
)

func normalizeURL(u *url.URL) string {
	path := u.Path
	if path != "/" && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	normalized := u.Scheme + "://" + u.Host + path
	if u.RawQuery != "" {
		normalized += "?" + u.RawQuery
	}
	return normalized
}

func Crawling(query string, allowedHostnames []string, depth int, threads int, timeoutSeconds int, cookie string, headers []string) (map[string]string, error) {

	targetURL := strings.TrimSpace(query)
	if targetURL == "" {
		return nil, fmt.Errorf("query in Crawling is empty")
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("Error parsing URL %s: %v\n", targetURL, err)
	}

	var domainsToAllow []string
	if len(allowedHostnames) > 0 {
		domainsToAllow = allowedHostnames
	} else {
		domainsToAllow = []string{parsedURL.Hostname()}
	}

	c := colly.NewCollector(
		colly.MaxDepth(depth),
		colly.Async(true),
		colly.AllowedDomains(domainsToAllow...),
	)

	c.UserAgent = uarand.GetRandom()
	c.SetRequestTimeout(time.Duration(timeoutSeconds) * time.Second)

	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: threads,
	})

	seen := make(map[string]string)
	var mu sync.Mutex

	c.OnHTML("a[href], link[href], script[src], iframe[src], form[action]", func(e *colly.HTMLElement) {
		var linkURL string
		switch {
		case e.Attr("href") != "":
			linkURL = e.Attr("href")
			if linkURL == "" || linkURL == "#" || strings.HasPrefix(linkURL, "javascript:") {
				return
			}
		case e.Attr("src") != "":
			linkURL = e.Attr("src")
		case e.Attr("action") != "":
			linkURL = e.Attr("action")
		}

		if linkURL != "" {
			if absoluteURL := e.Request.AbsoluteURL(linkURL); absoluteURL != "" {
				printUnique(seen, &mu, absoluteURL, allowedHostnames)
			}
		}
	})

	c.OnRequest(func(r *colly.Request) {
		if cookie != "" {
			r.Headers.Set("Cookie", cookie)
		}

		for _, h := range headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				r.Headers.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}

		printUnique(seen, &mu, r.URL.String(), allowedHostnames)
	})

	c.OnError(func(r *colly.Response, err error) {
		logify.Warningf("Error visiting %s: %v\n", r.Request.URL, err)
	})

	if err := c.Visit(targetURL); err != nil {
		logify.Warningf("Error visiting URL %s: %v\n", targetURL, err)
	}

	c.Wait()

	return seen, nil
}

func printUnique(seen map[string]string, mu *sync.Mutex, urlStr string, allowedHostnames []string) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return
	}

	currentHost := parsed.Hostname()
	isAllowed := false

	if len(allowedHostnames) == 0 {
		isAllowed = true
	} else {
		for _, allowed := range allowedHostnames {
			if currentHost == allowed {
				isAllowed = true
				break
			}
		}
	}

	if !isAllowed {
		return
	}

	normalized := normalizeURL(parsed)

	mu.Lock()
	defer mu.Unlock()

	if _, exists := seen[normalized]; !exists {
		seen[normalized] = currentHost
		logify.Infof("Found URL: %s", normalized)
	}
}
