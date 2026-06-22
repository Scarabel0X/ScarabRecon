package scraper

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/cyinnove/logify"
)

type Source interface {
	Name() string
	NeedsAPIKey() bool
	Search(domain string, client *http.Client, apiKey string) ([]string, error)
}

func GetAPIKey(sourceName string) string {
	logify.Infof(" Fetching API Key for %s...\n", sourceName)
	return "DUMMY_API_KEY_FOR_NOW"
}

func NewSession(timeout int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}
func RunAllSources(domain string, activeSources []Source, timeout int) map[string]string {

	uniqueURLs := make(map[string]string)
	client := NewSession(timeout)

	for _, src := range activeSources {
		var apiKey string

		if src.NeedsAPIKey() {
			apiKey = GetAPIKey(src.Name())
		}

		logify.Infof(" Starting source: %s for domain: %s\n", src.Name(), domain)

		urls, err := src.Search(domain, client, apiKey)
		if err != nil {
			logify.Warningf(" Error running source %s: %v\n", src.Name(), err)
			continue
		}

		for _, u := range urls {
			if parsed, err := url.Parse(u); err == nil {
				uniqueURLs[u] = parsed.Hostname()
			} else {
				uniqueURLs[u] = domain
			}
		}

		logify.Infof(" %s found %d URLs\n", src.Name(), len(urls))
	}

	logify.Infof(" Total unique URLs collected: %d\n", len(uniqueURLs))

	return uniqueURLs
}
