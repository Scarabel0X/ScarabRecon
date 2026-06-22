package commoncrawl

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/corpix/uarand"
)

type CommoncrawlSource struct{}

func (c *CommoncrawlSource) Name() string {
	return "commoncrawl"
}

func (c *CommoncrawlSource) NeedsAPIKey() bool {
	return false
}

func (c *CommoncrawlSource) Search(query string, client *http.Client, apikey string) ([]string, error) {

	host := strings.TrimPrefix(query, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimSuffix(host, "/")

	if host == "" {
		return nil, fmt.Errorf("invalid query")
	}

	api, err := latestCDXAPI(client)
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("url", host+"/*")
	q.Set("output", "json")
	q.Set("collapse", "urlkey")

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", uarand.GetRandom())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("commoncrawl http %d", resp.StatusCode)
	}

	sc := bufio.NewScanner(resp.Body)

	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	type row struct {
		URL string `json:"url"`
	}

	var out []string
	for sc.Scan() {
		var r row
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue
		}
		if r.URL == "" {
			continue
		}
		out = append(out, r.URL)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type ccCollection struct {
	CDXAPI string `json:"cdx-api"`
}

var (
	once     sync.Once
	cached   string
	cacheErr error
)

func latestCDXAPI(client *http.Client) (string, error) {
	once.Do(func() {
		cached, cacheErr = fetchLatestCDXAPI(client)
	})
	return cached, cacheErr
}

func fetchLatestCDXAPI(client *http.Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://index.commoncrawl.org/collinfo.json", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Scarburl")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("collinfo http %d", resp.StatusCode)
	}

	var cols []ccCollection
	if err := json.NewDecoder(resp.Body).Decode(&cols); err != nil {
		return "", err
	}
	for _, c := range cols {
		if c.CDXAPI != "" {
			return c.CDXAPI, nil // newest-first
		}
	}
	return "", fmt.Errorf("no commoncrawl cdx api found")
}
