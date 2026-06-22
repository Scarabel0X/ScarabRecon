package urlscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/corpix/uarand"
)

// URLScanSource هو الـ Struct اللي هيمثل السورس ده
type URLScanSource struct{}

// 1. Name: بترجع اسم السورس
func (u *URLScanSource) Name() string {
	return "urlscan"
}

// 2. NeedsAPIKey: بترجع true لأننا محتاجين مفتاح
func (u *URLScanSource) NeedsAPIKey() bool {
	return false
}

// 3. Run: بتاخد المفتاح وتروح تجيب الداتا
func (u *URLScanSource) Search(query string, client *http.Client, apikey string) ([]string, error) {

	host := strings.TrimPrefix(query, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimSuffix(host, "/")

	if host == "" {
		return nil, fmt.Errorf("invalid query")
	}

	qs := url.Values{}
	qs.Set("q", "domain:"+host)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://urlscan.io/api/v1/search/?"+qs.Encode(), nil)
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
		return nil, fmt.Errorf("urlscan http %d", resp.StatusCode)
	}

	// We keep parsing intentionally small: page.url is enough for URL enumeration.
	var parsed struct {
		Results []struct {
			Page struct {
				URL string `json:"url"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		u := strings.TrimSpace(r.Page.URL)
		if u == "" {
			continue
		}
		out = append(out, u)
	}
	return out, nil
}
