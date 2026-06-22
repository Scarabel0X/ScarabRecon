package webarchive

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

// WebArchiveSource هو الـ Struct اللي هيمثل السورس ده
type WebArchiveSource struct{}

// 1. Name: بترجع اسم السورس
func (w *WebArchiveSource) Name() string {
	return "webarchive"
}

// 2. NeedsAPIKey: بترجع false لأننا مش محتاجين مفتاح
func (w *WebArchiveSource) NeedsAPIKey() bool {
	return false
}

func (w *WebArchiveSource) Search(query string, client *http.Client, apikey string) ([]string, error) {

	host := strings.TrimPrefix(query, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimSuffix(host, "/")

	if host == "" {
		return nil, fmt.Errorf("invalid query")
	}

	cdx := "https://web.archive.org/cdx/search/cdx"
	q := url.Values{}
	q.Set("url", "*."+host+"/*")
	q.Set("output", "json")
	q.Set("fl", "original")
	q.Set("collapse", "urlkey")
	q.Set("filter", "statuscode:200")

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cdx+"?"+q.Encode(), nil)
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
		return nil, fmt.Errorf("webarchive http %d", resp.StatusCode)
	}

	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(rows))
	for i := 1; i < len(rows); i++ { // header row at 0
		if len(rows[i]) < 1 {
			continue
		}
		u := strings.TrimSpace(rows[i][0])
		if u == "" {
			continue
		}
		out = append(out, u)
	}
	return out, nil
}
