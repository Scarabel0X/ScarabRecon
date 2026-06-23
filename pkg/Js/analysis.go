package js

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/corpix/uarand"
	"github.com/cyinnove/logify"
)

func Analysis(urls []string, threads int, cookie string, headers []string, targetdomain string) ([]ScanResult, map[string]int, error) {
	restotal := map[string]int{
		"Subdomains":   0,
		"CloudBuckets": 0,
		"Endpoints":    0,
		"Parameters":   0,
		"Secrets":      0,
		"NpmPackages":  0,
	}
	if len(urls) == 0 {
		logify.Errorf("No URLs provided for scanning")
		return nil, restotal, errors.New("no URLs provided")
	}

	results := make([]ScanResult, len(urls))
	errs := make(chan error, len(urls))

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	for i, u := range urls {
		i, u := i, u
		wg.Add(1)
		sem <- struct{}{}

		go func() {
			defer wg.Done()

			defer func() { <-sem }()

			res, resInt, err := scanJSURL(u, cookie, headers, targetdomain)
			if err != nil {
				logify.Warningf("Failed to scan JS URL %s: %v", u, err)
				return
			}
			results[i] = res

			mu.Lock()
			for t := range restotal {
				restotal[t] += resInt[t]
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	close(errs)

	errorCount := len(errs)
	if errorCount > 0 {
		logify.Warningf("Scan completed with %d errors", errorCount)
		// For simplicity, return the first error along with any partial results.
		return results, restotal, <-errs
	}

	return results, restotal, nil

}

// JS analysis functions

// getFileContent fetches the raw contents of a JavaScript file from the given URL.
func getFileContent(url string, cookie string, headers []string) (string, error) {

	client := getClient()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logify.Errorf("Failed to create HTTP request for %s: %v", url, err)
		return "", err
	}
	req.Header.Set("User-Agent", uarand.GetRandom())

	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := client.Do(req)

	if err != nil {
		logify.Errorf("HTTP request failed for %s: %v", url, err)
		return "", err
	}
	defer resp.Body.Close()

	// Create a context with timeout for reading the body (max 60 seconds)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Read body with context timeout
	bodyChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			errChan <- err
			return
		}
		bodyChan <- body
	}()

	select {
	case <-ctx.Done():
		logify.Errorf("Timeout reading response body from %s (exceeded 60 seconds)", url)
		return "", fmt.Errorf("timeout reading response body: %w", ctx.Err())
	case err := <-errChan:
		logify.Errorf("Failed to read response body from %s: %v", url, err)
		return "", err
	case body := <-bodyChan:

		return string(body), nil
	}
}

// AnalyzeJSContent runs all regex-based extractors over the given JavaScript
// source and returns the collected findings.
func AnalyzeJSContent(source string, targetDomain string) (ScanResult, map[string]int, error) {
	resInt := make(map[string]int)
	pretty := BeautifyJS(source)

	subdomains := make(map[string]struct{})
	for _, m := range subdomainRegex.FindAllString(pretty, -1) {
		if host, valid := cleanAndValidateSubdomain(m, targetDomain); valid {

			subdomains[host] = struct{}{}
		}
	}

	clouds := make(map[string]struct{})
	for _, m := range cloudBucketRegex.FindAllString(pretty, -1) {
		clouds[m] = struct{}{}
	}

	endpoints := make(map[string]struct{})
	for _, m := range endpointRegex.FindAllString(pretty, -1) {
		endpoints[m] = struct{}{}
	}

	params := make(map[string]struct{})
	if subs := parameterRegex.FindAllStringSubmatch(pretty, -1); subs != nil {
		for _, s := range subs {
			if len(s) >= 3 {
				params[s[2]] = struct{}{}
			}
		}
	}

	// NPM packages: extract only from node_modules paths.
	// The nodeModulesRegex captures the package name from paths like /node_modules/package-name/
	npm := make(map[string]struct{})
	if subs := nodeModulesRegex.FindAllStringSubmatch(pretty, -1); subs != nil {
		for _, s := range subs {
			if len(s) >= 2 {
				// s[1] contains the package name extracted from the node_modules path
				npm[s[1]] = struct{}{}
			}
		}
	}

	// Secrets from YAML-defined patterns.
	var secretMatches []*SecretMatch
	seenSecrets := make(map[string]struct{})

	if patterns, err := loadSecretPatterns(); err == nil {

		for _, p := range patterns {
			matches := p.Re.FindAllString(pretty, -1)
			for _, m := range matches {

				if m == "" || len(m) < 20 {
					continue
				}

				key := p.Name + "::" + m
				if _, exists := seenSecrets[key]; exists {
					continue
				}
				seenSecrets[key] = struct{}{}
				secretMatches = append(secretMatches, &SecretMatch{
					Name:  p.Name,
					Match: m,
				})
			}
		}
	} else {
		logify.Warningf("Failed to load secret patterns: %v", err)
	}

	result := ScanResult{
		Subdomains:   setToSlice(subdomains),
		CloudBuckets: setToSlice(clouds),
		Endpoints:    setToSlice(endpoints),
		Parameters:   setToSlice(params),
		Secrets:      secretMatches,
		NpmPackages:  setToSlice(npm),
	}

	resInt = map[string]int{
		"Subdomains":   len(result.Subdomains),
		"CloudBuckets": len(result.CloudBuckets),
		"Endpoints":    len(result.Endpoints),
		"Parameters":   len(result.Parameters),
		"Secrets":      len(result.Secrets),
		"NpmPackages":  len(result.NpmPackages),
	}
	logify.Infof("Analysis complete: %d subdomains, %d cloud buckets, %d endpoints, %d parameters, %d secrets, %d NPM packages",
		len(result.Subdomains), len(result.CloudBuckets), len(result.Endpoints),
		len(result.Parameters), len(result.Secrets), len(result.NpmPackages))

	return result, resInt, nil
}

// ScanJSURL fetches a JavaScript file from the given URL and analyzes it.
func scanJSURL(url string, cookie string, headers []string, targetDomain string) (ScanResult, map[string]int, error) {
	body, err := getFileContent(url, cookie, headers)
	if err != nil {
		logify.Errorf("Failed to fetch JS file from %s: %v", url, err)
		return ScanResult{}, nil, err
	}
	res, resInt, err := AnalyzeJSContent(body, targetDomain)
	if err != nil {
		logify.Errorf("Failed to analyze JS content from %s: %v", url, err)
		return ScanResult{}, nil, err
	}
	res.URL = url
	return res, resInt, nil
}

func cleanAndValidateSubdomain(match string, targetDomain string) (string, bool) {
	match = strings.TrimSpace(strings.ToLower(match))

	if strings.HasPrefix(match, "//") {
		match = "https:" + match
	}

	if strings.HasPrefix(match, "http://") || strings.HasPrefix(match, "https://") {
		if parsedURL, err := url.Parse(match); err == nil {
			match = parsedURL.Host
			return match, true
		}
	}

	parts := strings.Split(strings.ToLower(targetDomain), ".")

	containsValidPart := false
	for i, part := range parts {
		if i == len(parts)-1 {
			continue
		}

		if part != "" && strings.Contains(match, part) {
			containsValidPart = true
			break
		}
	}

	if !containsValidPart {
		return "", false
	}

	if strings.ContainsAny(match, "()[]{}'\"`;>=<+*!,\\") {
		return "", false
	}

	if !strings.Contains(match, ".") {
		return "", false
	}

	return match, true
}
