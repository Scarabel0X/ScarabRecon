package utils

import (
	"net/url"
	"strings"
)

func CategorizeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "pages"
	}

	path := strings.ToLower(parsed.Path)

	staticExts := []string{".css", ".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot"}
	for _, ext := range staticExts {
		if strings.HasSuffix(path, ext) {
			return "Static"
		}
	}

	sensitiveExts := []string{".pdf", ".zip", ".bak", ".tar.gz", ".env", ".sql", ".txt", ".xlsx", ".doc", ".log"}
	for _, ext := range sensitiveExts {
		if strings.HasSuffix(path, ext) {
			return "Sensitive"
		}
	}

	if strings.HasSuffix(path, ".js") {
		return "javascript"
	}

	if strings.Contains(path, "/api/") || strings.Contains(path, "graphql") || strings.HasSuffix(path, ".json") {
		return "apis"
	}

	// Parametrized URLs
	if len(parsed.Query()) > 0 {
		return "Param_URLs"
	}

	return "pages"
}

func SanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "http://", "")
	name = strings.ReplaceAll(name, "https://", "")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, ":", "_")
	return name
}
