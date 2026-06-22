package js

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	//

	"github.com/cyinnove/logify"
	"github.com/ditashi/jsbeautifier-go/jsbeautifier"
	"gopkg.in/yaml.v3"
)

//go:embed data/regexes.yaml
var jsData embed.FS

// setToSlice converts a string-set map into a slice for output.
func setToSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	return out
}

// getClient creates an HTTP client with a reasonable timeout and relaxed TLS
// verification, using a random User-Agent header for each request.
func getClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

// EncodeResultsJSON encodes scan results as pretty-printed JSON.
func EncodeResultsJSON(results []ScanResult) ([]byte, error) {
	return json.MarshalIndent(results, "", "  ")
}

// For files larger than 2MB, beautification is skipped to avoid performance issues.
func BeautifyJS(source string) string {
	const maxBeautifySize = 2 * 1024 * 1024 // 2MB

	if len(source) > maxBeautifySize {

		return source
	}

	// Run beautification with timeout
	prettyChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		opts := jsbeautifier.DefaultOptions()
		pretty, err := jsbeautifier.Beautify(&source, opts)
		if err != nil {
			errChan <- err
			return
		}
		prettyChan <- pretty
	}()

	// 30 second timeout for beautification
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	select {
	case <-timeout.C:
		logify.Warningf("Beautification timeout after 30 seconds, using original source")
		return source
	case err := <-errChan:
		logify.Warningf("JavaScript beautification failed: %v, using original source", err)
		return source
	case pretty := <-prettyChan:

		return pretty
	}
}

func isUrl(url string) bool {
	return strings.Contains(url, "http")
}

// loadSecretPatterns reads and compiles secret patterns from data/regexes.yaml.
func loadSecretPatterns() ([]*compiledSecret, error) {
	secretsOnce.Do(func() {
		data, err := jsData.ReadFile("data/regexes.yaml")
		if err != nil {
			compiledSecretsErr = fmt.Errorf("read embedded secrets config: %w", err)
			logify.Errorf("Failed to read secrets config: %v", err)
			return
		}

		var cfg secretConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			compiledSecretsErr = fmt.Errorf("unmarshal secrets config: %w", err)
			logify.Errorf("Failed to parse secrets config YAML: %v", compiledSecretsErr)
			return
		}

		loadedCount := 0
		skippedCount := 0
		for _, s := range cfg.Signatures {
			p := s.Pattern
			if p.Name == "" || p.Value == "" {
				skippedCount++
				continue
			}
			re, err := regexp.Compile(p.Value)
			if err != nil {
				logify.Warningf("Failed to compile secret pattern '%s': %v", p.Name, err)
				skippedCount++
				continue
			}
			compiledSecrets = append(compiledSecrets, &compiledSecret{
				Name: p.Name,
				Re:   re,
			})
			loadedCount++
		}

		if len(compiledSecrets) == 0 && compiledSecretsErr == nil {
			compiledSecretsErr = errors.New("no valid secret patterns loaded")
			logify.Warningf("No valid secret patterns were loaded")
		}
	})
	return compiledSecrets, compiledSecretsErr
}
