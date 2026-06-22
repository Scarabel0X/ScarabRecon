package js

import (
	"regexp"
	"sync"
)

// SecretSignature represents a single secret pattern loaded from the YAML
// configuration file under data/regexes.yaml.
type SecretSignature struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// secretConfig mirrors the structure of data/regexes.yaml.
type secretConfig struct {
	Signatures []struct {
		Pattern SecretSignature `yaml:"pattern"`
	} `yaml:"signatures"`
}

// ScanResult represents the extracted data from a single JavaScript file.
type ScanResult struct {
	URL          string         `json:"url"`
	Subdomains   []string       `json:"subdomains"`
	CloudBuckets []string       `json:"cloud_buckets"`
	Endpoints    []string       `json:"endpoints"`
	Parameters   []string       `json:"parameters"`
	Secrets      []*SecretMatch `json:"secrets"`
	NpmPackages  []string       `json:"npm_packages"`
}

// SecretMatch represents a single discovered secret.
type SecretMatch struct {
	Name  string `json:"name"`
	Match string `json:"match"`
}

type compiledSecret struct {
	Name string
	Re   *regexp.Regexp
}

var (
	secretsOnce        sync.Once
	compiledSecrets    []*compiledSecret
	compiledSecretsErr error
)
