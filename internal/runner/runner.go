package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"scaraburl/pkg/Active/crawl"
	"scaraburl/pkg/Active/headless"
	js "scaraburl/pkg/Js"
	scraper "scaraburl/pkg/Scraper"
	"scaraburl/pkg/Scraper/commoncrawl"
	"scaraburl/pkg/Scraper/urlscan"
	"scaraburl/pkg/Scraper/webarchive"
	"scaraburl/pkg/utils"
	"strings"

	"github.com/cyinnove/logify"
)

func Runn(domains []string, allowedDomains []string, timeout int, threads int, depth int, active bool, js bool, cookie string, headers []string) (map[string]string, error) {

	domainFinalMap := make(map[string]string)

	rootDir := "ScarabRecon"
	if err := os.MkdirAll(rootDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create root directory: %v", err)
	}

	for _, currentDomain := range domains {
		fmt.Printf("\n==================================================\n")
		logify.Infof("Currently working on target domain: %s\n", currentDomain)
		fmt.Printf("==================================================\n")

		// 1.Passive Enumeration
		fmt.Println("\n[*] Starting Passive Enumeration...")

		sources := []scraper.Source{
			&webarchive.WebArchiveSource{},
			&urlscan.URLScanSource{},
			&commoncrawl.CommoncrawlSource{},
		}

		passiveMap := scraper.RunAllSources(currentDomain, sources, timeout)
		logify.Infof("Passive Phase found %d URLs\n", len(passiveMap))

		// 2. Active Enumeration
		activeMap := make(map[string]string)

		if active {
			logify.Infof("Starting Active Enumeration...")

			targetURL := formatAsURL(currentDomain)

			logify.Infof("Running Crawler on: %s\n", targetURL)
			crawlingMap, err := crawl.Crawling(targetURL, allowedDomains, depth, threads, timeout, cookie, headers)
			if err != nil {
				logify.Infof("Crawling error: %v\n", err)
				if crawlingMap == nil {
					crawlingMap = make(map[string]string)
				}
			}
			logify.Infof("Crawler found %d URLs\n", len(crawlingMap))

			// Basic path
			ensureBaseURLs(currentDomain, crawlingMap)

			logify.Infof("Running Headless Browser on Crawled URLs...")
			headlessMap, err := headless.Headless(crawlingMap, allowedDomains, timeout, cookie, headers)
			if err != nil {
				logify.Infof("Headless error: %v\n", err)
				if headlessMap == nil {
					headlessMap = make(map[string]string)
				}
			}
			logify.Infof("Headless found %d URLs\n", len(headlessMap))

			for u, d := range crawlingMap {
				activeMap[u] = d
			}
			for u, d := range headlessMap {
				activeMap[u] = d
			}
		} else {
			logify.Infof("Active Enumeration is Disabled (Skipping...)")
		}

		// 3. Merge Passive and Active results
		for u, d := range passiveMap {
			domainFinalMap[u] = d
			// overallUniqueURLs[u] = true
		}
		for u, d := range activeMap {
			domainFinalMap[u] = d
			// overallUniqueURLs[u] = true
		}

		if js {
			fmt.Println("\n[*] Starting Javascript Analysis...")
			jsRes, resInt, err := JsAnalysis(domainFinalMap, currentDomain, threads, cookie, headers)
			if err != nil {
				logify.Errorf("Error In Analysis Javascript ! ", err)
			}
			logify.Infof("Final JS Summary: %d Secrets, %d Endpoints, %d Subdomains , %d CloudBuckets , %d NpmPackages , %d Parameters found across all files.",
				resInt["Secrets"], resInt["Endpoints"], resInt["Subdomains"], resInt["CloudBuckets"], resInt["NpmPackages"], resInt["Parameters"])
			// 4. Saving results in folders
			logify.Infof("Categorizing and saving results for %s...\n", currentDomain)
			errr := saveResults(rootDir, currentDomain, domainFinalMap, jsRes)
			if errr != nil {
				logify.Errorf("Error in save Results : ", errr)
			}

			logify.Infof("Finished processing domain: %s\n", currentDomain)
		} else {
			// 4. Saving results in folders
			logify.Infof("Categorizing and saving results for %s...\n", currentDomain)
			errr := saveResults(rootDir, currentDomain, domainFinalMap, nil)
			if errr != nil {
				logify.Errorf("Error in save Results : ", errr)
			}
			logify.Infof("Finished processing domain: %s\n", currentDomain)
		}

	}

	logify.Infof("Enumeration completed successfully!")
	return domainFinalMap, nil
}

// =====================================================================
// JS Analysis
// =====================================================================

func JsAnalysis(urls map[string]string, target string, threads int, cookie string, headers []string) ([]js.ScanResult, map[string]int, error) {
	var jsUrl []string
	for u, _ := range urls {
		if utils.CategorizeURL(u) == "javascript" {
			jsUrl = append(jsUrl, u)
		}
	}
	if len(jsUrl) == 0 {
		return nil, nil, fmt.Errorf("Not found Js URLs In this target %s", target)
	}

	logify.Infof("Starting JS analysis on %d URLs with %d threads...", len(urls), threads)

	results, resInt, err := js.Analysis(jsUrl, threads, cookie, headers, target)
	if err != nil {
		logify.Warningf("Scan completed with some errors: %v", err)
	}
	return results, resInt, nil
}

// =====================================================================
// Helper Functions
// =====================================================================

func formatAsURL(input string) string {
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		return "https://" + input
	}
	return input
}

func ensureBaseURLs(domain string, targetMap map[string]string) {
	cleanDomain := strings.TrimSpace(domain)
	cleanDomain = strings.TrimPrefix(cleanDomain, "http://")
	cleanDomain = strings.TrimPrefix(cleanDomain, "https://")

	httpURL := "http://" + cleanDomain
	httpsURL := "https://" + cleanDomain

	if _, exists := targetMap[httpURL]; !exists {
		targetMap[httpURL] = cleanDomain
	}
	if _, exists := targetMap[httpsURL]; !exists {
		targetMap[httpsURL] = cleanDomain
	}
}

func saveResults(rootDir string, inputDomain string, finalMap map[string]string, results []js.ScanResult) error {
	// Base Folder(e.g., ScarabRecon/target.com)
	inputDomainDir := filepath.Join(rootDir, utils.SanitizeFilename(inputDomain))

	if err := os.MkdirAll(inputDomainDir, 0755); err != nil {
		return fmt.Errorf("failed to create input domain directory: %v", err)
	}

	if results != nil {
		data, err := js.EncodeResultsJSON(results)
		if err != nil {
			return fmt.Errorf("failed to encode JS results: %v", err)
		}

		jsOutputPath := filepath.Join(inputDomainDir, "Js_Results.json")
		if err := os.WriteFile(jsOutputPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write JS output file: %v", err)
		}

		logify.Infof("JS Analysis results successfully saved to %s", jsOutputPath)
	}

	// Save rest of files
	groupedData := make(map[string]map[string][]string)

	for u, d := range finalMap {
		category := utils.CategorizeURL(u)
		if groupedData[d] == nil {
			groupedData[d] = make(map[string][]string)
		}
		groupedData[d][category] = append(groupedData[d][category], u)
	}

	for discoveredDomain, categories := range groupedData {
		discoveredDomainDir := filepath.Join(inputDomainDir, utils.SanitizeFilename(discoveredDomain))
		os.MkdirAll(discoveredDomainDir, 0755)

		for categoryName, urls := range categories {
			filePath := filepath.Join(discoveredDomainDir, categoryName+".json")

			jsonData, err := json.MarshalIndent(urls, "", "  ")
			if err != nil {
				logify.Warningf("Failed to marshal JSON for %s: %v\n", categoryName, err)
				continue
			}

			err = os.WriteFile(filePath, jsonData, 0644)
			if err != nil {
				logify.Warningf("Failed to write JSON file %s: %v\n", filePath, err)
				continue
			}
		}
	}

	return nil
}
