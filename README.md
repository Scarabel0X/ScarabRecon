
# 🚀 ScarabRecon

A fast, concurrent, and high-performance reconnaissance tool built in Go. `ScarabRecon` helps security researchers and bug bounty hunters scrape historical URLs from multiple OSINT sources and deeply analyze JavaScript files to extract hidden subdomains, endpoints, and secrets with high accuracy.

---

## ✨ Features

- **Historical URL Scraping:** Fetch historical data from **CommonCrawl**, **WebArchive**, and **UrlScan**.
- **Smart JS Analysis:** Extracts subdomains, custom endpoints, cloud buckets, parameters, and sensitive secrets.
- **Advanced Noise Filtering:** Built-in intelligence to filter out common JavaScript variables and false-positive subdomains (e.g., `this.style.display`).
- **High Performance:** Multi-threaded execution for blazing-fast scanning.

---

## 🛠️ Installation

Make sure you have [Go](https://go.dev/) installed on your system (Version 1.21 or higher is recommended).

You can install `ScarabRecon` directly using the following command:

```bash
go install github.com/Scarabel0X/ScarabRecon@latest
```

---

## ⚙️ Command-Line Flags

| Flag | Description | Default |
| --- | --- | --- |
| `-d` | Specify the single target **domain** to perform reconnaissance on. | Optional |
| `-l` | Path to a **file containing a list of domains** to loop over and scan sequentially. | Optional |
| `-a` | **In-Scope Domains Filter**. Provide specific domains you want to keep. Any assets/files out of this scope will be ignored. If left empty, everything will be collected. | Empty (All) |
| `-t` | **Concurrency Level** (Number of threads) for faster execution. | `20` |
| `--timeout` | The maximum **timeout** duration that the tool will wait for HTTP requests. | `10s` |
| `--depth` | The maximum recursive **crawling depth**. Increase this number for deeper directory discovery. | `3` |
| `--active` | Toggles **Active Enumeration**. If set to `false`, it performs passive OSINT only (skips live crawling and headless browser actions). | `true` |
| `--js` | Toggles deep **JavaScript analysis**. If set to `false`, it skips downloading and analyzing JS files. | `true` |
| `-c` | Custom **Cookies** string to pass along with crawler and headless browser requests (useful for authenticated scanning). | Optional |
| `-H` | Custom **HTTP Headers** required to bypass protections or authorize active enumeration requests. | Optional |

---

## 🎯 Usage Examples

### 1. Basic Scan (Passive + Active Crawling)

```bash
ScarabRecon -d target.com -t 50

```

### 2. Multi-Domain Scan from a File (Passive Only)

```bash
ScarabRecon -l targets.txt --active=false

```

### 3. Authenticated Scanning with Custom Scope & Headers

```bash
ScarabRecon -d target.com -a target.com,api.target.com -c "session=12345" -H "Authorization: Bearer token"

```

---

## 📂 Output Directory Structure

When `ScarabRecon` finishes running, it generates a main directory named `ScarabRecon/`. Inside, the results are organized dynamically based on the tested target and discovered domains:

```text

ScarabRecon/                      # Main output directory
└── target.com                    # Folder named after your tested target
    ├── sub.target.com            # Subfolder for each discovered subdomain
    │   └── javascript.json       # JSON file containing URLs found specific to this subdomain
    │   └── pages.json            # JSON file containing Pages URLs found specific to this subdomain
    │   └── static.json           # JSON file containing Static like .jpg, .png, .gif.... URLs found specific to this subdomain  
    │   └── apis.json             # JSON file containing apis URLs found specific to this subdomain    
    │   └── parametrized URLs.json # JSON file containing Parameterized URLs found specific to this subdomain
    │
    └── Js_Results.json          # Standalone file containing deep JS analysis results (Secrets, Endpoints, etc.)

```

* Each discovered domain/subdomain gets its own dedicated folder containing a `javascript.json`,`pages.json`,`parametrizedURLs.json`,`apis.json`,`static.json` file.
* A standalone `Js_Results.json` is created per target to save extracted secrets, subdomains, parameters, and endpoints found in JS files.

