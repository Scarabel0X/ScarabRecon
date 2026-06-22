package js

import "regexp"

var (
	subdomainRegex = regexp.MustCompile(`(?mi)(?:https?:\/\/)?(?:www\.)?(?<subdomain>[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+){0,4})\.(?<domain>[A-Za-z0-9-]+)\.(?<tld>[A-Za-z]{2,})(?::\d+)?(?:[\/?#][^\s'"<>)]*)?`)

	cloudBucketRegex = regexp.MustCompile(`(?im)([\w]+\.){1,10}(s3\.amazonaws\.com|rds\.amazonaws\.com|cache\.amazonaws\.com|blob\.core\.windows\.net|onedrive\.live\.com|1drv\.com|storage\.googleapis\.com|storage\.cloud\.google\.com|storage-download\.googleapis\.com|content-storage-upload\.googleapis\.com|content-storage-download\.googleapis\.com|cloudfront\.net|digitaloceanspaces\.com|oraclecloud\.com|aliyuncs\.com|firebaseio\.com|rackcdn\.com|objects\.cdn\.dream\.io|objects-us-west-1\.dream\.io)|(?im)(s3\.amazonaws\.com|[\w-]+\.amazonaws\.com)/([a-zA-Z0-9._-]+)|(?im)[\w-]+\.execute-api\.[\w-]+\.amazonaws\.com`)
	endpointRegex    = regexp.MustCompile(`(?:"|')((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\..[a-zA-Z]{2,}[^"']{0,}|(?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,}|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/.]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|)|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|)|[a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|))(?:"|')`)

	parameterRegex = regexp.MustCompile(`(?m)([?&])([a-zA-Z_][a-zA-Z0-9_]*)=`)

	nodeModulesRegex = regexp.MustCompile(`/node_modules/(@?[a-z-_.0-9]+)/`)

	// Slightly simplified compared to the documentation – matches JSON keys
	// like "react": "^18.0.0" or 'lodash': "4.17.21".
	packageNameRegex = regexp.MustCompile("[\"']([^\"']+)[\"']\\s*:")
)
