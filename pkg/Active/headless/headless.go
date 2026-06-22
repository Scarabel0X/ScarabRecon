package headless

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/cyinnove/logify"
)

func isAllowedDomain(urlStr string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	for _, a := range allowed {
		if host == a {
			return true
		}
	}
	return false
}

func Headless(targets map[string]string, allowedHostnames []string, timeout int, cookie string, headers []string) (map[string]string, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	seen := make(map[string]string)
	var mu sync.Mutex

	for targetURL := range targets {
		logify.Infof(" Headless running on: %s\n", targetURL)

		ctx, cancel := context.WithTimeout(browserCtx, time.Duration(timeout)*time.Second)

		tabCtx, tabCancel := chromedp.NewContext(ctx)

		chromedp.ListenTarget(tabCtx, func(ev interface{}) {
			if ev, ok := ev.(*network.EventRequestWillBeSent); ok {
				reqURL := ev.Request.URL

				if isAllowedDomain(reqURL, allowedHostnames) {
					parsedReq, err := url.Parse(reqURL)
					if err == nil {
						reqHost := parsedReq.Hostname()

						mu.Lock()
						if _, exists := seen[reqURL]; !exists {
							seen[reqURL] = reqHost
							// logify.Infof(" [Headless +]", reqURL)
						}
						mu.Unlock()
					}
				}
			}
		})

		headerMap := make(map[string]interface{})
		if cookie != "" {
			headerMap["Cookie"] = cookie
		}
		for _, h := range headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		err := chromedp.Run(tabCtx,
			network.SetExtraHTTPHeaders(network.Headers(headerMap)),
			chromedp.Navigate(targetURL),
			chromedp.WaitReady("body"),
		)

		if err != nil && err != context.DeadlineExceeded {
			logify.Warningf(" [Headless -]  error on %s: %v\n", targetURL, err)
		}

		tabCancel()
		cancel()
	}

	return seen, nil
}
