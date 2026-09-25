// Package chromesolver clears Yandex's anti-bot check with a headless Chrome,
// for exit nodes and desktop clients. It lives outside package yandex so the
// mobile build, which uses the platform WebView instead, does not link chromedp.
package chromesolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// solveTimeout bounds one browser pass: start Chrome, load the document, get
// through the check. A real browser clears it in a second or two.
const solveTimeout = 45 * time.Second

// Solver implements yandex.CaptchaSolver with a headless Chrome/Chromium.
type Solver struct {
	execPath string
}

// New returns a Solver using the Chrome binary at execPath.
func New(execPath string) *Solver {
	return &Solver{execPath: execPath}
}

// Find looks for a Chrome or Chromium binary on PATH.
func Find() (string, error) {
	for _, name := range []string{
		"chrome-headless-shell", "google-chrome", "google-chrome-stable",
		"chromium", "chromium-browser", "chrome",
	} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no chrome/chromium binary on PATH")
}

// Solve loads pageURL in a fresh headless Chrome until the document page is up,
// then returns the cookies for every host it passed through, as a JSON object of
// URL -> Cookie header.
func (s *Solver) Solve(pageURL string) (string, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(s.execPath),
		// Exit nodes run as root, where Chrome refuses to start sandboxed.
		chromedp.NoSandbox,
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	actx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	ctx, cancelCtx := chromedp.NewContext(actx)
	defer cancelCtx()
	ctx, cancel := context.WithTimeout(ctx, solveTimeout)
	defer cancel()

	// Start the navigation without waiting for the load event: behind the
	// check is the full editor, which can take longer than the whole budget
	// to finish loading, and only its early inline config matters here.
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
		_, _, errText, _, err := page.Navigate(pageURL).Do(c)
		if err == nil && errText != "" {
			err = errors.New(errText)
		}
		return err
	})); err != nil {
		return "", fmt.Errorf("load %s: %w", pageURL, err)
	}

	// The check runs, sets its cookie and navigates back to the document;
	// done once the real page (with its inline client-config) is showing.
	var loc string
	for {
		var ready bool
		err := chromedp.Run(ctx,
			chromedp.Location(&loc),
			chromedp.Evaluate(`!!document.getElementById("client-config")`, &ready),
		)
		if err == nil && ready && !strings.Contains(loc, "captcha") {
			break
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("still on %q after %s", loc, solveTimeout)
		case <-time.After(300 * time.Millisecond):
		}
	}

	out := map[string]string{}
	for _, u := range []string{pageURL, loc} {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		origin := parsed.Scheme + "://" + parsed.Host + "/"
		if _, done := out[origin]; done {
			continue
		}
		var cookies []*network.Cookie
		if err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
			var err error
			cookies, err = network.GetCookies().WithURLs([]string{origin}).Do(c)
			return err
		})); err != nil {
			return "", fmt.Errorf("read cookies: %w", err)
		}
		var parts []string
		for _, c := range cookies {
			parts = append(parts, c.Name+"="+c.Value)
		}
		out[origin] = strings.Join(parts, "; ")
	}
	b, err := json.Marshal(out)
	return string(b), err
}
