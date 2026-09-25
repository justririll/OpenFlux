package yandex

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Yandex now fronts docs.yandex.* with a JavaScript anti-bot check: a client
// without a JS engine is redirected to /showcaptchafast, a "Verification" page
// that fingerprints the browser and, if it looks real, sets a pass cookie and
// bounces back to the document. A real browser clears it in about a second
// without any user input; plain HTTP never can, whatever User-Agent it sends.
//
// The pass is only a cookie, though. Verified from a residential IP: once a
// real browser engine has cleared the check, replaying its cookie set from Go's
// ordinary net/http gets the document page with client-config intact, even with
// the bare "Mozilla/5.0" User-Agent. No TLS fingerprint impersonation needed.
//
// So the transports keep doing their own HTTP and only borrow a browser to clear
// the check: when a fetch lands on a captcha page, the installed CaptchaSolver
// loads the document in a real engine (an Android WebView on the phone, headless
// Chrome on an exit node), hands back its cookies, and the fetch is retried with
// them. The pass is bound to the IP it was earned from, so each peer solves for
// itself.

// CaptchaSolver clears Yandex's anti-bot check in a real browser engine.
type CaptchaSolver interface {
	// Solve loads pageURL until the browser gets past the anti-bot check and
	// returns the cookies it holds afterwards, encoded as a JSON object mapping
	// a URL to the Cookie header the browser would send to it, e.g.
	// {"https://docs.yandex.ru/": "i=...; yandexuid=..."}. It blocks.
	Solve(pageURL string) (string, error)
}

var (
	solverMu sync.Mutex
	solver   CaptchaSolver

	// solveMu serialises solves: several transports (or a reconnect loop and a
	// fresh Start) can hit the check at once, and one browser pass clears it
	// for all of them.
	solveMu    sync.Mutex
	lastSolved time.Time

	// passJar holds the browser's pass cookies. Every Yandex document fetch
	// reads from it, so one solve serves all transports in the process.
	passJar, _ = cookiejar.New(nil)
)

// SetCaptchaSolver installs the browser used to clear Yandex's anti-bot check.
// nil removes it, after which a captcha is only surfaced as a [CAPTCHA] log line.
func SetCaptchaSolver(s CaptchaSolver) {
	solverMu.Lock()
	solver = s
	solverMu.Unlock()
}

func currentSolver() CaptchaSolver {
	solverMu.Lock()
	defer solverMu.Unlock()
	return solver
}

// isCaptchaURL reports whether a URL is one of Yandex's anti-bot pages.
func isCaptchaURL(u string) bool {
	return strings.Contains(u, "showcaptcha") || strings.Contains(u, "checkcaptcha")
}

// solveCaptcha runs the installed solver for pageURL and loads the cookies it
// returns into passJar. It reports whether a pass was obtained; false means no
// solver is installed or it failed, and the caller falls back to surfacing the
// captcha.
func solveCaptcha(pageURL string) bool {
	s := currentSolver()
	if s == nil {
		return false
	}

	requested := time.Now()
	solveMu.Lock()
	defer solveMu.Unlock()
	// Someone else solved while we waited for the lock: their cookies are
	// already in passJar. A pass from before this call is the one that was
	// just refused, so it does not count.
	if lastSolved.After(requested) {
		return true
	}

	log.Printf("[CAPTCHA] anti-bot check hit, clearing it in a browser...")
	start := time.Now()
	raw, err := s.Solve(pageURL)
	if err != nil {
		log.Printf("[CAPTCHA] browser solve failed: %v", err)
		return false
	}
	n, err := loadPassCookies(raw)
	if err != nil {
		log.Printf("[CAPTCHA] browser returned unusable cookies: %v", err)
		return false
	}
	if n == 0 {
		log.Printf("[CAPTCHA] browser returned no cookies")
		return false
	}
	lastSolved = time.Now()
	log.Printf("[CAPTCHA] cleared in %s (%d cookies)", time.Since(start).Round(100*time.Millisecond), n)
	return true
}

// loadPassCookies parses a solver result (URL -> Cookie header) into passJar
// and returns how many cookies it stored.
func loadPassCookies(raw string) (int, error) {
	var byURL map[string]string
	if err := json.Unmarshal([]byte(raw), &byURL); err != nil {
		return 0, err
	}
	n := 0
	for rawURL, header := range byURL {
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			return 0, fmt.Errorf("bad cookie URL %q", rawURL)
		}
		cookies := parseCookieHeader(header)
		passJar.SetCookies(u, cookies)
		n += len(cookies)
	}
	return n, nil
}

// parseCookieHeader splits a "a=1; b=2" Cookie header into cookies.
func parseCookieHeader(header string) []*http.Cookie {
	var out []*http.Cookie
	for _, part := range strings.Split(header, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || name == "" {
			continue
		}
		out = append(out, &http.Cookie{Name: name, Value: value, Path: "/"})
	}
	return out
}

// passAwareJar is a per-session cookie jar that also offers the shared pass
// cookies. What the server sets lands in the session's own jar and wins on a
// name clash; the pass cookies fill in the rest, on every redirect hop.
type passAwareJar struct {
	own *cookiejar.Jar
}

func newPassAwareJar() *passAwareJar {
	own, _ := cookiejar.New(nil)
	return &passAwareJar{own: own}
}

func (j *passAwareJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.own.SetCookies(u, cookies)
}

func (j *passAwareJar) Cookies(u *url.URL) []*http.Cookie {
	out := j.own.Cookies(u)
	seen := make(map[string]bool, len(out))
	for _, c := range out {
		seen[c.Name] = true
	}
	for _, c := range passJar.Cookies(u) {
		if !seen[c.Name] {
			out = append(out, c)
		}
	}
	return out
}
