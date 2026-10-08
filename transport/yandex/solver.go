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

	"universal-bypass-tool/utils"
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

	// After a failed solve the browser is not tried again until solveRetryAt,
	// backing off from solveBackoffBase to solveBackoffMax. Once Yandex serves
	// its real (interactive) captcha to an IP, relaunching Chrome every few
	// seconds cannot pass it and only deepens the IP's bot reputation: on one
	// exit node three instances did so ~180 times an hour for over a day.
	// Guarded by solveMu.
	solveFailures int
	solveRetryAt  time.Time
)

const (
	solveBackoffBase = 5 * time.Minute
	solveBackoffMax  = time.Hour
)

// captchaRetryIn is how long until the solver will try again after a failure;
// zero when it is ready. Fetchers hold at least this long before refetching,
// so a blocked IP is not pestered with document requests either.
func captchaRetryIn() time.Duration {
	solveMu.Lock()
	defer solveMu.Unlock()
	if d := time.Until(solveRetryAt); d > 0 {
		return d
	}
	return 0
}

// recordSolveFailure schedules the next browser attempt. Caller holds solveMu.
func recordSolveFailure() {
	solveFailures++
	d := solveBackoffBase << (solveFailures - 1)
	if d > solveBackoffMax || d <= 0 {
		d = solveBackoffMax
	}
	solveRetryAt = time.Now().Add(d)
	log.Printf("[CAPTCHA] next browser attempt in %s (failure %d in a row)", d, solveFailures)
}

var (

	// passJar holds the browser's pass cookies. Every Yandex document fetch
	// reads from it, so one solve serves all transports in the process.
	passJar, _ = cookiejar.New(nil)

	// passUA is the User-Agent of the browser that earned the pass, when the
	// solver reports it; see documentUserAgent.
	passUAMu sync.Mutex
	passUA   string
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
	// Still backing off from a failure: do not relaunch the browser.
	if time.Now().Before(solveRetryAt) {
		return false
	}

	log.Printf("[CAPTCHA] anti-bot check hit, clearing it in a browser...")
	start := time.Now()
	raw, err := s.Solve(pageURL)
	if err != nil {
		log.Printf("[CAPTCHA] browser solve failed: %v", err)
		recordSolveFailure()
		return false
	}
	n, err := loadPassCookies(raw)
	if err != nil {
		log.Printf("[CAPTCHA] browser returned unusable cookies: %v", err)
		recordSolveFailure()
		return false
	}
	if n == 0 {
		log.Printf("[CAPTCHA] browser returned no cookies")
		recordSolveFailure()
		return false
	}
	lastSolved = time.Now()
	solveFailures, solveRetryAt = 0, time.Time{}
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
	// Optional: the browser's User-Agent, sent along under a non-URL key. The
	// pass may be tied to the browser that earned it, so document fetches
	// then present the same User-Agent.
	if ua, ok := byURL[passUAKey]; ok {
		delete(byURL, passUAKey)
		passUAMu.Lock()
		passUA = ua
		passUAMu.Unlock()
		utils.Debugf("[CAPTCHA] browser User-Agent: %s", ua)
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
		names := make([]string, len(cookies))
		for i, c := range cookies {
			names[i] = c.Name
		}
		utils.Debugf("[CAPTCHA] pass cookies for %s: %s", u.Host, strings.Join(names, ","))
	}
	return n, nil
}

// passUAKey carries the browser's User-Agent in a solver result.
const passUAKey = "user-agent"

// documentUserAgent is the User-Agent for document fetches: the browser's,
// once a solver has reported it, else the bare token that the page is served
// to without a pass.
func documentUserAgent() string {
	passUAMu.Lock()
	defer passUAMu.Unlock()
	if passUA != "" {
		return passUA
	}
	return "Mozilla/5.0"
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
	var own, pass, shadowed []string
	for _, c := range out {
		own = append(own, c.Name)
	}
	for _, c := range passJar.Cookies(u) {
		if !seen[c.Name] {
			out = append(out, c)
			pass = append(pass, c.Name)
		} else {
			shadowed = append(shadowed, c.Name)
		}
	}
	utils.Debugf("[CAPTCHA] cookies to %s: server-set=%v pass=%v pass-overridden=%v", u.Host, own, pass, shadowed)
	return out
}
