package yandex

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
)

type VolgaConfig struct {
	MaxIdleConnsPerHost int
	MaxIdleConns        int
	IdleConnTimeout     time.Duration
	RelayTimeout        time.Duration

	WorkerCount int
	QueueSize   int

	BatchSize     int
	BatchTimeout  time.Duration
	BatchMaxBytes int

	MaxPayloadBytes int
	MinPayloadBytes int

	ReconnectMinDelay   time.Duration
	ReconnectMaxDelay   time.Duration
	ReconnectMultiplier float64

	WSHandshakeTimeout time.Duration
	WSReadTimeout      time.Duration
	KeepAliveInterval  time.Duration
}

// relayWorkers sizes the relay pool.
//
// This was a flat 2000, which is far more than a tunnel can use: batches
// carry up to 20 packets, so even a busy link keeps only tens of requests in
// flight. The cost showed up when several exit nodes shared one small VPS -
// 2000 goroutines and up to 2000 idle TLS connections per instance, all
// contending for the same core, which is enough to starve every link but one.
//
// Set OPENFLUX_RELAY_WORKERS to override.
func relayWorkers() int {
	if env := os.Getenv("OPENFLUX_RELAY_WORKERS"); env != "" {
		if n, err := strconv.Atoi(env); err == nil && n > 0 {
			return n
		}
		utils.Debugf("[VOLGA] ignoring invalid OPENFLUX_RELAY_WORKERS=%q", env)
	}
	n := 128 * runtime.NumCPU()
	if n < 128 {
		n = 128
	}
	if n > 1024 {
		n = 1024
	}
	return n
}

func DefaultVolgaConfig() VolgaConfig {
	workers := relayWorkers()
	return VolgaConfig{
		// One idle connection per worker is the most that can ever be
		// needed, and nothing is gained by keeping more than that alive.
		MaxIdleConnsPerHost: workers,
		MaxIdleConns:        workers * 2,
		IdleConnTimeout:     90 * time.Second,
		RelayTimeout:        30 * time.Second,

		WorkerCount: workers,
		// The queue only has to absorb a burst while the workers drain it.
		// A million entries reserved tens of megabytes per instance up front
		// for a backlog that would mean the link was already dead.
		QueueSize: 65536,

		BatchSize:     20,
		BatchTimeout:  2 * time.Millisecond,
		BatchMaxBytes: 4 * 1024 * 1024,

		MaxPayloadBytes: 5_000_000,
		MinPayloadBytes: 200,

		ReconnectMinDelay:   500 * time.Millisecond,
		ReconnectMaxDelay:   30 * time.Second,
		ReconnectMultiplier: 1.5,

		WSHandshakeTimeout: 10 * time.Second,
		WSReadTimeout:      60 * time.Second,
		KeepAliveInterval:  10 * time.Second,
	}
}

// A full browser User-Agent from a datacenter IP trips Yandex's anti-bot and
// gets a showcaptcha page instead of the document; the bare token is served the
// real page with client-config intact. Verified with curl from the exit node:
// Firefox/153 and the real Firefox/133 both -> captcha; "Mozilla/5.0" -> OK.
// So keep this deliberately minimal -- do NOT "upgrade" it to a realistic UA.
const volgaUserAgent = "Mozilla/5.0"

var reClientConfig = regexp.MustCompile(`<script[^>]*id="client-config"[^>]*>(.*?)</script>`)

var (
	b64BufPool = sync.Pool{
		New: func() interface{} { return make([]byte, 0, 16*1024*1024) },
	}
	jsonBufPool = sync.Pool{
		New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 128*1024)) },
	}
	blobBufPool = sync.Pool{
		New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 64*1024)) },
	}
)

func base64Encode(data []byte) string {
	buf := b64BufPool.Get().([]byte)
	need := base64.StdEncoding.EncodedLen(len(data))
	if cap(buf) < need {
		buf = make([]byte, need)
	} else {
		buf = buf[:need]
	}
	base64.StdEncoding.Encode(buf, data)
	out := string(buf)
	b64BufPool.Put(buf[:0])
	return out
}

type VolgaStats struct {
	PacketsSent    atomic.Uint64
	PacketsRecv    atomic.Uint64
	BytesSent      atomic.Uint64
	BytesReceived  atomic.Uint64
	HTTPReqsSent   atomic.Uint64
	HTTPReqsFailed atomic.Uint64
	WSReconnects   atomic.Uint64
	QueueDrops     atomic.Uint64
	WorkerBusy     atomic.Int64
	BatchesSent    atomic.Uint64
	PacketsBatched atomic.Uint64
}

type volgaAuth struct {
	Session     *http.Client
	AccessToken string
	Token       string
	RequestPath string
	ResourceURL string
	DocID       string
	UserID      int
	UserIDStr   string
	Sign        string
	TS          string
	SessionID   string
	Cookies     []*http.Cookie

	// VolgaOrigin and PushURL are read from the authorization response
	// rather than hardcoded. A document opened on disk.yandex.com
	// authorizes against volga.yandex.com, and posting its relay traffic to
	// volga.yandex.ru is a different origin: the session does not apply
	// there and every relay POST comes back 401.
	VolgaOrigin string
	PushURL     string
}

// defaultPushURL is used when the authorization response omits the xiva URL.
const defaultPushURL = "https://push.yandex.ru/v2"

// authorize fetches the document page and trades its client-config for a
// Volga session. If Yandex's anti-bot check gets in the way, it is cleared in
// a browser when a CaptchaSolver is installed, else surfaced as [CAPTCHA].
func authorize(docURL string) (*volgaAuth, error) {
	a, captchaURL, err := authorizeOnce(docURL)
	if captchaURL != "" && solveCaptcha(docURL) {
		a, captchaURL, err = authorizeOnce(docURL)
	}
	if captchaURL != "" {
		log.Printf("[CAPTCHA] %s", captchaURL)
		return nil, fmt.Errorf("captcha required (open the surfaced link and solve it)")
	}
	return a, err
}

func authorizeOnce(docURL string) (*volgaAuth, string, error) {
	utils.Debugf("[VOLGA] authorize(%s)", docURL)

	// Offers the browser's pass cookies (if any) on every hop.
	jar := newPassAwareJar()
	session := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var finalBody []byte
	var finalURL string
	currentURL := docURL

	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", currentURL, nil)
		req.Header.Set("User-Agent", volgaUserAgent)
		// No browser-style Accept/Accept-Language here: with them Yandex's
		// anti-bot rejects even a valid pass cookie and re-serves the captcha
		// (verified); fetchDocInfo sends neither and gets through.
		if i > 0 {
			req.Header.Set("Referer", docURL)
		}

		resp, err := session.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("GET %s: %w", currentURL, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		utils.Debugf("[VOLGA] GET %s -> %d (%d bytes)", currentURL, resp.StatusCode, len(body))

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				return nil, "", fmt.Errorf("redirect without Location from %s", currentURL)
			}
			if strings.HasPrefix(loc, "/") {
				u, _ := url.Parse(currentURL)
				loc = u.Scheme + "://" + u.Host + loc
			}
			// The anti-bot check: let the caller clear it or surface it.
			if isCaptchaURL(loc) {
				return nil, loc, nil
			}
			currentURL = loc
			continue
		}

		finalBody = body
		finalURL = currentURL
		break
	}

	if finalBody == nil {
		return nil, "", fmt.Errorf("too many redirects from %s", docURL)
	}

	utils.Debugf("[VOLGA] final URL: %s", finalURL)

	m := reClientConfig.FindSubmatch(finalBody)
	if len(m) < 2 {
		preview := string(finalBody)
		if len(preview) > 3000 {
			preview = preview[:3000]
		}
		utils.Debugf("[VOLGA] HTML preview: %s", preview)
		return nil, "", fmt.Errorf("client-config not found in %s", finalURL)
	}

	var cfg map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(m[1]))
	dec.UseNumber()
	if err := dec.Decode(&cfg); err != nil {
		return nil, "", fmt.Errorf("parse client-config: %w", err)
	}

	utils.Debugf("[VOLGA] client-config keys: %v", mapKeys(cfg))

	office, _ := cfg["officeActionData"].(map[string]interface{})
	editor, _ := cfg["editorParams"].(map[string]interface{})

	if office == nil {
		return nil, "", fmt.Errorf("officeActionData missing (keys: %v)", mapKeys(cfg))
	}

	utils.Debugf("[VOLGA] office keys: %v", mapKeys(office))

	actionURL := getStr(office, "action_url")
	accessToken := getStr(office, "access_token")
	ttl := office["access_token_ttl"]

	utils.Debugf("[VOLGA] action_url: %s", actionURL)
	utils.Debugf("[VOLGA] access_token: %d bytes", len(accessToken))
	utils.Debugf("[VOLGA] access_token_ttl: %v (%T)", ttl, ttl)

	a := &volgaAuth{
		Session:     session,
		AccessToken: accessToken,
		ResourceURL: getStr(office, "resource_url"),
		DocID:       getStr(editor, "idDoc"),
	}

	if actionURL == "" {
		return nil, "", fmt.Errorf("action_url missing (keys: %v)", mapKeys(office))
	}
	if a.AccessToken == "" {
		return nil, "", fmt.Errorf("access_token missing")
	}

	ttlStr := formatTTL(ttl)
	utils.Debugf("[VOLGA] ttl formatted: %q", ttlStr)

	form := url.Values{}
	form.Set("access_token", a.AccessToken)
	form.Set("access_token_ttl", ttlStr)
	body := form.Encode()

	utils.Debugf("[VOLGA] POST %s (body %d bytes)", actionURL, len(body))

	req2, _ := http.NewRequest("POST", actionURL, strings.NewReader(body))
	req2.Header.Set("User-Agent", volgaUserAgent)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Origin", originOf(finalURL, "https://disk.yandex.ru"))
	req2.Header.Set("Referer", finalURL)
	req2.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req2.Header.Set("Accept-Language", "ru-RU,ru;q=0.9")
	req2.Header.Set("Upgrade-Insecure-Requests", "1")
	req2.Header.Set("Sec-Fetch-Dest", "iframe")
	req2.Header.Set("Sec-Fetch-Mode", "navigate")
	req2.Header.Set("Sec-Fetch-Site", "cross-site")

	resp2, err := session.Do(req2)
	if err != nil {
		return nil, "", fmt.Errorf("POST auth/initial: %w", err)
	}
	resp2.Body.Close()

	utils.Debugf("[VOLGA] auth/initial -> %d", resp2.StatusCode)

	if resp2.StatusCode != 302 {
		return nil, "", fmt.Errorf("auth/initial status %d (expected 302)", resp2.StatusCode)
	}

	location := resp2.Header.Get("Location")
	if location == "" {
		return nil, "", fmt.Errorf("auth/initial no Location")
	}

	utils.Debugf("[VOLGA] Location: %s", location[:minInt(len(location), 300)])

	if strings.Contains(location, "/document/error/") {
		return nil, "", fmt.Errorf("auth/initial returned /document/error/ — check access_token_ttl and Referer")
	}

	locParsed, err := url.Parse(location)
	if err != nil {
		return nil, "", fmt.Errorf("parse Location: %w", err)
	}
	qs := locParsed.Query()

	a.Token = qs.Get("token")
	a.RequestPath = qs.Get("request-path")

	jsonStr := qs.Get("json")
	if jsonStr == "" {
		return nil, "", fmt.Errorf("no json in Location (token=%v rp=%v)",
			a.Token != "", a.RequestPath != "")
	}

	var jsonData map[string]interface{}
	dec2 := json.NewDecoder(strings.NewReader(jsonStr))
	dec2.UseNumber()
	if err := dec2.Decode(&jsonData); err != nil {
		return nil, "", fmt.Errorf("parse Location json: %w", err)
	}

	a.SessionID = getStr(jsonData, "sessionId")
	a.UserID = int(getFloat(jsonData, "userId"))

	// The redirect lands on the volga host this document belongs to, which
	// is the only host its session is valid for.
	a.VolgaOrigin = locParsed.Scheme + "://" + locParsed.Host

	a.PushURL = defaultPushURL
	if xiva, ok := jsonData["xiva"].(map[string]interface{}); ok {
		a.Sign = getStr(xiva, "sign")
		a.TS = getStr(xiva, "ts")
		a.UserIDStr = getStr(xiva, "user")
		if pushURL := getStr(xiva, "url"); pushURL != "" {
			a.PushURL = pushURL
		}
	}

	req3, _ := http.NewRequest("GET", location, nil)
	req3.Header.Set("User-Agent", volgaUserAgent)
	req3.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req3.Header.Set("Referer", actionURL)
	resp3, err := session.Do(req3)
	if err != nil {
		return nil, "", fmt.Errorf("GET Location: %w", err)
	}
	io.Copy(io.Discard, resp3.Body)
	resp3.Body.Close()

	a.Cookies = jar.Cookies(locParsed)

	if a.Token == "" || a.RequestPath == "" || a.UserIDStr == "" || a.Sign == "" {
		return nil, "", fmt.Errorf("incomplete auth: token=%v rp=%v user=%v sign=%v",
			a.Token != "", a.RequestPath != "", a.UserIDStr != "", a.Sign != "")
	}

	utils.Debugf("[VOLGA] auth OK: user=%d(%s) rp=%s sign=%s ts=%s origin=%s push=%s",
		a.UserID, a.UserIDStr, a.RequestPath, a.Sign, a.TS, a.VolgaOrigin, a.PushURL)
	return a, "", nil
}

// volgaOrigin is the scheme://host the session was issued for, falling back
// to the .ru host for sessions established before it was recorded.
func (a *volgaAuth) volgaOrigin() string {
	if a.VolgaOrigin != "" {
		return a.VolgaOrigin
	}
	return "https://volga.yandex.ru"
}

// pushWebsocketBase turns the advertised xiva URL into its WebSocket endpoint.
func (a *volgaAuth) pushWebsocketBase() string {
	base := a.PushURL
	if base == "" {
		base = defaultPushURL
	}
	if rest, ok := strings.CutPrefix(base, "https://"); ok {
		base = "wss://" + rest
	} else if rest, ok := strings.CutPrefix(base, "http://"); ok {
		base = "ws://" + rest
	}
	return strings.TrimSuffix(base, "/") + "/subscribe/websocket"
}

// originOf reduces a URL to scheme://host, or returns fallback if it cannot.
func originOf(rawURL, fallback string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fallback
	}
	return parsed.Scheme + "://" + parsed.Host
}

func getStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(v, 10)
	case int:
		return strconv.Itoa(v)
	}
	return ""
}

func getFloat(m map[string]interface{}, key string) float64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return v
	case json.Number:
		f, _ := v.Float64()
		return f
	case int64:
		return float64(v)
	case int:
		return float64(v)
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	}
	return 0
}

func formatTTL(v interface{}) string {
	switch x := v.(type) {
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	case string:
		return x
	case nil:
		return "0"
	default:
		return fmt.Sprintf("%v", x)
	}
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type relayClient struct {
	auth   *volgaAuth
	config VolgaConfig
	stats  *VolgaStats

	httpClient *http.Client
	workers    int
	queue      chan []byte
	batchQueue chan []byte
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc

	bundleID atomic.Uint64
	seq      atomic.Uint64
	localID  atomic.Uint64

	mu       sync.Mutex
	frontier string
}

func newRelayClient(auth *volgaAuth, cfg VolgaConfig, stats *VolgaStats) *relayClient {
	tr := &http.Transport{
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:     cfg.IdleConnTimeout,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &relayClient{
		auth:   auth,
		config: cfg,
		stats:  stats,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   cfg.RelayTimeout,
			Jar:       auth.Session.Jar,
		},
		workers:    cfg.WorkerCount,
		queue:      make(chan []byte, cfg.QueueSize),
		batchQueue: make(chan []byte, cfg.QueueSize),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (r *relayClient) Start() {
	for i := 0; i < r.workers; i++ {
		r.wg.Add(1)
		go r.worker(i)
	}
	utils.Debugf("[VOLGA] relay pool started: %d workers, batch=%d timeout=%v",
		r.workers, r.config.BatchSize, r.config.BatchTimeout)
}

func (r *relayClient) Stop() {
	// Do NOT close queue/batchQueue here. Send() still fires during teardown --
	// from the tunnel's send path and from the transport keep-alive, which Stop
	// signals but does not join -- and a send on a closed channel panics. That
	// was the intermittent crash right after Disconnect. Cancelling the context
	// makes every worker flush and return (they select on ctx.Done); wg.Wait()
	// joins them, after which the channels are unreferenced and collected.
	r.cancel()
	r.wg.Wait()
}

func (r *relayClient) Send(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if len(data) > r.config.MaxPayloadBytes {
		return fmt.Errorf("packet too large: %d > %d", len(data), r.config.MaxPayloadBytes)
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	// Bail out once stopped so a late keep-alive or tunnel send does no work
	// (the channels are intentionally left open; see Stop).
	select {
	case <-r.ctx.Done():
		return fmt.Errorf("relay stopped")
	default:
	}

	select {
	case r.batchQueue <- cp:
		return nil
	default:
		r.stats.QueueDrops.Add(1)
		return fmt.Errorf("queue full")
	}
}

func (r *relayClient) worker(id int) {
	defer r.wg.Done()

	batch := make([][]byte, 0, r.config.BatchSize)
	totalBytes := 0
	timer := time.NewTimer(r.config.BatchTimeout)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		r.stats.WorkerBusy.Add(1)
		err := r.sendBatch(batch)
		if err != nil {
			r.stats.HTTPReqsFailed.Add(1)
			utils.Debugf("[VOLGA] batch send failed: %v", err)
		} else {
			r.stats.HTTPReqsSent.Add(1)
			r.stats.BatchesSent.Add(1)
		}
		r.stats.WorkerBusy.Add(-1)
		batch = batch[:0]
		totalBytes = 0
	}

	for {
		select {
		case <-r.ctx.Done():
			flush()
			return

		case pkt, ok := <-r.batchQueue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, pkt)
			totalBytes += len(pkt)

			if len(batch) >= r.config.BatchSize || totalBytes >= r.config.BatchMaxBytes {
				flush()
			} else if len(batch) == 1 {
				timer.Reset(r.config.BatchTimeout)
			}

		case <-timer.C:
			flush()
		}
	}
}

func (r *relayClient) sendBatch(batch [][]byte) error {
	blob := blobBufPool.Get().(*bytes.Buffer)
	blob.Reset()

	var lenBuf [2]byte
	var totalBytes int
	for _, p := range batch {
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(p)))
		blob.Write(lenBuf[:])
		blob.Write(p)
		totalBytes += len(p)
	}

	encoded := base64Encode(blob.Bytes())
	blobBufPool.Put(blob)

	frontier := r.getFrontier()
	opID := fmt.Sprintf("1-%d.%d", r.auth.UserID, r.seq.Add(1))
	relayOpID := fmt.Sprintf("1-%d.%d", r.auth.UserID, r.seq.Add(1))

	bundle := []interface{}{
		map[string]interface{}{
			"id":         opID,
			"frontier":   frontier,
			"undoable":   true,
			"actionName": "textInsert",
			"ops":        []interface{}{[]interface{}{"it", "vyd:t/00000000000008", 0, "A"}},
			"sideEffect": false,
			"localId":    r.localID.Add(1),
		},
		map[string]interface{}{
			"id":         relayOpID,
			"frontier":   []interface{}{opID},
			"undoable":   false,
			"actionName": "setCaret",
			"ops": []interface{}{
				[]interface{}{"us", r.auth.UserID, []interface{}{
					[]interface{}{
						[]interface{}{"vyd:t/00000000000008", 0, -1},
						[]interface{}{"vyd:t/00000000000008", 0, -1},
					},
				}},
			},
			"sideEffect": true,
			"localId":    r.localID.Add(1),
		},
		encoded,
	}

	payload := map[string]interface{}{
		"message": map[string]interface{}{
			"bundleId": r.bundleID.Add(1),
			"bundle":   bundle,
		},
		"targetUserId": nil,
	}

	buf := jsonBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		jsonBufPool.Put(buf)
		return err
	}
	bodyCopy := make([]byte, buf.Len())
	copy(bodyCopy, buf.Bytes())
	jsonBufPool.Put(buf)

	urlStr := fmt.Sprintf("%s/session/main/%s/relay", r.auth.volgaOrigin(), r.auth.RequestPath)
	req, err := http.NewRequestWithContext(r.ctx, "POST", urlStr, bytes.NewReader(bodyCopy))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", volgaUserAgent)
	req.Header.Set("Authorization", "Bearer "+r.auth.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", r.auth.volgaOrigin())
	req.Header.Set("Referer", r.auth.volgaOrigin()+"/document/?request-path="+r.auth.RequestPath)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.ContentLength = int64(len(bodyCopy))

	var cookieParts []string
	for _, c := range r.auth.Cookies {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	if len(cookieParts) > 0 {
		req.Header.Set("Cookie", strings.Join(cookieParts, "; "))
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	r.stats.PacketsSent.Add(uint64(len(batch)))
	r.stats.PacketsBatched.Add(uint64(len(batch)))
	r.stats.BytesSent.Add(uint64(totalBytes))
	return nil
}

func (r *relayClient) SetFrontier(opID string) {
	r.mu.Lock()
	r.frontier = opID
	r.mu.Unlock()
}

func (r *relayClient) getFrontier() []interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frontier == "" {
		return []interface{}{}
	}
	return []interface{}{r.frontier}
}

type wsListener struct {
	auth   *volgaAuth
	config VolgaConfig
	stats  *VolgaStats
	relay  *relayClient
	onData func([]byte)

	ctx    context.Context
	cancel context.CancelFunc
}

func newWSListener(auth *volgaAuth, cfg VolgaConfig, stats *VolgaStats,
	relay *relayClient, onData func([]byte)) *wsListener {

	ctx, cancel := context.WithCancel(context.Background())
	return &wsListener{
		auth:   auth,
		config: cfg,
		stats:  stats,
		relay:  relay,
		onData: onData,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (w *wsListener) Start() {
	go w.run()
}

func (w *wsListener) Stop() {
	w.cancel()
}

func (w *wsListener) run() {
	delay := w.config.ReconnectMinDelay

	for {
		select {
		case <-w.ctx.Done():
			return
		default:
		}

		if err := w.connect(); err != nil {
			utils.Debugf("[VOLGA] WS error: %v", err)
		}
		if w.ctx.Err() != nil {
			return
		}

		w.stats.WSReconnects.Add(1)
		utils.Debugf("[VOLGA] WS reconnect in %v", delay)
		select {
		case <-time.After(delay):
		case <-w.ctx.Done():
			return
		}

		delay = time.Duration(float64(delay) * w.config.ReconnectMultiplier)
		if delay > w.config.ReconnectMaxDelay {
			delay = w.config.ReconnectMaxDelay
		}
	}
}

func (w *wsListener) connect() error {
	wsURL := w.auth.pushWebsocketBase() + "?" +
		"service=volga" +
		"&user=" + url.QueryEscape(w.auth.UserIDStr) +
		"&sign=" + w.auth.Sign +
		"&ts=" + w.auth.TS +
		"&client=web" +
		"&session=" + w.auth.SessionID +
		"&fetch_history=" + url.QueryEscape(w.auth.UserIDStr+":volga:0:1") +
		"&x_request_attempt=0"

	header := http.Header{}
	header.Set("User-Agent", volgaUserAgent)
	header.Set("Origin", w.auth.volgaOrigin())

	var cookieParts []string
	for _, c := range w.auth.Cookies {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	header.Set("Cookie", strings.Join(cookieParts, "; "))

	dialer := websocket.Dialer{
		HandshakeTimeout: w.config.WSHandshakeTimeout,
		ReadBufferSize:   4 << 20,
		WriteBufferSize:  4 << 20,
	}

	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	utils.Debugf("[VOLGA] WS connected: user=%s", w.auth.UserIDStr)

	for {
		select {
		case <-w.ctx.Done():
			return nil
		default:
		}

		conn.SetReadDeadline(time.Now().Add(w.config.WSReadTimeout))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		w.handleMessage(msg)
	}
}

func (w *wsListener) handleMessage(raw []byte) {
	var envelope struct {
		Operation string `json:"operation"`
		Message   string `json:"message"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return
	}

	if envelope.Operation == "ping" {
		return
	}
	if envelope.Operation != "SESSION" && envelope.Operation != "WORKER" {
		return
	}
	if envelope.Message == "" {
		return
	}

	var inner struct {
		T       string          `json:"t"`
		UserID  int             `json:"userId"`
		Bundle  json.RawMessage `json:"bundle"`
		Message json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal([]byte(envelope.Message), &inner); err != nil {
		return
	}

	if inner.UserID == w.auth.UserID {
		return
	}

	switch inner.T {
	case "relay":
		w.handleRelayMessage(inner.Message)
	case "exchange":
		w.handleBundle(inner.Bundle)
	}
}

func (w *wsListener) handleRelayMessage(raw json.RawMessage) {
	var relay struct {
		Bundle []json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(raw, &relay); err != nil {
		return
	}
	for _, item := range relay.Bundle {
		w.handleBundleItem(item)
	}
}

func (w *wsListener) handleBundle(raw json.RawMessage) {
	var asArray []json.RawMessage
	if err := json.Unmarshal(raw, &asArray); err == nil {
		for _, item := range asArray {
			w.handleBundleItem(item)
		}
		return
	}

	var asObject struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil {
		for _, item := range asObject.Value {
			w.handleBundleItem(item)
		}
	}
}

func (w *wsListener) handleBundleItem(raw json.RawMessage) {
	var asObj struct {
		ID     string `json:"id"`
		Action string `json:"actionName"`
	}
	if err := json.Unmarshal(raw, &asObj); err == nil && asObj.Action != "" {
		if asObj.ID != "" {
			w.relay.SetFrontier(asObj.ID)
		}
		return
	}

	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil && asStr != "" {
		decoded, err := base64.StdEncoding.DecodeString(asStr)
		if err != nil {
			return
		}
		packets := decodeBatch(decoded)
		w.stats.PacketsRecv.Add(uint64(len(packets)))
		w.stats.BytesReceived.Add(uint64(len(decoded)))
		for _, pkt := range packets {
			if w.onData != nil {
				w.onData(pkt)
			}
		}
	}
}

func decodeBatch(decoded []byte) [][]byte {
	var packets [][]byte
	for len(decoded) >= 2 {
		ln := int(binary.BigEndian.Uint16(decoded[:2]))
		decoded = decoded[2:]
		if ln == 0 || len(decoded) < ln {
			break
		}
		packets = append(packets, decoded[:ln])
		decoded = decoded[ln:]
	}
	if len(packets) == 0 && len(decoded) > 0 {
		packets = append(packets, decoded)
	}
	return packets
}

type YandexVolgaTransport struct {
	*transport.BaseTransport

	docURL string
	config VolgaConfig
	stats  *VolgaStats

	auth  *volgaAuth
	relay *relayClient
	ws    *wsListener

	onDataMu sync.RWMutex
	onData   func([]byte)

	keepAliveStop chan struct{}
}

func NewYandexVolgaTransport(docURL string, cfg transport.TransportConfig) *YandexVolgaTransport {
	return &YandexVolgaTransport{
		BaseTransport: transport.NewBaseTransport(cfg),
		docURL:        docURL,
		config:        DefaultVolgaConfig(),
		stats:         &VolgaStats{},
		keepAliveStop: make(chan struct{}),
	}
}

func (t *YandexVolgaTransport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	utils.Debugf("[VOLGA] authorizing...")
	auth, err := authorize(t.docURL)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	t.auth = auth

	t.relay = newRelayClient(auth, t.config, t.stats)
	t.relay.Start()

	t.ws = newWSListener(auth, t.config, t.stats, t.relay, func(data []byte) {
		t.onDataMu.RLock()
		cb := t.onData
		t.onDataMu.RUnlock()
		if cb != nil {
			cb(data)
		}
		t.RecordReceive(len(data))
	})
	t.ws.Start()

	go t.keepAliveLoop()
	go t.statsLoop()
	t.SetConnected(true)

	utils.Debugf("[VOLGA] transport started: user=%d(%s) rp=%s",
		auth.UserID, auth.UserIDStr, auth.RequestPath)
	return nil
}

func (t *YandexVolgaTransport) Stop() error {
	select {
	case <-t.keepAliveStop:
	default:
		close(t.keepAliveStop)
	}
	if t.ws != nil {
		t.ws.Stop()
	}
	if t.relay != nil {
		t.relay.Stop()
	}
	t.SetConnected(false)
	return t.BaseTransport.Stop()
}

func (t *YandexVolgaTransport) Send(data []byte) error {
	if t.relay == nil {
		return fmt.Errorf("transport not started")
	}
	return t.relay.Send(data)
}

func (t *YandexVolgaTransport) Receive(callback func([]byte)) {
	t.onDataMu.Lock()
	t.onData = callback
	t.onDataMu.Unlock()
}

func (t *YandexVolgaTransport) IsConnected() bool {
	return t.BaseTransport.IsConnected()
}

func (t *YandexVolgaTransport) Stats() transport.TransportStats {
	base := t.BaseTransport.Stats()
	return transport.TransportStats{
		BytesSent:     t.stats.BytesSent.Load(),
		BytesReceived: t.stats.BytesReceived.Load(),
		PacketsSent:   t.stats.PacketsSent.Load(),
		PacketsRecv:   t.stats.PacketsRecv.Load(),
		Reconnects:    t.stats.WSReconnects.Load(),
		Connected:     t.IsConnected(),
		Uptime:        base.Uptime,
	}
}

func (t *YandexVolgaTransport) keepAliveLoop() {
	ticker := time.NewTicker(t.config.KeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.keepAliveStop:
			return
		case <-ticker.C:
			if !t.IsRunning() {
				return
			}
			_ = t.relay.Send([]byte{0x00})
		}
	}
}

func (t *YandexVolgaTransport) statsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastSent, lastBytes, lastHTTP, lastFailed, lastRecv, lastRecvBytes, lastBatches, lastBatched uint64

	for {
		select {
		case <-t.keepAliveStop:
			return
		case <-ticker.C:
			sent := t.stats.PacketsSent.Load()
			bytes := t.stats.BytesSent.Load()
			httpReqs := t.stats.HTTPReqsSent.Load()
			failed := t.stats.HTTPReqsFailed.Load()
			recv := t.stats.PacketsRecv.Load()
			recvBytes := t.stats.BytesReceived.Load()
			batches := t.stats.BatchesSent.Load()
			batched := t.stats.PacketsBatched.Load()

			utils.Debugf("[VOLGA-STATS] send %d pkt/s (%d KB/s) | http %d req/s fail %d | batch %d (avg %.1f pkt) | recv %d pkt/s (%d KB/s) | busy %d/%d",
				(sent-lastSent)/5, (bytes-lastBytes)/5/1024,
				(httpReqs-lastHTTP)/5, failed-lastFailed,
				(batches-lastBatches)/5,
				float64(batched-lastBatched)/float64(maxU64(batches-lastBatches, 1)),
				(recv-lastRecv)/5, (recvBytes-lastRecvBytes)/5/1024,
				t.stats.WorkerBusy.Load(), t.config.WorkerCount)

			lastSent, lastBytes = sent, bytes
			lastHTTP, lastFailed = httpReqs, failed
			lastRecv, lastRecvBytes = recv, recvBytes
			lastBatches, lastBatched = batches, batched
		}
	}
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
