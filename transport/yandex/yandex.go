package yandex

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
)

type YandexDocsInfo struct {
	CookieStr   string
	Token       string
	DocID       string
	CallbackURL string
	UserID      string
	Origin      string
	Host        string
	WsURL       string
	Permissions map[string]interface{}
	OpenCmd     map[string]interface{}
}

// keepAliveMarker was this transport's own keep-alive payload before the
// keep-alive moved to the outermost layer, where it is encrypted along with
// everything else. It is still recognised on receipt so a peer running an
// older build does not inject its keep-alives into the network stack.
const keepAliveMarker = "---KA---"

// cursorFrame wraps an already-encoded payload in the socket.io cursor
// message the document editor relays to the other collaborator.
func cursorFrame(payload string) string {
	return `42["message",{"type":"cursor","cursor":"18;` + payload + `"}]`
}

func authTokenFrame(token string) string {
	return `40{"token":"` + token + `"}`
}

const (
	// wsReadTimeout bounds a single blocking read. A silent peer - NAT
	// timeout, half-open TCP, the phone changing networks - used to park
	// ReadMessage forever: no error, so no reconnect, so the tunnel stayed
	// dead until the process was restarted. The deadline turns that silence
	// into an ordinary read error. 60s comfortably covers both the socket.io
	// server ping and our own 10s keep-alive.
	wsReadTimeout = 60 * time.Second

	// wsWriteTimeout caps a single write so a stalled send buffer cannot
	// wedge the writer goroutine.
	wsWriteTimeout = 15 * time.Second

	// sessionHealthyAfter is how long a session must live to count as
	// healthy, resetting the reconnect backoff so routine long-lived
	// reconnects do not inherit a grown delay.
	sessionHealthyAfter = 15 * time.Second

	// writerIdleWake bounds how long the writer parks on an empty queue, so
	// it notices Stop promptly.
	writerIdleWake = 500 * time.Millisecond
)

type DocSession struct {
	Info    YandexDocsInfo
	Conn    *websocket.Conn
	UserID  string
	writeMu sync.Mutex
}

func (s *DocSession) safeWrite(messageType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	// Without a deadline a stalled socket blocks the writer indefinitely,
	// which is one of the ways the tunnel used to wedge until a restart.
	if err := s.Conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout)); err != nil {
		return err
	}
	return s.Conn.WriteMessage(messageType, data)
}

type YandexDocsTransport struct {
	*transport.BaseTransport

	url     string
	session *DocSession

	// writeQueue outlives any single session, so a reconnect does not lose
	// the packets already queued for it.
	writeQueue chan []byte

	stopped  chan struct{}
	stopOnce sync.Once

	userCounter atomic.Int32
	baseUserID  string
	userID      string // stable across reconnects; guarded by Mu
}

func NewYandexDocsTransport(url string, config transport.TransportConfig) *YandexDocsTransport {
	queueSize := config.MaxQueueSize
	if queueSize <= 0 {
		queueSize = 1024
	}
	t := &YandexDocsTransport{
		BaseTransport: transport.NewBaseTransport(config),
		url:           url,
		writeQueue:    make(chan []byte, queueSize),
		stopped:       make(chan struct{}),
	}
	t.baseUserID = randUserID()
	return t
}

func (t *YandexDocsTransport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	t.baseUserID = randUserID()
	utils.SafeGo("yandex.writer", t.writerLoop)
	utils.SafeGo("yandex.connect", t.connectLoop)

	return nil
}

// Stop tears the live socket down as well as clearing the running flag.
// Without closing the connection the reader would sit in ReadMessage until
// its deadline expired, keeping a goroutine and an fd alive across a
// stop/start cycle - which is exactly what the mobile bridges do.
func (t *YandexDocsTransport) Stop() error {
	err := t.BaseTransport.Stop()
	t.stopOnce.Do(func() { close(t.stopped) })
	if session := t.currentSession(); session != nil {
		_ = session.Conn.Close()
	}
	return err
}

func (t *YandexDocsTransport) Send(data []byte) error {
	if !t.IsConnected() {
		return fmt.Errorf("transport not connected")
	}

	select {
	case t.writeQueue <- data:
		t.RecordSend(len(data))
		return nil
	default:
		return fmt.Errorf("write queue full")
	}
}

func (t *YandexDocsTransport) currentSession() *DocSession {
	t.Mu.RLock()
	defer t.Mu.RUnlock()
	return t.session
}

func (t *YandexDocsTransport) setSession(session *DocSession) {
	t.Mu.Lock()
	t.session = session
	t.Mu.Unlock()
	t.SetConnected(true)
}

func (t *YandexDocsTransport) clearSession(session *DocSession) {
	t.Mu.Lock()
	if t.session == session {
		t.session = nil
	}
	t.Mu.Unlock()
	t.SetConnected(false)
}

// dropSession closes session if it is still the live one, unblocking the
// reader so connectLoop can replace it. Safe from any goroutine, and safe to
// call more than once.
func (t *YandexDocsTransport) dropSession(session *DocSession, reason string) {
	if session == nil || t.currentSession() != session {
		return
	}
	utils.Debugf("[YDOCS] dropping session: %s", reason)
	t.SetConnected(false)
	_ = session.Conn.Close()
}

// sessionUserID returns the document user id, allocated once and then reused
// for every reconnect so the document keeps seeing a single collaborator.
func (t *YandexDocsTransport) sessionUserID() string {
	t.Mu.Lock()
	defer t.Mu.Unlock()
	if t.userID == "" {
		t.userID = t.baseUserID + fmt.Sprintf("%03d", t.userCounter.Add(1)%1000)
	}
	return t.userID
}

// connectLoop owns the entire connection lifecycle in a single goroutine.
// Reconnects used to be scheduled by whichever goroutine noticed the failure,
// so a read error and a failed keep-alive could each start one and the
// loser's socket was orphaned - leaking an fd, a goroutine and a second live
// reader per reconnect. A single owner makes that overlap impossible.
func (t *YandexDocsTransport) connectLoop() {
	attempt := 0

	for t.IsRunning() {
		startedAt := time.Now()
		if err := t.runSession(); err != nil {
			utils.Debugf("[YDOCS] session ended: %v", err)
		}
		if !t.IsRunning() {
			return
		}

		// A session that stayed up counts as healthy: restart the backoff so
		// routine long-lived reconnects do not inherit a grown delay.
		if time.Since(startedAt) > sessionHealthyAfter {
			attempt = 0
		}
		attempt++
		if attempt >= t.GetConfig().MaxReconnectAttempts {
			utils.Debugf("[YDOCS] giving up after %d attempts", attempt)
			return
		}
		t.RecordReconnect()

		d := reconnectBackoff(attempt)
		utils.Debugf("[YDOCS] reconnecting in %v (attempt %d)", d, attempt)
		select {
		case <-time.After(d):
		case <-t.stopped:
			return
		}
	}
}

// runSession builds one WebSocket session and reads it until it fails. It
// always releases the socket before returning.
func (t *YandexDocsTransport) runSession() error {
	userID := t.sessionUserID()

	info, err := t.fetchDocInfo(t.url, userID)
	if err != nil {
		return fmt.Errorf("fetchDocInfo: %w", err)
	}

	// Hard TCP dial timeout so a stuck connect/DNS to the balancer host
	// can't hang the whole transport (HandshakeTimeout alone proved
	// insufficient on iOS).
	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		NetDialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0")
	headers.Set("Origin", info.Origin)
	headers.Set("Cookie", info.CookieStr)
	headers.Set("Host", info.Host)

	utils.Debugf("[YDOCS] WebSocket dial %s", info.WsURL)
	conn, resp, err := dialer.Dial(info.WsURL, headers)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		return fmt.Errorf("websocket dial (http %d): %w", status, err)
	}
	// The old code never closed the socket, leaking one fd and one blocked
	// goroutine on every single reconnect.
	defer conn.Close()
	utils.Debugf("[YDOCS] WebSocket connected to %s", info.Host)

	session := &DocSession{Info: info, Conn: conn, UserID: userID}
	t.setSession(session)
	defer t.clearSession(session)

	if err := session.safeWrite(websocket.TextMessage, []byte(authTokenFrame(info.Token))); err != nil {
		return fmt.Errorf("auth handshake: %w", err)
	}

	authData := map[string]interface{}{
		"type": "auth", "docid": info.DocID, "token": "fghhfgsjdgfjs",
		"user": map[string]interface{}{"id": userID}, "editorType": 0,
		"lastOtherSaveTime": -1, "permissions": info.Permissions,
		"openCmd": info.OpenCmd, "coEditingMode": "fast", "jwtOpen": info.Token,
	}
	messagePart, _ := json.Marshal([]interface{}{"message", authData})
	if err := session.safeWrite(websocket.TextMessage, []byte(fmt.Sprintf("42%s", string(messagePart)))); err != nil {
		return fmt.Errorf("auth message: %w", err)
	}

	for t.IsRunning() {
		if err := conn.SetReadDeadline(time.Now().Add(wsReadTimeout)); err != nil {
			return fmt.Errorf("set read deadline: %w", err)
		}
		_, message, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		t.handleMessage(session, message)
	}
	return nil
}

func (t *YandexDocsTransport) writerLoop() {
	for t.IsRunning() {
		// Block on the queue rather than polling it every 10ms: the old poll
		// burned a core and added up to 10ms of latency to every packet.
		select {
		case packet := <-t.writeQueue:
			session := t.currentSession()
			if session == nil {
				continue // no live socket; the tunnel's TCP layer retransmits
			}
			payload := base64.StdEncoding.EncodeToString(packet)
			msg := cursorFrame(payload)

			if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
				utils.Debugf("[YDOCS] Write error: %v", err)
				// This socket is gone. Tear it down now instead of leaving
				// the reader parked until its deadline expires.
				t.dropSession(session, "write error")
			}
		case <-time.After(writerIdleWake):
		case <-t.stopped:
			return
		}
	}
}

func (t *YandexDocsTransport) handleMessage(session *DocSession, data []byte) {
	text := string(data)

	if strings.Contains(text, keepAliveMarker) {
		return
	}

	// Socket.IO ping - respond with pong (use safeWrite)
	if text == "2" {
		if session != nil && session.Conn != nil {
			session.safeWrite(websocket.TextMessage, []byte("3"))
		}
		return
	}
	if text == "3" {
		return
	}

	if strings.Contains(text, "saveChanges") || strings.Contains(text, "cursor") {
		base64Str := t.extractBase64String(text)
		if base64Str == "" {
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(base64Str)
		if err != nil {
			utils.Debugf("[YDOCS] Base64 decode error: %v", err)
			return
		}

		t.RecordReceive(len(decoded))
		t.CallReceive(decoded)
	}
}

func (t *YandexDocsTransport) extractBase64String(response string) string {
	if strings.Contains(response, "saveChanges") {
		marker := `"excelAdditionalInfo":"`
		left := strings.Index(response, marker) + len(marker)
		if left < len(marker) {
			return ""
		}
		right := strings.Index(response[left:], `"`)
		if right == -1 {
			return ""
		}
		return response[left : left+right]
	}

	re := regexp.MustCompile(`"cursor":"[^;]+;([^"]+)"`)
	matches := re.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// reconnectBackoff returns an exponential backoff with jitter, capped at 15s.
func reconnectBackoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	shift := n - 1
	if shift > 5 {
		shift = 5
	}
	d := 500 * time.Millisecond * time.Duration(1<<uint(shift))
	if d > 15*time.Second {
		d = 15 * time.Second
	}
	// add up to +50% jitter
	d += time.Duration(rand.Int63n(int64(d/2) + 1))
	return d
}

func (t *YandexDocsTransport) fetchDocInfo(url, userID string) (YandexDocsInfo, error) {
	client := &http.Client{
		// Cap redirects so an auth/login redirect loop fails fast instead of
		// hanging until the timeout (a private doc redirects to passport).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects (login required? doc not public?)")
			}
			return nil
		},
		Timeout: 15 * time.Second,
	}

	utils.Debugf("[YDOCS] fetchDocInfo GET %s", url)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return YandexDocsInfo{}, err
	}
	defer resp.Body.Close()

	htmlBytes, _ := io.ReadAll(resp.Body)
	html := string(htmlBytes)
	utils.Debugf("[YDOCS] response status=%d finalURL=%s body=%dB", resp.StatusCode, resp.Request.URL.String(), len(html))

	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}

	re := regexp.MustCompile(`<script[^>]*id="client-config"[^>]*>(.*?)</script>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) < 2 {
		// Help diagnose: is this a login page, a new-editor page, etc.?
		hint := "no client-config script"
		if strings.Contains(html, "passport") || strings.Contains(strings.ToLower(html), "login") {
			hint = "looks like a login page (doc not public?)"
		}
		return YandexDocsInfo{}, fmt.Errorf("config not found: %s (status %d, final %s)", hint, resp.StatusCode, resp.Request.URL.String())
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(matches[1]), &config); err != nil {
		return YandexDocsInfo{}, fmt.Errorf("client-config is not valid JSON: %w", err)
	}

	officeAction, ok := config["officeActionData"].(map[string]interface{})
	if !ok || officeAction == nil {
		return YandexDocsInfo{}, fmt.Errorf("officeActionData missing - will reconnect")
	}

	editorConfigRaw, ok := officeAction["editor_config"].(map[string]interface{})
	if !ok || editorConfigRaw == nil {
		return YandexDocsInfo{}, fmt.Errorf("editor_config nil - will reconnect")
	}

	balancerURL, ok := officeAction["balancer_url"].(string)
	if !ok || balancerURL == "" {
		return YandexDocsInfo{}, fmt.Errorf("officeActionData.balancer_url missing - will reconnect")
	}
	host := strings.TrimPrefix(balancerURL, "https://")

	document, ok := editorConfigRaw["document"].(map[string]interface{})
	if !ok || document == nil {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.document missing - will reconnect")
	}

	token, ok := editorConfigRaw["token"].(string)
	if !ok || token == "" {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.token missing - will reconnect")
	}

	docKey, ok := document["key"].(string)
	if !ok || docKey == "" {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.document.key missing - will reconnect")
	}

	perms, _ := document["permissions"].(map[string]interface{})
	if perms == nil {
		perms = make(map[string]interface{})
	}

	return YandexDocsInfo{
		CookieStr:   strings.Join(cookies, "; "),
		Token:       token,
		DocID:       docKey,
		Origin:      balancerURL,
		Host:        host,
		WsURL:       fmt.Sprintf("wss://%s/2024.1.1-375/doc/%s/c/?EIO=4&transport=websocket", host, docKey),
		Permissions: perms,
		OpenCmd: map[string]interface{}{
			"c":      "open",
			"id":     docKey,
			"userid": userID,
			"format": document["fileType"],
			"url":    document["url"],
			"title":  document["title"],
			"lcid":   25,
		},
	}, nil
}

func randUserID() string {
	return fmt.Sprintf("%010d", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(1000000000))
}
