// Package gui はローカルHTTPサーバーとして動作するWebベースGUIを提供する。
// Edge WebView2を使った専用ウィンドウで表示する。
package gui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	webview "github.com/jchv/go-webview2"

	"github.com/balrogsxt/StarResonanceAPI/mumu"
	"github.com/balrogsxt/StarResonanceAPI/notifier"
)

// DeviceSessionInfo はキャプチャセッション情報をGUIに渡す型
type DeviceSessionInfo struct {
	Label     string
	ClientIP  string
	UserUID   uint64
	MapID     uint32
	LineID    uint32
	Confirmed bool
}

// Server はGUI用HTTPサーバー
type Server struct {
	port             int
	mumuCfg          mumu.Config
	patroller        *mumu.Patroller
	patrolChannels   []uint32 // 起動時に設定から読み込んだチャンネルリスト
	patrolDwellSecs  float64  // デフォルト滞在秒数
	patrolChannelsFile string // channels.txt パス（ホットリロード用）
	getSessions      func() []DeviceSessionInfo // ADB ↔ UID 対応用セッション提供コールバック
	testDetectFn     func()                     // テスト検知発火コールバック
	saveChannelsFn   func([]uint32) error        // channels.txt 保存コールバック
	getConfigFn      func() ([]byte, error)      // config.json 読み込みコールバック
	saveConfigFn     func([]byte) error          // config.json 保存コールバック

	mu       sync.RWMutex
	logLines []string     // 検知ログ（最大80件）
	clients  []chan string // SSEクライアント
}

// New はGUIサーバーを作成する
func New(port int, mumuCfg mumu.Config, patrolChannels []uint32, patrolDwellSecs float64, patrolChannelsFile string) *Server {
	return &Server{
		port:               port,
		mumuCfg:            mumuCfg,
		patroller:          mumu.NewPatroller(mumuCfg),
		patrolChannels:     patrolChannels,
		patrolDwellSecs:    patrolDwellSecs,
		patrolChannelsFile: patrolChannelsFile,
	}
}

// SetSessionProvider はADD ↔ UID 対応に使うセッション情報提供関数を設定する。
// /api/device-map エンドポイントが利用する。
func (s *Server) SetSessionProvider(fn func() []DeviceSessionInfo) {
	s.getSessions = fn
}

// SetTestDetectFn はテスト通知ボタンから呼ばれるコールバックを設定する。
func (s *Server) SetTestDetectFn(fn func()) {
	s.testDetectFn = fn
}

// SetSaveChannelsFn はチャンネルリスト保存コールバックを設定する。
func (s *Server) SetSaveChannelsFn(fn func([]uint32) error) {
	s.saveChannelsFn = fn
}

// SetConfigFns は config.json の読み書きコールバックを設定する。
func (s *Server) SetConfigFns(getFn func() ([]byte, error), saveFn func([]byte) error) {
	s.getConfigFn = getFn
	s.saveConfigFn = saveFn
}

// OnDetect は検知イベントをGUIのログに追加するコールバック
func (s *Server) OnDetect(det notifier.Detection) {
	line := fmt.Sprintf("[%s] %s", det.Time.Format("15:04:05"), notifier.Format(det))
	s.mu.Lock()
	s.logLines = append(s.logLines, line)
	if len(s.logLines) > 200 {
		s.logLines = s.logLines[len(s.logLines)-200:]
	}
	clients := make([]chan string, len(s.clients))
	copy(clients, s.clients)
	s.mu.Unlock()

	for _, ch := range clients {
		select {
		case ch <- line:
		default:
		}
	}
}

// AddLog は1行のログをGUIのSSEストリームとlogLinesに追加する
func (s *Server) AddLog(line string) {
	s.mu.Lock()
	s.logLines = append(s.logLines, line)
	if len(s.logLines) > 200 {
		s.logLines = s.logLines[len(s.logLines)-200:]
	}
	clients := make([]chan string, len(s.clients))
	copy(clients, s.clients)
	s.mu.Unlock()

	for _, ch := range clients {
		select {
		case ch <- line:
		default:
		}
	}
}

// guiWriter は標準 log 出力をGUIのSSEにも転送する io.Writer
type guiWriter struct {
	base io.Writer
	srv  *Server
	buf  []byte
}

func (w *guiWriter) Write(p []byte) (int, error) {
	n, err := w.base.Write(p)
	w.buf = append(w.buf, p...)
	for {
		idx := -1
		for i, b := range w.buf {
			if b == '\n' {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		line := strings.TrimRight(string(w.buf[:idx]), "\r")
		w.buf = w.buf[idx+1:]
		if line != "" {
			w.srv.AddLog(line)
		}
	}
	return n, err
}

// LogWriter は log.SetOutput() に渡す io.Writer を返す。
// これを差し込むことで全ログがGUIのログボックスにも表示される。
func (s *Server) LogWriter(base io.Writer) io.Writer {
	return &guiWriter{base: base, srv: s}
}

// Start はHTTPサーバーをバックグラウンドで起動する（内部用）
func (s *Server) startHTTP(ctx context.Context) (string, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/device-map", s.handleDeviceMap)
	mux.HandleFunc("/api/switch", s.handleSwitch)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/patrol/start", s.handlePatrolStart)
	mux.HandleFunc("/api/patrol/stop", s.handlePatrolStop)
	mux.HandleFunc("/api/patrol/status", s.handlePatrolStatus)
	mux.HandleFunc("/api/patrol/channels", s.handlePatrolChannels)
	mux.HandleFunc("/api/test-detect", s.handleTestDetect)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/events", s.handleSSE)

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("GUI server listen: %w", err)
	}

	srv := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && ctx.Err() == nil {
			log.Printf("[GUI] HTTP server error: %v", err)
		}
	}()

	// 起動時にデバイス一覧を取得してログに出力する
	go func() {
		time.Sleep(1 * time.Second) // HTTPサーバー起動待ち
		log.Println("[MuMu] 起動時デバイス確認...")
		devices, err := mumu.ListDevices(s.mumuCfg)
		if err != nil {
			log.Printf("[MuMu] 起動時デバイス取得失敗: %v", err)
			return
		}
		if len(devices) == 0 {
			log.Println("[MuMu] 起動時デバイスが見つかりません。MuMu Playerを起動してadb connectで接続してください")
		} else {
			log.Printf("[MuMu] 起動時デバイス: %v", devices)
		}
	}()

	url := fmt.Sprintf("http://%s", ln.Addr().String())
	return url, nil
}

// RunWindow はHTTPサーバーを起動しEdge WebView2の専用ウィンドウを開く。
// この関数はウィンドウが閉じられるまでブロックする（メインスレッドで呼ぶこと）。
func (s *Server) RunWindow(ctx context.Context) error {
	url, err := s.startHTTP(ctx)
	if err != nil {
		return err
	}
	log.Printf("[GUI] opening window: %s", url)

	w := webview.NewWithOptions(webview.WebViewOptions{
		Debug: false,
		WindowOptions: webview.WindowOptions{
			Title:  "LoyalBoarlet Monitor",
			Width:  1000,
			Height: 720,
			Center: true,
		},
	})
	if w == nil {
		// WebView2が利用不可（未インストール等）→フォールバックとしてブラウザで開く
		log.Println("[GUI] WebView2 unavailable, falling back to browser")
		openBrowser(url)
		<-ctx.Done()
		return nil
	}
	defer w.Destroy()
	w.Navigate(url)
	w.Run()
	return nil
}

// Start はHTTPサーバーをバックグラウンド起動してブラウザで開く（GUIウィンドウ不要な場合）
func (s *Server) Start(ctx context.Context) error {
	url, err := s.startHTTP(ctx)
	if err != nil {
		return err
	}
	log.Printf("[GUI] http server: %s", url)
	openBrowser(url)
	<-ctx.Done()
	return nil
}

func openBrowser(url string) {
	cmd := exec.Command("cmd", "/c", "start", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		log.Printf("[GUI] browser open failed: %v", err)
	}
}

// handleIndex はメインHTMLページを返す
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, indexHTML)
}

// handleDeviceMap はADBデバイスのエミュレータIPを取得し、
// キャプチャセッション（UID等）と紐付けた一覧をJSONで返す。
func (s *Server) handleDeviceMap(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	adbDevices, err := mumu.ListDevices(s.mumuCfg)
	if err != nil {
		log.Printf("[MuMu] device-map: ListDevices error: %v", err)
	}

	// clientIP → セッション情報マップを構築
	ipToSess := make(map[string]DeviceSessionInfo)
	if s.getSessions != nil {
		for _, sess := range s.getSessions() {
			if sess.ClientIP != "" {
				ipToSess[sess.ClientIP] = sess
			}
		}
	}

	type DeviceEntry struct {
		Serial    string `json:"serial"`
		DeviceIP  string `json:"device_ip"`
		UserUID   uint64 `json:"user_uid"`
		Label     string `json:"label"`
		MapID     uint32 `json:"map_id"`
		LineID    uint32 `json:"line_id"`
		Confirmed bool   `json:"confirmed"`
	}

	entries := make([]DeviceEntry, len(adbDevices))
	var wg sync.WaitGroup
	for i, serial := range adbDevices {
		entries[i] = DeviceEntry{Serial: serial}
		wg.Add(1)
		go func(idx int, ser string) {
			defer wg.Done()
			ipCh := make(chan string, 1)
			go func() {
				ip, ipErr := mumu.GetDeviceIP(ser, s.mumuCfg)
				if ipErr != nil {
					log.Printf("[MuMu] GetDeviceIP %s: %v", ser, ipErr)
					ip = ""
				}
				ipCh <- ip
			}()
			var devIP string
			select {
			case devIP = <-ipCh:
			case <-ctx.Done():
			}
			entries[idx].DeviceIP = devIP
			if devIP != "" {
				if sess, ok := ipToSess[devIP]; ok {
					entries[idx].UserUID = sess.UserUID
					entries[idx].Label = sess.Label
					entries[idx].MapID = sess.MapID
					entries[idx].LineID = sess.LineID
					entries[idx].Confirmed = sess.Confirmed
				}
			}
		}(i, serial)
	}
	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"devices": entries})
}

// handleDevices はADB接続デバイス一覧をJSONで返す
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := mumu.ListDevices(s.mumuCfg)
	if err != nil {
		log.Printf("[MuMu] adb devices エラー: %v", err)
	}
	if devices == nil {
		devices = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"devices": devices,
	})
}

// handleSwitch はチャンネル切替リクエストを処理する
func (s *Server) handleSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Serial  string `json:"serial"`
		Channel uint32 `json:"channel"`
		All     bool   `json:"all"` // true の場合 serial は無視して全デバイス
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	type result struct {
		Serial string `json:"serial"`
		Error  string `json:"error,omitempty"`
		OK     bool   `json:"ok"`
	}
	var results []result

	if req.All {
		serials, err := mumu.ListDevices(s.mumuCfg)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		for serial, err := range mumu.SwitchAll(serials, req.Channel, s.mumuCfg) {
			r := result{Serial: serial, OK: err == nil}
			if err != nil {
				r.Error = err.Error()
			}
			results = append(results, r)
		}
	} else {
		err := mumu.SwitchChannel(req.Serial, req.Channel, s.mumuCfg)
		r := result{Serial: req.Serial, OK: err == nil}
		if err != nil {
			r.Error = err.Error()
		}
		results = append(results, r)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"results": results,
	})
}

// handleLogs は既存ログ一覧をJSONで返す
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	lines := make([]string, len(s.logLines))
	copy(lines, s.logLines)
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"logs": lines,
	})
}

// handlePatrolChannels はconfig読み込み済みのチャンネルリストを返す（GET）または保存する（POST）
func (s *Server) handlePatrolChannels(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Channels []uint32 `json:"channels"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		s.patrolChannels = req.Channels
		if s.saveChannelsFn != nil {
			if err := s.saveChannelsFn(req.Channels); err != nil {
				log.Printf("[GUI] channels保存失敗: %v", err)
				http.Error(w, "save failed: "+err.Error(), 500)
				return
			}
			log.Printf("[GUI] channels.txt に %d件保存しました", len(req.Channels))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"channels":   s.patrolChannels,
		"dwell_secs": s.patrolDwellSecs,
	})
}

// handleConfig は config.json の読み込み（GET）または保存（POST）を行う
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if s.saveConfigFn == nil {
			http.Error(w, "save not configured", 503)
			return
		}
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := s.saveConfigFn(buf); err != nil {
			log.Printf("[GUI] config保存失敗: %v", err)
			http.Error(w, "save failed: "+err.Error(), 500)
			return
		}
		log.Printf("[GUI] config.json を保存しました")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
		return
	}
	if s.getConfigFn == nil {
		http.Error(w, "config not available", 503)
		return
	}
	data, err := s.getConfigFn()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// handlePatrolStart は巡回を開始する
func (s *Server) handlePatrolStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Serials   []string `json:"serials"`
		Channels  []uint32 `json:"channels"`
		DwellSecs float64  `json:"dwell_secs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	channels := req.Channels
	if len(channels) == 0 {
		channels = s.patrolChannels
	}
	dwell := req.DwellSecs
	if dwell <= 0 {
		dwell = s.patrolDwellSecs
	}
	s.patroller.Start(req.Serials, channels, dwell, s.patrolChannelsFile)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// handleTestDetect はテスト用ゴールドウリボ検知を発火する
func (s *Server) handleTestDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	if s.testDetectFn == nil {
		http.Error(w, "test detect not configured", 503)
		return
	}
	go s.testDetectFn()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// handlePatrolStop は巡回を停止する
func (s *Server) handlePatrolStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	s.patroller.Stop()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// handlePatrolStatus は現在の巡回状態を返す
func (s *Server) handlePatrolStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.patroller.Status())
}

// handleSSE はServer-Sent Eventsで検知ログをリアルタイム配信する
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan string, 32)
	s.mu.Lock()
	s.clients = append(s.clients, ch)
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		for i, c := range s.clients {
			if c == ch {
				s.clients = append(s.clients[:i], s.clients[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
	}()

	ctx := r.Context()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			escaped := strings.ReplaceAll(msg, "\n", "\\n")
			fmt.Fprintf(w, "data: %s\n\n", escaped)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

const indexHTML = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LoyalBoarlet Monitor</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eaeaea; min-height: 100vh; padding: 16px; }
h1 { color: #e94560; font-size: 1.4em; margin-bottom: 16px; }
h2 { color: #eaeaea; background: #0f3460; padding: 8px 12px; border-radius: 6px 6px 0 0; font-size: 0.95em; }
.card { background: #16213e; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
.card-body { padding: 12px; }
label { color: #a0a0b0; font-size: 0.85em; }
input[type=number], input[type=text] {
  background: #0f3460; color: #eaeaea; border: 1px solid #e94560;
  border-radius: 4px; padding: 5px 8px; width: 80px; font-size: 0.9em;
}
input[type=text].wide { width: 100%; }
button {
  background: #e94560; color: #fff; border: none; border-radius: 4px;
  padding: 6px 14px; cursor: pointer; font-size: 0.9em; transition: background .2s;
}
button:hover { background: #c73652; }
button:disabled { background: #555; cursor: default; }
button.secondary { background: #0f3460; }
button.secondary:hover { background: #1a4a80; }
button.green { background: #2e7d32; }
button.green:hover { background: #388e3c; }
.flex-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
.flex-row:last-child { margin-bottom: 0; }
.device-list { display: flex; flex-direction: column; gap: 6px; }
.device-row { display: flex; gap: 8px; align-items: center; background: #0f3460; border-radius: 6px; padding: 8px 12px; flex-wrap: wrap; }
.serial { color: #7ec8e3; font-family: monospace; font-size: 0.9em; flex: 1; min-width: 160px; }
.log-box {
  background: #0d0d1a; font-family: monospace; font-size: 0.8em;
  height: 260px; overflow-y: auto; padding: 8px; border-radius: 0 0 8px 8px;
  border: 1px solid #0f3460;
}
.log-line { color: #b0b0c0; padding: 1px 0; white-space: pre-wrap; word-break: break-all; }
.log-line.detect { color: #ffd700; font-weight: bold; }
.no-devices { color: #606080; font-size: 0.85em; padding: 4px 0; }
#status-bar { color: #4caf50; font-size: 0.82em; }
.patrol-status { background: #0d1b33; border-radius: 6px; padding: 8px 12px; font-size: 0.85em; margin-bottom: 8px; }
.patrol-status span { margin-right: 16px; }
.patrol-status .running { color: #4caf50; font-weight: bold; }
.patrol-status .stopped { color: #888; }
.ch-list { background: #0d0d1a; border-radius: 4px; padding: 8px; font-family: monospace; font-size: 0.78em; color: #7ec8e3; max-height: 60px; overflow-y: auto; word-break: break-all; margin-bottom: 4px; }
input[type=checkbox] { accent-color: #e94560; width: 16px; height: 16px; }
.check-label { display: flex; align-items: center; gap: 6px; cursor: pointer; color: #eaeaea; }
.cfg-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px 20px; }
@media(max-width:640px){ .cfg-grid { grid-template-columns: 1fr; } }
.cfg-field { display: flex; flex-direction: column; gap: 3px; }
.cfg-field label { color: #a0a0b0; font-size: 0.82em; }
.cfg-field input[type=text], .cfg-field input[type=number], .cfg-field textarea {
  width: 100%; background: #0f3460; color: #eaeaea; border: 1px solid #334466;
  border-radius: 4px; padding: 5px 8px; font-size: 0.88em; box-sizing: border-box;
}
.cfg-field textarea { min-height: 56px; resize: vertical; font-family: monospace; }
.cfg-save-bar { display:flex; gap:8px; align-items:center; margin-top:10px; }
.cfg-note { font-size:0.75em; color:#606080; margin-top:4px; }
</style>
</head>
<body>
<h1>🐗 LoyalBoarlet Monitor</h1>

<!-- デバイス一覧 & 手動切替 -->
<div class="card">
  <h2>📱 デバイス一覧 &amp; 手動切替</h2>
  <div class="card-body">
    <div class="flex-row">
      <button onclick="refreshDevices()">🔄 デバイス再取得</button>
      <label>一括切替 Ch:</label>
      <input type="number" id="allch" min="1" max="999" value="1">
      <button onclick="switchAll()">▶ 全切替</button>
      <span id="status-bar"></span>
    </div>
    <div class="device-list" id="device-list"><div class="no-devices">読み込み中...</div></div>
  </div>
</div>

<!-- チャンネル巡回 -->
<div class="card">
  <h2>🔁 チャンネル巡回</h2>
  <div class="card-body">
    <div class="patrol-status" id="patrol-status">
      <span class="stopped" id="ps-state">■ 停止中</span>
      <span id="ps-ch"></span>
      <span id="ps-prog"></span>
    </div>
    <div class="flex-row">
      <label>滞在(秒):</label>
      <input type="number" id="patrol-dwell" min="1" max="3600" value="30" style="width:70px">
      <button class="green" id="btn-patrol-start" onclick="patrolStart()">▶ 巡回開始</button>
      <button class="secondary" id="btn-patrol-stop" onclick="patrolStop()" disabled>■ 停止</button>
    </div>
    <div style="margin-bottom:6px">
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:4px">
        <label>巡回チャンネル:</label>
        <button class="secondary" style="padding:3px 8px;font-size:0.8em" onclick="editChannels()">✏ 編集</button>
        <button class="secondary" style="padding:3px 8px;font-size:0.8em" id="btn-ch-save" onclick="saveChannels()" disabled>💾 ファイルに保存</button>
        <span id="ch-save-status" style="font-size:0.8em;color:#a0a0b0"></span>
      </div>
      <div class="ch-list" id="ch-list">読み込み中...</div>
    </div>
    <div>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px">
        <label>巡回対象デバイス:</label>
        <button class="secondary" style="padding:3px 8px;font-size:0.8em" onclick="refreshDevices()">🔄 再取得</button>
        <button class="secondary" style="padding:3px 8px;font-size:0.8em" onclick="selectAllDevices(true)">全選択</button>
        <button class="secondary" style="padding:3px 8px;font-size:0.8em" onclick="selectAllDevices(false)">全解除</button>
      </div>
      <div id="patrol-devices" class="device-list"><div class="no-devices">デバイス更新ボタンで取得</div></div>
    </div>
  </div>
</div>

<!-- 設定 -->
<div class="card">
  <h2>⚙️ 設定 (config.json)</h2>
  <div class="card-body">
    <div class="cfg-grid" id="cfg-grid"><div style="color:#606080;font-size:0.85em">読み込み中...</div></div>
    <div class="cfg-save-bar">
      <button class="green" onclick="saveConfig()">💾 保存 (config.json)</button>
      <span id="cfg-status" style="font-size:0.85em;color:#a0a0b0"></span>
    </div>
    <div class="cfg-note">※ 保存後はアプリを再起動すると全設定が反映されます。Network・ログファイルパス等は再起動が必要です。</div>
  </div>
</div>

<!-- テスト通知 -->
<div class="card">
  <h2>🧪 テスト</h2>
  <div class="card-body">
    <div class="flex-row">
      <button class="secondary" onclick="testDetect()">🐗 ゴールドウリボ通知テスト</button>
      <span id="test-status" style="font-size:0.85em;color:#a0a0b0"></span>
    </div>
    <div style="font-size:0.78em;color:#606080;margin-top:4px">プレイヤーの現在位置・Chをゴールドウリボ出現として Discord/GSheets に送信します</div>
  </div>
</div>

<!-- 検知ログ -->
<div class="card">
  <h2>📋 検知ログ</h2>
  <div class="log-box" id="log-box"></div>
</div>

<script>
const logBox = document.getElementById('log-box');
const statusBar = document.getElementById('status-bar');
let allDeviceSerials = [];
let patrolChannels = [];

function appendLog(text) {
  const d = document.createElement('div');
  d.className = 'log-line' + (text.includes('DETECTION') || text.includes('検知') ? ' detect' : '');
  d.textContent = text;
  logBox.appendChild(d);
  while (logBox.children.length > 300) logBox.removeChild(logBox.firstChild);
  logBox.scrollTop = logBox.scrollHeight;
}

fetch('/api/logs').then(r=>r.json()).then(d=>{ (d.logs||[]).forEach(appendLog); });

const es = new EventSource('/events');
es.onmessage = e => appendLog(e.data.replace(/\\n/g, '\n'));
es.onerror = () => appendLog('[SSE] 接続切断 - 再接続中...');

// ── デバイス ──
async function refreshDevices() {
  let d;
  try {
    const r = await fetch('/api/device-map');
    d = await r.json();
  } catch(e) {
    appendLog('[GUI] デバイス取得失敗: ' + e);
    return;
  }
  const entries = d.devices || [];
  allDeviceSerials = entries.map(e => e.serial);

  const list = document.getElementById('device-list');
  const patrolList = document.getElementById('patrol-devices');
  if (entries.length === 0) {
    list.innerHTML = '<div class="no-devices">ADBデバイスが見つかりません</div>';
    patrolList.innerHTML = '<div class="no-devices">ADBデバイスが見つかりません</div>';
    return;
  }
  list.innerHTML = entries.map(e => ` + "`" + `
    <div class="device-row">
      <div style="flex:1;min-width:160px">
        <span class="serial">${e.serial}</span>
        ${e.device_ip ? ` + "`" + `<span style="color:#606080;font-size:0.78em;margin-left:6px">${e.device_ip}</span>` + "`" + ` : ''}
      </div>
      ${e.user_uid ? ` + "`" + `<span style="color:#4caf50;font-size:0.82em;margin-right:4px">UID:${e.user_uid}</span>` + "`" + ` : '<span style="color:#606080;font-size:0.82em;margin-right:4px">未接続</span>'}
      <label>Ch:</label>
      <input type="number" id="ch_${CSS.escape(e.serial)}" min="1" max="999" value="1" style="width:70px">
      <button onclick="switchOne('${e.serial}')">切替</button>
    </div>` + "`" + `).join('');

  patrolList.innerHTML = entries.map(e => ` + "`" + `
    <div class="device-row">
      <label class="check-label">
        <input type="checkbox" id="pch_${CSS.escape(e.serial)}" checked>
        <span class="serial">${e.serial}</span>
        ${e.user_uid ? ` + "`" + `<span style="color:#4caf50;font-size:0.78em;margin-left:4px">UID:${e.user_uid}</span>` + "`" + ` : ''}
      </label>
    </div>` + "`" + `).join('');
}

function selectAllDevices(checked) {
  allDeviceSerials.forEach(s => {
    const el = document.getElementById('pch_' + CSS.escape(s));
    if (el) el.checked = checked;
  });
}

function selectedSerials() {
  return allDeviceSerials.filter(s => {
    const el = document.getElementById('pch_' + CSS.escape(s));
    return el && el.checked;
  });
}

async function switchOne(serial) {
  const ch = parseInt(document.getElementById('ch_' + CSS.escape(serial)).value);
  if (!ch || ch < 1) { alert('チャンネル番号を入力してください'); return; }
  setStatus('切替中...');
  const r = await fetch('/api/switch', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({serial, channel: ch})
  });
  const d = await r.json();
  const res = (d.results||[])[0];
  setStatus(res && res.ok ? '✅ ' + serial + ' → Ch' + ch : '❌ ' + (res && res.error || '不明'));
}

async function switchAll() {
  const ch = parseInt(document.getElementById('allch').value);
  if (!ch || ch < 1) { alert('チャンネル番号を入力してください'); return; }
  setStatus('全切替中...');
  const r = await fetch('/api/switch', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({all: true, channel: ch})
  });
  const d = await r.json();
  const results = d.results || [];
  const ok = results.filter(r=>r.ok).length;
  const ng = results.filter(r=>!r.ok).length;
  setStatus('✅ ' + ok + '台成功' + (ng ? ' / ❌ ' + ng + '台失敗' : '') + ' → Ch' + ch);
}

// ── 巡回 ──
async function loadPatrolChannels() {
  const r = await fetch('/api/patrol/channels');
  const d = await r.json();
  patrolChannels = d.channels || [];
  if (d.dwell_secs > 0) document.getElementById('patrol-dwell').value = d.dwell_secs;
  renderChannelList();
}

function renderChannelList() {
  document.getElementById('ch-list').textContent = patrolChannels.length
    ? patrolChannels.join(', ')
    : '(未設定)';
}

function editChannels() {
  const cur = patrolChannels.join(',');
  const input = prompt('巡回チャンネルをカンマ区切りで入力:', cur);
  if (input === null) return;
  patrolChannels = input.split(',').map(s=>parseInt(s.trim())).filter(n=>n>0);
  renderChannelList();
  document.getElementById('btn-ch-save').disabled = false;
  document.getElementById('ch-save-status').textContent = '未保存';
}

async function saveChannels() {
  const el = document.getElementById('ch-save-status');
  el.textContent = '保存中...';
  try {
    const r = await fetch('/api/patrol/channels', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({channels: patrolChannels})
    });
    const d = await r.json();
    if (d.ok) {
      el.textContent = '✅ 保存完了';
      document.getElementById('btn-ch-save').disabled = true;
    } else {
      el.textContent = '❌ 失敗';
    }
  } catch(e) {
    el.textContent = '❌ ' + e;
  }
  setTimeout(() => { if(el.textContent.includes('保存完了')) el.textContent = ''; }, 4000);
}

async function patrolStart() {
  const serials = selectedSerials();
  const dwell = parseFloat(document.getElementById('patrol-dwell').value) || 30;
  const r = await fetch('/api/patrol/start', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({serials, channels: patrolChannels, dwell_secs: dwell})
  });
  const d = await r.json();
  if (d.ok) updatePatrolUI(true);
}

async function patrolStop() {
  await fetch('/api/patrol/stop', {method:'POST'});
  updatePatrolUI(false);
}

function updatePatrolUI(running) {
  document.getElementById('btn-patrol-start').disabled = running;
  document.getElementById('btn-patrol-stop').disabled = !running;
}

async function pollPatrolStatus() {
  try {
    const r = await fetch('/api/patrol/status');
    const d = await r.json();
    const stateEl = document.getElementById('ps-state');
    const chEl = document.getElementById('ps-ch');
    const progEl = document.getElementById('ps-prog');
    if (d.running) {
      stateEl.className = 'running';
      stateEl.textContent = '▶ 巡回中';
      chEl.textContent = 'Ch: ' + d.current_channel;
      progEl.textContent = (d.current_index+1) + ' / ' + d.total_channels;
      updatePatrolUI(true);
    } else {
      stateEl.className = 'stopped';
      stateEl.textContent = '■ 停止中';
      chEl.textContent = '';
      progEl.textContent = '';
      updatePatrolUI(false);
    }
  } catch(_) {}
  setTimeout(pollPatrolStatus, 2000);
}

function setStatus(msg) {
  statusBar.textContent = msg;
  setTimeout(()=>{ if(statusBar.textContent===msg) statusBar.textContent=''; }, 5000);
}

// ── テスト通知 ──
async function testDetect() {
  const el = document.getElementById('test-status');
  el.textContent = '送信中...';
  try {
    const r = await fetch('/api/test-detect', {method: 'POST'});
    const d = await r.json();
    el.textContent = d.ok ? '✅ 送信しました' : '❌ 失敗: ' + JSON.stringify(d);
  } catch(e) {
    el.textContent = '❌ エラー: ' + e;
  }
  setTimeout(() => { el.textContent = ''; }, 5000);
}

// ── 設定 ──
let currentCfg = {};

const CFG_FIELDS = [
  {k:'discord_webhook',   label:'Discord Webhook URL', type:'text',   desc:'空にするとDiscord通知無効'},
  {k:'debounce_seconds',  label:'デバウンス(秒)',       type:'number', desc:'同Ch+場所の重複通知を抑制する秒数'},
  {k:'chat_exclude',      label:'チャット除外キーワード', type:'csv',   desc:'カンマ区切り。例: いない,終わった'},
  {k:'patrol_dwell_secs', label:'巡回滞在(秒)',         type:'number', desc:'各Chに滞在する標準秒数'},
  {k:'adb_path',          label:'ADBパス',             type:'text',   desc:'adb.exeのフルパスまたは「adb」'},
  {k:'mumu_delay_ms',     label:'ADB間隔(ms)',         type:'number', desc:'各ADBコマンド間の待機時間'},
  {k:'mumu_tap_x',        label:'タップX座標',         type:'number', desc:'チャンネル入力欄のタップX'},
  {k:'mumu_tap_y',        label:'タップY座標',         type:'number', desc:'チャンネル入力欄のタップY'},
  {k:'mumu_clear_length', label:'クリア文字数',         type:'number', desc:'入力前にDELを送る回数'},
  {k:'mumu_pre_keycode',  label:'プリキーコード',       type:'text',   desc:'タップ前に送るキーコード'},
];

function renderConfigGrid(cfg) {
  currentCfg = Object.assign({}, cfg);
  const grid = document.getElementById('cfg-grid');
  grid.innerHTML = CFG_FIELDS.map(f => {
    let val = cfg[f.k];
    let inputHtml;
    if (f.type === 'csv') {
      const csvVal = Array.isArray(val) ? val.join(', ') : (val || '');
      inputHtml = '<textarea id="cfg_' + f.k + '" rows="2">' + csvVal + '</textarea>';
    } else if (f.type === 'number') {
      inputHtml = '<input type="number" id="cfg_' + f.k + '" value="' + (val ?? '') + '" step="any">';
    } else {
      inputHtml = '<input type="text" id="cfg_' + f.k + '" value="' + (val ?? '') + '">';
    }
    return '<div class="cfg-field"><label>' + f.label + '</label>' + inputHtml + '<span style="font-size:0.72em;color:#555">' + f.desc + '</span></div>';
  }).join('');
}

async function loadConfig() {
  try {
    const r = await fetch('/api/config');
    const cfg = await r.json();
    renderConfigGrid(cfg);
  } catch(e) {
    document.getElementById('cfg-grid').textContent = '読み込み失敗: ' + e;
  }
}

async function saveConfig() {
  const el = document.getElementById('cfg-status');
  const updated = Object.assign({}, currentCfg);
  CFG_FIELDS.forEach(f => {
    const inp = document.getElementById('cfg_' + f.k);
    if (!inp) return;
    if (f.type === 'number') {
      const n = parseFloat(inp.value);
      if (!isNaN(n)) updated[f.k] = n;
    } else if (f.type === 'csv') {
      updated[f.k] = inp.value.split(',').map(s=>s.trim()).filter(s=>s);
    } else {
      updated[f.k] = inp.value;
    }
  });
  el.textContent = '保存中...';
  try {
    const r = await fetch('/api/config', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(updated)
    });
    const d = await r.json();
    el.textContent = d.ok ? '✅ 保存完了' : '❌ 失敗: ' + JSON.stringify(d);
    if (d.ok) currentCfg = updated;
  } catch(e) {
    el.textContent = '❌ エラー: ' + e;
  }
  setTimeout(() => { if(el.textContent.includes('保存完了')) el.textContent = ''; }, 4000);
}

refreshDevices();
loadPatrolChannels();
pollPatrolStatus();
loadConfig();
</script>
</body>
</html>`
