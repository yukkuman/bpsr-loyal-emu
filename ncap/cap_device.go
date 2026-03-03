package ncap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/balrogsxt/StarResonanceAPI/global"
	"github.com/balrogsxt/StarResonanceAPI/location"
	"github.com/balrogsxt/StarResonanceAPI/notifier"
	"github.com/balrogsxt/StarResonanceAPI/pb"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// loyalBoarletTemplateID はゴールドウリボのテンプレートID
const loyalBoarletTemplateID = 10904

// positiveKeywords はワールドチャット検知キーワード
var positiveKeywords = []string{"金豚", "金ウリボ", "金ウリ", "ゴールドウリボ"}

// negativeKeywords はこれらを含むメッセージを誤検知として除外する（固定）
var negativeKeywords = []string{"銀", "ナッポ", "ナポ", "なぽ"}

// locationHints はチャンネル番号の隣に現れることが多い場所ヒントワード
var locationHints = []string{
	"偵察", "ミンホル", "ミンスターホルン", "テント", "崖", "カナミア",
	"休憩", "ミンスター", "畑", "麦", "tnt", "ぽにょ", "ポニョ", "ぽにょ",
	"qk", "右", "左",
}

// chatChLocationPatterns は「数字+ロケーションワード」「ロケーションワード+数字」パターン
// init() でビルドされる
var chatChLocationPatterns []*regexp.Regexp

func init() {
	for _, loc := range locationHints {
		esc := regexp.QuoteMeta(strings.ToLower(loc))
		// 数字→ロケーション: 「45 休憩」「45休憩」
		chatChLocationPatterns = append(chatChLocationPatterns,
			regexp.MustCompile(`([0-9]{1,3})\s*`+esc))
		// ロケーション→数字: 「休憩 45」「休憩45」
		chatChLocationPatterns = append(chatChLocationPatterns,
			regexp.MustCompile(esc+`\s*([0-9]{1,3})`))
	}
}

// playerPosition はプレイヤー座標
type playerPosition struct {
	X, Y, Z float32
}

// tcpSubStream はサーバーアドレスごとの独立した TCP 再組み立て状態
type tcpSubStream struct {
	buf       *bytes.Buffer
	nextSeq   uint32
	cache     map[uint32][]byte
	cacheTime map[uint32]time.Time
	lastPkt   time.Time
}

func newTCPSubStream() *tcpSubStream {
	return &tcpSubStream{
		buf:       bytes.NewBuffer(nil),
		cache:     make(map[uint32][]byte),
		cacheTime: make(map[uint32]time.Time),
	}
}

// session は1エミュレータインスタンス分のキャプチャ状態
type session struct {
	mu    sync.Mutex
	label string // "Instance-1" etc.

	clientEndpoint  string // "ip:port"（セッションキー、TCP接続ごとにユニーク）
	clientIP        string // エミュレータのIPアドレス（ポートなし、表示用）
	serverIP        string // 現在のプライマリゲームサーバーアドレス
	serverConfirmed bool      // 0x15/IDENT-P3 でサーバー確定済み
	confirmedAt     time.Time // serverConfirmed が true になった時刻（チャット紐付けの優先度に使用）

	// TCP 再組み立て（サーバーアドレスごとに独立）
	streams map[string]*tcpSubStream // key = "ip:port"

	// ゲーム状態
	userUID   uint64
	mapID     uint32
	lineID    uint32
	playerPos *playerPosition

	// サーバー判定用シグネチャ
	serverSignature      []byte
	loginReturnSignature []byte

	// タイムアウト設定
	idleTimeout     time.Duration
	gapTimeout      time.Duration
	lastAnyPacketAt time.Time
}

// getStream はサーバーアドレスに対応する sub-stream を返す（なければ新規作成）
func (s *session) getStream(serverAddr string) *tcpSubStream {
	if st, ok := s.streams[serverAddr]; ok {
		return st
	}
	st := newTCPSubStream()
	s.streams[serverAddr] = st
	return st
}

// newSession は新しいセッションを初期化する
func newSession(clientEndpoint, clientIP, label string) *session {
	return &session{
		label:           label,
		clientEndpoint:  clientEndpoint,
		clientIP:        clientIP,
		streams:         make(map[string]*tcpSubStream),
		serverSignature: []byte{0x00, 0x63, 0x33, 0x53, 0x42, 0x00},
		loginReturnSignature: []byte{
			0x00, 0x00, 0x00, 0x62,
			0x00, 0x03,
			0x00, 0x00, 0x00, 0x01,
			0x00, 0x11, 0x45, 0x14,
			0x00, 0x00, 0x00, 0x00,
			0x0a, 0x4e, 0x08, 0x01, 0x22, 0x24,
		},
		idleTimeout: 15 * time.Second,
		gapTimeout:  3 * time.Second,
	}
}

// resetTCPState は全 sub-stream をクリアする
func (s *session) resetTCPState() {
	s.streams = make(map[string]*tcpSubStream)
}

// CapDevice はマルチセッション対応の抓包デバイス
type CapDevice struct {
	deviceName string
	device     *pcap.Handle

	// セッション管理
	sessionsMu       sync.RWMutex
	sessions         map[string]*session // key = clientEndpoint ("ip:port")
	activeConns      map[string]string   // key = "src:port->dst:port", value = clientEndpoint
	instanceCounter  int
	freeInstanceNums []int               // 解放済みのインスタンス番号プール（再利用）

	// パケットキュー
	packetQueue *Queue[gopacket.Packet]

	// 検知・通知
	notifyFn      func(notifier.Detection)
	locStore      *location.Store
	debounce      time.Duration
	debounceMu    sync.Mutex
	debounceCache map[string]time.Time

	// チャット除外キーワード（config.json の chat_exclude から設定）
	chatExclude []string

	// チャット重複排除（複数インスタンスが同じメッセージを受信しても1回だけ通知）
	chatDedupMu sync.Mutex
	chatDedup   map[string]time.Time // key=sender+"\x00"+message, value=最終受信時刻
}

// NewCapDevice は新しいCapDeviceを生成する
func NewCapDevice(device *pcap.Handle, deviceName string) *CapDevice {
	return &CapDevice{
		deviceName:    deviceName,
		device:        device,
		sessions:      make(map[string]*session),
		activeConns:   make(map[string]string),
		packetQueue:   NewQueue[gopacket.Packet](),
		debounceCache: make(map[string]time.Time),
		debounce:      30 * time.Second,
		chatDedup:     make(map[string]time.Time),
	}
}

// SetNotifier は検知時に呼び出す関数を設定する
func (cd *CapDevice) SetNotifier(fn func(notifier.Detection)) {
	cd.notifyFn = fn
}

// SetChatExclude は config 由来の追加除外キーワードを設定する
func (cd *CapDevice) SetChatExclude(keywords []string) {
	cd.chatExclude = keywords
}

// nextInstanceNum は再利用可能な最小のインスタンス番号を返す
// (sessionsMu を保持した状態で呼ぶこと)
func (cd *CapDevice) nextInstanceNum() int {
	if len(cd.freeInstanceNums) > 0 {
		n := cd.freeInstanceNums[0]
		cd.freeInstanceNums = cd.freeInstanceNums[1:]
		return n
	}
	cd.instanceCounter++
	return cd.instanceCounter
}

// releaseInstanceLabel はラベル文字列からインスタンス番号を抽出してフリーリストに戻す
// (sessionsMu を保持した状態で呼ぶこと)
func (cd *CapDevice) releaseInstanceLabel(label string) {
	var n int
	if _, err := fmt.Sscanf(label, "Instance-%d", &n); err == nil && n > 0 {
		cd.freeInstanceNums = append(cd.freeInstanceNums, n)
		sort.Ints(cd.freeInstanceNums)
	}
}

// SetLocations はロケーションストアを設定する
func (cd *CapDevice) SetLocations(store *location.Store) {
	cd.locStore = store
}

// SetDebounce はデバウンス期間を設定する
func (cd *CapDevice) SetDebounce(d time.Duration) {
	cd.debounce = d
}

// CaptureSession はGUI向けにエクスポートするセッション情報
type CaptureSession struct {
	Label     string
	ClientIP  string
	UserUID   uint64
	MapID     uint32
	LineID    uint32
	Confirmed bool
}

// Sessions は現在の全セッションのスナップショットを返す。
// clientIP 単位で重複を除き、Confirmed または UserUID が有効なものを優先する。
func (cd *CapDevice) Sessions() []CaptureSession {
	cd.sessionsMu.RLock()
	defer cd.sessionsMu.RUnlock()

	seen := make(map[string]CaptureSession) // key = clientIP
	for _, s := range cd.sessions {
		s.mu.Lock()
		if s.clientIP == "" {
			s.mu.Unlock()
			continue
		}
		cur, exists := seen[s.clientIP]
		// confirmed または UID あり を優先して上書き
		if !exists || (!cur.Confirmed && s.serverConfirmed) || (cur.UserUID == 0 && s.userUID != 0) {
			seen[s.clientIP] = CaptureSession{
				Label:     s.label,
				ClientIP:  s.clientIP,
				UserUID:   s.userUID,
				MapID:     s.mapID,
				LineID:    s.lineID,
				Confirmed: s.serverConfirmed,
			}
		}
		s.mu.Unlock()
	}

	result := make([]CaptureSession, 0, len(seen))
	for _, v := range seen {
		result = append(result, v)
	}
	return result
}

// Start はパケットキャプチャを開始する
func (cd *CapDevice) Start() error {
	if cd.device == nil {
		return fmt.Errorf("網卡設備未設置")
	}
	if err := cd.device.SetBPFFilter("ip and tcp"); err != nil {
		return fmt.Errorf("設置過濾器失敗: %v", err)
	}

	log.Println("启动网络抓包:", cd.deviceName)

	go func() {
		for {
			if packet, ok := cd.packetQueue.Dequeue(); ok {
				cd.handlePacket(packet)
			} else {
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	go cd.cleanupSessions()

	packetSource := gopacket.NewPacketSource(cd.device, cd.device.LinkType())
	for packet := range packetSource.Packets() {
		if packet != nil {
			cd.packetQueue.Enqueue(packet)
		}
	}
	log.Fatalf("データパケットチャンネルが閉じられました")
	return nil
}

// cleanupSessions はアイドルセッションのTCP状態をリセットする
func (cd *CapDevice) cleanupSessions() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		cd.sessionsMu.RLock()
		var list []*session
		// 同一セッションが複数エンドポイントに登録されている場合も重複除去
		seen := make(map[*session]struct{})
		for _, s := range cd.sessions {
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				list = append(list, s)
			}
		}
		cd.sessionsMu.RUnlock()

		for _, s := range list {
			s.mu.Lock()
			if s.lastAnyPacketAt != (time.Time{}) && now.Sub(s.lastAnyPacketAt) > s.idleTimeout {
				hasData := false
				for _, st := range s.streams {
					if st.buf.Len() > 0 || len(st.cache) > 0 {
						hasData = true
						break
					}
				}
			if hasData || s.serverIP != "" {
				log.Printf("[%s] idle timeout → 状態リセット", s.label)
				s.resetTCPState()
				s.serverIP = ""

				if s.userUID != 0 {
					// 認証済みセッション（UID確定済）はマップに残して再接続時に再利用
					// インスタンスカウンターが増えないようにする
					s.serverConfirmed = false
					// エイリアス（チャンネル切替エンドポイント）のみ削除、primary endpointは残す
					cd.sessionsMu.Lock()
					for ep, sess := range cd.sessions {
						if sess == s && ep != s.clientEndpoint {
							delete(cd.sessions, ep)
						}
					}
					for k, v := range cd.activeConns {
						if _, ok := cd.sessions[v]; !ok {
							delete(cd.activeConns, k)
						}
					}
					cd.sessionsMu.Unlock()
				} else {
					// 未認証セッションはマップから完全削除してインスタンス番号を返却
					s.serverConfirmed = false
					cd.sessionsMu.Lock()
					cd.releaseInstanceLabel(s.label)
					for ep, sess := range cd.sessions {
						if sess == s {
							delete(cd.sessions, ep)
						}
					}
					for k, v := range cd.activeConns {
						if _, ok := cd.sessions[v]; !ok {
							delete(cd.activeConns, k)
						}
					}
					cd.sessionsMu.Unlock()
				}
			}
			}
			// 長時間アイドルの sub-stream を定期クリア
			for addr, st := range s.streams {
				if !st.lastPkt.IsZero() && now.Sub(st.lastPkt) > s.idleTimeout*2 {
					delete(s.streams, addr)
				}
			}
			s.mu.Unlock()
		}
	}
}

// ───── セッション管理 ─────

// mergeSessionIfDuplicate は同じ clientIP・userUID を持つ既存セッションが見つかれば
// newSess を existing にマージして既存セッションに統合する。
// newSess.mu は呼び出し元で保持している前提（sessionsMu → の順で追加取得）。
func (cd *CapDevice) mergeSessionIfDuplicate(newSess *session) {
	cd.sessionsMu.Lock()
	defer cd.sessionsMu.Unlock()

	var existing *session
	for ep, s := range cd.sessions {
		if s == newSess { // 同一セッションオブジェクト（別エンドポイント含む）はスキップ
			_ = ep
			continue
		}
		if s.userUID == 0 || s.userUID != newSess.userUID {
			continue
		}
		if s.clientIP != newSess.clientIP {
			continue
		}
		existing = s
		break
	}
	if existing == nil {
		return
	}

	log.Printf("[%s] → [%s] セッションマージ (UID=%d)", newSess.label, existing.label, newSess.userUID)

	// activeConns の向き先を既存セッションに変更
	for k, v := range cd.activeConns {
		if v == newSess.clientEndpoint {
			cd.activeConns[k] = existing.clientEndpoint
		}
	}

	// 重要な状態を既存セッションにコピー（packet処理は単一goroutineなので安全）
	if newSess.lineID != 0 {
		existing.lineID = newSess.lineID
		existing.mapID = newSess.mapID
		existing.serverConfirmed = true
		existing.confirmedAt = time.Now()
	}
	if newSess.serverIP != "" {
		existing.serverIP = newSess.serverIP
	}
	existing.userUID = newSess.userUID
	existing.lastAnyPacketAt = newSess.lastAnyPacketAt

	// newSess の TCP sub-stream を existing に移植する。
	// マージ後も同じ serverAddr のパケットが届くため、再組み立てバッファを引き継ぐ。
	for addr, st := range newSess.streams {
		if _, exists := existing.streams[addr]; !exists {
			existing.streams[addr] = st
		}
	}

	// newSess のラベルを既存セッションのラベルに揃えてログを統一
	origLabel := newSess.label // 番号返却用に保存
	newSess.label = existing.label

	// インスタンス番号をフリーリストに返却
	cd.releaseInstanceLabel(origLabel)
	// newSess のエンドポイントも existing に向けて残す。
	// こうすることでマージ後も同一ポートへのパケットが existing で処理され、
	// 0x06 (SyncNearEntities) 等の検知パケットが失われない。
	cd.sessions[newSess.clientEndpoint] = existing
}

func (cd *CapDevice) getOrCreateSession(clientEndpoint, clientIP string) *session {
	cd.sessionsMu.Lock()
	defer cd.sessionsMu.Unlock()
	if sess, ok := cd.sessions[clientEndpoint]; ok {
		return sess
	}
	num := cd.nextInstanceNum()
	label := fmt.Sprintf("Instance-%d", num)
	sess := newSession(clientEndpoint, clientIP, label)
	cd.sessions[clientEndpoint] = sess
	log.Printf("[%s] 新セッション作成: clientEndpoint=%s", label, clientEndpoint)
	return sess
}

// reuseOrCreateSession は同じ clientIP の確認済みセッションがあれば再利用し、
// 新エンドポイントを既存セッションに紐付ける（チャンネル移動時のインスタンス増加を防ぐ）。
// 注意: ゲームサーバー接続では使用しないこと（別アカウントを誤マージする）。
func (cd *CapDevice) reuseOrCreateSession(clientEndpoint, clientIP string) (*session, bool) {
	cd.sessionsMu.Lock()
	defer cd.sessionsMu.Unlock()

	// 既存エンドポイントがあればそのまま返す
	if sess, ok := cd.sessions[clientEndpoint]; ok {
		return sess, false
	}

	// 新規作成
	num := cd.nextInstanceNum()
	label := fmt.Sprintf("Instance-%d", num)
	sess := newSession(clientEndpoint, clientIP, label)
	cd.sessions[clientEndpoint] = sess
	log.Printf("[%s] 新セッション作成: clientEndpoint=%s", label, clientEndpoint)
	return sess, true
}

// findConfirmedSessionByClientIP は同 clientIP で確認済み（serverConfirmed or UID確定）の
// セッションを返す。チャットサーバー接続の紐付けに使用する。
// 同じ clientIP に複数の確認済みセッションがある場合（同一エミュレータ上の複数アカウント等）、
// 最後にゲームパケットが届いた時刻（lastAnyPacketAt）が最新のセッションを返す。
// これにより「直前にログインしたアカウント」のチャット接続が正しく紐付く。
func (cd *CapDevice) findConfirmedSessionByClientIP(clientIP string) *session {
	cd.sessionsMu.RLock()
	defer cd.sessionsMu.RUnlock()

	seenPtr := make(map[*session]struct{})
	var best *session
	for _, s := range cd.sessions {
		if _, dup := seenPtr[s]; dup {
			continue
		}
		seenPtr[s] = struct{}{}
		if s.clientIP != clientIP {
			continue
		}
		if !s.serverConfirmed && s.userUID == 0 {
			continue
		}
		// confirmedAt（セッション確立時刻）が最新のものを選ぶ。
		// 同一エミュレータ上の複数アカウントで同一 clientIP を持つ場合、
		// チャット接続の直前にログインしたアカウントが最新の confirmedAt を持つ。
		if best == nil || s.confirmedAt.After(best.confirmedAt) {
			best = s
		}
	}
	return best
}

func (cd *CapDevice) lookupSessionByConn(srcKey, revKey string) *session {
	cd.sessionsMu.RLock()
	defer cd.sessionsMu.RUnlock()
	if ep, ok := cd.activeConns[srcKey]; ok {
		if s, ok2 := cd.sessions[ep]; ok2 {
			return s
		}
	}
	if ep, ok := cd.activeConns[revKey]; ok {
		if s, ok2 := cd.sessions[ep]; ok2 {
			return s
		}
	}
	return nil
}

func (cd *CapDevice) getSessionByEndpoint(endpoint string) *session {
	cd.sessionsMu.RLock()
	defer cd.sessionsMu.RUnlock()
	return cd.sessions[endpoint]
}

func (cd *CapDevice) registerConn(srcKey, revKey, clientEndpoint string) {
	cd.sessionsMu.Lock()
	defer cd.sessionsMu.Unlock()
	cd.activeConns[srcKey] = clientEndpoint
	cd.activeConns[revKey] = clientEndpoint
}

// ───── パケット処理 ─────

func isPrivateIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 10 ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
		(ip4[0] == 192 && ip4[1] == 168)
}

func (cd *CapDevice) handlePacket(packet gopacket.Packet) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("handlePacket panic: %v", r)
		}
	}()

	if packet == nil {
		return
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return
	}
	payload := tcp.Payload
	if len(payload) == 0 {
		return
	}

	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()
	srcKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, tcp.SrcPort, dstIP, tcp.DstPort)
	revKey := fmt.Sprintf("%s:%d->%s:%d", dstIP, tcp.DstPort, srcIP, tcp.SrcPort)
	now := time.Now()

	// ① 既知の接続かチェック
	if sess := cd.lookupSessionByConn(srcKey, revKey); sess != nil {
		// どちら側がサーバーか判定（sub-stream のキーに使用）
		var serverAddr string
		if isPrivateIP(ip.SrcIP) {
			serverAddr = fmt.Sprintf("%s:%d", dstIP, tcp.DstPort) // client→server
		} else {
			serverAddr = fmt.Sprintf("%s:%d", srcIP, tcp.SrcPort) // server→client
		}
		sess.mu.Lock()
		sess.lastAnyPacketAt = now
		cd.reassembleTcpStream(sess, serverAddr, tcp, payload, now)
		sess.mu.Unlock()
		return
	}

	srcPrivate := isPrivateIP(ip.SrcIP)
	dstPrivate := isPrivateIP(ip.DstIP)

	if srcPrivate && !dstPrivate {
		// ② クライアント→サーバー：シグネチャでサーバーを識別
		cd.handleClientToServer(srcIP, srcKey, revKey, tcp, payload, now)
	} else if !srcPrivate && dstPrivate {
		// ③ サーバー→クライアント（fast-path：IDENT-P3前に届くケース）
		cd.handleServerToClientFast(srcIP, dstIP, srcKey, revKey, tcp, payload, now)
	}
	// 両方同じ側 → 無視
}

// handleClientToServer はクライアント→サーバー方向でゲームサーバーを識別する
func (cd *CapDevice) handleClientToServer(clientIP, srcKey, revKey string, tcp *layers.TCP, payload []byte, now time.Time) {
	clientEndpoint := fmt.Sprintf("%s:%d", clientIP, tcp.SrcPort)

	serverAddr := ""
	parts := strings.SplitN(revKey, "->", 2)
	if len(parts) == 2 {
		serverAddr = parts[0]
	}

	// 既存セッションがある場合は高速パス（識別不要）
	if existing := cd.getSessionByEndpoint(clientEndpoint); existing != nil {
		existing.mu.Lock()
		defer existing.mu.Unlock()

		// 同サーバーかつ sub-stream 確立済み → そのまま reassemble
		if existing.serverIP == serverAddr {
			if st, ok := existing.streams[serverAddr]; ok && st.nextSeq != 0 {
				cd.registerConn(srcKey, revKey, clientEndpoint)
				existing.lastAnyPacketAt = now
				cd.reassembleTcpStream(existing, serverAddr, tcp, payload, now)
				return
			}
		}

		// serverConfirmed後は既存 sub-stream があればそのまま（チャンネル切替時）
		if existing.serverConfirmed {
			if st, ok := existing.streams[serverAddr]; ok && st.nextSeq != 0 {
				if existing.serverIP != serverAddr {
					log.Printf("[%s] C→S: 接続切替登録 [%s] → [%s]", existing.label, existing.serverIP, serverAddr)
					existing.serverIP = serverAddr
				}
				cd.registerConn(srcKey, revKey, clientEndpoint)
				existing.lastAnyPacketAt = now
				cd.reassembleTcpStream(existing, serverAddr, tcp, payload, now)
				return
			}
		}

		// 既存セッション上で再識別（serverIP変更後の最初のパケット等）
		identified, initNextSeq, serverConfirmedNew := cd.tryIdentify(existing.serverSignature, existing.loginReturnSignature, tcp, payload)
		if !identified {
			return
		}
		if serverConfirmedNew {
			existing.serverConfirmed = true
			existing.confirmedAt = time.Now()
			log.Printf("[%s] IDENT-P3 でサーバー識別: %s", existing.label, serverAddr)
		} else {
			log.Printf("[%s] シグネチャでサーバー識別: %s", existing.label, serverAddr)
		}
		existing.getStream(serverAddr).nextSeq = initNextSeq
		if existing.serverIP != serverAddr {
			prev := existing.serverIP
			existing.serverIP = serverAddr
			if !existing.serverConfirmed {
				existing.resetTCPState()
				log.Printf("[%s] C→S: サーバー更新 [%s] → [%s]", existing.label, prev, serverAddr)
			}
		}
		cd.registerConn(srcKey, revKey, clientEndpoint)
		existing.lastAnyPacketAt = now
		cd.reassembleTcpStream(existing, serverAddr, tcp, payload, now)
		return
	}

	// DstPort < 9000 はチャットサーバー等。インスタンス識別は不要なので即スキップ。
	if tcp.DstPort < 9000 {
		return
	}

	defaultServerSig := []byte{0x00, 0x63, 0x33, 0x53, 0x42, 0x00}
	defaultLoginSig := []byte{
		0x00, 0x00, 0x00, 0x62, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x11, 0x45, 0x14, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x4e, 0x08, 0x01, 0x22, 0x24,
	}
	identified, initNextSeq, serverConfirmedNew := cd.tryIdentify(defaultServerSig, defaultLoginSig, tcp, payload)
	if !identified {
		return
	}

	sess := cd.getOrCreateSession(clientEndpoint, clientIP)
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if serverConfirmedNew {
		sess.serverConfirmed = true
		sess.confirmedAt = time.Now()
		log.Printf("[%s] IDENT-P3 でサーバー識別: %s", sess.label, serverAddr)
	} else {
		log.Printf("[%s] シグネチャでサーバー識別: %s", sess.label, serverAddr)
	}
	sess.getStream(serverAddr).nextSeq = initNextSeq
	if sess.serverIP != serverAddr {
		sess.serverIP = serverAddr
	}
	cd.registerConn(srcKey, revKey, clientEndpoint)
	sess.lastAnyPacketAt = now
	cd.reassembleTcpStream(sess, serverAddr, tcp, payload, now)
}

// tryIdentify はペイロードがゲームサーバーへのパケットかシグネチャで確認する
// 戻り値: (identified, initNextSeq, serverConfirmed)
func (cd *CapDevice) tryIdentify(serverSig, loginRetSig []byte, tcp *layers.TCP, payload []byte) (bool, uint32, bool) {
	// ログインリターンパケット (len=0x62)
	if len(payload) == 0x62 && len(loginRetSig) >= 20 {
		if bytes.Equal(payload[0:10], loginRetSig[0:10]) && bytes.Equal(payload[14:20], loginRetSig[14:20]) {
			return true, tcp.Seq + uint32(len(payload)), false
		}
	}

	// IDENT-P3 (payload[4]==0 && payload[5]==5)
	if len(payload) >= 10 && payload[4] == 0 && payload[5] == 5 {
		if cd.scanForP3Signature(payload[10:]) {
			return true, tcp.Ack, true
		}
	}

	// 通常シグネチャパケット (payload[4]==0)
	if len(payload) > 10 && payload[4] == 0 {
		data := payload[10:]
		payloadMs := bytes.NewBuffer(data)
		for payloadMs.Len() >= 4 {
			var lenBuf [4]byte
			n, err := payloadMs.Read(lenBuf[:])
			if err != nil || n != 4 {
				break
			}
			msgLen := binary.BigEndian.Uint32(lenBuf[:])
			if msgLen < 4 || msgLen > uint32(payloadMs.Len()) || msgLen > 0x0FFFFFFF {
				break
			}
			tmp := make([]byte, msgLen-4)
			n, err = payloadMs.Read(tmp)
			if err != nil || uint32(n) != msgLen-4 {
				break
			}
			sigLen := len(serverSig)
			if len(tmp) >= 5+sigLen && bytes.Equal(tmp[5:5+sigLen], serverSig) {
				return true, tcp.Seq + uint32(len(payload)), false
			}
		}
	}

	return false, 0, false
}

// handleServerToClientFast はサーバー→クライアント方向のfast-path処理
// チャンネル変更時に IDENT-P3 より先に 0x15 が届くケースに対応する
func (cd *CapDevice) handleServerToClientFast(srcIP, dstIP, srcKey, revKey string, tcp *layers.TCP, payload []byte, now time.Time) {
	// ポート443 は HTTPS/Discord/Cloudflare → ゲームサーバーではないので無視
	if tcp.SrcPort == 443 {
		return
	}

	clientIP := dstIP
	clientEndpoint := fmt.Sprintf("%s:%d", dstIP, tcp.DstPort)

	sess := cd.getSessionByEndpoint(clientEndpoint)
	if sess == nil {
		if tcp.SrcPort >= 9000 {
			// ゲームサーバー: IPが同じでも別アカウントの可能性があるため常に新規作成。
			// 同一アカウントの再接続は mergeSessionIfDuplicate (0x15 受信時) でマージする。
			sess = cd.getOrCreateSession(clientEndpoint, clientIP)
		} else {
			// チャットサーバー等 (SrcPort < 9000):
			// どのインスタンスのチャットかは区別不要。
			// port 5003 のみ処理。任意の確認済みセッションに紐付けて解析する。
			if tcp.SrcPort != 5003 {
				return
			}
			sess = cd.findConfirmedSessionByClientIP(clientIP)
			if sess == nil {
				return
			}
			cd.sessionsMu.Lock()
			cd.sessions[clientEndpoint] = sess
			cd.sessionsMu.Unlock()
		}
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	newServerAddr := fmt.Sprintf("%s:%d", srcIP, tcp.SrcPort)

	if !sess.serverConfirmed && sess.userUID == 0 {
		// 完全未確定（UID未取得）時のみ旧ロジック：ゲームサーバーポート（9000以上）以外は無視
		if tcp.SrcPort < 9000 {
			return
		}
		if sess.serverIP != newServerAddr {
			log.Printf("[%s] fast-path: サーバー変更 [%s] → [%s]", sess.label, sess.serverIP, newServerAddr)
			sess.serverIP = newServerAddr
			// 未確定時は古い sub-stream をクリア
			sess.streams = make(map[string]*tcpSubStream)
			cd.sessionsMu.Lock()
			for k, v := range cd.activeConns {
				if v == clientEndpoint {
					delete(cd.activeConns, k)
				}
			}
			cd.sessionsMu.Unlock()
		}
	} else {
		// serverConfirmed、またはUID確定済み（idle timeout後のチャットサーバー接続等）：
		// TCPリセットなしで各 serverAddr の sub-stream に振り分ける
		// （10045↔10497 などダンジョン遷移時の複数サーバー同時通信に対応）
		if sess.serverIP != newServerAddr {
			log.Printf("[%s] fast-path: 接続受付 [%s] (primary=[%s])", sess.label, newServerAddr, sess.serverIP)
		}
	}

	cd.registerConn(srcKey, revKey, clientEndpoint)
	sess.lastAnyPacketAt = now
	cd.reassembleTcpStream(sess, newServerAddr, tcp, payload, now)
}

// scanForP3Signature は IDENT-P3 の専用シグネチャを探す
func (cd *CapDevice) scanForP3Signature(data []byte) bool {
	signature := []byte{0x00, 0x06, 0x26, 0xad, 0x66, 0x00}
	reader := bytes.NewReader(data)
	for {
		lenBuf := make([]byte, 4)
		n, err := reader.Read(lenBuf)
		if err != nil || n != 4 {
			break
		}
		length := binary.BigEndian.Uint32(lenBuf)
		if length < 4 || length > 0x0FFFFFFF {
			break
		}
		if int(length-4) > reader.Len() {
			break
		}
		data1 := make([]byte, length-4)
		n, err = reader.Read(data1)
		if err != nil || uint32(n) != length-4 {
			break
		}
		sigLen := len(signature)
		if len(data1) >= 5+sigLen && bytes.Equal(data1[5:5+sigLen], signature) {
			return true
		}
	}
	return false
}

// ───── TCP 再組み立て ─────

// reassembleTcpStream は serverAddr の sub-stream に対して TCP を再組み立てする
func (cd *CapDevice) reassembleTcpStream(sess *session, serverAddr string, tcp *layers.TCP, payload []byte, now time.Time) {
	st := sess.getStream(serverAddr)

	if st.nextSeq == 0 {
		st.nextSeq = tcp.Seq
	}

	st.cache[tcp.Seq] = make([]byte, len(payload))
	copy(st.cache[tcp.Seq], payload)
	st.cacheTime[tcp.Seq] = now

	cd.cleanupOldCache(st, sess.gapTimeout, now)

	buf := bytes.NewBuffer(nil)
	cur := st.nextSeq
	for {
		if d, exists := st.cache[cur]; exists {
			buf.Write(d)
			delete(st.cache, cur)
			delete(st.cacheTime, cur)
			st.nextSeq = cur + uint32(len(d))
			cur = st.nextSeq
			st.lastPkt = now
		} else {
			break
		}
	}

	if buf.Len() > 0 {
		st.buf.Write(buf.Bytes())
	}

	cd.parseMessages(sess, st)
}

func (cd *CapDevice) cleanupOldCache(st *tcpSubStream, gapTimeout time.Duration, now time.Time) {
	if len(st.cache) < 100 {
		return
	}
	for seq, t := range st.cacheTime {
		if now.Sub(t) > gapTimeout {
			delete(st.cache, seq)
			delete(st.cacheTime, seq)
		}
	}
	if len(st.cache) > 1000 {
		cnt := 0
		for seq := range st.cache {
			if cnt >= 500 {
				break
			}
			delete(st.cache, seq)
			delete(st.cacheTime, seq)
			cnt++
		}
	}
}

func (cd *CapDevice) parseMessages(sess *session, st *tcpSubStream) {
	data := st.buf.Bytes()
	total := len(data)
	offset := 0

	for offset < total {
		if offset+4 > total {
			break
		}
		pktSize := binary.BigEndian.Uint32(data[offset : offset+4])
		if pktSize <= 4 || pktSize > 0x0FFFFF {
			break
		}
		if offset+int(pktSize) > total {
			break
		}
		pkt := make([]byte, pktSize)
		copy(pkt, data[offset:offset+int(pktSize)])
		cd.handleProcess(sess, pkt)
		offset += int(pktSize)
	}

	if offset > 0 {
		rem := data[offset:]
		st.buf.Reset()
		st.buf.Write(rem)
	}
}

// ───── パケット解析 ─────

func (cd *CapDevice) handleProcess(sess *session, packets []byte) {
	if len(packets) < 4 {
		return
	}
	reader := NewByteReader(packets)
	for reader.Remaining() > 0 {
		pktSize, ok := reader.TryPeekUInt32BE()
		if !ok {
			break
		}
		if pktSize < 6 || pktSize > uint32(reader.Remaining()) || pktSize > 0x0FFFFFFF {
			break
		}
		pktData, err := reader.ReadBytes(int(pktSize))
		if err != nil {
			break
		}
		if len(pktData) < 6 {
			continue
		}
		pr := NewByteReader(pktData)
		sizeAgain, err := pr.ReadUInt32BE()
		if err != nil || sizeAgain != pktSize {
			continue
		}
		pktType, err := pr.ReadUInt16BE()
		if err != nil {
			continue
		}
		isZstd := (pktType & 0x8000) != 0
		msgTypeId := pktType & 0x7FFF
		cd.dispatchMessage(sess, msgTypeId, pr, isZstd)
	}
}

func (cd *CapDevice) dispatchMessage(sess *session, msgTypeId uint16, reader *ByteReader, isZstd bool) {
	switch msgTypeId {
	case 1, 3:
		// チャット専用フレーム: 16バイトヘッダをスキップしてチャットスキャン
		raw := reader.ReadRemaining()
		if isZstd {
			raw = decompressZstd(raw)
		}
		cd.tryScanFrameAsChat(sess, raw)
	case 2: // NotifyMsg
		// まずゲームロジック（サービスUUID一致時）として処理。
		// サービスUUID不一致の場合もチャット候補としてスキャンする。
		raw := reader.ReadRemaining()
		if isZstd {
			raw = decompressZstd(raw)
		}
		if !cd.processNotifyMsgBytes(sess, raw) {
			// UUID不一致 → チャット候補として試みる
			cd.tryScanFrameAsChat(sess, raw)
		}
	case 6: // FrameDown
		cd.processFrameDown(sess, reader, isZstd)
	}
}

// tryScanFrameAsChat は生バイト列の先頭16バイトをヘッダとしてスキップしチャットをスキャンする。
// TypeScript PacketListener の parseChatFromFrame と同じオフセット戦略。
// TODO: チャット検知を一時的に無効化
func (cd *CapDevice) tryScanFrameAsChat(sess *session, raw []byte) {
	// チャット検知は現在無効化中
	_ = sess
	_ = raw
}

func (cd *CapDevice) processNotifyMsg(sess *session, reader *ByteReader, isZstd bool) {
	raw := reader.ReadRemaining()
	if isZstd {
		raw = decompressZstd(raw)
	}
	cd.processNotifyMsgBytes(sess, raw)
}

// processNotifyMsgBytes はバイト列から NotifyMsg を処理する。
// サービスUUIDが一致した場合 true を返す。
func (cd *CapDevice) processNotifyMsgBytes(sess *session, raw []byte) bool {
	if len(raw) < 16 {
		return false
	}
	serviceUuid := binary.BigEndian.Uint64(raw[0:8])
	methodId := binary.BigEndian.Uint32(raw[12:16])
	if serviceUuid != 0x0000000063335342 {
		return false
	}
	msgPayload := raw[16:]
	cd.processNotifyMethod(sess, methodId, msgPayload)
	return true
}

func (cd *CapDevice) processFrameDown(sess *session, reader *ByteReader, isZstd bool) {
	if _, err := reader.ReadUInt32BE(); err != nil {
		return
	}
	if reader.Remaining() == 0 {
		return
	}
	nested := reader.ReadRemaining()
	if isZstd {
		nested = decompressZstd(nested)
	}
	cd.handleProcess(sess, nested)
}

func (cd *CapDevice) processNotifyMethod(sess *session, methodId uint32, payload []byte) {
	switch methodId {
	case 0x03:
		cd.processSyncSceneData(sess, payload)
	case 0x00000006:
		cd.processSyncNearEntities(sess, payload)
	case 0x00000015:
		cd.processSyncContainerData(sess, payload)
	case 0x00000016:
		// lineId は 0x15 で取得済み。差分パケットからは取得しない
	case 0x0000002E:
		cd.processSyncToMeDeltaInfo(sess, payload)
	case 0x0000002D:
		cd.processSyncNearDeltaInfo(sess, payload)
	default:
		// ワールドチャット候補：未知メソッドをキーワードスキャン（現在無効化中）
		// cd.tryScanChatPayload(sess, payload)
	}
}

// ───── 0x15 SyncContainerData ─────

func (cd *CapDevice) processSyncContainerData(sess *session, payload []byte) {
	var msg pb.SyncContainerData
	if err := proto.Unmarshal(payload, &msg); err != nil {
		log.Printf("[%s][0x15] proto解析失敗: %v (len=%d)", sess.label, err, len(payload))
		return
	}
	vdata := msg.GetVData()
	if vdata == nil {
		return
	}

	if cid := uint64(vdata.GetCharId()); cid > 0 && sess.userUID != cid {
		sess.userUID = cid
		log.Printf("[%s][0x15] charId=%d", sess.label, cid)
		cd.mergeSessionIfDuplicate(sess) // 同一キャラの既存セッションがあれば統合
	}

	sd := vdata.GetSceneData()
	if sd == nil {
		return
	}

	mapID := uint32(sd.GetMapId())
	lineID := uint32(sd.GetLineId())
	log.Printf("[%s][0x15] mapID=%d lineID=%d", sess.label, mapID, lineID)

	if lineID == 0 {
		return
	}

	oldCh := sess.lineID
	if mapID != 0 {
		sess.mapID = mapID
	}
	sess.lineID = lineID
	sess.serverConfirmed = true // 0x15 でCh確定→以降のfast-path切り替えをゲームサーバーのみ許可
	if sess.confirmedAt.IsZero() {
		sess.confirmedAt = time.Now() // 最初の0x15確定時のみ記録（チャット紐付けの優先度用）
	}

	if oldCh == 0 {
		log.Printf("[%s][Ch確定] Ch %d に入りました (mapID=%d)", sess.label, lineID, mapID)
	} else if oldCh != lineID {
		log.Printf("[%s][Ch変更] Ch %d → Ch %d (mapID=%d)", sess.label, oldCh, lineID, mapID)
	}
}

// ───── 0x06 SyncNearEntities ─────

func (cd *CapDevice) processSyncNearEntities(sess *session, payload []byte) {
	var msg pb.SyncNearEntities
	if err := proto.Unmarshal(payload, &msg); err != nil {
		log.Printf("[%s][0x06] proto解析失敗: %v", sess.label, err)
		return
	}

	for _, item := range msg.GetAppear() {
		if item.GetEntityType() != pb.EEntityType_EntMonster {
			continue
		}
		attrs := item.GetAttrs()
		if attrs == nil {
			continue
		}

		var name string
		var tmplID uint64
		var posX, posY, posZ float32

		for _, attr := range attrs.GetAttrs() {
			if attr.Id == nil {
				continue
			}
			switch attr.GetId() {
			case 0x01: // 名前
				if v, n := protowire.ConsumeString(attr.GetRawData()); n > 0 && v != "" {
					name = v
				}
			case 0x0A: // テンプレートID
				if v, n := protowire.ConsumeVarint(attr.GetRawData()); n > 0 {
					tmplID = v
					if mn, ok := global.MonsterNames[v]; ok && name == "" {
						name = mn
					}
				}
			case 53: // 座標
				var posMsg pb.Vector3
				if err := proto.Unmarshal(attr.GetRawData(), &posMsg); err == nil {
					posX, posY, posZ = posMsg.GetX(), posMsg.GetY(), posMsg.GetZ()
				}
			}
		}

		if tmplID == loyalBoarletTemplateID || isLoyalBoarletName(name) {
			pos := &playerPosition{X: posX, Y: posY, Z: posZ}
			log.Printf("[%s][検知] ゴールドウリボ: name=%s tmplID=%d pos=(%.1f,%.1f,%.1f) Ch=%d",
				sess.label, name, tmplID, posX, posY, posZ, sess.lineID)
			cd.triggerDetection(sess, notifier.SourceAuto, name, pos, 0)
		}
	}
}

func isLoyalBoarletName(name string) bool {
	if name == "" {
		return false
	}
	for _, kw := range []string{"ゴールドウリボ", "金ウリボ", "金ウリ", "金豚", "小猪·闪闪", "金猪"} {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

// ───── 0x2E SyncToMeDeltaInfo ─────

func (cd *CapDevice) processSyncToMeDeltaInfo(sess *session, payload []byte) {
	var msg pb.SyncToMeDeltaInfo
	if err := proto.Unmarshal(payload, &msg); err != nil {
		return
	}
	info := msg.GetDeltaInfo()
	if info == nil {
		return
	}
	if info.Uuid != nil {
		if uid := uint64(info.GetUuid()); uid != 0 && uid != sess.userUID {
			sess.userUID = uid
			log.Printf("[%s][0x2E] UUID=%d (UID=%d)", sess.label, uid, uid>>16)
			cd.mergeSessionIfDuplicate(sess) // 同一キャラの既存セッションがあれば統合
		}
	}
	bd := info.GetBaseDelta()
	if bd == nil || bd.Attrs == nil {
		return
	}
	for _, attr := range bd.Attrs.GetAttrs() {
		if attr.GetId() == 53 {
			var v pb.Vector3
			if proto.Unmarshal(attr.GetRawData(), &v) == nil {
				if sess.playerPos == nil {
					sess.playerPos = &playerPosition{}
				}
				sess.playerPos.X = v.GetX()
				sess.playerPos.Y = v.GetY()
				sess.playerPos.Z = v.GetZ()
			}
		}
	}
}

// ───── 0x2D SyncNearDeltaInfo ─────

func (cd *CapDevice) processSyncNearDeltaInfo(sess *session, payload []byte) {
	// 将来的に周辺エンティティの死亡検知等を実装するための拡張ポイント
	_ = sess
	_ = payload
}

// ───── 0x03 SyncSceneData ─────

func (cd *CapDevice) processSyncSceneData(sess *session, payload []byte) {
	if len(payload) < 43 {
		return
	}
	l := int(payload[42])
	st := 43
	if st+l > len(payload) {
		l = len(payload) - st
	}
	if l <= 0 {
		return
	}
	log.Printf("[%s][0x03] シーン切替: %s", sess.label, string(payload[st:st+l]))
}

// ───── ワールドチャット raw スキャン ─────

// ───── チャット proto パーサー ─────

type protoField struct {
	num uint32
	wt  byte
	vi  uint64
	raw []byte
}

func parseProtoFields(b []byte) []protoField {
	var out []protoField
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			break
		}
		b = b[n:]
		wt := byte(tag & 0x07)
		num := uint32(tag >> 3)
		switch wt {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return out
			}
			b = b[n:]
			out = append(out, protoField{num: num, wt: 0, vi: v})
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return out
			}
			b = b[n:]
			out = append(out, protoField{num: num, wt: 2, raw: b[:l]})
			b = b[l:]
		default:
			return out
		}
	}
	return out
}

func protoUnwrapFields(fields []protoField) []protoField {
	for depth := 0; depth < 2; depth++ {
		if len(fields) == 1 && fields[0].wt == 2 {
			inner := parseProtoFields(fields[0].raw)
			if len(inner) > 0 {
				fields = inner
				continue
			}
		}
		break
	}
	return fields
}

func toHalfWidth(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '０' && r <= '９' {
			b.WriteRune(r - '０' + '0')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func extractChatChannel(text string) uint32 {
	norm := strings.ToLower(toHalfWidth(text))

	// 数字+ロケーションワード または ロケーションワード+数字
	// 「45 休憩」「休憩 45」「45休憩」「休憩45」などに対応
	for _, p := range chatChLocationPatterns {
		if m := p.FindStringSubmatch(norm); len(m) > 1 {
			if n, err := strconv.ParseUint(m[1], 10, 32); err == nil {
				return uint32(n)
			}
		}
	}

	return 0
}

func (cd *CapDevice) tryScanChatPayload(sess *session, payload []byte) {
	if len(payload) < 4 {
		return
	}

	fields := protoUnwrapFields(parseProtoFields(payload))
	if len(fields) == 0 {
		return
	}

	var channel uint32
	var sender, message string
	channelFound := false

	extractMsg := func(b []byte) {
		for _, sf := range parseProtoFields(b) {
			if sf.num == 3 && sf.wt == 2 {
				message = string(sf.raw)
			}
		}
	}
	extractSender := func(b []byte) {
		for _, sf := range parseProtoFields(b) {
			if sf.num == 2 && sf.wt == 2 {
				sender = string(sf.raw)
			}
		}
		if sender == "" {
			sender = string(b)
		}
	}

	for _, f := range fields {
		switch {
		case f.num == 1 && f.wt == 0:
			channel = uint32(f.vi)
			channelFound = true
		case f.num == 2 && f.wt == 2:
			for _, sf := range parseProtoFields(f.raw) {
				if sf.num == 2 && sf.wt == 2 {
					extractSender(sf.raw)
				}
				if sf.num == 4 && sf.wt == 2 {
					extractMsg(sf.raw)
				}
			}
		case f.num == 4 && f.wt == 2:
			extractMsg(f.raw)
		}
	}

	// ワールドチャット（channel==1）のみ処理
	// channel フィールドが存在しない or ≠1 の場合はデバッグログのみ
	if message == "" {
		return
	}

	senderDisplay := sender
	if senderDisplay == "" {
		senderDisplay = "?"
	}

	chLabel := "?"
	if channelFound {
		chLabel = fmt.Sprintf("%d", channel)
	}

	// 重複排除：複数インスタンスが同じメッセージを受信しても1回だけ処理する
	dedupKey := senderDisplay + "\x00" + message
	cd.chatDedupMu.Lock()
	now := time.Now()
	if t, seen := cd.chatDedup[dedupKey]; seen && now.Sub(t) < 5*time.Second {
		cd.chatDedupMu.Unlock()
		return
	}
	cd.chatDedup[dedupKey] = now
	// 古いエントリを定期的に削除（10秒以上前のもの）
	for k, t := range cd.chatDedup {
		if now.Sub(t) > 10*time.Second {
			delete(cd.chatDedup, k)
		}
	}
	cd.chatDedupMu.Unlock()

	// チャット全件ログ
	log.Printf("[チャット ch=%s] %s: %s", chLabel, senderDisplay, message)

	// ワールドチャット (channel==1) 以外は検知対象外
	if !channelFound || channel != 1 {
		return
	}

	lower := strings.ToLower(toHalfWidth(message))
	// 固定除外キーワード
	for _, nkw := range negativeKeywords {
		if strings.Contains(lower, nkw) {
			log.Printf("[チャット除外(固定:%s)] %s: %s", nkw, senderDisplay, message)
			return
		}
	}
	// config 由来の追加除外キーワード
	for _, nkw := range cd.chatExclude {
		if nkw != "" && strings.Contains(lower, strings.ToLower(toHalfWidth(nkw))) {
			log.Printf("[チャット除外(設定:%s)] %s: %s", nkw, senderDisplay, message)
			return
		}
	}
	for _, kw := range positiveKeywords {
		if strings.Contains(lower, kw) {
			chatCh := extractChatChannel(message)
			chStr := "不明"
			if chatCh > 0 {
				chStr = fmt.Sprintf("%d", chatCh)
			}
			log.Printf("[チャット検知!] ch=%s kw=%s  %s: %s", chStr, kw, senderDisplay, message)
			cd.triggerDetection(sess, notifier.SourceChat, kw, sess.playerPos, chatCh)
			return
		}
	}
}

// ───── 検知・通知 ─────

func (cd *CapDevice) triggerDetection(sess *session, source, name string, pos *playerPosition, chatLineID uint32) {
	if cd.notifyFn == nil {
		return
	}

	// デバウンスキーの決定:
	//   SourceAuto (モブ自動検知): Ch番号単位でデバウンス。
	//     同一Ch内の同一モブは複数インスタンスが検知しても1回だけ通知。
	//     別Chは独立して通知。lineID=0（未確定）の場合はラベル番号で退避。
	//   SourceChat (チャット検知): ch番号付きでグローバルデバウンス。
	var key string
	switch source {
	case notifier.SourceChat:
		keyName := name
		if chatLineID > 0 {
			keyName = fmt.Sprintf("%s|ch%d", name, chatLineID)
		}
		key = fmt.Sprintf("GLOBAL|%s|%s", source, keyName)
	default: // SourceAuto など
		chKey := sess.label // lineID未確定時はラベルで代替
		if sess.lineID != 0 {
			chKey = fmt.Sprintf("ch%d", sess.lineID)
		}
		key = fmt.Sprintf("%s|%s|%s", chKey, source, name)
	}
	cd.debounceMu.Lock()
	if last, ok := cd.debounceCache[key]; ok && time.Since(last) < cd.debounce {
		cd.debounceMu.Unlock()
		log.Printf("[%s] デバウンス: %s (%v 経過)", sess.label, name, time.Since(last).Round(time.Second))
		return
	}
	cd.debounceCache[key] = time.Now()
	cd.debounceMu.Unlock()

	locName := ""
	if cd.locStore != nil && pos != nil && sess.mapID != 0 {
		vec := location.Vec3{X: pos.X, Y: pos.Y, Z: pos.Z}
		if loc, ok := cd.locStore.Nearest(sess.mapID, vec); ok {
			locName = loc.Name
		}
	}

	det := notifier.Detection{
		Source:        source,
		LineID:        sess.lineID,
		ChatLineID:    chatLineID,
		Location:      locName,
		MonsterName:   name,
		InstanceLabel: sess.label,
		Time:          time.Now(),
	}
	if source == notifier.SourceChat {
		det.Message = name
		det.MonsterName = ""
	}

	go cd.notifyFn(det)
}

// ForceDetect はテスト用。確認済みセッションのプレイヤー位置をゴールドウリボ検知として通知する。
// notifyFn と locStore を直接参照して triggerDetection と同等の処理を行う。
func (cd *CapDevice) ForceDetect() {
	if cd.notifyFn == nil {
		log.Println("[ForceDetect] notifyFn が未設定です")
		return
	}

	cd.sessionsMu.RLock()
	var best *session
	seen := make(map[*session]struct{})
	for _, s := range cd.sessions {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		if s.serverConfirmed && s.lineID != 0 {
			if best == nil || s.confirmedAt.After(best.confirmedAt) {
				best = s
			}
		}
	}
	cd.sessionsMu.RUnlock()

	if best == nil {
		log.Println("[ForceDetect] 確認済みセッションが見つかりません (Ch未確定)")
		return
	}

	best.mu.Lock()
	pos := best.playerPos
	mapID := best.mapID
	lineID := best.lineID
	label := best.label
	best.mu.Unlock()

	locName := ""
	if cd.locStore != nil && pos != nil && mapID != 0 {
		vec := location.Vec3{X: pos.X, Y: pos.Y, Z: pos.Z}
		if loc, ok := cd.locStore.Nearest(mapID, vec); ok {
			locName = loc.Name
		}
	}

	posStr := "不明"
	if pos != nil {
		posStr = fmt.Sprintf("(%.1f, %.1f, %.1f)", pos.X, pos.Y, pos.Z)
	}
	log.Printf("[ForceDetect] テスト通知発火: Ch=%d label=%s pos=%s loc=%s", lineID, label, posStr, locName)

	cd.notifyFn(notifier.Detection{
		Source:        notifier.SourceAuto,
		LineID:        lineID,
		MonsterName:   "ゴールドウリボ(テスト)",
		Location:      locName,
		InstanceLabel: label,
		Time:          time.Now(),
	})
}

// ───── ユーティリティ ─────

func decompressZstd(buf []byte) []byte {
	if len(buf) < 4 {
		return buf
	}
	r, err := zstd.NewReader(bytes.NewReader(buf))
	if err != nil {
		return buf
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return buf
	}
	return out
}

func isPlayerUUID(uuid uint64) bool { return (uuid & 0xFFFF) == 640 }
func isMonsterUUID(uuid uint64) bool { return (uuid & 0xFFFF) == 64 }

// suppress unused warnings
var _ = isPlayerUUID
var _ = isMonsterUUID
