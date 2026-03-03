// Package mumu はMuMu Playerエミュレーターに対してADB経由でチャンネル切替を行う。
// uribo-discord-watcher/src/mumu.rs をGo移植したもの。
package mumu

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config はADB操作の設定
type Config struct {
	ADBPath     string
	TapX        int
	TapY        int
	ClearLength int
	PreKeycode  string
	GlobalDelay time.Duration
}

// DefaultConfig はデフォルト値を返す
func DefaultConfig() Config {
	return Config{
		ADBPath:     "adb",
		TapX:        975,
		TapY:        664,
		ClearLength: 3,
		PreKeycode:  "KEYCODE_P",
		GlobalDelay: 800 * time.Millisecond,
	}
}

// newCmd は HideWindow: true でコマンドを作成する（GUIモード時のコンソール点滅防止）
func newCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

func runAdb(cfg Config, args ...string) (string, error) {
	cmd := newCmd(cfg.ADBPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("adb %v: %w\n%s", args, err, string(out))
	}
	if cfg.GlobalDelay > 0 {
		time.Sleep(cfg.GlobalDelay)
	}
	return strings.TrimSpace(string(out)), nil
}

func adb(serial string, cfg Config, args ...string) (string, error) {
	full := append([]string{"-s", serial}, args...)
	return runAdb(cfg, full...)
}

// RestartServer は adb kill-server → adb start-server でADBサーバーを再起動する。
// ADB接続が切れた場合の復旧に使用する。
func RestartServer(cfg Config) error {
	log.Println("[MuMu] adb kill-server...")
	// kill-server は失敗しても無視（既に停止済みの場合あり）
	_ = newCmd(cfg.ADBPath, "kill-server").Run()
	time.Sleep(500 * time.Millisecond)

	log.Println("[MuMu] adb start-server...")
	out, err := newCmd(cfg.ADBPath, "start-server").CombinedOutput()
	if err != nil {
		return fmt.Errorf("adb start-server: %w\n%s", err, string(out))
	}
	log.Println("[MuMu] ADBサーバー再起動完了")
	time.Sleep(500 * time.Millisecond)
	return nil
}

// ListDevices は接続中のADBデバイス一覧を返す。
// 毎回 adb kill-server/start-server を実行してからデバイスを列挙する。
func ListDevices(cfg Config) ([]string, error) {
	if restartErr := RestartServer(cfg); restartErr != nil {
		log.Printf("[MuMu] ADB再起動失敗: %v", restartErr)
	}
	log.Println("[MuMu] デバイス一覧を取得中...")
	devices, err := listDevicesOnce(cfg)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		log.Println("[MuMu] デバイスが見つかりません。ADBでエミュレーターが認識されているか確認してください")
	}
	return devices, nil
}

func listDevicesOnce(cfg Config) ([]string, error) {
	out, err := runAdb(cfg, "devices")
	if err != nil {
		log.Printf("[MuMu] adb devices 失敗: %v", err)
		return nil, err
	}
	// 生出力を全行ログ（\n 展開して見やすく）
	log.Printf("[MuMu] adb devices 出力:\n%s", out)

	var devices []string
	var offline []string
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		switch parts[1] {
		case "device":
			devices = append(devices, parts[0])
		case "offline", "unauthorized":
			offline = append(offline, parts[0]+"("+parts[1]+")")
		}
	}
	if len(offline) > 0 {
		log.Printf("[MuMu] 接続不可デバイス: %v", offline)
	}
	log.Printf("[MuMu] 有効デバイス: %v (%d台)", devices, len(devices))
	return devices, nil
}

// SwitchChannel は指定デバイスを指定チャンネルに切り替える。
// 失敗した場合は adb kill-server/start-server で復旧してリトライする。
func SwitchChannel(serial string, channel uint32, cfg Config) error {
	err := switchChannelOnce(serial, channel, cfg)
	if err != nil {
		log.Printf("[MuMu] switch_channel失敗(%v)、ADBサーバーを再起動してリトライ...", err)
		if restartErr := RestartServer(cfg); restartErr != nil {
			log.Printf("[MuMu] ADB再起動失敗: %v", restartErr)
			return err // 再起動失敗なら元のエラーを返す
		}
		return switchChannelOnce(serial, channel, cfg)
	}
	return nil
}

func switchChannelOnce(serial string, channel uint32, cfg Config) error {
	log.Printf("[MuMu] switch_channel: serial=%s channel=%d", serial, channel)

	// Pキーでチャンネル入力を開く
	if cfg.PreKeycode != "" {
		if _, err := adb(serial, cfg, "shell", "input", "keyevent", cfg.PreKeycode); err != nil {
			return fmt.Errorf("pre_keycode: %w", err)
		}
	}

	// タップで入力欄をフォーカス
	if cfg.TapX > 0 && cfg.TapY > 0 {
		tapArgs := []string{"shell", "input", "tap",
			fmt.Sprintf("%d", cfg.TapX),
			fmt.Sprintf("%d", cfg.TapY),
		}
		if _, err := adb(serial, cfg, tapArgs...); err != nil {
			return fmt.Errorf("tap: %w", err)
		}
	}

	// 既存テキストを削除
	for i := 0; i < cfg.ClearLength; i++ {
		if _, err := adb(serial, cfg, "shell", "input", "keyevent", "KEYCODE_DEL"); err != nil {
			return fmt.Errorf("clear[%d]: %w", i, err)
		}
	}

	// チャンネル番号を入力
	if _, err := adb(serial, cfg, "shell", "input", "text", fmt.Sprintf("%d", channel)); err != nil {
		return fmt.Errorf("input text: %w", err)
	}

	// Enterで確定
	if _, err := adb(serial, cfg, "shell", "input", "keyevent", "KEYCODE_ENTER"); err != nil {
		return fmt.Errorf("enter: %w", err)
	}

	// Pキーでチャンネル入力を閉じる（満員時のダイアログも閉じる）
	if cfg.PreKeycode != "" {
		if _, err := adb(serial, cfg, "shell", "input", "keyevent", cfg.PreKeycode); err != nil {
			return fmt.Errorf("pre_keycode: %w", err)
		}
	}

	log.Printf("[MuMu] switch_channel done: serial=%s channel=%d", serial, channel)
	return nil
}

// SwitchAll は全デバイスを同じチャンネルに切り替える
func SwitchAll(serials []string, channel uint32, cfg Config) map[string]error {
	results := make(map[string]error)
	for _, serial := range serials {
		results[serial] = SwitchChannel(serial, channel, cfg)
	}
	return results
}

// GetDeviceIP は指定デバイスの仮想NWインターフェースIPを返す。
// "adb -s <serial> shell ip route get 1" の出力から src フィールドをパースする。
func GetDeviceIP(serial string, cfg Config) (string, error) {
	cmd := newCmd(cfg.ADBPath, "-s", serial, "shell", "ip", "route", "get", "1")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ip route get: %w", err)
	}
	// 例: "1.0.0.0 via 10.0.2.2 dev eth0 src 192.168.9.101 uid 0"
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "src" && i+1 < len(fields) {
				ip := fields[i+1]
				// ローカルループバックはスキップ
				if ip != "127.0.0.1" && ip != "::1" {
					return ip, nil
				}
			}
		}
	}
	return "", fmt.Errorf("could not parse IP from adb output: %q", strings.TrimSpace(string(out)))
}

// ───── チャンネルリスト ─────

// LoadChannels はファイルからチャンネル番号リストを読み込む。
// カンマ区切りまたは1行1番号の形式に対応する。
func LoadChannels(path string) ([]uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var channels []uint32
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// カンマ区切り対応
		for _, part := range strings.Split(line, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			n, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				continue
			}
			channels = append(channels, uint32(n))
		}
	}
	return channels, scanner.Err()
}

// SaveChannels は channels を 1行1番号のテキストとして path に上書き保存する。
func SaveChannels(path string, channels []uint32) error {
	var sb strings.Builder
	for _, ch := range channels {
		sb.WriteString(strconv.FormatUint(uint64(ch), 10))
		sb.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(sb.String()), 0644)
}

// ───── 巡回（パトロール） ─────

// PatrolStatus は現在の巡回状態
type PatrolStatus struct {
	Running        bool     `json:"running"`
	CurrentChannel uint32   `json:"current_channel"`
	CurrentIndex   int      `json:"current_index"`
	TotalChannels  int      `json:"total_channels"`
	Serials        []string `json:"serials"`
	DwellSecs      float64  `json:"dwell_secs"`
}

// Patroller はチャンネル巡回を管理する
type Patroller struct {
	cfg    Config
	mu     sync.RWMutex
	status PatrolStatus
	cancel context.CancelFunc
}

// NewPatroller はPatrollerを作成する
func NewPatroller(cfg Config) *Patroller {
	return &Patroller{cfg: cfg}
}

// Status は現在の巡回状態を返す
func (p *Patroller) Status() PatrolStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.status
}

// Stop は巡回を停止する
func (p *Patroller) Stop() {
	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	p.status.Running = false
	p.mu.Unlock()
	log.Println("[MuMu] 巡回停止")
}

// Start は指定デバイス・チャンネルリストで巡回を開始する。
// すでに巡回中の場合は停止してから再起動する。
// serials が空の場合は adb devices で自動検出する。
// channels が空の場合は何もしない。
// channelsFile が指定されている場合、各チャンネル滞在後にファイル更新を確認し
// 変更があれば自動リロードして最初から巡回し直す。
func (p *Patroller) Start(serials []string, channels []uint32, dwellSecs float64, channelsFile string) {
	if len(channels) == 0 {
		log.Println("[MuMu] 巡回: チャンネルリストが空のため開始しない")
		return
	}
	p.Stop()

	ctx, cancel := context.WithCancel(context.Background())

	p.mu.Lock()
	p.cancel = cancel
	p.status = PatrolStatus{
		Running:       true,
		TotalChannels: len(channels),
		Serials:       serials,
		DwellSecs:     dwellSecs,
	}
	p.mu.Unlock()

	dwell := time.Duration(float64(time.Second) * dwellSecs)
	if dwell < 100*time.Millisecond {
		dwell = 5 * time.Second
	}

	// channels.txt の初回モッドタイムを記録
	var lastModTime time.Time
	if channelsFile != "" {
		if fi, err := os.Stat(channelsFile); err == nil {
			lastModTime = fi.ModTime()
		}
	}

	go func() {
		defer func() {
			p.mu.Lock()
			p.status.Running = false
			p.mu.Unlock()
			log.Println("[MuMu] 巡回終了")
		}()

		log.Printf("[MuMu] 巡回開始: %d チャンネル, 滞在=%.1fs, デバイス=%v",
			len(channels), dwellSecs, serials)

		idx := 0
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			ch := channels[idx%len(channels)]

			// デバイス一覧を取得（空なら自動検出）
			targets := serials
			if len(targets) == 0 {
				var err error
				targets, err = ListDevices(p.cfg)
				if err != nil {
					log.Printf("[MuMu] 巡回: デバイス取得失敗: %v", err)
					select {
					case <-ctx.Done():
						return
					case <-time.After(3 * time.Second):
					}
					continue
				}
				if len(targets) == 0 {
					log.Println("[MuMu] 巡回: 対象デバイスが0台。MuMu Playerが起動しているか確認してください")
					select {
					case <-ctx.Done():
						return
					case <-time.After(5 * time.Second):
					}
					continue
				}
			}

			p.mu.Lock()
			p.status.CurrentChannel = ch
			p.status.CurrentIndex = idx % len(channels)
			p.status.Serials = targets
			p.mu.Unlock()

			log.Printf("[MuMu] 巡回: [%d/%d] Ch%d → デバイス%v (%d台)",
				idx%len(channels)+1, len(channels), ch, targets, len(targets))

			for _, serial := range targets {
				if err := SwitchChannel(serial, ch, p.cfg); err != nil {
					log.Printf("[MuMu] 巡回: serial=%s ch=%d 失敗: %v", serial, ch, err)
				} else {
					log.Printf("[MuMu] 巡回: serial=%s ch=%d OK", serial, ch)
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(dwell):
			}

			// channels.txt が更新されていたらリロードして最初から巡回し直す
			if channelsFile != "" {
				if fi, statErr := os.Stat(channelsFile); statErr == nil && fi.ModTime().After(lastModTime) {
					if newChs, loadErr := LoadChannels(channelsFile); loadErr == nil && len(newChs) > 0 {
						log.Printf("[MuMu] channels.txt 更新検知: %d → %d チャンネル、最初から再巡回",
							len(channels), len(newChs))
						channels = newChs
						idx = 0
						lastModTime = fi.ModTime()
						p.mu.Lock()
						p.status.TotalChannels = len(channels)
						p.mu.Unlock()
						continue
					} else if loadErr != nil {
						log.Printf("[MuMu] channels.txt リロード失敗: %v", loadErr)
					}
				}
			}

			idx++
		}
	}()
}
