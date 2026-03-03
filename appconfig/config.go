package appconfig

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
)

// Config holds runtime settings loaded from config.json.
type Config struct {
	// Network interface description; "auto" to auto-select the most active card.
	Network string `json:"network"`

	// Seconds to sample all interfaces when Network == "auto". Default: 3.
	AutoCheck int `json:"auto_check"`

	// Path to locations.json file. Default: "data/locations.json".
	Locations string `json:"locations"`

	// Discord Webhook URL. Leave empty to disable Discord notifications.
	DiscordWebhook string `json:"discord_webhook"`

	// Seconds to suppress duplicate notifications for the same Ch+Location key.
	// Default: 30.
	DebounceSeconds int `json:"debounce_seconds"`

	// ChatExclude is a list of keywords that, if found in a world-chat message,
	// suppress the LoyalBoarlet detection. Useful for filtering false-positives.
	// Example: ["いない", "終わった", "違う"]
	ChatExclude []string `json:"chat_exclude"`

	// --- GUI / MuMu Player 設定 ---

	// GUIPort はWebGUIのポート番号。0でGUI無効。デフォルト: 8080
	GUIPort int `json:"gui_port"`

	// ADBPath はadb.exeのパス。デフォルト: "adb"
	ADBPath string `json:"adb_path"`

	// MumuSerials はMuMu Player端末のADBシリアル一覧（例: ["127.0.0.1:16384","127.0.0.1:16416"]）
	// 空の場合は "adb devices" で自動検出する
	MumuSerials []string `json:"mumu_serials"`

	// MumuTapX, MumuTapY はチャンネル入力欄のタップ座標（MuMu標準解像度基準）
	MumuTapX int `json:"mumu_tap_x"`
	MumuTapY int `json:"mumu_tap_y"`

	// MumuClearLength は入力前にDELキーを送る回数（既存文字を消去）
	MumuClearLength int `json:"mumu_clear_length"`

	// MumuPreKeycode はタップ前に送るキーコード（チャンネル入力欄を開く）
	MumuPreKeycode string `json:"mumu_pre_keycode"`

	// MumuDelayMs は各ADBコマンド間のウェイト(ms)。デフォルト: 800
	MumuDelayMs int `json:"mumu_delay_ms"`

	// --- チャンネル巡回設定 ---

	// PatrolChannelsFile はチャンネルリストファイルのパス。デフォルト: "channels.txt"
	PatrolChannelsFile string `json:"patrol_channels_file"`

	// PatrolDwellSecs は各チャンネルに滞在する秒数。デフォルト: 30
	PatrolDwellSecs float64 `json:"patrol_dwell_secs"`

	// PatrolSerials は巡回に使うADBシリアル一覧。空の場合は全デバイスを使用。
	PatrolSerials []string `json:"patrol_serials"`
}

func defaultConfig() *Config {
	return &Config{
		AutoCheck:       3,
		DebounceSeconds: 30,
		Locations:       "data/locations.json",
		GUIPort:         8080,
		ADBPath:         "adb",
		MumuTapX:        975,
		MumuTapY:        664,
		MumuClearLength: 3,
		MumuPreKeycode:     "KEYCODE_P",
		MumuDelayMs:        800,
		PatrolChannelsFile: "channels.txt",
		PatrolDwellSecs:    30,
	}
}

// Load reads config.json at path. A missing file yields defaults without error.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return defaultConfig(), nil
		}
		return nil, err
	}
	cfg := defaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if cfg.AutoCheck <= 0 {
		cfg.AutoCheck = 3
	}
	if cfg.DebounceSeconds <= 0 {
		cfg.DebounceSeconds = 30
	}
	if cfg.Locations == "" {
		cfg.Locations = "data/locations.json"
	}
	if cfg.GUIPort == 0 {
		cfg.GUIPort = 8080
	}
	if cfg.ADBPath == "" {
		cfg.ADBPath = "adb"
	}
	if cfg.MumuTapX == 0 {
		cfg.MumuTapX = 975
	}
	if cfg.MumuTapY == 0 {
		cfg.MumuTapY = 664
	}
	if cfg.MumuClearLength == 0 {
		cfg.MumuClearLength = 3
	}
	if cfg.MumuPreKeycode == "" {
		cfg.MumuPreKeycode = "KEYCODE_P"
	}
	if cfg.MumuDelayMs == 0 {
		cfg.MumuDelayMs = 800
	}
	return cfg, nil
}

// Save writes cfg as indented JSON to path.
func Save(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
