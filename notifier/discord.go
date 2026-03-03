// Package notifier sends LoyalBoarlet detection notifications to Discord.
package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Source labels for detection origin.
const (
	SourceAuto = "自動"
	SourceChat = "チャット"
)

// Detection carries all information for one LoyalBoarlet notification.
type Detection struct {
	// Source is SourceAuto ("自動") or SourceChat ("チャット").
	Source string

	// LineID is the game channel number (Ch) of the capturing instance.
	LineID uint32

	// ChatLineID is the channel number extracted from the chat message text.
	// Populated only when Source == SourceChat. Takes priority over LineID in Format.
	ChatLineID uint32

	// Location is the human-readable location name resolved from coordinates.
	Location string

	// MonsterName is the in-game monster name (may be empty for chat detections).
	MonsterName string

	// Message is the raw world-chat text (populated for SourceChat).
	Message string

	// InstanceLabel identifies which emulator instance made the detection.
	// E.g. "192.168.1.2:50011->1.2.3.4:5000"
	InstanceLabel string

	// Time is the moment of detection.
	Time time.Time
}

// DiscordWebhook sends notifications via a Discord incoming webhook.
type DiscordWebhook struct {
	URL string
}

// Send posts the detection as a text message to the configured webhook.
// It is a no-op when URL is empty.
func (d *DiscordWebhook) Send(det Detection) error {
	if d == nil || d.URL == "" {
		return nil
	}
	payload := map[string]any{
		"content": Format(det),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := http.Post(d.URL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord webhook returned %s: %s", resp.Status, string(body))
	}
	return nil
}

// Format produces the human-readable notification text matching the spec.
//
//	【ゴールドウリボ出現】
//	Ch: 45
//	場所: テント裏
//	検知方法: 自動
//	時刻: 2026-03-01 20:00
func Format(det Detection) string {
	ch := "不明"
	if det.Source == SourceChat {
		if det.ChatLineID > 0 {
			ch = fmt.Sprintf("%d", det.ChatLineID)
		}
	} else if det.LineID > 0 {
		ch = fmt.Sprintf("%d", det.LineID)
	}
	loc := det.Location
	if loc == "" {
		loc = "不明"
	}
	ts := det.Time.Format("2006-01-02 15:04")
	return fmt.Sprintf("【ゴールドウリボ出現】\nCh: %s\n場所: %s\n検知方法: %s\n時刻: %s", ch, loc, det.Source, ts)
}
