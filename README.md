# LoyalBoarlet Monitor

複数インスタンスでスターレゾナンスでゴールドウリボを自動検知し、Discordへ通知するツール。

---

## 配布版の使い方

### 必要なソフトウェア

| ソフト | 用途 | 入手先 |
|---|---|---|
| **Npcap** | ネットワークキャプチャ | https://npcap.com/ |

> Npcap インストール時は **「WinPcap API-compatible Mode」にチェック**を入れてください。

### セットアップ

1. `config.json` の `discord_webhook` に通知先の Webhook URL を設定
2. `LoyalBoarlet.exe` を起動
3. ブラウザで `http://127.0.0.1:8080` が開く（または自動で GUI ウィンドウが起動）
4. エミュを検知させ、巡回チャンネル一覧にチャンネルを挿入
5. チャンネル入力欄の座標を設定(初期設定は解像度1280 * 720前提)

### 配布ファイル一覧

```
LoyalBoarlet.exe        ← 実行ファイル
config.json             ← 設定ファイル（config.example.json をコピーして作成）
channels.txt            ← 巡回チャンネルリスト（1行1番号）
data/
  locations.json        ← マップ場所名データ
```

---

## ビルド方法（開発者向け）

### 前提条件

- Go 1.23+
- MinGW-w64 (GCC) が PATH に存在すること
- [Npcap SDK](https://npcap.com/#download) を `C:\npcap-sdk` に展開

### ビルドコマンド

```powershell
# リリースビルド（コンソール非表示）
.\build.ps1

# デバッグビルド（コンソール表示あり）
.\build.ps1 -Debug

# Npcap SDK のパスを指定する場合
.\build.ps1 -NpcapSdk "C:\path\to\npcap-sdk"
```

出力先: `release\LoyalBoarlet.exe` および `LoyalBoarlet-vX.Y.Z-windows-amd64.zip`

### 手動ビルド

```powershell
$env:CGO_ENABLED = "1"
$env:CGO_CFLAGS  = "-IC:\npcap-sdk\Include"
$env:CGO_LDFLAGS = "-LC:\npcap-sdk\Lib\x64 -lwpcap"
go build -ldflags "-s -w -H windowsgui -X main.Version=dev" -o LoyalBoarlet.exe .
```

---

## 設定ファイル (config.json)

| キー | デフォルト | 説明 |
|---|---|---|
| `network` | `"auto"` | NIC名。`"auto"` で自動選択 |
| `discord_webhook` | `""` | Discord Webhook URL |
| `debounce_seconds` | `30` | 同Ch同場所の重複通知を抑制する秒数 |
| `gui_port` | `8080` | Web GUI ポート番号 |
| `adb_path` | `"adb"` | adb.exe のパス |
| `mumu_tap_x/y` | `975, 664` | チャンネル入力欄タップ座標 |
| `mumu_delay_ms` | `800` | ADB コマンド間ウェイト (ms) |
| `patrol_channels_file` | `"channels.txt"` | 巡回チャンネルリストファイル |
| `patrol_dwell_secs` | `30` | 各チャンネル滞在秒数 |

---

## ライセンス

このプロジェクトは [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE) のもとで公開されています。

### 原著作物について

本ソフトウェアは [balrogsxt/StarResonanceAPI](https://github.com/balrogsxt/StarResonanceAPI)（Copyright (C) balrogsxt）を元に改変・拡張したものです。

AGPL-3.0 に基づき、以下の条件が適用されます：

- 改変版を配布・公開する場合は、改変後のソースコードも AGPL-3.0 で公開する必要があります
- 元の著作権表示を維持する必要があります
- 派生物も同じく AGPL-3.0 ライセンスを適用する必要があります
