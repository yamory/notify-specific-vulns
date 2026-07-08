# yamory 脆弱性 Slack 通知

yamory IT資産API を1時間ごとにポーリングし、条件（キーワード × CVSS / KEV / PoC）に合致する
**新規の脆弱性だけ**を Slack に通知します。GitHub Actions のみで動作します（外部インフラ不要）。

> 📦 **自社のGitHubリポジトリに移行して利用する場合は [MIGRATION.md](MIGRATION.md) の手順書をご覧ください。**

## 仕組み

```
GitHub Actions (毎時) 
  └─ notify_vulns.py
       ├─ config.json の検索パターンごとに yamory API を検索
       ├─ state/notified.json に無い vulnId のみを「新規」と判定
       ├─ 新規分を CVE-ID 単位にまとめて Slack Incoming Webhook へ通知
       └─ 通知済み vulnId を state/notified.json に追記 → git commit & push
```

- **重複判定**: `vulnId`（資産 × 脆弱性）単位。一度記録されたIDは二度と通知されません。
- **通知単位**: CVE-ID でグルーピングし、該当資産を1メッセージ内にまとめて表示します。

## セットアップ

1. このリポジトリを GitHub に push する
2. リポジトリの **Settings → Secrets and variables → Actions** を開き、
   **Repository secrets** の欄（New repository secret）に以下を登録
   （⚠️ Environment secrets に登録するとワークフローから参照できません）
   | Secret | 内容 |
   |---|---|
   | `YAMORY_API_TOKEN` | yamory の API アクセストークン（下記参照。トークン値のみを登録） |
   | `SLACK_WEBHOOK_URL` | Slack Incoming Webhook の URL |

### YAMORY_API_TOKEN の取得手順

1. yamory の **チーム設定画面** を開く
2. **アクセストークンを発行**し、利用スコープで **「API サーバー」** を選択
3. 発行されたトークン値をそのまま Secret に登録（`token ` プレフィックスはスクリプトが自動で付与します）

（参考: https://docs.yamory.io/deb2f7f8a32846a5a0bd80bb40cfb770 ）
3. **初回は Seed 実行**（重要）: Actions タブ → `yamory vulnerability notify` → `Run workflow` →
   `seed = true` で実行。既存の該当脆弱性が台帳に記録され、**大量の初回通知を防ぎます**。
4. 以降は毎時0分（UTC）に自動実行され、新規分だけが通知されます。

### SLACK_WEBHOOK_URL の取得手順

Slack の **Incoming Webhook（着信ウェブフック）** の URL を使用します。
`https://hooks.slack.com/services/T.../B.../XXX...` という形式で、この URL に JSON を
POST すると特定のチャンネルにメッセージが投稿されます。

1. **Slack アプリを作成**
   - https://api.slack.com/apps を開き **Create New App** → **From scratch**
   - アプリ名（例: `yamory-vuln-notify`）と通知先のワークスペースを選択
2. **Incoming Webhooks を有効化**
   - 左メニューの **Incoming Webhooks** を開き、トグルを **On** にする
3. **Webhook URL を発行**
   - ページ下部の **Add New Webhook to Workspace** をクリック
   - 通知を投稿したいチャンネル（例: `#vuln-alerts`）を選んで **許可する**
   - 発行された `https://hooks.slack.com/services/...` 形式の URL をコピー
4. **GitHub Secrets に登録**
   - リポジトリの **Settings → Secrets and variables → Actions → New repository secret**
   - Name: `SLACK_WEBHOOK_URL` / Value: コピーした URL

動作確認は curl でできます:

```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"text": "テスト通知です"}' \
  "$SLACK_WEBHOOK_URL"
```

> **注意**
> - **URL 自体が認証情報です**。この URL を知っていれば誰でもそのチャンネルに投稿できるため、
>   コードや README に直接書かず、必ず GitHub Secrets で管理してください。
> - **投稿先チャンネルは URL に固定**です。別のチャンネルに通知したい場合は、
>   新しい Webhook を発行して Secret を差し替えます。
> - ワークスペースのアプリ作成が管理者承認制の場合は、Slack 管理者への申請が必要です。

## 検索条件の変更

[config.json](config.json) を編集します。`params` は yamory API のクエリパラメータがそのまま渡ります。

```json
{
  "label": "IBM Websphere / CVSS 9.0以上",
  "params": { "keyword": "IBM Websphere", "cvssScore": "9.0" }
}
```

利用できる主なパラメータ: `keyword`, `cvssScore`, `includeKev`, `includePoc`,
`triageLevel`, `vulnType`, `status`, `detectedDate`
（詳細: https://docs.yamory.io/c84d53e92a35427ba68f410b2ccb10d2 ）

## ローカルでの動作確認

```bash
export YAMORY_API_TOKEN="..."
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
python3 notify_vulns.py            # 通常実行
SEED_MODE=true python3 notify_vulns.py  # 台帳記録のみ（通知なし）
```

## 無料枠について

毎時実行 = 月約730回。1回あたり1分未満のため、
Public リポジトリなら無制限、Private でも無料枠 2,000分/月 に収まります。

## ファイル構成

| ファイル | 役割 |
|---|---|
| [notify_vulns.py](notify_vulns.py) | メインスクリプト（Python 標準ライブラリのみ） |
| [config.json](config.json) | 検索パターン定義 |
| [state/notified.json](state/notified.json) | 通知済み vulnId 台帳（Actions が自動コミット） |
| [.github/workflows/vuln-notify.yml](.github/workflows/vuln-notify.yml) | 毎時実行ワークフロー |
