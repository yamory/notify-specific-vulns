# 移行手順書 — 自社GitHubリポジトリでの利用開始

本リポジトリ（yamory 脆弱性 Slack 通知）を、お客様ご自身の GitHub リポジトリに移行して
利用開始するまでの手順です。所要時間はおよそ 30 分です。

## 全体の流れ

```
1. 事前準備（yamory APIトークン / Slack Webhook の発行）
2. 自社リポジトリの作成とコードの移行
3. 台帳の初期化
4. Secrets の登録
5. 初回 Seed 実行（既存脆弱性の記録）
6. 動作確認
```

---

## 1. 事前準備

以下の2つを先に発行しておきます。

### yamory API アクセストークン

1. yamory の **チーム設定画面** を開く
2. **アクセストークンを発行** し、利用スコープで **「API サーバー」** を選択
3. 発行されたトークン値を控える（後で Secrets に登録します）

参考: https://docs.yamory.io/deb2f7f8a32846a5a0bd80bb40cfb770

> yamory 側で API の IPアドレス制限を設定している場合、GitHub Actions のランナーは
> 固定IPではないため接続できません（403エラー）。IP制限を解除するか、
> セルフホストランナーの利用をご検討ください。

### Slack Incoming Webhook

1. https://api.slack.com/apps → **Create New App** → **From scratch**
   （アプリ名例: `yamory-vuln-notify`、通知先ワークスペースを選択）
2. 左メニュー **Incoming Webhooks** → トグルを **On**
3. **Add New Webhook to Workspace** → 通知先チャンネルを選んで許可
4. 発行された `https://hooks.slack.com/services/...` の URL を控える

> Webhook URL は認証情報です。必ず GitHub Secrets で管理し、
> コードやドキュメントに直接書かないでください。

---

## 2. 自社リポジトリの作成とコードの移行

### 2-1. リポジトリを作成

GitHub で新規リポジトリを作成します。

- **Visibility は Private を推奨**します。通知済み台帳（`state/notified.json`）に
  自社環境で検知した CVE-ID と検知日時が蓄積されるためです
- リポジトリ名は任意（例: `yamory-vuln-notify`）

### 2-2. コードを移行（推奨: 履歴を持たずクリーンに開始）

```bash
# 提供リポジトリを取得
git clone --depth 1 https://github.com/yamory/notify-specific-vulns.git
cd notify-specific-vulns

# 提供元の履歴を切り離し、自社リポジトリ用に初期化
rm -rf .git
git init -b main
git add .
git commit -m "Add yamory vulnerability Slack notifier"

# 自社リポジトリへ push（URLは作成したリポジトリのものに置き換え）
git remote add origin https://github.com/<your-org>/<your-repo>.git
git push -u origin main
```

<details>
<summary>（代替）開発履歴ごと移行する場合</summary>

```bash
git clone https://github.com/yamory/notify-specific-vulns.git
cd notify-specific-vulns
git remote set-url origin https://github.com/<your-org>/<your-repo>.git
git push -u origin main
```

</details>

> **フォークは使わないでください。** フォークしたリポジトリでは定期実行
> （schedule トリガー）がデフォルトで無効化されるためです。

### 2-3. Organization のポリシー確認（該当する場合のみ）

Organization で「Actions はコミットSHA固定必須」等のポリシーがある場合も、
本リポジトリのワークフローは対応済みです（`actions/checkout` `actions/setup-python` を
フルSHAで固定）。「許可された Actions のみ」ポリシーの場合は、この2つの
Action を許可リストに追加してください。

---

## 3. 台帳の初期化

`state/notified.json` に検証時のデータが残っている場合は、初期化してからコミットします。

```bash
cat > state/notified.json <<'EOF'
{
  "vulnIds": {}
}
EOF
git add state/notified.json
git commit -m "Reset notified ledger"
git push
```

---

## 4. Secrets の登録

リポジトリの **Settings → Secrets and variables → Actions** を開き、
**Repository secrets** の欄（**New repository secret**）に以下の2つを登録します。

| Name | Value |
|---|---|
| `YAMORY_API_TOKEN` | 手順1で発行した yamory API アクセストークン（トークン値のみ） |
| `SLACK_WEBHOOK_URL` | 手順1で発行した Slack Webhook URL |

> ⚠️ **Environment secrets ではなく Repository secrets に登録してください。**
> Environment secrets に登録するとワークフローから参照できず、認証エラーになります。

> Secrets は暗号化されて保存され、登録後は本人を含め誰も値を閲覧できません。
> リポジトリが Public でも外部に公開されることはありません。

---

## 5. 初回 Seed 実行（重要）

台帳が空の状態で通常実行すると、**現在該当しているすべての脆弱性が一斉に通知されます**。
これを防ぐため、初回は「通知せずに記録だけする」Seed モードで実行します。

1. リポジトリの **Actions** タブ → 左の **yamory vulnerability notify** を選択
2. 右側の **Run workflow** をクリック
3. **`seed` にチェックを入れて** **Run workflow** を実行
4. 実行完了後、`state/notified.json` に既存の該当脆弱性が記録されたコミットが
   自動で追加されていることを確認

> 逆に「導入時点の該当分も一度すべて通知してほしい」場合は、Seed 実行を
> スキップしてください。次の定期実行で全件が通知されます（件数によっては
> 複数メッセージに分かれます）。

---

## 6. 動作確認

- **Actions タブ**で実行が success になっていること
- 以後、**毎時0分（UTC）** に自動実行されます（GitHub の仕様で数分遅れることがあります）
- 新規の脆弱性が検知されると、Slack に以下の形式で通知されます：

> 🚨 **yamory 新規脆弱性通知 (N件)**
> **CVE-XXXX-XXXXX** (CVSS 9.8 / KEV該当 / PoCあり) ← yamoryアプリの検索結果へのリンク
> 検知条件: IBM Websphere / CVSS 9.0以上
> 概要: 脆弱性の説明文（日本語優先）
> 対象資産 (2件):
> • チーム名 > プロジェクト名 > 資産名 バージョン

即時にテストしたい場合は **Run workflow**（seed のチェックなし）で手動実行できます。

---

## 7. 検索条件のカスタマイズ

[config.json](config.json) を編集して push すると、次回実行から反映されます。

```json
{
  "label": "通知に表示される条件名",
  "params": { "keyword": "検索キーワード", "cvssScore": "9.0" }
}
```

`params` に指定できる主なパラメータ（yamory IT資産APIのクエリがそのまま渡ります）:
`keyword`, `cvssScore`, `includeKev`, `includePoc`, `triageLevel`, `vulnType`, `status`, `detectedDate`

詳細: https://docs.yamory.io/c84d53e92a35427ba68f410b2ccb10d2

実行スケジュールを変えたい場合は
[.github/workflows/vuln-notify.yml](.github/workflows/vuln-notify.yml) の
`cron: "0 * * * *"` を編集してください（UTC表記）。

---

## 8. 運用上の注意

- **無料枠**: 毎時実行＝月約730回、1回15〜30秒程度。Private リポジトリの無料枠
  （2,000分/月）に十分収まります。Public なら無制限です
- **定期実行の自動停止対策は実装済み**: GitHub はリポジトリに60日間活動がないと
  schedule 実行を自動停止することがありますが、本ワークフローは毎実行時に
  実行ログ（`state/last-run.log`）をコミットするため、活動が途切れず自動停止は発生しません
- **トークンのローテーション**: yamory トークンや Webhook を再発行した場合は、
  Secrets の値を差し替えるだけで反映されます（コード変更不要）
- **通知の重複判定**: 資産×脆弱性（vulnId）単位です。通知済みのCVEでも、
  新しい資産で同じCVEが検知された場合は、その資産についてのみ再度通知されます

## 9. トラブルシューティング

| 症状 | 原因と対処 |
|---|---|
| `ERROR: YAMORY_API_TOKEN is not set` | Secrets 未登録、または Environment secrets に登録している → **Repository secrets** に登録し直す |
| `yamory API error 401` | トークンが無効、またはスコープ違い → 利用スコープ **「API サーバー」** で発行したトークンか確認 |
| `yamory API error 403` | yamory 側の IPアドレス制限 → GitHub Actions ランナーのIPは固定できないため、IP制限の解除が必要 |
| Slack に通知が来ない（実行は success） | ログに「新規脆弱性なし」→ 正常（台帳に記録済み）。全件再通知したい場合は台帳を初期化（手順3） |
| Actions が実行されない | フォークで移行していないか確認。また Organization の Actions 許可設定を確認 |
