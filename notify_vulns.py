#!/usr/bin/env python3
"""yamory IT資産APIから条件に合致する脆弱性を取得し、新規分をSlackに通知する。

- 検索パターンは config.json に定義（キーワード × CVSS/KEV/PoC）
- 重複判定は vulnId 単位（state/notified.json に記録済みのIDは通知しない）
- Slack通知は CVE-ID 単位でグルーピング（複数資産をまとめて1件で通知）
- SEED_MODE=true のときは通知せず、現時点の該当IDを台帳に記録するだけ（初回投入用）

必要な環境変数:
  YAMORY_API_TOKEN  : yamory APIアクセストークン（"token " プレフィックスは自動付与）
  SLACK_WEBHOOK_URL : Slack Incoming Webhook URL（SEED_MODE=true のときは省略可）
  SEED_MODE         : "true" で台帳への記録のみ行う（省略時 false）

標準ライブラリのみで動作する。
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API_URL = "https://yamoryapi.yamory.io/v1/asset-vulns"
PAGE_SIZE = 1000
MAX_PAGES = 50  # 暴走防止の上限（PAGE_SIZE * MAX_PAGES 件まで）
CVES_PER_MESSAGE = 8  # Slackの1メッセージあたり50ブロック制限に収めるための分割単位

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
STATE_PATH = os.path.join(BASE_DIR, "state", "notified.json")


# ---------------------------------------------------------------- yamory API


def api_get(token: str, params: dict):
    # yamory API の認証形式は "Authorization: token {アクセストークン}"
    # https://docs.yamory.io/deb2f7f8a32846a5a0bd80bb40cfb770
    auth = token if token.lower().startswith(("token ", "bearer ")) else f"token {token}"
    query = urllib.parse.urlencode(params)
    req = urllib.request.Request(
        f"{API_URL}?{query}",
        headers={"Authorization": auth, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as res:
            return json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"yamory API error {e.code}: {body}") from e


def extract_items(payload) -> list[dict]:
    """レスポンスから脆弱性リストを取り出す（トップレベル構造の差異を吸収）。"""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("vulns", "items", "contents", "content", "data", "results"):
            if isinstance(payload.get(key), list):
                return payload[key]
    raise RuntimeError(
        f"Unexpected API response structure: {str(payload)[:300]}"
    )


def fetch_pattern(token: str, params: dict) -> list[dict]:
    """1つの検索パターンについて全ページ取得する。"""
    items: list[dict] = []
    for page in range(MAX_PAGES):
        q = dict(params)
        # bool は "true"/"false" 文字列に変換
        for k, v in q.items():
            if isinstance(v, bool):
                q[k] = "true" if v else "false"
        q["page"] = page
        q["size"] = PAGE_SIZE
        batch = extract_items(api_get(token, q))
        items.extend(batch)
        if len(batch) < PAGE_SIZE:
            break
    return items


# ------------------------------------------------------------------- 台帳


def load_state() -> dict:
    if not os.path.exists(STATE_PATH):
        return {"vulnIds": {}}
    with open(STATE_PATH, encoding="utf-8") as f:
        state = json.load(f)
    state.setdefault("vulnIds", {})
    return state


def save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")


# ------------------------------------------------------------------ Slack


def cve_flags(vulns: list[dict]) -> str:
    parts = []
    scores = [v.get("cvssScore") for v in vulns if v.get("cvssScore") is not None]
    if scores:
        parts.append(f"CVSS {max(scores)}")
    if any(v.get("isKev") for v in vulns):
        parts.append("KEV該当")
    if any(v.get("hasPoc") for v in vulns):
        parts.append("PoCあり")
    return " / ".join(parts) if parts else "-"


def build_cve_block(cve_key: str, entries: list[dict]) -> list[dict]:
    """1つのCVEグループをSlackブロックにする。entriesは {vuln, labels} のリスト。"""
    vulns = [e["vuln"] for e in entries]
    labels = sorted({lb for e in entries for lb in e["labels"]})

    asset_lines = []
    seen_assets = set()
    for v in vulns:
        team = v.get("teamName") or "(チーム不明)"
        project = v.get("projectName") or "(プロジェクト不明)"
        asset = v.get("assetName") or "(資産名不明)"
        version = v.get("version") or ""
        key = (team, project, asset, version)
        if key in seen_assets:
            continue
        seen_assets.add(key)
        line = f"• {team} > {project} > {asset}"
        if version:
            line += f" {version}"
        asset_lines.append(line)
    if len(asset_lines) > 10:
        rest = len(asset_lines) - 10
        asset_lines = asset_lines[:10] + [f"… 他 {rest} 件"]

    detail_url = next((v.get("detailUrl") for v in vulns if v.get("detailUrl")), None)
    title = f"*{cve_key}*  ({cve_flags(vulns)})"
    if detail_url:
        title = f"*<{detail_url}|{cve_key}>*  ({cve_flags(vulns)})"

    text = "\n".join(
        [
            title,
            f"検知条件: {', '.join(labels)}",
            f"対象資産 ({len(seen_assets)}件):",
            *asset_lines,
        ]
    )
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}},
        {"type": "divider"},
    ]


def post_slack(webhook_url: str, blocks: list[dict], fallback: str) -> None:
    payload = json.dumps({"text": fallback, "blocks": blocks}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            res.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"Slack webhook error {e.code}: {body}") from e


def notify_slack(webhook_url: str, groups: dict[str, list[dict]]) -> None:
    cve_keys = sorted(groups.keys())
    total = len(cve_keys)
    for i in range(0, total, CVES_PER_MESSAGE):
        chunk = cve_keys[i : i + CVES_PER_MESSAGE]
        blocks: list[dict] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f":rotating_light: yamory 新規脆弱性通知 ({total}件)",
                    "emoji": True,
                },
            }
        ]
        for cve_key in chunk:
            blocks.extend(build_cve_block(cve_key, groups[cve_key]))
        fallback = f"yamory 新規脆弱性通知: {', '.join(chunk)}"
        post_slack(webhook_url, blocks, fallback)


# ------------------------------------------------------------------- main


def main() -> int:
    token = os.environ.get("YAMORY_API_TOKEN")
    if not token:
        print("ERROR: YAMORY_API_TOKEN is not set", file=sys.stderr)
        return 1
    seed_mode = os.environ.get("SEED_MODE", "").lower() == "true"
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not seed_mode and not webhook_url:
        print("ERROR: SLACK_WEBHOOK_URL is not set", file=sys.stderr)
        return 1

    with open(CONFIG_PATH, encoding="utf-8") as f:
        config = json.load(f)

    state = load_state()
    notified: dict = state["vulnIds"]

    # 全パターンを検索し、vulnId ごとに集約（マッチした条件ラベルも記録）
    found: dict[str, dict] = {}
    for pattern in config["patterns"]:
        label = pattern["label"]
        items = fetch_pattern(token, pattern["params"])
        print(f"[fetch] {label}: {len(items)} 件")
        for v in items:
            vuln_id = str(v.get("vulnId") or "")
            if not vuln_id:
                continue
            entry = found.setdefault(vuln_id, {"vuln": v, "labels": set()})
            entry["labels"].add(label)

    # 未通知の vulnId のみ抽出
    new_entries = {vid: e for vid, e in found.items() if vid not in notified}
    print(f"[diff] 検出 {len(found)} 件 / 新規 {len(new_entries)} 件")

    # CVE-ID 単位にグルーピング（cveId が無いものは vulnId をキーに）
    groups: dict[str, list[dict]] = {}
    for vid, e in new_entries.items():
        cve_key = e["vuln"].get("cveId") or f"yamory:{vid}"
        groups.setdefault(cve_key, []).append(
            {"vuln": e["vuln"], "labels": sorted(e["labels"])}
        )

    if seed_mode:
        print(f"[seed] 通知をスキップし {len(new_entries)} 件を台帳に記録します")
    elif groups:
        notify_slack(webhook_url, groups)
        print(f"[slack] {len(groups)} CVE ({len(new_entries)} vulnId) を通知しました")
    else:
        print("[slack] 新規脆弱性なし。通知をスキップします")

    # 台帳更新
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for vid, e in new_entries.items():
        notified[vid] = {
            "cveId": e["vuln"].get("cveId"),
            "recordedAt": now,
            "seeded": seed_mode,
        }
    save_state(state)
    print(f"[state] 台帳を更新しました (合計 {len(notified)} 件)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
