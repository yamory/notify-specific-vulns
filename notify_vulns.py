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


def api_get_url(token: str, url: str):
    # yamory API の認証形式は "Authorization: token {アクセストークン}"
    # https://docs.yamory.io/deb2f7f8a32846a5a0bd80bb40cfb770
    auth = token if token.lower().startswith(("token ", "bearer ")) else f"token {token}"
    req = urllib.request.Request(
        url,
        headers={"Authorization": auth, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as res:
            return json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"yamory API error {e.code}: {body}") from e


def api_get(token: str, params: dict):
    return api_get_url(token, f"{API_URL}?{urllib.parse.urlencode(params)}")


def _fetch_linked(token: str, url, label: str):
    """URL文字列ならそのAPIを呼んで辞書を返す（失敗は警告のみ）。"""
    if not (isinstance(url, str) and url.startswith("https://")):
        return None
    try:
        result = api_get_url(token, url)
    except (RuntimeError, urllib.error.URLError, TimeoutError) as e:
        print(f"[warn] {label}の取得に失敗: {e}", file=sys.stderr)
        return None
    return result if isinstance(result, dict) else None


def fetch_vuln_detail(token: str, item: dict) -> None:
    """脆弱性の詳細情報をリンクをたどって取得し、item に添付する。

    yamory API はリンク形式:
      asset-vulns の yamoryVuln → /v1/asset-yamoryVulns/{id}（説明文など）
      その cves[0] → /v1/cves/{CVE-ID}（CVSSスコアなど）
    取得結果は item["yamoryVulnDetail"] / item["cveDetail"] に入り、
    find_value のネスト探索の対象になる。取得失敗は警告のみで処理を続行する。
    """
    detail = _fetch_linked(token, item.get("yamoryVuln"), "脆弱性詳細")
    if detail is None:
        return
    item["yamoryVulnDetail"] = detail
    cves = detail.get("cves")
    if isinstance(cves, list) and cves:
        cve = _fetch_linked(token, cves[0], "CVE詳細")
        if cve is not None:
            item["cveDetail"] = cve


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


# 実レスポンスの項目はネストを含む（例: yamoryVuln オブジェクト内にCVE等の詳細がある）。
# トップレベル → 1段ネストの辞書、の順で候補キーを探す。
VULN_ID_KEYS = ("vulnId", "vulnerabilityId", "vulnID", "id")
CVE_ID_KEYS = ("cveId", "cveID", "cve", "relatedCveId")
CVE_LIST_KEYS = ("cveIds", "cves", "referenceIds")
# CVE詳細APIでは cvss オブジェクト内に文字列で入っている（v3優先、無ければv2）
CVSS_KEYS = (
    "cvssScore",
    "cvss_v3_base_score",
    "cvss_v2_base_score",
    "cvssBaseScore",
    "baseScore",
)
URL_KEYS = ("detailUrl", "detailURL", "permalink")


def _collect_dicts(v: dict, depth: int = 3) -> list[dict]:
    """v 自身と、ネストされた辞書（リスト内の辞書も含む）を depth 段まで集める。"""
    result = [v]
    if depth <= 0:
        return result
    for val in v.values():
        if isinstance(val, dict):
            result.extend(_collect_dicts(val, depth - 1))
        elif isinstance(val, list):
            for x in val:
                if isinstance(x, dict):
                    result.extend(_collect_dicts(x, depth - 1))
    return result


def find_value(v: dict, keys, list_keys=()):
    dicts = _collect_dicts(v)
    for d in dicts:
        for key in keys:
            if d.get(key):
                return d[key]
    for d in dicts:
        for key in list_keys:
            values = d.get(key)
            if isinstance(values, list) and values:
                return values[0]
    return None


def get_vuln_id(v: dict) -> str:
    value = find_value(v, VULN_ID_KEYS)
    return str(value) if value else ""


def get_cve_id(v: dict) -> str:
    # 実レスポンスでは referenceId にCVE-ID（等の脆弱性識別子）が入っている
    ref = v.get("referenceId")
    if ref:
        return str(ref)
    value = find_value(v, CVE_ID_KEYS, CVE_LIST_KEYS)
    return str(value) if value else ""


def get_cvss(v: dict):
    value = find_value(v, CVSS_KEYS)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


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
    scores = [s for s in (get_cvss(v) for v in vulns) if s is not None]
    if scores:
        parts.append(f"CVSS {max(scores)}")
    if any(find_value(v, ("isKev", "isCisaKev")) for v in vulns):
        parts.append("KEV該当")
    if any(find_value(v, ("hasPoc", "hasPoC")) for v in vulns):
        parts.append("PoCあり")
    return " / ".join(parts) if parts else "-"


def get_description(vulns: list[dict]) -> str:
    """詳細APIレスポンスから脆弱性の説明文（日本語優先）を取り出す。"""
    for v in vulns:
        detail = v.get("yamoryVulnDetail")
        if isinstance(detail, dict):
            desc = detail.get("descriptionJp") or detail.get("description")
            if desc:
                return str(desc)
    return ""


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

    detail_url = next(
        (find_value(v, URL_KEYS) for v in vulns if find_value(v, URL_KEYS)), None
    )
    if not detail_url and cve_key.upper().startswith("CVE-"):
        detail_url = f"https://nvd.nist.gov/vuln/detail/{cve_key}"
    title = f"*{cve_key}*  ({cve_flags(vulns)})"
    if detail_url:
        title = f"*<{detail_url}|{cve_key}>*  ({cve_flags(vulns)})"

    lines = [title, f"検知条件: {', '.join(labels)}"]
    desc = get_description(vulns)
    if desc:
        lines.append(f"概要: {desc[:200]}{'…' if len(desc) > 200 else ''}")
    lines.append(f"対象資産 ({len(seen_assets)}件):")
    lines.extend(asset_lines)
    text = "\n".join(lines)
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
    skipped = 0
    sample_item = None
    for pattern in config["patterns"]:
        label = pattern["label"]
        items = fetch_pattern(token, pattern["params"])
        print(f"[fetch] {label}: {len(items)} 件")
        for v in items:
            if sample_item is None:
                sample_item = v
            vuln_id = get_vuln_id(v)
            if not vuln_id:
                skipped += 1
                continue
            entry = found.setdefault(vuln_id, {"vuln": v, "labels": set()})
            entry["labels"].add(label)

    # フィールド名のドキュメントと実レスポンスの差異を調査できるよう、常に出力する
    if sample_item is not None:
        print(f"[info] レスポンス項目のフィールド名: {sorted(sample_item.keys())}")
        # 詳細APIのスキーマも毎回1件だけ取得して確認できるようにする
        # （脆弱性マスタ情報＝公開情報のため、内容をログに出しても資産情報は漏れない）
        fetch_vuln_detail(token, sample_item)
        detail = sample_item.get("yamoryVulnDetail")
        if detail:
            print(f"[info] 脆弱性詳細のフィールド名: {sorted(detail.keys())}")
        cve_detail = sample_item.get("cveDetail")
        if cve_detail:
            print(f"[info] CVE詳細のフィールド名: {sorted(cve_detail.keys())}")
            print(
                f"[info] CVE詳細の内容(先頭800文字): "
                f"{json.dumps(cve_detail, ensure_ascii=False)[:800]}"
            )
    if skipped:
        print(f"[warn] IDフィールドを解決できず {skipped} 件をスキップしました", file=sys.stderr)

    # 未通知の vulnId のみ抽出
    new_entries = {vid: e for vid, e in found.items() if vid not in notified}
    print(f"[diff] 検出 {len(found)} 件 / 新規 {len(new_entries)} 件")

    # 新規分のみ詳細API（yamoryVuln のURL）を呼び、CVSS等の情報を補完する
    if not seed_mode:
        for e in new_entries.values():
            if "yamoryVulnDetail" not in e["vuln"]:
                fetch_vuln_detail(token, e["vuln"])

    # CVE-ID 単位にグルーピング（CVEが無いものは vulnId をキーに）
    groups: dict[str, list[dict]] = {}
    for vid, e in new_entries.items():
        cve_key = get_cve_id(e["vuln"]) or f"yamory:{vid}"
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
            "cveId": get_cve_id(e["vuln"]) or None,
            "recordedAt": now,
            "seeded": seed_mode,
        }
    save_state(state)
    print(f"[state] 台帳を更新しました (合計 {len(notified)} 件)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
