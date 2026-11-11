"""识别引擎：基于套路库的关键词加权评分。

原理很简单，也故意保持简单：
- 每个套路有一组关键词（带权重）和强信号组合；
- 文本命中关键词得分，命中强信号组合额外加分；
- 单个普通词不触发高风险，只有强信号或多个中等信号叠加才拉高风险。

口径：所有结论都是“疑似”，绝不说“这一定是诈骗”。
有疑问请拨打全国反诈专线 96110。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

PATTERNS_PATH = Path(__file__).with_name("patterns.json")

# 风险等级
RISK_LOW = "低"
RISK_MEDIUM = "中"
RISK_HIGH = "高"
RISK_CRITICAL = "极高"

DISCLAIMER = (
    "本工具只是辅助判断，不能保证 100% 准确；"
    "凡是涉及钱，先挂断再核实；有疑问请拨打全国反诈专线 96110。"
)

# 良性文本的特征。命中时扣分，但强信号组合命中时不扣
# （真骗局也可能提到“验证码”，不能因为一句“验证码”就放过）。
# 每条：(正则, 扣分, 说明)
BENIGN_PATTERNS: list[tuple[str, int, str]] = [
    (
        r"验证码.{0,12}(有效期|分钟内有效|请勿泄露)",
        3,
        "看起来像官方验证码短信",
    ),
    (
        r"(您的|你好).{0,20}(快递|包裹).{0,20}(已送达|已签收|正在派送|派送中|已到达)",
        3,
        "看起来像快递送达通知",
    ),
    (
        r"尾号\d{4}.{0,30}(余额|到账|支出|入账)",
        3,
        "看起来像银行余额 / 收支短信",
    ),
    (
        r"(爸|妈|爸爸|妈妈).{0,30}(回家|吃饭|注意身体|天冷|多穿)",
        3,
        "看起来像家人日常问候",
    ),
]

# 出现电话 / 视频语境的词：用于判断是否需要附上 AI 换脸换声核验清单
CALL_WORDS = ("打电话", "电话", "视频通话", "视频", "语音", "通话", "来电")

# 冒充类套路：命中这类套路且在电话 / 视频语境下，附 AI 换脸换声核验清单
IMPERSONATION_IDS = ("impersonate_family", "impersonate_boss", "impersonate_police")


def load_patterns() -> dict:
    """加载套路库。"""
    with open(PATTERNS_PATH, encoding="utf-8") as f:
        return json.load(f)


def _score_category(text: str, pattern: dict) -> dict:
    """给单个套路打分。返回分数、命中词、命中组合。"""
    # 找出所有关键词出现的位置；重叠的只计一次（权重高、跨度长的优先），
    # 避免“中奖”和“中奖了”在同一处重复计分。
    matches: list[tuple[int, int, int, str]] = []
    for kw in pattern.get("keywords", []):
        kw_text = kw["text"]
        if not kw_text:
            continue
        start = 0
        while True:
            idx = text.find(kw_text, start)
            if idx < 0:
                break
            matches.append((idx, idx + len(kw_text), kw["weight"], kw_text))
            start = idx + 1
    matches.sort(key=lambda m: (-m[2], -(m[1] - m[0]), m[0]))
    hits: list[dict] = []
    occupied: list[tuple[int, int]] = []
    for start, end, weight, kw_text in matches:
        if any(start < o_end and end > o_start for o_start, o_end in occupied):
            continue
        hits.append({"text": kw_text, "weight": weight})
        occupied.append((start, end))
    score = sum(hit["weight"] for hit in hits)
    combos_hit: list[dict] = []
    for combo in pattern.get("combos", []):
        words = combo["keywords"]
        if words and all(w in text for w in words):
            combos_hit.append(
                {"label": combo["label"], "bonus": combo["bonus"]}
            )
            score += combo["bonus"]
    return {"score": score, "hits": hits, "combos": combos_hit}


def _generic_bonus(text: str, generic_signals: list[dict]) -> dict:
    """通用诈骗特征加分（不归属任何一类，只推高整体风险）。"""
    hits: list[dict] = []
    bonus = 0
    for sig in generic_signals:
        if sig["text"] and sig["text"] in text:
            hits.append({"text": sig["text"], "weight": sig["weight"]})
            bonus += sig["weight"]
    return {"bonus": bonus, "hits": hits}


def _benign_penalty(text: str, has_combo: bool) -> dict:
    """良性文本扣分。强信号组合命中时不扣，避免放过真骗局。"""
    if has_combo:
        return {"penalty": 0, "matched": []}
    matched: list[str] = []
    penalty = 0
    for regex, points, label in BENIGN_PATTERNS:
        if re.search(regex, text):
            matched.append(label)
            penalty += points
    return {"penalty": penalty, "matched": matched}


def _risk_from_score(score: int, has_combo: bool, distinct_hits: int) -> str:
    """按分数定风险等级。单个普通词到不了高风险。"""
    if score >= 9 and (has_combo or distinct_hits >= 4):
        return RISK_CRITICAL
    if score >= 6 and (has_combo or distinct_hits >= 3):
        return RISK_HIGH
    if score >= 3:
        return RISK_MEDIUM
    return RISK_LOW


def analyze(text: str) -> dict:
    """分析一段文本，返回结构化结果。

    返回：
        risk: "低" / "中" / "高" / "极高"
        category_id / category_name: 最可能的骗局类型（没有则为 None）
        score: 总分
        signals: 命中的危险信号（词、组合、通用特征）
        benign_notes: 命中的良性特征
        advice: 针对性建议 + 通用建议
        ai_clone_checklist: 需要时附上的 AI 换脸换声核验清单
        note: 补充说明（如文本为空、过短）
    """
    data = load_patterns()
    categories = data["categories"]
    generic_signals = data.get("generic_signals", [])

    text = (text or "").strip()
    if not text:
        return {
            "risk": RISK_LOW,
            "category_id": None,
            "category_name": None,
            "score": 0,
            "signals": [],
            "benign_notes": [],
            "advice": ["请粘贴一段可疑短信或聊天记录再分析。"],
            "ai_clone_checklist": None,
            "note": "未输入文本，无法判断。",
        }

    # 1. 每个套路打分，取最高分的一类
    scored = []
    for pattern in categories:
        if pattern.get("match") == "manual":
            continue  # AI 换脸换声不参与关键词匹配
        result = _score_category(text, pattern)
        result["pattern"] = pattern
        scored.append(result)
    scored.sort(key=lambda r: (r["score"], len(r["combos"])), reverse=True)
    best = scored[0]
    pattern = best["pattern"]
    has_combo = len(best["combos"]) > 0
    distinct_hits = len(best["hits"])

    # 2. 通用诈骗特征加分
    generic = _generic_bonus(text, generic_signals)

    # 3. 良性特征扣分（强信号组合命中时不扣）
    benign = _benign_penalty(text, has_combo)

    total = max(0, best["score"] + generic["bonus"] - benign["penalty"])
    category_score = best["score"]

    # 4. 定风险等级
    if category_score >= 3:
        risk = _risk_from_score(total, has_combo, distinct_hits)
        category_id = pattern["id"]
        category_name = pattern["name"]
    elif generic["bonus"] >= 3:
        # 多个通用诈骗特征，但归不到某一类
        risk = RISK_MEDIUM
        category_id = None
        category_name = None
    else:
        risk = RISK_LOW
        category_id = None
        category_name = None

    # 5. 收集信号说明
    signals: list[str] = []
    for hit in best["hits"]:
        signals.append(f"命中关键词“{hit['text']}”")
    for combo in best["combos"]:
        signals.append(f"命中强信号组合：{combo['label']}")
    for hit in generic["hits"]:
        signals.append(f"通用诈骗特征“{hit['text']}”")

    # 6. 建议
    advice: list[str] = []
    if category_id:
        advice.extend(pattern.get("advice", []))
        advice.append(f"核实渠道：{pattern.get('verify', '有疑问拨打 96110。')}")
    if risk in (RISK_HIGH, RISK_CRITICAL):
        advice.append("凡是涉及转账、验证码、银行卡信息，先停下来核实，不要马上操作。")
    elif risk == RISK_MEDIUM:
        advice.append("建议通过官方渠道核实后再决定，不要直接按对方说的做。")
    else:
        advice.append("未发现明显诈骗特征，但仍建议保持警惕；对方一旦提到钱、验证码或链接，先停下来核实。")

    # 7. AI 换脸换声核验清单：冒充类 + 电话/视频语境
    ai_clone_checklist = None
    ai_pattern = next(
        (c for c in categories if c["id"] == "ai_clone"), None
    )
    call_context = any(w in text for w in CALL_WORDS)
    if ai_pattern and category_id in IMPERSONATION_IDS and call_context:
        ai_clone_checklist = list(ai_pattern.get("checklist", []))

    note = ""
    if len(text) < 4:
        note = "文本过短，信号不足，结论仅供参考。"

    return {
        "risk": risk,
        "category_id": category_id,
        "category_name": category_name,
        "score": total,
        "signals": signals,
        "benign_notes": benign["matched"],
        "advice": advice,
        "ai_clone_checklist": ai_clone_checklist,
        "note": note,
    }
