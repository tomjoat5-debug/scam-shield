# Scam Shield — AI 反诈识别助手

[![CI](https://github.com/tomjoat5-debug/scam-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/tomjoat5-debug/scam-shield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![Dependencies: zero](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#quick-start)

Paste a suspicious text message or chat record, and find out whether it looks like a scam, which scam pattern it matches, and what to do about it.

**中文简介**：粘贴一段可疑短信或聊天记录，告诉你它像哪种诈骗套路、风险多高、该怎么办。纯 Python 标准库，零依赖，不联网，本地就能跑。

## The problem it solves

Phone scams have moved. The official National Anti-Fraud Center app （国家反诈中心） does a good job blocking scam calls and texts by phone number — but it cannot see inside WeChat, QQ or Douyin chats, it cannot stop an AI-cloned voice calling from a normal-looking number, and it tells you "risky" without explaining which script the scammer is running.

This tool fills those three gaps. It does not replace the official app — it complements it:

| | 国家反诈中心 App | Scam Shield |
|---|---|---|
| Blocks scam calls / SMS by number | Yes | No |
| Reads chat content (WeChat / QQ / Douyin) | No | Yes — paste the chat |
| Catches AI-cloned voices | No | Checklist for verifying the caller |
| Explains which scam pattern it is | No | Yes |

## Quick start

No accounts, no API keys, no network needed. Python 3.12, standard library only.

```bash
git clone https://github.com/tomjoat5-debug/scam-shield.git
cd scam-shield

# Analyse a pasted text
python -m scam_shield "您好，这里是市公安局，您涉嫌一起洗钱案件，请将资金转入安全账户配合调查。"

# Or pipe from stdin
echo "恭喜您中奖了，先交500元保证金即可领奖" | python -m scam_shield

# Or read from a file
python -m scam_shield --file message.txt
```

Docker:

```bash
docker build -t scam-shield .
docker run --rm scam-shield "粘贴的文本"
```

Example output:

```
【结论】极高风险（非常像诈骗）
【像哪种骗局】冒充公检法
【为什么这么判断】
  - 命中关键词“安全账户”
  - 命中关键词“涉嫌洗钱”
  - 命中强信号组合：以涉嫌洗钱为由要求转入“安全账户”
【该怎么办】
  - 公检法不会通过电话、微信办案，更不会让你把钱转到“安全账户”
  - 立即挂断，不要按对方指示操作
  - 回拨当地公安局官方号码核实，或拨打 96110
【提醒】本工具只是辅助判断，不能保证 100% 准确；凡是涉及钱，先挂断再核实；有疑问请拨打全国反诈专线 96110。
```

## How detection works

- **Pattern library** (`scam_shield/patterns.json`, data separated from code): 12 common scam types, each with weighted keywords, strong-signal combinations, typical script points, advice and official verification channels.
- **Scoring**: a single ordinary word never triggers high risk. High / critical risk needs either a strong-signal combination or several medium signals stacked together.
- **False-positive control**: benign patterns (official verification-code SMS, delivery notifications, bank balance SMS, everyday family chat) lower the score — unless a strong scam signal is present.
- **AI voice / video clone**: keyword matching cannot catch a cloned voice, so when an impersonation scam arrives in a call / video context, the tool attaches a verification checklist instead (hang up and call back on the saved number, ask something only the real person knows, never transfer money on the call).
- **Fully local**: no network calls, no data leaves your machine.

Covered patterns: 冒充公检法， 冒充亲友借钱， 刷单返利， 虚假客服退款， 投资理财 / 杀猪盘， 中奖领奖， 冒充领导 / 老板， 机票退改签， 网贷注销 / 征信修复， 冒充快递丢件理赔， 兼职点赞 / 打字骗押金， AI 换脸换声。

## Limitations — read this first

- This is a **rule-based aid, not a verdict**. It cannot guarantee accuracy. New scam variants it has never seen may slip through.
- It analyses **text only**. It cannot listen to a call or watch a video for you.
- It is tuned for **Chinese-language** scam scripts.
- Every conclusion is phrased as "looks like" / "suspected" — never "this is definitely a scam".
- **When in doubt, call 96110** (the national anti-fraud hotline) or the official customer service number of the organisation involved. Never transfer money or share a verification code while you are still unsure.

## Contributing a new pattern

Patterns live in `scam_shield/patterns.json` — no code changes needed to add one:

1. Add an entry with `id`, `name`, `description`, `keywords` (with weights 1–3), `combos` (strong-signal combinations), `script_points`, `advice`, `verify`.
2. Add a test case in `tests/test_engine.py` (one realistic scam text, expected category and risk) and run `python -m unittest discover -s tests`.
3. Keep wording your own — do not copy text from anywhere.

## License

MIT — see [LICENSE](LICENSE).
