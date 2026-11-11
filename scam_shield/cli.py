"""命令行入口。

用法：
    python -m scam_shield "粘贴的文本"
    echo "粘贴的文本" | python -m scam_shield
    python -m scam_shield --file message.txt
"""

from __future__ import annotations

import argparse
import sys

from .engine import DISCLAIMER, analyze

RISK_LABEL = {
    "低": "低风险",
    "中": "中风险（疑似）",
    "高": "高风险（很像诈骗）",
    "极高": "极高风险（非常像诈骗）",
}


def format_report(result: dict) -> str:
    """把分析结果排成普通人能看懂的中文报告，结论先行。"""
    lines: list[str] = []
    risk = result["risk"]
    lines.append(f"【结论】{RISK_LABEL.get(risk, risk)}")

    if result["category_name"]:
        lines.append(f"【像哪种骗局】{result['category_name']}")
    elif risk in ("中", "高", "极高"):
        lines.append("【像哪种骗局】能看出多个诈骗特征，但暂时归不到某一类套路")

    if result["note"]:
        lines.append(f"【说明】{result['note']}")

    if result["signals"]:
        lines.append("【为什么这么判断】")
        for signal in result["signals"]:
            lines.append(f"  - {signal}")
    elif risk == "低":
        lines.append("【为什么这么判断】没有命中明显的诈骗特征。")

    if result["benign_notes"]:
        lines.append("【看起来正常的地方】")
        for note in result["benign_notes"]:
            lines.append(f"  - {note}")

    lines.append("【该怎么办】")
    for item in result["advice"]:
        lines.append(f"  - {item}")

    if result["ai_clone_checklist"]:
        lines.append("【AI 换脸换声核验清单】")
        lines.append("  对方可能是 AI 克隆的声音或面孔，电话、视频里看着像本人也不等于本人：")
        for item in result["ai_clone_checklist"]:
            lines.append(f"  - {item}")

    lines.append(f"【提醒】{DISCLAIMER}")
    return "\n".join(lines)


def read_input(args: argparse.Namespace) -> str:
    """按优先级读入文本：命令行参数 > --file > stdin。"""
    if args.text:
        return args.text
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            return f.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scam_shield",
        description="粘贴一段可疑短信或聊天记录，判断它像哪种诈骗套路、风险多高、该怎么办。",
    )
    parser.add_argument("text", nargs="?", help="要分析的文本")
    parser.add_argument("--file", help="从文件读取要分析的文本")
    args = parser.parse_args(argv)

    text = read_input(args)
    if not text.strip():
        print("没有输入文本。用法：")
        print('  python -m scam_shield "粘贴的文本"')
        print("  echo \"粘贴的文本\" | python -m scam_shield")
        print("  python -m scam_shield --file message.txt")
        return 0

    result = analyze(text)
    print(format_report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
