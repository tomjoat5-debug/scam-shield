"""AI 反诈识别助手（Scam Shield）。

粘贴一段可疑短信或聊天记录，判断它像哪种诈骗套路、风险多高、该怎么办。

口径：所有结论都是“疑似”，绝不说“这一定是诈骗”。
有疑问请拨打全国反诈专线 96110。
"""

from .engine import analyze

__version__ = "1.0.0"
__all__ = ["analyze"]
