# -*- coding: utf-8 -*-
"""CLI 演示：两道门分别怎么工作。

用法：
    python examples/demo.py                      # 演示全部注入样本
    python examples/demo.py <txt文件> [更多txt]   # 演示指定文件（模拟 OCR 输出）

演示内容：
  门 1 —— 把「一个改名成 .png 的 ELF 可执行文件」和「一个真 PNG」
         分别喂给 guard_upload，看字节层面谁进得来；
  门 2 —— 把样本文本当 OCR 输出，跑围栏 + 注入检测 + 落地一致性，
         打印告警与篡改证据。
"""
from __future__ import annotations

import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_input_guard import (  # noqa: E402
    SYSTEM_PROMPT,
    fence,
    guard_upload,
    injected_prompt_suffix,
    inspect,
    scan_filename,
    scan_untrusted,
)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX_SAMPLES = os.path.join(ROOT, "fixtures", "samples")

# 现场造的最小字节样本
REAL_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 32
ELF_AS_PNG = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64

BAR = "=" * 72


def demo_gate1() -> None:
    print(BAR)
    print("门 1  file_guard：文件真的是它声称的类型吗？")
    print(BAR)
    for label, name, ctype, content in [
        ("真 PNG（合法）", "photo.png", "image/png", REAL_PNG),
        ("改名攻击：ELF 扩展名改成 .png", "heart.png", "image/png", ELF_AS_PNG),
        ("改名攻击：ELF 连 MIME 都声明成图片", "heart.png", "image/png", ELF_AS_PNG),
    ]:
        r = guard_upload(name, ctype, content, 10 * 1024 * 1024)
        verdict = "✅ 放行" if r.ok else "❌ 拒绝 [%s] %d" % (r.code, r.status_code)
        print("\n[%s]\n  声明: filename=%s content-type=%s 实际字节: %d B\n  结论: %s"
              % (label, name, ctype, len(content), verdict))
        if not r.ok:
            print("  原因: %s" % r.message)


def demo_gate2(text: str, source_label: str) -> bool:
    print("\n" + "-" * 72)
    print("门 2  prompt_guard：原文 = %s" % source_label)
    print("-" * 72)
    print(text)
    print("-" * 72)

    hits = scan_untrusted(text, source="ocr")
    candidate = {"amount": "0.01", "merchant": "某某科技有限公司",
                 "transaction_date": "2026-09-01", "warnings": []}
    report = inspect(candidate, text)

    # 围栏形状
    fenced = fence("ocr", text)
    print("围栏后的提示词片段（前 3 行）:")
    for line in fenced.splitlines()[:3]:
        print("    | %s" % line[:60])
    print("    | ...")
    print("    | %s" % fenced.splitlines()[-1][:60])
    print("    | %s" % injected_prompt_suffix()[:50] + "...")

    print("\n检测结果:")
    if not hits:
        print("  ✅ 未检出指令性语句")
    for h in hits:
        print("  ⚠️ 命中「%s」… %s" % (h["label"], h["excerpt"][:40]))
    if report["suspected_injection"]:
        for w in report["warnings"]:
            print("  🚨 %s" % w)
        print("  ⇒ suspected_injection=True（建议标 HIGH + 转人工复核）")
        return True
    print("  ✅ 干净输入，无告警")
    return False


def main(argv):
    print(BAR)
    print("ai-input-guard CLI 演示 —— AI 应用的输入防护")
    print(BAR)
    demo_gate1()

    targets = argv[1:]
    if not targets:
        with io.open(os.path.join(ROOT, "fixtures", "manifest.json"), "r", encoding="utf-8") as f:
            manifest = json.load(f)
        targets = [os.path.join(FIX_SAMPLES, s["text_file"]) for s in manifest["samples"]]

    print("\n" + BAR)
    print("样本集演示（%d 个）" % len(targets))
    print(BAR)
    flagged = 0
    for path in targets:
        if not os.path.exists(path):
            print("跳过（不存在）: %s" % path)
            continue
        with io.open(path, "r", encoding="utf-8") as f:
            text = f.read()
        if demo_gate2(text, os.path.basename(path)):
            flagged += 1

    print("\n" + BAR)
    print("汇总: %d/%d 个样本被标记为疑似注入" % (flagged, len(targets)))
    print("注: 这是【检测】演示 —— 库不拦截，只提供证据。")
    print(BAR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
