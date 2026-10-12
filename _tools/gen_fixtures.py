# -*- coding: utf-8 -*-
"""从 manifest.json 生成 samples/*.txt —— 保证两份内容永远一致（同一事实一个出口）。

重跑方式（项目根目录下）：
    python _tools/gen_fixtures.py
"""
import io
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "fixtures")


def main() -> int:
    with io.open(os.path.join(FIX, "manifest.json"), "r", encoding="utf-8") as f:
        manifest = json.load(f)

    for s in manifest["samples"]:
        path = os.path.join(FIX, "samples", s["text_file"])
        with io.open(path, "w", encoding="utf-8", newline="") as f:
            f.write(s["text"])
        print("wrote", s["text_file"], len(s["text"]), "chars")
    print("total", len(manifest["samples"]), "samples")

    # 反向核对：磁盘上的文件内容必须与 manifest 逐字一致
    mismatch = []
    for s in manifest["samples"]:
        path = os.path.join(FIX, "samples", s["text_file"])
        with io.open(path, "r", encoding="utf-8") as f:
            if f.read() != s["text"]:
                mismatch.append(s["text_file"])
    if mismatch:
        print("MISMATCH:", mismatch)
        return 1
    print("VERIFY OK: all samples byte-identical to manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
