# -*- coding: utf-8 -*-
"""变异验证：把代码改坏，证明测试真的能抓 bug。

三个变异对应三类缺陷形态：
  M1  sniff_kind 认不出来时**猜** text（守卫静默放行）
  M2  泄漏探针里掺一条系统提示词中没有的探针（恒不命中，被同组掩盖）
  M3  grounding 比对前**不剔除**注入行（注入句自带目标值 ⇒ 判据失效）

纪律：注入 → 跑测试必须变红且红在预期用例 → 逐字节还原 → md5 校验一致。
"""
import hashlib
import io
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN = os.path.join(ROOT, "ai_input_guard")
PY = sys.executable
JUNIT = os.path.join(ROOT, "_junit_mut.xml")

MUTATIONS = [
    (
        "M1 sniff_guess_text",
        "file_guard.py",
        '    if _looks_like_text(head):\n        return "text"\n    return "unknown"',
        '    return "text"',
        "test_sniff_unknown_never_guesses_text",
    ),
    (
        "M2 dead_leak_probe",
        "prompt_guard.py",
        '_LEAK_PROBES: Sequence[str] = (\n    "待处理的数据",',
        '_LEAK_PROBES: Sequence[str] = (\n    "待处理的数据",\n    "这条探针根本不在提示词里",',
        "test_leak_probes_are_verbatim_fragments_of_the_system_prompt",
    ),
    (
        "M3 no_strip_injection",
        "prompt_guard.py",
        '    keep = [ln for ln in body.splitlines()\n            if not any(re.search(p, ln, flags=re.I) for _, p in INJECTION_PATTERNS)]',
        '    keep = body.splitlines()',
        None,   # 预期红在 grounding 相关用例上（下面按前缀判定）
    ),
]

# 变异 3 允许变红的用例前缀
M3_PREFIXES = ("test_rewritten_amount_is_caught_by_grounding",
               "test_grounding_strips_injection_lines_before_match")


def md5(path):
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def run_tests():
    p = subprocess.run(
        [PY, "-m", "pytest", os.path.join(ROOT, "tests"), "-q",
         "--junitxml=" + JUNIT, "-p", "no:cacheprovider"],
        capture_output=True, text=True)
    import xml.etree.ElementTree as ET
    tree = ET.parse(JUNIT).getroot()
    suite = tree if tree.tag == "testsuite" else tree.find("testsuite")
    failures = []
    for case in suite.iter("testcase"):
        for kind in ("failure", "error"):
            node = case.find(kind)
            if node is not None:
                msg = (node.get("message") or "")[:120].replace("\n", " ")
                failures.append("%s::%s | %s" % (kind, case.get("name"), msg))
    return failures


def main():
    print("=" * 72)
    results = []
    for name, fname, old, new, expected_case in MUTATIONS:
        path = os.path.join(GEN, fname)
        before = md5(path)
        with io.open(path, "r", encoding="utf-8", newline="") as f:
            src = f.read()
        if src.count(old) != 1:
            print("%-28s INJECT FAILED (pattern count=%d)" % (name, src.count(old)))
            results.append((name, "INJECT_FAILED"))
            continue
        with io.open(path, "w", encoding="utf-8", newline="") as f:
            f.write(src.replace(old, new))
        failures = run_tests()
        # 还原并校验 md5
        with io.open(path, "w", encoding="utf-8", newline="") as f:
            f.write(src)
        after = md5(path)
        restored = "RESTORED_OK" if after == before else "RESTORE_MISMATCH(%s!=%s)" % (after, before)

        names = [f.split(" | ")[0].split("::")[-1] for f in failures]
        if expected_case:
            ok = expected_case in names and failures
        else:
            ok = any(any(n == pre or n.startswith(pre) for pre in M3_PREFIXES) for n in names)
        print("%-28s %-14s red=%d expected=%s %s"
              % (name, "KILLED" if ok else "SURVIVED", len(names), ok, restored))
        if not ok:
            for f in failures[:6]:
                print("      ", f)
        results.append((name, "KILLED" if ok else "SURVIVED", restored))

    print("=" * 72)
    bad = [r for r in results if r[1] != "KILLED" or "OK" not in r[2]]
    print("SUMMARY: %d/%d killed, %d bad" % (len(results) - len(bad), len(results), len(bad)))
    for r in bad:
        print("  BAD:", r)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
