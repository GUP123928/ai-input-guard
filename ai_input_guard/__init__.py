# -*- coding: utf-8 -*-
"""ai-input-guard：AI 应用的输入防护库。

两道门，缺一不可：

- **文件门**（`file_guard`）：上传的文件真的是它声称的类型吗？
  —— 内容嗅探 + 扩展名一致性 + 大小 + 空文件。
- **内容门**（`prompt_guard`）：进了系统之后，文件里的话能不能指挥模型？
  —— 不可信数据围栏 + 注入检测 + 泄漏检测 + 落地一致性校验。

```python
from ai_input_guard import guard_upload, inspect

# 门 1：文件进系统之前
result = guard_upload(filename, content_type, content, max_bytes=10 * 1024 * 1024)
if not result.ok:
    raise UploadRejected(result)   # 或 render(result.payload())

# 门 2：抽出的结果与原文核对
report = inspect(candidate, ocr_text, filename=filename)
if report["suspected_injection"]:
    for w in report["warnings"]:
        print(w)
```
"""
from ai_input_guard.file_guard import (  # noqa: F401
    ALLOWED_EXTENSIONS,
    ALLOWED_MIME,
    CODE_BAD_EXTENSION,
    CODE_BAD_MIME,
    CODE_EMPTY,
    CODE_MISMATCH,
    CODE_TOO_LARGE,
    EXPECTED_KIND_BY_SUFFIX,
    GuardResult,
    UploadRejected,
    guard_upload,
    human_size,
    kind_label,
    sniff_kind,
)
from ai_input_guard.prompt_guard import (  # noqa: F401
    INJECTION_PATTERNS,
    SYSTEM_PROMPT,
    fence,
    grounding_check,
    injected_prompt_suffix,
    inspect,
    leak_check,
    leak_probe_selfcheck,
    scan_filename,
    scan_untrusted,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # file_guard
    "ALLOWED_EXTENSIONS", "ALLOWED_MIME", "EXPECTED_KIND_BY_SUFFIX",
    "CODE_EMPTY", "CODE_TOO_LARGE", "CODE_BAD_EXTENSION", "CODE_BAD_MIME", "CODE_MISMATCH",
    "GuardResult", "UploadRejected", "guard_upload", "human_size", "kind_label", "sniff_kind",
    # prompt_guard
    "INJECTION_PATTERNS", "SYSTEM_PROMPT",
    "fence", "grounding_check", "injected_prompt_suffix", "inspect",
    "leak_check", "leak_probe_selfcheck", "scan_filename", "scan_untrusted",
]
