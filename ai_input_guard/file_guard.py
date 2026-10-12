# -*- coding: utf-8 -*-
r"""上传文件守卫：**内容嗅探** + 扩展名一致性 + 大小 + 空文件 + 可读拒绝原因。

## 为什么要有这个模块

任何接受用户上传的系统都面临同一个问题：客户端声明的东西**不构成事实**。
改一个后缀名、改一个 ``Content-Type``，就能让任意字节流进你的系统 ——
然后它们会被当成图片喂给 OCR、被当成 PDF 解析、被当成文本拼接进提示词。

本模块把「这个文件能不能进系统」的判断**收成一个函数**：``guard_upload()``。

## 三条刻意的设计决定

1. **嗅探是真闸门，MIME 只是「声明」**。 ``ALLOWED_MIME`` 里保留
   ``application/octet-stream``（"我不知道这文件是什么"）是为了兼容既有客户端 ——
   它事实上让 MIME 白名单**形同虚设**（客户端只要声明 octet-stream 就能绕过）。
   既然如此，就不要假装 MIME 能拦住什么：**真正拦人的是 ``sniff_kind()``
   与扩展名的比对**，MIME 白名单只负责挡掉"明确声明成可执行文件类型"
   这种**已经自首**的请求。

2. ⭐⭐ **``kind`` 的名字必须诚实**。 ``sniff_kind()`` 返回的是**从字节里读出来的事实**，
   不是猜测的意图；认不出来就是 ``unknown``，**不猜**。
   （把「认不出」说成「文本」是一种编造事实 —— 它会让守卫在真实攻击样本上静默放行。）

3. **拒绝原因必须给"人能照着做"的信息**。每条 ``message`` 都回答三件事：
   **它是什么** · **期望是什么** · **能怎么办**。同时给出**稳定的 ``code``**，
   让界面 / 脚本可以按码分派而不必匹配任何一国的自然语言文案。

## 文本的判定（不能只试 UTF-8）

文本有可能是 GBK。只按 "能 UTF-8 解码" 判文本会把 GBK 文本误判成二进制
⇒ 于是改成**「无 NUL 且无 ASCII 控制字符」**作为文本判据 —— 它对 UTF-8
与 GBK 都成立，且对 ELF / ZIP / 随机二进制都不成立（那些几乎必然含 NUL
或控制字节）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------- 白名单

ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".webp", ".txt"}

ALLOWED_MIME = {
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/webp",
    "text/plain",
    # `application/octet-stream` = 客户端没声明类型（浏览器/命令行工具的常见行为）。
    # ⚠️ 它在白名单里 ⇒ MIME 检查**形同虚设**；真正的闸门是下面的内容嗅探。见模块 docstring 第 1 条。
    "application/octet-stream",
}

#: 扩展名 → 期望的 `sniff_kind()` 结果。**二者必须一致**，不一致即判为伪装。
EXPECTED_KIND_BY_SUFFIX: Dict[str, str] = {
    ".pdf": "pdf",
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".webp": "webp",
    ".txt": "text",
}

# ---------------------------------------------------------------- 魔数

#: 顺序**有意义**：自首型格式（可执行/压缩包）排在文本启发式之前。
#: 每项 = (kind, 偏移, 字节串)
MAGIC: List[Tuple[str, int, bytes]] = [
    ("elf", 0, b"\x7fELF"),
    ("zip", 0, b"PK\x03\x04"),
    ("gzip", 0, b"\x1f\x8b"),
    ("rar", 0, b"Rar!"),
    ("sevenzip", 0, b"7z\xbc\xaf"),
    ("pe_executable", 0, b"MZ"),
    ("shell_script", 0, b"#!"),
    ("pdf", 0, b"%PDF-"),
    ("png", 0, b"\x89PNG\r\n\x1a\n"),
    ("jpeg", 0, b"\xff\xd8\xff"),
    ("webp", 0, b"RIFF"),
]

#: 文本启发式只看前这么多字节（够判了，也避免整文件扫描）。
SNIFF_SAMPLE_BYTES = 8192

#: `kind` → 中文名（给**人**看的；界面不要另建一份映射）
KIND_LABELS: Dict[str, str] = {
    "pdf": "PDF 文档",
    "png": "PNG 图片",
    "jpeg": "JPEG 图片",
    "webp": "WEBP 图片",
    "text": "纯文本",
    "elf": "ELF 可执行程序",
    "zip": "ZIP 压缩包",
    "gzip": "GZIP 压缩包",
    "rar": "RAR 压缩包",
    "sevenzip": "7z 压缩包",
    "pe_executable": "Windows 可执行程序",
    "shell_script": "脚本文件",
    "unknown": "无法识别的二进制数据",
}

#: 稳定的拒绝码（**不要**靠匹配自然语言文案来分派）
CODE_EMPTY = "empty_file"
CODE_TOO_LARGE = "too_large"
CODE_BAD_EXTENSION = "unsupported_extension"
CODE_BAD_MIME = "unsupported_mime"
CODE_MISMATCH = "content_mismatch"


def kind_label(kind: Optional[str]) -> str:
    """`kind` 的中文名；未登记（含 `None`）一律返回「无法识别的二进制数据」。"""
    return KIND_LABELS.get(kind or "", KIND_LABELS["unknown"])


def human_size(size: int) -> str:
    """把字节数写成**人能读**的形式。"""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            if unit == "B":
                return "%d B" % size
            return "%.1f %s" % (value, unit)
        value /= 1024.0
    return "%.1f GB" % value


def _looks_like_text(sample: bytes) -> bool:
    """文本判据：**无 NUL 且无 ASCII 控制字符**。

    这样写是为了同时接受 UTF-8 与 GBK（见模块 docstring「文本的判定」）。
    """
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    for byte in sample:
        if byte < 9 or 13 < byte < 32:
            return False
    return True


def sniff_kind(content: bytes) -> str:
    """从**字节**判断文件到底是什么，返回 `KIND_LABELS` 的键。

    ⚠️ 认不出来返回 `unknown`，**不猜**。这是本模块最重要的不变式 ——
    「猜成 text」会让守卫在真实攻击样本上静默放行。
    """
    if not content:
        return "unknown"
    head = content[:SNIFF_SAMPLE_BYTES]
    for kind, offset, magic in MAGIC:
        if len(head) >= offset + len(magic) and head[offset:offset + len(magic)] == magic:
            # `RIFF` 只是容器头，必须再核 `WEBP` 才是真 WEBP（否则 AVI/WAV 也会被当成图片）。
            if kind == "webp":
                if len(head) >= 12 and head[8:12] == b"WEBP":
                    return "webp"
                continue
            return kind
    if _looks_like_text(head):
        return "text"
    return "unknown"


@dataclass(frozen=True)
class GuardResult:
    """一次上传校验的结论。

    `ok=True` 时 `code` 为空串；`ok=False` 时 `code` 一定是 `CODE_*` 之一。
    字段刻意**全部可序列化** —— 它要能直接进 JSON 响应。
    """

    ok: bool
    code: str = ""
    message: str = ""
    status_code: int = 200
    suffix: str = ""
    detected: Optional[str] = None
    expected: Optional[str] = None
    size: int = 0
    max_bytes: int = 0
    content_type: Optional[str] = None
    extra: Dict[str, object] = field(default_factory=dict)

    def payload(self) -> Dict[str, object]:
        """响应体：`detail` **保持字符串**（既有前端与测试都读 `d.detail`），
        结构化字段**并列**给出（失败原因要有出口，但别把既有出口砸了）。"""
        body: Dict[str, object] = {"detail": self.message, "code": self.code}
        if self.detected is not None:
            body["detected"] = self.detected
        if self.expected is not None:
            body["expected"] = self.expected
        body["suffix"] = self.suffix
        body["size"] = self.size
        body.update(self.extra)
        return body


class UploadRejected(Exception):
    """上传被守卫拒绝。

    用自定义异常而不是 `HTTPException` 的唯一理由：要产出
    ``{"detail": "…人话…", "code": "…"}`` —— `HTTPException` 的 `detail`
    一旦是 dict，既有前端 ``String(d.detail)`` 就会变成 ``[object Object]``。
    ⭐ **既有出口必须与新出口并存**，不能二选一。
    """

    def __init__(self, result: GuardResult):
        super().__init__(result.message)
        self.result = result
        self.status_code = result.status_code


def guard_upload(
    filename: str,
    content_type: Optional[str],
    content: bytes,
    max_bytes: int,
) -> GuardResult:
    """校验一次上传。**顺序即优先级**：空 → 超大 → 扩展名 → MIME → 内容嗅探。

    :param filename: 客户端给的原文件名（**不参与落盘路径**，只用来取后缀）
    :param content_type: 客户端声明的 MIME（**只是声明**，见模块 docstring 第 1 条）
    :param content: 已读入内存的字节（**调用方负责**按 `max_bytes + 1` 限流）
    :param max_bytes: 大小上限
    """
    raw_name = filename or ""
    suffix = PurePath(raw_name).suffix.lower() if raw_name else ""
    size = len(content)
    declared = (content_type or "").strip() or None

    if size == 0:
        return GuardResult(
            ok=False, code=CODE_EMPTY, status_code=415, suffix=suffix, size=size,
            max_bytes=max_bytes, content_type=declared,
            message="文件是空的（0 字节），无法处理。请重新选择文件。",
        )

    if size > max_bytes:
        return GuardResult(
            ok=False, code=CODE_TOO_LARGE, status_code=413, suffix=suffix, size=size,
            max_bytes=max_bytes, content_type=declared,
            message=("文件 %s 超过大小上限 %s。请压缩文件或分批上传。"
                     % (human_size(size), human_size(max_bytes))),
        )

    if suffix not in ALLOWED_EXTENSIONS:
        return GuardResult(
            ok=False, code=CODE_BAD_EXTENSION, status_code=415, suffix=suffix, size=size,
            max_bytes=max_bytes, content_type=declared,
            message=("不支持的文件类型「%s」，仅支持 PDF、PNG、JPG、JPEG、WEBP、TXT。"
                     % (suffix or "无扩展名")),
            extra={"allowed": sorted(ALLOWED_EXTENSIONS)},
        )

    if declared and declared not in ALLOWED_MIME:
        return GuardResult(
            ok=False, code=CODE_BAD_MIME, status_code=415, suffix=suffix, size=size,
            max_bytes=max_bytes, content_type=declared,
            message=("声明的文件类型「%s」不被允许，仅支持 PDF、PNG、JPG、JPEG、WEBP、TXT。"
                     % declared),
            extra={"allowed_mime": sorted(ALLOWED_MIME)},
        )

    detected = sniff_kind(content)
    expected = EXPECTED_KIND_BY_SUFFIX[suffix]
    if detected != expected:
        return GuardResult(
            ok=False, code=CODE_MISMATCH, status_code=415, suffix=suffix, size=size,
            max_bytes=max_bytes, content_type=declared,
            detected=detected, expected=expected,
            message=("文件内容与扩展名不符：文件实际是「%s」，但扩展名「%s」应该是「%s」。"
                     "请不要通过改扩展名上传；请上传原格式文件或联系管理员。"
                     % (kind_label(detected), suffix, kind_label(expected))),
        )

    return GuardResult(
        ok=True, suffix=suffix, size=size, max_bytes=max_bytes,
        content_type=declared, detected=detected, expected=expected,
    )
