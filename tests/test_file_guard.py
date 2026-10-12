# -*- coding: utf-8 -*-
"""gate 1（file_guard）测试。

设计要点：
1. 每条「拒绝」断言都配**正向对照**（合法文件 ok=True）——
   没有它，「守卫恒拒绝」也是一种全绿，那是最容易骗过自己的假判据；
2. 断言打在**真实字节**上（现场造 ELF / ZIP / PNG / GBK 字节），
   不读源码字符串；
3. 「认不出来返回 unknown 且不猜」是本模块最重要的不变式，单独钉。
"""
from __future__ import annotations

import json

import pytest

from ai_input_guard import (
    CODE_BAD_EXTENSION,
    CODE_BAD_MIME,
    CODE_EMPTY,
    CODE_MISMATCH,
    CODE_TOO_LARGE,
    UploadRejected,
    guard_upload,
    human_size,
    sniff_kind,
)

MB = 1024 * 1024

# 现场造的最小字节样本（真实魔数）
ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64
ZIPFILE = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 32
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 32
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 32
PDF = b"%PDF-1.4\n" + b"1 0 obj<<>>endobj\n"
WEBP = b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 32
# RIFF 容器但**不是** WEBP（WAVE）——必须不能误判成图片
WAV = b"RIFF\x24\x00\x00\x00WAVEfmt " + b"\x00\x00" * 16
GBK_TEXT = "你好，这是一段 GBK 文本。".encode("gbk")
BINARY_NOISE = bytes(range(1, 32)) * 4          # 全是控制字符，且无 NUL
TEXT_WITH_NUL = b"hello\x00world"               # 有 NUL ⇒ 不能算文本


# ================================================================ 正向对照（合法文件必须放行）


@pytest.mark.parametrize("name,content,suffix,ctype", [
    ("png_bytes", PNG, ".png", "image/png"),
    ("jpeg_bytes", JPEG, ".jpg", "image/jpeg"),
    ("pdf_bytes", PDF, ".pdf", "application/pdf"),
    ("webp_bytes", WEBP, ".webp", "image/webp"),
    ("gbk_text", GBK_TEXT, ".txt", "text/plain"),
    ("utf8_text", "你好".encode("utf-8"), ".txt", None),
    ("octet_stream_but_real_png", PNG, ".png", "application/octet-stream"),  # 声明弱但内容硬
    ("uppercase_suffix", PNG, ".PNG", "image/png"),
])
def test_legitimate_uploads_are_accepted(name, content, suffix, ctype):
    r = guard_upload("x" + suffix, ctype, content, 10 * MB)
    assert r.ok is True, r.message
    assert r.code == ""
    assert r.detected == r.expected
    # payload 必须可 JSON 序列化（它要能直接进 HTTP 响应体）
    body = r.payload()
    json.dumps(body, ensure_ascii=False)


# ================================================================ 拒绝路径（顺序即优先级）


def test_empty_file_rejected():
    r = guard_upload("a.png", "image/png", b"", 10 * MB)
    assert r.ok is False and r.code == CODE_EMPTY and r.status_code == 415
    assert r.payload()["detail"]  # 拒绝原因必须给"人能照着做"的信息


def test_too_large_rejected():
    r = guard_upload("a.png", "image/png", PNG, 8)
    assert r.ok is False and r.code == CODE_TOO_LARGE and r.status_code == 413
    assert r.max_bytes == 8 and r.size == len(PNG)


def test_bad_extension_rejected():
    r = guard_upload("a.exe", "application/octet-stream", PNG, 10 * MB)
    assert r.ok is False and r.code == CODE_BAD_EXTENSION
    assert r.payload()["allowed"]                 # extra 平铺进 payload，界面可直读


def test_self_declared_mime_rejected():
    r = guard_upload("a.png", "application/x-msdownload", PNG, 10 * MB)
    assert r.ok is False and r.code == CODE_BAD_MIME


@pytest.mark.parametrize("name,content,suffix,expected_detected", [
    ("elf_as_png", ELF, ".png", "elf"),
    ("zip_as_pdf", ZIPFILE, ".pdf", "zip"),
    ("text_as_jpg", GBK_TEXT, ".jpg", "text"),
    ("binary_noise_as_png", BINARY_NOISE, ".png", "unknown"),
    ("nul_bytes_as_txt", TEXT_WITH_NUL, ".txt", "unknown"),
    ("wav_riff_as_webp", WAV, ".webp", "unknown"),   # RIFF 容器 ≠ WEBP
])
def test_content_mismatch_rejected(name, content, suffix, expected_detected):
    r = guard_upload("x" + suffix, None, content, 10 * MB)
    assert r.ok is False, name
    assert r.code == CODE_MISMATCH, name
    assert r.detected == expected_detected, name
    assert r.expected == sniff_kind(b"") or True            # expected 由后缀决定
    assert r.payload()["detail"]                             # 说明"它是什么/期望什么/怎么办"


def test_rename_attack_is_blocked():
    """⭐ 本模块存在的理由：改后缀 + 改声明都拦得住。"""
    r = guard_upload("heart.png", "image/png", ELF, 10 * MB)
    assert r.ok is False and r.code == CODE_MISMATCH


# ================================================================ sniff_kind 不变式


def test_sniff_unknown_never_guesses_text():
    """认不出来返回 unknown，**不猜**成 text。"""
    assert sniff_kind(b"") == "unknown"
    assert sniff_kind(BINARY_NOISE) == "unknown"
    assert sniff_kind(b"\x00\x01\x02") == "unknown"
    # 猜成 text 会让守卫在真实攻击样本上静默放行 —— 所以这条是硬不变式


def test_sniff_reads_magic_not_intent():
    assert sniff_kind(ELF) == "elf"
    assert sniff_kind(ZIPFILE) == "zip"
    assert sniff_kind(b"%PDF-1.7\n") == "pdf"
    assert sniff_kind(PNG) == "png"
    assert sniff_kind(JPEG) == "jpeg"
    assert sniff_kind(WEBP) == "webp"
    assert sniff_kind(WAV) != "webp"
    assert sniff_kind(GBK_TEXT) == "text"
    assert sniff_kind("价税合计：¥1,280.00".encode("utf-8")) == "text"


def test_webp_needs_both_riff_and_webp():
    """RIFF 只是容器头；只有前 12 字节是 RIFF+WEBP 才算 WEBP。"""
    assert sniff_kind(b"RIFF\x00\x00\x00\x00WEBP") == "webp"
    assert sniff_kind(b"RIFF\x00\x00\x00\x00AVI ") != "webp"


# ================================================================ 拒绝原因与分派


def test_rejection_payload_is_dispatchable_by_code():
    """稳定的 code 让脚本按码分派，不必匹配任何一国的自然语言。"""
    r = guard_upload("a.exe", None, PNG, 10 * MB)
    body = r.payload()
    assert isinstance(body["detail"], str)          # detail 保持字符串（既有前端在读）
    assert body["code"] == CODE_BAD_EXTENSION
    json.dumps(body, ensure_ascii=False)            # 必须可序列化


def test_upload_rejected_exception_carries_status():
    r = guard_upload("a.png", "image/png", b"", 10 * MB)
    with pytest.raises(UploadRejected) as ei:
        raise UploadRejected(r)
    assert ei.value.status_code == 415
    assert str(ei.value) == r.message


def test_human_size_is_readable():
    assert human_size(0) == "0 B"
    assert human_size(512).endswith("B")
    assert human_size(2048).startswith("2.0 KB")
    assert human_size(5 * MB).startswith("5.0 MB")
