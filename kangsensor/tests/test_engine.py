"""Tests for the RuleEngine core logic."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from kangsensor.core.engine import RuleEngine, Finding, _is_binary, _redact_snippet
from kangsensor.rules.library import RuleLibrary


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    lib = RuleLibrary()
    lib.load_builtin()
    return RuleEngine(lib.rules)


# ---------------------------------------------------------------------------
# Binary detection
# ---------------------------------------------------------------------------

class TestBinaryDetection:
    def test_null_heavy_is_binary(self) -> None:
        data = b"\x00" * 1000 + b"some text"
        assert _is_binary(data) is True

    def test_text_is_not_binary(self) -> None:
        data = b"NIK: 3273011234567890\n"
        assert _is_binary(data) is False

    def test_empty_is_not_binary(self) -> None:
        assert _is_binary(b"") is False


# ---------------------------------------------------------------------------
# Snippet truncation
# ---------------------------------------------------------------------------

class TestRedactSnippet:
    def test_short_text_unchanged(self) -> None:
        assert _redact_snippet("hello") == "hello"

    def test_long_text_truncated(self) -> None:
        s = _redact_snippet("a" * 200, max_len=100)
        assert len(s) <= 100
        assert "..." in s

    def test_exactly_100_unchanged(self) -> None:
        s = "x" * 100
        assert _redact_snippet(s) == s


# ---------------------------------------------------------------------------
# RuleEngine.evaluate
# ---------------------------------------------------------------------------

class TestRuleEngineEvaluate:
    def test_returns_list(self, engine: RuleEngine) -> None:
        result = engine.evaluate("no sensitive data here")
        assert isinstance(result, list)

    def test_finding_fields(self, engine: RuleEngine) -> None:
        findings = engine.evaluate("NIK: 3273011234567890", file_path="x.txt")
        nik = [f for f in findings if f.rule_id == "ID_NIK"]
        if nik:
            f = nik[0]
            assert isinstance(f, Finding)
            assert f.file_path == "x.txt"
            assert 0 <= f.confidence <= 100
            assert f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            assert f.line_no >= 1

    def test_empty_payload(self, engine: RuleEngine) -> None:
        assert engine.evaluate("") == []

    def test_multiline_line_numbers(self, engine: RuleEngine) -> None:
        text = "line one\nline two\nNIK: 3273011234567890\nline four"
        findings = engine.evaluate(text, file_path="test.txt")
        nik = [f for f in findings if f.rule_id == "ID_NIK"]
        if nik:
            assert nik[0].line_no == 3

    def test_source_clipboard(self, engine: RuleEngine) -> None:
        findings = engine.evaluate("NIK: 3273011234567890", source="clipboard")
        for f in findings:
            if f.rule_id == "ID_NIK":
                assert f.source == "clipboard"


# ---------------------------------------------------------------------------
# evaluate_file
# ---------------------------------------------------------------------------

class TestEvaluateFile:
    def test_nonexistent_file_returns_empty(self, engine: RuleEngine, tmp_path: Path) -> None:
        result = engine.evaluate_file(str(tmp_path / "missing.txt"))
        assert result == []

    def test_binary_file_returns_empty(self, engine: RuleEngine, tmp_path: Path) -> None:
        binary = tmp_path / "file.bin"
        binary.write_bytes(b"\x00" * 4000)
        assert engine.evaluate_file(str(binary)) == []

    def test_text_file_detected(self, engine: RuleEngine, tmp_path: Path) -> None:
        txt = tmp_path / "nik.txt"
        txt.write_text("Pak Budi NIK saya 3273011234567890\n", encoding="utf-8")
        findings = engine.evaluate_file(str(txt))
        nik = [f for f in findings if f.rule_id == "ID_NIK"]
        assert len(nik) >= 1


# ---------------------------------------------------------------------------
# Audit log chain
# ---------------------------------------------------------------------------

class TestAuditChain:
    def test_chain_valid_after_appends(self, tmp_path: Path) -> None:
        from kangsensor.core.audit import AuditLog
        log = AuditLog(tmp_path / "audit.db")
        log.append("TEST", rule_id="ID_NIK", severity="HIGH", action_taken="log")
        log.append("TEST", rule_id="PII_EMAIL", severity="LOW", action_taken="log")
        ok, msg = log.verify_chain()
        assert ok, msg

    def test_tamper_detected(self, tmp_path: Path) -> None:
        import sqlite3
        from kangsensor.core.audit import AuditLog

        log = AuditLog(tmp_path / "audit2.db")
        log.append("TEST", rule_id="ID_NIK", severity="HIGH", action_taken="log")
        log.append("TEST2", rule_id="PII_EMAIL", severity="LOW", action_taken="log")

        # Tamper with a row
        conn = sqlite3.connect(str(tmp_path / "audit2.db"))
        conn.execute("UPDATE audit_log SET rule_id='TAMPERED' WHERE id=1")
        conn.commit()
        conn.close()

        log2 = AuditLog(tmp_path / "audit2.db")
        ok, msg = log2.verify_chain()
        assert not ok
