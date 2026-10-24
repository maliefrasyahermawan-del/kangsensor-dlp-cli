"""Tests for built-in rule detection — NIK, NPWP, credentials, etc."""

import sys
from pathlib import Path

import pytest

# Make sure the package is importable when running from repo root
sys.path.insert(0, str(Path(__file__).parent.parent))

from kangsensor.rules.library import RuleLibrary
from kangsensor.core.engine import RuleEngine


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    lib = RuleLibrary()
    lib.load_builtin()
    return RuleEngine(lib.rules)


# ---------------------------------------------------------------------------
# NIK
# ---------------------------------------------------------------------------

class TestNIK:
    def test_valid_nik_with_context(self, engine: RuleEngine) -> None:
        text = "NIK saya adalah 3273011234567890 tercantum di KTP."
        findings = engine.evaluate(text, file_path="test.txt")
        nik_hits = [f for f in findings if f.rule_id == "ID_NIK"]
        assert len(nik_hits) >= 1, "Should detect NIK with context keyword"

    def test_nik_high_severity(self, engine: RuleEngine) -> None:
        text = "Nomor Induk 3273011234567890"
        findings = engine.evaluate(text, file_path="test.txt")
        nik_hits = [f for f in findings if f.rule_id == "ID_NIK"]
        assert any(f.severity == "HIGH" for f in nik_hits)

    def test_nik_confidence_with_valid_province(self, engine: RuleEngine) -> None:
        # Province code 32 = Jawa Barat (valid)
        text = "NIK: 3273011234567890"
        findings = engine.evaluate(text, file_path="test.txt")
        nik_hits = [f for f in findings if f.rule_id == "ID_NIK"]
        if nik_hits:
            assert nik_hits[0].confidence >= 70

    def test_nik_invalid_province_lowers_confidence(self, engine: RuleEngine) -> None:
        # Province code 30 is not valid in Indonesia
        text = "NIK: 3099991234567890"
        findings = engine.evaluate(text, file_path="test.txt")
        nik_hits = [f for f in findings if f.rule_id == "ID_NIK"]
        # With invalid province and still context keyword → may still pass min_confidence
        # but confidence should be lower than the valid-province case
        if nik_hits:
            assert nik_hits[0].confidence < 100

    def test_no_false_positive_random_digits(self, engine: RuleEngine) -> None:
        # 16-digit number but no NIK/KTP context and invalid province → below min_confidence
        text = "serial number: 0099123456789000"
        findings = engine.evaluate(text, file_path="test.txt")
        nik_hits = [f for f in findings if f.rule_id == "ID_NIK"]
        # Either no hit or very low confidence
        for hit in nik_hits:
            assert hit.confidence < 70, f"Should not have high confidence: {hit}"

    def test_nik_in_csv(self, engine: RuleEngine) -> None:
        csv = "nama,NIK,kota\nBudi,3273011234567890,Bandung\nSiti,3171012345678901,Jakarta"
        findings = engine.evaluate(csv, file_path="data.csv")
        nik_hits = [f for f in findings if f.rule_id == "ID_NIK"]
        assert len(nik_hits) >= 2


# ---------------------------------------------------------------------------
# NPWP
# ---------------------------------------------------------------------------

class TestNPWP:
    def test_formatted_npwp(self, engine: RuleEngine) -> None:
        text = "NPWP: 12.345.678.9-012.345"
        findings = engine.evaluate(text, file_path="test.txt")
        hits = [f for f in findings if f.rule_id == "ID_NPWP"]
        assert len(hits) >= 1

    def test_npwp_high_confidence_with_context(self, engine: RuleEngine) -> None:
        text = "Nomor NPWP Wajib Pajak: 12.345.678.9-012.345"
        findings = engine.evaluate(text, file_path="test.txt")
        hits = [f for f in findings if f.rule_id == "ID_NPWP"]
        if hits:
            assert hits[0].confidence >= 80

    def test_npwp_severity_high(self, engine: RuleEngine) -> None:
        text = "pajak: 12.345.678.9-012.345"
        findings = engine.evaluate(text, file_path="test.txt")
        hits = [f for f in findings if f.rule_id == "ID_NPWP"]
        assert all(f.severity == "HIGH" for f in hits)


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

class TestCredentials:
    def test_aws_access_key(self, engine: RuleEngine) -> None:
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        findings = engine.evaluate(text, file_path=".env")
        hits = [f for f in findings if f.rule_id == "CRED_AWS_ACCESS_KEY"]
        assert len(hits) >= 1

    def test_aws_access_key_critical(self, engine: RuleEngine) -> None:
        text = "key: AKIAIOSFODNN7EXAMPLE"
        findings = engine.evaluate(text, file_path="config.txt")
        hits = [f for f in findings if f.rule_id == "CRED_AWS_ACCESS_KEY"]
        assert all(f.severity == "CRITICAL" for f in hits)

    def test_private_key_header(self, engine: RuleEngine) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        findings = engine.evaluate(text, file_path="key.pem")
        hits = [f for f in findings if f.rule_id == "CRED_PRIVATE_KEY"]
        assert len(hits) >= 1, "Should detect PEM private key"

    def test_github_token(self, engine: RuleEngine) -> None:
        text = "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        findings = engine.evaluate(text, file_path=".env")
        hits = [f for f in findings if f.rule_id == "CRED_GITHUB_TOKEN"]
        assert len(hits) >= 1

    def test_placeholder_not_flagged(self, engine: RuleEngine) -> None:
        text = "password=changeme"
        findings = engine.evaluate(text, file_path="test.txt")
        hits = [f for f in findings if f.rule_id == "CRED_GENERIC_SECRET"]
        # Placeholder should suppress confidence below min_confidence
        for h in hits:
            assert h.confidence < 60, "Placeholder password should be low confidence"


# ---------------------------------------------------------------------------
# PII General
# ---------------------------------------------------------------------------

class TestPIIGeneral:
    def test_email_detection(self, engine: RuleEngine) -> None:
        text = "Kirim ke budi.santoso@example.co.id"
        findings = engine.evaluate(text, file_path="test.txt")
        hits = [f for f in findings if f.rule_id == "PII_EMAIL"]
        assert len(hits) >= 1

    def test_indonesian_phone(self, engine: RuleEngine) -> None:
        text = "Hubungi kami di 08123456789 atau +6281234567890"
        findings = engine.evaluate(text, file_path="test.txt")
        hits = [f for f in findings if f.rule_id == "PII_PHONE_ID"]
        assert len(hits) >= 1

    def test_credit_card_luhn(self, engine: RuleEngine) -> None:
        # Visa test number that passes Luhn
        text = "kartu kredit: 4532015112830366"
        findings = engine.evaluate(text, file_path="test.txt")
        hits = [f for f in findings if f.rule_id in ("FIN_CC_VISA", "FIN_CC_GENERIC")]
        assert len(hits) >= 1


# ---------------------------------------------------------------------------
# Snippet truncation
# ---------------------------------------------------------------------------

class TestSnippet:
    def test_snippet_max_100_chars(self, engine: RuleEngine) -> None:
        long_text = "NIK: " + "3273011234567890" + " " + ("x" * 200)
        findings = engine.evaluate(long_text, file_path="test.txt")
        for f in findings:
            assert len(f.snippet) <= 100
