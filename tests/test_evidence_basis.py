"""Tests for evidence provenance labeling (observed vs inferred)."""

from aibom_scanner.models import Severity
from aibom_scanner.risk_engine import set_evidence_basis
from aibom_scanner.scanner import scan_directory


class TestSetEvidenceBasis:
    def test_no_evidence_no_providers_is_inferred(self):
        risks = [{"title": "x", "affected_providers": []}]
        set_evidence_basis(risks)
        assert risks[0]["evidence_basis"] == "inferred"

    def test_providers_make_it_observed(self):
        risks = [{"title": "x", "affected_providers": ["openai"]}]
        set_evidence_basis(risks)
        assert risks[0]["evidence_basis"] == "observed"

    def test_evidence_makes_it_observed(self):
        risks = [{"title": "x", "affected_providers": [], "evidence": ["app.py:1"]}]
        set_evidence_basis(risks)
        assert risks[0]["evidence_basis"] == "observed"

    def test_missing_keys_default_to_inferred(self):
        risks = [{"title": "x"}]
        set_evidence_basis(risks)
        assert risks[0]["evidence_basis"] == "inferred"

    def test_severities_are_unchanged(self):
        risks = [
            {"title": "a", "severity": Severity.HIGH, "affected_providers": []},
            {"title": "b", "severity": Severity.CRITICAL, "affected_providers": ["openai"]},
        ]
        set_evidence_basis(risks)
        assert risks[0]["severity"] == Severity.HIGH
        assert risks[1]["severity"] == Severity.CRITICAL

    def test_no_risks_are_dropped(self):
        risks = [{"title": str(i), "affected_providers": []} for i in range(5)]
        set_evidence_basis(risks)
        assert len(risks) == 5

    def test_relabels_on_repeat_call(self):
        risks = [{"title": "x", "affected_providers": [], "evidence_basis": "observed"}]
        set_evidence_basis(risks)
        assert risks[0]["evidence_basis"] == "inferred"


class TestScanDirectoryEvidenceBasis:
    def test_every_risk_is_labeled(self, tmp_repo):
        result = scan_directory(tmp_repo)
        assert result.risks
        assert all(r["evidence_basis"] in ("observed", "inferred") for r in result.risks)

    def test_detected_provider_yields_observed_findings(self, tmp_repo):
        result = scan_directory(tmp_repo)
        observed = [r for r in result.risks if r["evidence_basis"] == "observed"]
        assert observed

    def test_repo_with_no_ai_yields_only_inferred(self, tmp_path):
        (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")
        result = scan_directory(tmp_path)
        assert result.risks
        assert all(r["evidence_basis"] == "inferred" for r in result.risks)
