"""Tests for coverage accounting — both ratios, zero guards, exhaustive attribution."""

from aibom_scanner.scanner import build_coverage_report, scan_directory


def _total_unscanned(report):
    return sum(report.unscanned_by_extension.values())


class TestBuildCoverageReport:
    def test_full_coverage(self):
        files = ["a.py", "b.js"]
        report = build_coverage_report(files, files)
        assert report.files_in_tree == 2
        assert report.source_files_seen == 2
        assert report.files_scanned == 2
        assert report.coverage_pct == 100.0
        assert report.readable_coverage_pct == 100.0
        assert report.unsupported_languages == []

    def test_non_source_files_excluded_from_denominator(self):
        files = ["a.py", "README.md", "logo.png"]
        report = build_coverage_report(files, ["a.py"])
        assert report.files_in_tree == 3
        assert report.source_files_seen == 1
        assert report.coverage_pct == 100.0

    def test_unsupported_language_lowers_both_ratios(self):
        files = ["a.py", "b.php", "c.php"]
        report = build_coverage_report(files, ["a.py"])
        assert report.unscanned_by_extension == {".php": 2}
        assert report.unsupported_languages == [".php"]
        assert report.coverage_pct == 33.3
        assert report.readable_coverage_pct == 33.3

    def test_skipped_by_path_splits_the_two_ratios(self):
        files = ["a.py", "tests/b.py", "tests/c.py"]
        report = build_coverage_report(files, ["a.py"])
        assert report.skipped_by_path == 2
        assert report.unscanned_by_extension == {}
        assert report.coverage_pct == 33.3
        assert report.readable_coverage_pct == 100.0

    def test_both_ratios_reported_independently(self):
        # Half the repo unreadable, half of the rest excluded as tests.
        files = ["a.py", "tests/b.py", "c.cpp", "d.cpp"]
        report = build_coverage_report(files, ["a.py"])
        assert report.coverage_pct == 25.0
        assert report.readable_coverage_pct == 33.3

    def test_empty_repo_guards_both_denominators(self):
        report = build_coverage_report([], [])
        assert report.source_files_seen == 0
        assert report.coverage_pct == 0.0
        assert report.readable_coverage_pct == 0.0

    def test_docs_only_repo_has_no_source(self):
        report = build_coverage_report(["README.md", "docs/guide.md"], [])
        assert report.files_in_tree == 2
        assert report.source_files_seen == 0
        assert report.coverage_pct == 0.0
        assert report.readable_coverage_pct == 0.0

    def test_all_tests_repo_guards_readable_denominator(self):
        files = ["tests/a.py", "tests/b.py"]
        report = build_coverage_report(files, [])
        assert report.skipped_by_path == 2
        assert report.coverage_pct == 0.0
        assert report.readable_coverage_pct == 0.0

    def test_all_unsupported_repo(self):
        files = ["a.php", "b.scala"]
        report = build_coverage_report(files, [])
        assert report.coverage_pct == 0.0
        assert report.readable_coverage_pct == 0.0
        assert report.unsupported_languages == [".php", ".scala"]

    def test_attribution_is_exhaustive_and_non_overlapping(self):
        files = ["a.py", "tests/b.py", "c.php", "d.cs", "README.md"]
        report = build_coverage_report(files, ["a.py", "d.cs"])
        assert report.files_scanned + report.skipped_by_path + _total_unscanned(report) == report.source_files_seen

    def test_unsupported_languages_excludes_scannable_extensions(self):
        # A .py file the scanner declined to read is not an unsupported language.
        report = build_coverage_report(["a.py", "b.py"], ["a.py"])
        assert report.unscanned_by_extension == {".py": 1}
        assert report.unsupported_languages == []


class TestScanDirectoryCoverage:
    def test_coverage_attached_to_result(self, tmp_repo):
        result = scan_directory(tmp_repo)
        assert result.coverage is not None
        assert result.coverage.files_scanned > 0
        assert result.coverage.source_files_seen >= result.coverage.files_scanned

    def test_coverage_attribution_holds_on_real_scan(self, tmp_repo):
        cov = scan_directory(tmp_repo).coverage
        assert cov.files_scanned + cov.skipped_by_path + _total_unscanned(cov) == cov.source_files_seen

    def test_empty_repo_coverage_is_zeroed(self, empty_repo):
        cov = scan_directory(empty_repo).coverage
        assert cov.source_files_seen == 0
        assert cov.coverage_pct == 0.0
        assert cov.readable_coverage_pct == 0.0

    def test_csharp_repo_is_scanned_not_skipped(self, tmp_path):
        (tmp_path / "Program.cs").write_text("var x = new OpenAI();\n")
        cov = scan_directory(tmp_path).coverage
        assert cov.files_scanned == 1
        assert cov.unsupported_languages == []

    def test_unsupported_language_surfaces(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\n")
        (tmp_path / "deploy.ps1").write_text("Write-Host hi\n")
        cov = scan_directory(tmp_path).coverage
        assert cov.unsupported_languages == [".ps1"]
        assert cov.unscanned_by_extension[".ps1"] == 1
