"""Tests for the v1.1.0 extension set and the comment/asset noise guard."""

import pytest

from aibom_scanner.detectors.ai_sdk import (
    SCANNABLE_EXTENSIONS,
    SOURCE_EXTENSIONS,
    UNSUPPORTED_EXTENSIONS,
    _is_noise_line,
    scan_file,
    should_scan_file,
)

NEW_EXTENSIONS = [".cs", ".fs", ".vb", ".vue", ".svelte", ".cjs", ".sh", ".swift"]


class TestNewExtensions:
    @pytest.mark.parametrize("ext", NEW_EXTENSIONS)
    def test_extension_is_scannable(self, ext):
        assert ext in SCANNABLE_EXTENSIONS
        assert should_scan_file(f"src/Program{ext}")

    @pytest.mark.parametrize("ext", NEW_EXTENSIONS)
    def test_extension_still_skipped_in_test_dirs(self, ext):
        assert not should_scan_file(f"tests/Program{ext}")
        assert not should_scan_file(f"fixtures/Program{ext}")

    def test_csharp_file_is_read(self):
        # v1.2 adds `using`-directive patterns (see test_dotnet_detection.py),
        # so `using Anthropic;` is now a detected import, not just read-but-blind.
        content = 'var client = new OpenAI();\nusing Anthropic;'
        detections = scan_file("Program.cs", content)
        assert {d.provider for d in detections} == {"openai", "anthropic"}

    def test_source_extensions_is_union(self):
        assert SOURCE_EXTENSIONS == SCANNABLE_EXTENSIONS | UNSUPPORTED_EXTENSIONS

    def test_unsupported_extensions_are_not_scannable(self):
        assert not (UNSUPPORTED_EXTENSIONS & SCANNABLE_EXTENSIONS)
        assert not should_scan_file("lib/handler.php")
        assert not should_scan_file("scripts/deploy.ps1")


class TestNoiseGuard:
    @pytest.mark.parametrize("line", [
        "# import openai",
        "// require('openai')",
        "/* from anthropic import Anthropic */",
        " * import openai",
        "<!-- import openai -->",
        "-- import openai",
    ])
    def test_comment_led_lines_are_noise(self, line):
        assert _is_noise_line(line)

    @pytest.mark.parametrize("line", [
        'import AnthropicLogo from "assets/llm-icons/anthropic.svg";',
        'import logo from "./openai.png";',
        "import style from './openai.css';",
        'const f = require("fonts/openai.woff2");',
    ])
    def test_asset_imports_are_noise(self, line):
        assert _is_noise_line(line)

    @pytest.mark.parametrize("line", [
        "import openai  # noqa",
        'const openai = require("openai")',
        'client = OpenAI(base_url="https://api.deepseek.com")',
    ])
    def test_real_usage_is_not_noise(self, line):
        assert not _is_noise_line(line)

    def test_commented_import_not_detected(self):
        assert scan_file("app.py", "# from openai import OpenAI") == []

    def test_asset_import_not_detected(self):
        content = 'import AnthropicLogo from "assets/llm-icons/anthropic.svg";'
        assert scan_file("Icon.vue", content) == []

    def test_noqa_import_still_detected(self):
        detections = scan_file("app.py", "import openai  # noqa")
        assert {d.provider for d in detections} == {"openai"}

    def test_require_still_detected(self):
        detections = scan_file("app.cjs", 'const openai = require("openai")')
        assert {d.provider for d in detections} == {"openai"}

    def test_base_url_still_detected(self):
        content = 'client = OpenAI(base_url="https://api.deepseek.com")'
        assert "deepseek" in {d.provider for d in scan_file("app.py", content)}
