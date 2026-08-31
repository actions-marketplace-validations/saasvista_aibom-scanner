"""Regression tests for issue #2 — false-positive provider detections.

Provider names that are common English words (replicate, together, cohere)
matched `from <anything> import <word>`, so any repo with a same-named local
module was mis-flagged. Separately, mapping the `boto3` dependency to
aws_bedrock flagged Bedrock for any repo touching AWS at all.

https://github.com/saasvista/aibom-scanner/issues/2
"""
import pytest

from aibom_scanner.detectors.ai_sdk import DEPENDENCY_MAP, scan_dependencies, scan_file


class TestLocalModuleImportsAreNotProviders:
    """`from <pkg> import <word>` imports a local symbol, not the SDK."""

    @pytest.mark.parametrize("code", [
        "from app.services import replicate",
        "from myapp.tasks import together",
        "from utils import cohere",
        "from mypkg import replicate, os",
        "from .helpers import together",
    ])
    def test_local_import_is_not_a_detection(self, code):
        assert scan_file("app.py", code) == []


class TestRealSdkImportsStillDetected:
    """Anchoring must not cost us true positives."""

    @pytest.mark.parametrize("code,provider", [
        ("import replicate", "replicate"),
        ("from replicate import Client", "replicate"),
        ("from replicate.client import Client", "replicate"),
        ("import cohere", "cohere"),
        ("from cohere.client import Client", "cohere"),
        ("import together", "together_ai"),
        ("from together import Together", "together_ai"),
    ])
    def test_top_level_import_detected(self, code, provider):
        assert any(d.provider == provider for d in scan_file("app.py", code))

    @pytest.mark.parametrize("code,provider", [
        ("    import cohere", "cohere"),
        ("        from replicate import Client", "replicate"),
    ])
    def test_indented_import_detected(self, code, provider):
        """Imports inside try/except or functions are still real usage."""
        assert any(d.provider == provider for d in scan_file("app.py", code))

    def test_js_require_still_detected(self):
        code = "const r = require('replicate')"
        assert any(d.provider == "replicate" for d in scan_file("app.js", code))


class TestBoto3DoesNotImplyBedrock:
    """boto3 is the whole AWS SDK — its presence is not Bedrock usage."""

    def test_boto3_not_in_dependency_map(self):
        assert "boto3" not in DEPENDENCY_MAP

    def test_boto3_requirement_yields_no_provider(self):
        deps = scan_dependencies("requirements.txt", "boto3==1.34.0\n")
        assert [d for d in deps if d["provider"] == "aws_bedrock"] == []

    def test_boto3_import_alone_is_not_bedrock(self):
        assert scan_file("app.py", "import boto3") == []

    @pytest.mark.parametrize("code", [
        "client = BedrockRuntime()",
        "resp = bedrock.invoke_model(modelId=m)",
        'client = boto3.client("bedrock-runtime")',
    ])
    def test_real_bedrock_usage_still_detected(self, code):
        """Bedrock is detected from actual usage, which is the correct signal."""
        assert any(d.provider == "aws_bedrock" for d in scan_file("app.py", code))
