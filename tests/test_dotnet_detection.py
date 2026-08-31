"""Tests for C#/.NET `using`-directive detection and NuGet manifest parsing (v1.2)."""

from pathlib import Path

import pytest

from aibom_scanner.detectors.ai_sdk import (
    _match_nuget_package,
    scan_dependencies,
    scan_file,
    should_scan_file,
)
from aibom_scanner.scanner import scan_directory

SAFEGUARD_MCP_FIXTURE = Path(
    "/home/mike/proj/ai-risk-compliance/backend/.repos-cache/OneIdentity/safeguard-mcp"
)


class TestUsingDirectivePatterns:
    """One detection test per `using` pattern in the C# / .NET block."""

    def test_mcp_using(self):
        detections = scan_file("Program.cs", "using ModelContextProtocol.Server;")
        assert {d.provider for d in detections} == {"mcp"}

    def test_mcp_using_bare_namespace(self):
        detections = scan_file("Program.cs", "using ModelContextProtocol;")
        assert {d.provider for d in detections} == {"mcp"}

    def test_semantic_kernel_using(self):
        detections = scan_file("Program.cs", "using Microsoft.SemanticKernel;")
        assert {d.provider for d in detections} == {"semantic_kernel"}

    def test_azure_openai_using(self):
        detections = scan_file("Program.cs", "using Azure.AI.OpenAI;")
        assert {d.provider for d in detections} == {"azure_openai"}

    def test_openai_using(self):
        detections = scan_file("Program.cs", "using OpenAI;")
        assert {d.provider for d in detections} == {"openai"}

    def test_anthropic_using(self):
        detections = scan_file("Program.cs", "using Anthropic;")
        assert {d.provider for d in detections} == {"anthropic"}

    def test_anthropic_sdk_using(self):
        detections = scan_file("Program.cs", "using Anthropic.SDK;")
        assert {d.provider for d in detections} == {"anthropic"}

    def test_aws_bedrock_using(self):
        detections = scan_file("Program.cs", "using Amazon.BedrockRuntime;")
        assert "aws_bedrock" in {d.provider for d in detections}

    def test_google_aiplatform_using(self):
        detections = scan_file("Program.cs", "using Google.Cloud.AIPlatform.V1;")
        assert {d.provider for d in detections} == {"google_ai"}

    def test_mscc_generativeai_using(self):
        detections = scan_file("Program.cs", "using Mscc.GenerativeAI;")
        assert {d.provider for d in detections} == {"google_ai"}


class TestMcpAttributes:
    """MCP attribute detection for all four attribute shapes."""

    def test_mcp_server_tool(self):
        detections = scan_file("Tools.cs", "[McpServerTool]")
        assert {d.provider for d in detections} == {"mcp"}

    def test_mcp_server_tool_type(self):
        detections = scan_file("Tools.cs", "[McpServerToolType]")
        assert {d.provider for d in detections} == {"mcp"}

    def test_mcp_server_resource(self):
        detections = scan_file("Resources.cs", "[McpServerResource]")
        assert {d.provider for d in detections} == {"mcp"}

    def test_mcp_server_resource_type(self):
        detections = scan_file("Resources.cs", "[McpServerResourceType]")
        assert {d.provider for d in detections} == {"mcp"}


class TestCollision:
    def test_azure_openai_using_does_not_also_trigger_openai(self):
        detections = scan_file("Program.cs", "using Azure.AI.OpenAI;")
        providers = {d.provider for d in detections}
        assert providers == {"azure_openai"}
        assert "openai" not in providers


class TestFalsePositives:
    def test_using_var_disposal_no_detection(self):
        assert scan_file("Program.cs", "using var client = new HttpClient();") == []

    def test_using_block_disposal_no_detection(self):
        assert scan_file("Program.cs", "using (var stream = File.OpenRead(p))") == []

    def test_using_system_text_json_no_detection(self):
        assert scan_file("Program.cs", "using System.Text.Json;") == []

    def test_using_microsoft_extensions_logging_no_detection(self):
        assert scan_file("Program.cs", "using Microsoft.Extensions.Logging;") == []

    def test_commented_out_using_no_detection(self):
        assert scan_file("Program.cs", "// using ModelContextProtocol;") == []

    def test_cs_file_with_no_ai_usage_no_detections(self):
        content = "namespace Foo;\n\npublic class Widget\n{\n    public int Count { get; set; }\n}\n"
        assert scan_file("Widget.cs", content) == []


class TestNugetPackageMatching:
    def test_azure_ai_openai_resolves_to_azure_openai(self):
        assert _match_nuget_package("Azure.AI.OpenAI") == "azure_openai"

    def test_openai_does_not_match_azure_prefix(self):
        assert _match_nuget_package("OpenAI") == "openai"

    def test_modelcontextprotocol_aspnetcore_resolves_to_mcp(self):
        assert _match_nuget_package("ModelContextProtocol.AspNetCore") == "mcp"

    def test_unrelated_package_resolves_to_none(self):
        assert _match_nuget_package("OneIdentity.SafeguardDotNet") is None

    def test_anthropic_prefix_does_not_match_unrelated_suffix(self):
        assert _match_nuget_package("AnthropicFoo") is None


class TestNugetManifestParsing:
    def test_csproj_package_reference(self):
        content = '<ItemGroup><PackageReference Include="ModelContextProtocol" Version="1.4.0" /></ItemGroup>'
        deps = scan_dependencies("src/App.csproj", content)
        assert {d["package"] for d in deps} == {"ModelContextProtocol"}
        assert deps[0]["version"] == "1.4.0"
        assert deps[0]["provider"] == "mcp"

    def test_fsproj_package_reference(self):
        content = '<PackageReference Include="Anthropic.SDK" Version="1.0.0" />'
        deps = scan_dependencies("src/App.fsproj", content)
        assert deps[0]["provider"] == "anthropic"

    def test_vbproj_package_reference(self):
        content = '<PackageReference Include="OpenAI" Version="2.0.0" />'
        deps = scan_dependencies("src/App.vbproj", content)
        assert deps[0]["provider"] == "openai"

    def test_directory_packages_props(self):
        content = '<ItemGroup><PackageVersion Include="Anthropic" Version="1.0.0" /></ItemGroup>'
        deps = scan_dependencies("Directory.Packages.props", content)
        assert deps[0]["package"] == "Anthropic"
        assert deps[0]["provider"] == "anthropic"

    def test_packages_config(self):
        content = '<packages><package id="Azure.AI.OpenAI" version="1.2.3" targetFramework="net48" /></packages>'
        deps = scan_dependencies("packages.config", content)
        assert deps[0]["package"] == "Azure.AI.OpenAI"
        assert deps[0]["provider"] == "azure_openai"

    def test_version_absent_emits_none_not_skipped(self):
        content = '<PackageReference Include="ModelContextProtocol" />'
        deps = scan_dependencies("src/App.csproj", content)
        assert len(deps) == 1
        assert deps[0]["version"] is None

    def test_attributes_reversed_order(self):
        content = '<PackageReference Version="1.0.0" Include="Anthropic.SDK" />'
        deps = scan_dependencies("src/App.csproj", content)
        assert deps[0]["package"] == "Anthropic.SDK"
        assert deps[0]["version"] == "1.0.0"

    def test_single_quotes(self):
        content = "<PackageReference Include='OpenAI' Version='2.0.0' />"
        deps = scan_dependencies("src/App.csproj", content)
        assert deps[0]["package"] == "OpenAI"
        assert deps[0]["version"] == "2.0.0"

    def test_commented_package_reference_not_detected(self):
        content = '<!-- <PackageReference Include="OpenAI" Version="1.0" /> -->'
        assert scan_dependencies("src/App.csproj", content) == []

    def test_malformed_xml_does_not_raise(self):
        content = '<PackageReference Include="OpenAI" Version='
        assert scan_dependencies("src/App.csproj", content) == []

    def test_package_id_emitted_as_written(self):
        content = '<PackageReference Include="ModelContextProtocol.AspNetCore" Version="1.4.0" />'
        deps = scan_dependencies("src/App.csproj", content)
        assert deps[0]["package"] == "ModelContextProtocol.AspNetCore"

    def test_unmapped_package_is_not_emitted(self):
        content = '<PackageReference Include="OneIdentity.SafeguardDotNet" Version="9.0.1" />'
        assert scan_dependencies("src/App.csproj", content) == []


class TestManifestPathExclusion:
    def test_test_project_csproj_is_not_scanned(self):
        assert not should_scan_file("tests/Foo.Tests/Foo.Tests.csproj")

    def test_src_csproj_is_scanned(self):
        assert should_scan_file("src/Foo/Foo.csproj")

    def test_packages_config_is_scanned(self):
        assert should_scan_file("packages.config")

    def test_directory_packages_props_is_scanned(self):
        assert should_scan_file("Directory.Packages.props")


class TestCoverageAccountingUnchangedByManifests:
    def test_csproj_present_does_not_change_coverage_pct(self, tmp_path):
        (tmp_path / "App.cs").write_text("var x = new OpenAI();\n")
        (tmp_path / "App.csproj").write_text(
            '<PackageReference Include="OpenAI" Version="1.0.0" />'
        )
        cov = scan_directory(tmp_path).coverage
        # .csproj is a manifest, not source: it must not enter source_files_seen,
        # exactly like package.json today.
        assert cov.source_files_seen == 1
        assert cov.coverage_pct == 100.0


@pytest.mark.skipif(
    not SAFEGUARD_MCP_FIXTURE.is_dir(), reason="safeguard-mcp fixture not present on this machine"
)
class TestSafeguardMcpFixtureEndToEnd:
    def test_mcp_in_providers(self):
        result = scan_directory(SAFEGUARD_MCP_FIXTURE)
        assert "mcp" in result.summary["providers"]

    def test_modelcontextprotocol_in_dependencies(self):
        result = scan_directory(SAFEGUARD_MCP_FIXTURE)
        packages = {d["package"] for d in result.dependencies}
        assert "ModelContextProtocol" in packages

    def test_detections_much_greater_than_one(self):
        result = scan_directory(SAFEGUARD_MCP_FIXTURE)
        assert len(result.detections) > 1

    def test_test_project_csproj_excluded(self):
        result = scan_directory(SAFEGUARD_MCP_FIXTURE)
        for dep in result.dependencies:
            assert "SafeguardMcp.Tests" not in dep["source_file"]
            assert "SafeguardMcp.IntegrationTests" not in dep["source_file"]
