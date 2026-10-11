"""JSON Contract v1 的真实扫描与机器入口回归。"""

from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

from typer.testing import CliRunner

from cli import cli
from scanner.json_contract import scan_path_contract

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "json-contract"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


class JsonContractTests(unittest.TestCase):
    """通过真实 parser/scanner 和 Typer CLI 验证 Contract。"""

    def setUp(self) -> None:
        self.runner = CliRunner()

    @staticmethod
    def fixture(name: str) -> Path:
        return FIXTURE_DIR / name

    def assert_count_invariants(self, result: dict[str, object]) -> None:
        resource_counts = result["resource_counts"]
        finding_counts = result["finding_counts"]
        self.assertEqual(resource_counts["total"], resource_counts["scanned"] + resource_counts["skipped"])
        self.assertEqual(
            finding_counts["total"],
            sum(finding_counts[level] for level in ("HIGH", "MEDIUM", "LOW", "UNKNOWN")),
        )
        if result["status"] == "PARTIAL" and finding_counts["total"] == 0:
            self.assertNotEqual(result["status"], "COMPLETED")

    def invoke_json(self, path: Path):
        return self.runner.invoke(cli, ["scan-json", str(path)])

    def test_safe_yaml_is_completed_with_zero_findings(self) -> None:
        """已完整加固的 Pod 扫描完成且零风险，不应被解释为失败。"""
        result = scan_path_contract(self.fixture("safe.yaml"))

        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["resource_counts"], {"total": 1, "scanned": 1, "skipped": 0})
        self.assertEqual(result["finding_counts"]["total"], 0)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["schema_version"], "1.0")
        self.assertEqual(result["scanner_version"], "0.2.0")
        self.assert_count_invariants(result)

    def test_pod_and_deployment_findings_have_structured_resource_paths(self) -> None:
        """Pod 与 Deployment 的真实风险保留 Kind、Namespace、Name 和各自 YAML 路径。"""
        result = scan_path_contract(self.fixture("workloads.yaml"))

        findings = [item for item in result["findings"] if item["rule_id"] == "KGL-SEC-001"]
        by_name = {item["resource"]["name"]: item for item in findings}
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(set(by_name), {"api-pod", "worker"})
        self.assertEqual(by_name["api-pod"]["severity"], "HIGH")
        self.assertEqual(by_name["api-pod"]["resource"], {
            "kind": "Pod", "namespace": "test", "name": "api-pod",
        })
        self.assertEqual(by_name["api-pod"]["path"], "spec.containers[0].securityContext.privileged")
        self.assertEqual(by_name["worker"]["resource"]["kind"], "Deployment")
        self.assertEqual(by_name["worker"]["path"], "spec.template.spec.containers[0].securityContext.privileged")
        self.assertEqual(by_name["worker"]["container"], {"name": "worker", "type": "container", "index": 0})

    def test_container_and_init_container_identity_is_preserved(self) -> None:
        """容器与 initContainer 同时命中时，类型、名称和路径索引都来自真实 Finding。"""
        result = scan_path_contract(self.fixture("init-containers.yaml"))
        findings = [item for item in result["findings"] if item["rule_id"] == "KGL-SEC-001"]

        self.assertEqual(len(findings), 2)
        by_type = {item["container"]["type"]: item for item in findings}
        self.assertEqual(by_type["container"]["container"], {"name": "app", "type": "container", "index": 0})
        self.assertEqual(by_type["container"]["path"], "spec.containers[0].securityContext.privileged")
        self.assertEqual(by_type["initContainer"]["container"], {"name": "setup", "type": "initContainer", "index": 0})
        self.assertEqual(by_type["initContainer"]["path"], "spec.initContainers[0].securityContext.privileged")

    def test_rbac_service_and_ingress_result_shapes_are_normalized(self) -> None:
        """RBAC、Service 和 Ingress 的不同原始结构都映射到统一 Finding。"""
        rbac = scan_path_contract(Path(__file__).resolve().parents[1] / "examples" / "insecure" / "danger-rbac.yaml")
        exposure = scan_path_contract(Path(__file__).resolve().parents[1] / "examples" / "insecure" / "danger-service.yaml")

        rbac_findings = rbac["findings"]
        exposure_findings = exposure["findings"]
        self.assertIn("KGL-RBAC-001", {finding["rule_id"] for finding in rbac_findings})
        self.assertTrue(all(finding["category"] == "RBAC" for finding in rbac_findings))
        self.assertTrue(all(finding["severity"] in {"HIGH", "MEDIUM", "LOW", "UNKNOWN"} for finding in rbac_findings))
        self.assertTrue(all(finding["resource"]["kind"] for finding in rbac_findings))
        self.assertTrue(all(finding["auto_fixable"] is False for finding in rbac_findings))

        exposure_ids = {finding["rule_id"] for finding in exposure_findings}
        exposure_kinds = {finding["resource"]["kind"] for finding in exposure_findings}
        self.assertIn("KGL-SVC-001", exposure_ids)
        self.assertIn("KGL-ING-003", exposure_ids)
        self.assertEqual(exposure_kinds, {"Service", "Ingress"})
        self.assertTrue(all(finding["category"] == "Service" for finding in exposure_findings))

    def test_mixed_supported_unsupported_and_out_of_scope_resources_are_explicit(self) -> None:
        """已支持 Pod 可扫描；DaemonSet 降为 PARTIAL，ConfigMap 明确标记范围外。"""
        result = scan_path_contract(self.fixture("mixed.yaml"))

        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["resource_counts"], {"total": 3, "scanned": 1, "skipped": 2})
        reasons = {entry["resource"]["kind"]: entry["reason"] for entry in result["skipped_resources"]}
        self.assertEqual(reasons, {"DaemonSet": "UNSUPPORTED_KIND", "ConfigMap": "OUT_OF_SCOPE"})
        self.assertEqual(result["finding_counts"]["total"], 0)
        self.assertEqual(result["diagnostics"][0]["code"], "PARTIAL_COVERAGE")
        self.assert_count_invariants(result)

        out_of_scope_only = scan_path_contract(self.fixture("out-of-scope.yaml"))
        self.assertEqual(out_of_scope_only["status"], "COMPLETED")
        self.assertEqual(out_of_scope_only["resource_counts"], {"total": 2, "scanned": 1, "skipped": 1})
        self.assertEqual(out_of_scope_only["skipped_resources"][0]["reason"], "OUT_OF_SCOPE")
        self.assert_count_invariants(out_of_scope_only)

    def test_windows_workload_is_excluded_from_linux_findings(self) -> None:
        """Windows 容器的 privileged 配置不能被当作 Linux Workload 规则结论。"""
        result = scan_path_contract(self.fixture("windows-mixed.yaml"))

        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["resource_counts"], {"total": 3, "scanned": 1, "skipped": 2})
        skipped_names = {item["resource"]["name"] for item in result["skipped_resources"]}
        self.assertEqual(skipped_names, {"windows-pod", "windows-deploy"})
        self.assertTrue(all(item["reason"] == "WINDOWS_LINUX_RULES_UNSUPPORTED" for item in result["skipped_resources"]))
        finding_names = {finding["resource"]["name"] for finding in result["findings"]}
        self.assertTrue(finding_names.isdisjoint(skipped_names))
        self.assert_count_invariants(result)

    def test_no_analyzable_target_is_failed(self) -> None:
        """只有 Windows 或未覆盖/范围外资源时，不能用空 Finding 表示扫描安全。"""
        windows_result = scan_path_contract(self.fixture("windows-only.yaml"))
        self.assertEqual(windows_result["status"], "FAILED")
        self.assertEqual(windows_result["resource_counts"]["scanned"], 0)
        self.assertEqual(windows_result["skipped_resources"][0]["reason"], "WINDOWS_LINUX_RULES_UNSUPPORTED")

        unsupported_result = scan_path_contract(self.fixture("unsupported.yaml"))
        self.assertEqual(unsupported_result["status"], "FAILED")
        self.assertEqual(unsupported_result["skipped_resources"][0]["reason"], "UNSUPPORTED_KIND")

    def test_windows_remains_in_service_selector_context(self) -> None:
        """跳过 Windows 安全规则不能让 Service 错报没有匹配的工作负载。"""
        result = scan_path_contract(self.fixture("windows-service.yaml"))
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["resource_counts"], {"total": 2, "scanned": 1, "skipped": 1})
        self.assertNotIn("KGL-SVC-006", {finding["rule_id"] for finding in result["findings"]})
        self.assertEqual(result["findings"], [])

    def test_engine_failure_has_no_false_success_or_input_leak(self) -> None:
        """真实引擎无法处理的畸形结构返回失败，并丢弃不完整风险结论。"""
        path = self.fixture("engine-error.yaml")
        result = self.invoke_json(path)
        payload = json.loads(result.stdout)
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(payload["status"], "FAILED")
        self.assertEqual(payload["resource_counts"], {"total": 1, "scanned": 0, "skipped": 1})
        self.assertEqual(payload["skipped_resources"][0]["reason"], "SCAN_FAILED")
        self.assertEqual(payload["findings"], [])
        self.assertIn("SCAN_FAILED", result.stderr)
        self.assertNotIn("not-an-object", result.stdout + result.stderr)
        self.assertNotIn(str(path), result.stdout + result.stderr)

    def test_inherited_container_location_does_not_guess_index(self) -> None:
        """继承的 Pod 路径没有容器索引时保留空值，同名容器不进行猜测或去重。"""
        result = scan_path_contract(self.fixture("inherited.yaml"))
        findings = [item for item in result["findings"] if item["rule_id"] == "KGL-SEC-003"]
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(item["path"] == "spec.securityContext.runAsUser" for item in findings))
        self.assertTrue(all(item["container"]["name"] == "same-name" for item in findings))
        self.assertTrue(all(item["container"]["index"] is None for item in findings))
        self.assertEqual({item["container"]["type"] for item in findings}, {None, "initContainer"})

    def test_empty_invalid_and_unrecognized_inputs_fail_with_safe_diagnostics(self) -> None:
        """空 YAML、语法错误和纯范围外资源均返回 FAILED 且不回显路径或 YAML。"""
        empty_path = self.fixture("empty.yaml")
        invalid_path = self.fixture("invalid.yaml")
        unknown_path = self.fixture("unknown.yaml")

        empty = scan_path_contract(empty_path)
        invalid = scan_path_contract(invalid_path)
        unknown = scan_path_contract(unknown_path)
        self.assertEqual(empty["status"], "FAILED")
        self.assertEqual(empty["diagnostics"][0]["code"], "EMPTY_INPUT")
        self.assertEqual(invalid["status"], "FAILED")
        self.assertEqual(invalid["diagnostics"][0]["code"], "INPUT_INVALID")
        self.assertEqual(unknown["status"], "FAILED")
        self.assertEqual(unknown["skipped_resources"][0]["reason"], "OUT_OF_SCOPE")

        cli_result = self.invoke_json(invalid_path)
        self.assertEqual(cli_result.exit_code, 1)
        self.assertEqual(json.loads(cli_result.stdout)["status"], "FAILED")
        self.assertIn("INPUT_INVALID", cli_result.stderr)
        self.assertNotIn(str(invalid_path), cli_result.stdout + cli_result.stderr)
        self.assertNotIn("apiVersion: v1", cli_result.stdout + cli_result.stderr)
        self.assertNotIn("bearer-token-DO-NOT-EMIT", cli_result.stdout + cli_result.stderr)

    def test_windows_utf8_path_and_chinese_finding_are_stable_in_a_real_process(self) -> None:
        """Windows 子进程可接收中文路径，中文 Finding 可正确 JSON 解码，输入字节保持不变。"""
        path = self.fixture("中文风险.yaml")
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        process = subprocess.run(
            [sys.executable, "cli.py", "scan-json", str(path)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            check=False,
        )
        after = hashlib.sha256(path.read_bytes()).hexdigest()

        self.assertEqual(process.returncode, 0)
        payload = json.loads(process.stdout)
        self.assertEqual(payload["status"], "COMPLETED")
        self.assertTrue(any(any(ord(character) > 127 for character in item["message"]) for item in payload["findings"]))
        self.assertTrue(all(ord(character) < 128 for character in process.stdout))
        self.assertEqual(process.stderr, "")
        self.assertEqual(before, after)
        self.assertNotIn(str(path), process.stdout)

    def test_cli_stdout_is_json_and_risk_findings_exit_successfully(self) -> None:
        """风险存在仍返回 0，stdout 只有可解析 JSON，部分覆盖诊断位于 stderr。"""
        path = self.fixture("cli-risk.yaml")
        result = self.invoke_json(path)

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "COMPLETED")
        self.assertGreater(payload["finding_counts"]["total"], 0)
        self.assertTrue(all(finding["rule_id"] for finding in payload["findings"]))
        self.assertEqual(result.stderr, "")
        self.assertNotIn(str(path), result.stdout)

        partial_path = self.fixture("mixed.yaml")
        partial_result = self.invoke_json(partial_path)
        self.assertEqual(partial_result.exit_code, 0)
        self.assertEqual(json.loads(partial_result.stdout)["status"], "PARTIAL")
        self.assertIn("PARTIAL_COVERAGE", partial_result.stderr)
        self.assertNotIn("Rich", partial_result.stdout)

    def test_normalized_results_are_stable_and_old_cli_is_unchanged(self) -> None:
        """重复扫描结果字节稳定；旧 scan 命令仍输出人类可读表格并保留失败码。"""
        path = self.fixture("stable.yaml")
        first = self.invoke_json(path)
        second = self.invoke_json(path)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.exit_code, 0)

        old_result = self.runner.invoke(cli, ["scan", str(path)])
        self.assertEqual(old_result.exit_code, 0)
        self.assertIn("KGL-POD-001", old_result.stdout)
        self.assertNotEqual(json.loads(first.stdout)["findings"], [])

        missing = self.runner.invoke(cli, ["scan", str(FIXTURE_DIR / "missing.yaml")])
        self.assertEqual(missing.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
