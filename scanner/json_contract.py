"""面向机器调用的 JSON Contract v1。"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scanner.parser import load_yaml_path
from scanner.scan_engine import SCANNED_RESOURCE_KINDS, is_windows_workload, scan_resources

SCHEMA_VERSION = "1.0"
# JSON Contract 使用独立的 schema_version；扫描器软件发行版本以此常量为准。
SCANNER_VERSION = "0.2.0"

UNSUPPORTED_WORKLOAD_KINDS = frozenset({
    "CronJob",
    "DaemonSet",
    "Job",
    "List",
    "ReplicaSet",
    "ReplicationController",
    "StatefulSet",
})
SEVERITIES = ("HIGH", "MEDIUM", "LOW", "UNKNOWN")
CONTAINER_PATH_RE = re.compile(r"(?:^|\.)(initContainers|containers)\[(\d+)\]")

YamlResource = dict[str, Any]
Risk = dict[str, Any]
JsonObject = dict[str, Any]


def _resource_identity(resource: YamlResource) -> JsonObject:
    metadata = resource.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    kind = resource.get("kind")
    name = metadata.get("name")
    namespace = metadata.get("namespace")
    return {
        "kind": kind.strip() if isinstance(kind, str) and kind.strip() else None,
        "namespace": namespace.strip() if isinstance(namespace, str) and namespace.strip() else None,
        "name": name.strip() if isinstance(name, str) and name.strip() else None,
    }


def _finding_resource(risk: Risk) -> JsonObject:
    resource_ref = risk.get("resource")
    if not isinstance(resource_ref, str) or "/" not in resource_ref:
        kind = None
        name = None
    else:
        kind, name = resource_ref.split("/", 1)
        kind = kind or None
        name = name or None

    namespace = risk.get("namespace")
    if not isinstance(namespace, str) or not namespace.strip() or namespace == "cluster-scope":
        namespace = None
    else:
        namespace = namespace.strip()

    return {"kind": kind, "namespace": namespace, "name": name}


def _normalize_finding(risk: Risk) -> JsonObject:
    raw_severity = risk.get("level")
    severity = str(raw_severity or "UNKNOWN").strip().upper()
    if severity not in SEVERITIES:
        severity = "UNKNOWN"

    raw_path = risk.get("path")
    path = raw_path if isinstance(raw_path, str) and raw_path else None
    container: JsonObject | None = None
    path_match = CONTAINER_PATH_RE.search(path or "")
    raw_container_name = risk.get("container")
    container_name = (
        raw_container_name
        if isinstance(raw_container_name, str) and raw_container_name not in {"", "-"}
        else None
    )
    raw_container_type = risk.get("container_type")

    if path_match or container_name is not None or raw_container_type is not None:
        inferred_type = None
        container_index = None
        if path_match:
            inferred_type = "initContainer" if path_match.group(1) == "initContainers" else "container"
            container_index = int(path_match.group(2))
        container_type = raw_container_type if raw_container_type in {"container", "initContainer"} else inferred_type
        container = {
            "name": container_name,
            "type": container_type,
            "index": container_index,
        }

    auto_fixable = risk.get("auto_fixable")
    if not isinstance(auto_fixable, bool):
        auto_fixable = None

    return {
        "rule_id": str(risk.get("rule_id") or "UNKNOWN"),
        "severity": severity,
        "category": str(risk.get("category") or "Workload"),
        "message": str(risk.get("message") or ""),
        "reason": str(risk.get("reason") or ""),
        "suggestion": str(risk.get("suggestion") or ""),
        "resource": _finding_resource(risk),
        "path": path,
        "container": container,
        "auto_fixable": auto_fixable,
    }


def _finding_sort_key(finding: JsonObject) -> tuple[str, ...]:
    resource = finding["resource"]
    container = finding["container"] or {}
    return (
        str(resource.get("kind") or ""),
        str(resource.get("namespace") or ""),
        str(resource.get("name") or ""),
        str(finding.get("path") or ""),
        str(finding.get("rule_id") or ""),
        str(container.get("type") or ""),
        str(container.get("index") if container.get("index") is not None else ""),
        str(container.get("name") or ""),
        str(finding.get("severity") or ""),
        str(finding.get("message") or ""),
    )


def _diagnostic(code: str, message: str) -> JsonObject:
    return {"code": code, "message": message}


def _base_contract(
    *,
    status: str,
    total: int,
    scanned: int,
    skipped: list[JsonObject],
    findings: list[JsonObject] | None = None,
    diagnostics: list[JsonObject] | None = None,
) -> JsonObject:
    normalized_findings = sorted(findings or [], key=_finding_sort_key)
    severity_counts = {severity: 0 for severity in SEVERITIES}
    for finding in normalized_findings:
        severity_counts[finding["severity"]] += 1

    return {
        "schema_version": SCHEMA_VERSION,
        "scanner_version": SCANNER_VERSION,
        "status": status,
        "resource_counts": {
            "total": total,
            "scanned": scanned,
            "skipped": len(skipped),
        },
        "finding_counts": {
            **severity_counts,
            "total": len(normalized_findings),
        },
        "findings": normalized_findings,
        "skipped_resources": sorted(
            skipped,
            key=lambda item: (
                str(item["resource"].get("kind") or ""),
                str(item["resource"].get("namespace") or ""),
                str(item["resource"].get("name") or ""),
                str(item["reason"]),
            ),
        ),
        "diagnostics": diagnostics or [],
    }


def _skipped_resource(resource: YamlResource, reason: str) -> JsonObject:
    return {"resource": _resource_identity(resource), "reason": reason}


def _failed_contract(code: str, message: str, total: int = 0) -> JsonObject:
    return _base_contract(
        status="FAILED",
        total=total,
        scanned=0,
        skipped=[],
        diagnostics=[_diagnostic(code, message)],
    )


def scan_path_contract(target_path: str | Path) -> JsonObject:
    """扫描文件或目录并返回 JSON Contract v1 数据，不暴露输入路径或异常原文。"""
    try:
        resources = load_yaml_path(target_path)
    except FileNotFoundError:
        return _failed_contract("INPUT_NOT_FOUND", "指定的扫描输入不存在。")
    except (PermissionError, NotADirectoryError, OSError):
        return _failed_contract("INPUT_READ_FAILED", "无法读取指定的扫描输入。")
    except ValueError:
        return _failed_contract("INPUT_INVALID", "扫描输入不是有效的 Kubernetes YAML。")
    except Exception:
        return _failed_contract("SCAN_FAILED", "扫描未能完成。")

    total = len(resources)
    if not resources:
        return _failed_contract("EMPTY_INPUT", "输入中没有可识别的 Kubernetes 资源。")

    skipped: list[JsonObject] = []
    blocking_skip = False
    analyzable_resources: list[YamlResource] = []

    for resource in resources:
        kind = str(resource.get("kind", "")).strip()
        if kind in SCANNED_RESOURCE_KINDS:
            if is_windows_workload(resource):
                skipped.append(_skipped_resource(resource, "WINDOWS_LINUX_RULES_UNSUPPORTED"))
                blocking_skip = True
            else:
                analyzable_resources.append(resource)
        elif kind in UNSUPPORTED_WORKLOAD_KINDS:
            skipped.append(_skipped_resource(resource, "UNSUPPORTED_KIND"))
            blocking_skip = True
        else:
            skipped.append(_skipped_resource(resource, "OUT_OF_SCOPE"))

    if not analyzable_resources:
        return _base_contract(
            status="FAILED",
            total=total,
            scanned=0,
            skipped=skipped,
            diagnostics=[_diagnostic(
                "NO_ANALYZABLE_TARGET",
                "没有可由当前规则集完成分析的目标；请查看 skipped_resources。",
            )],
        )

    try:
        scan_result = scan_resources(resources, skip_windows_workloads=True)
    except Exception:
        failed_skipped = [
            _skipped_resource(resource, "SCAN_FAILED")
            for resource in analyzable_resources
        ]
        return _base_contract(
            status="FAILED",
            total=total,
            scanned=0,
            skipped=[*skipped, *failed_skipped],
            diagnostics=[_diagnostic("SCAN_FAILED", "扫描未能完成。")],
        )

    findings = [_normalize_finding(risk) for risk in scan_result.get("risks", [])]
    status = "PARTIAL" if blocking_skip else "COMPLETED"
    diagnostics = (
        [_diagnostic("PARTIAL_COVERAGE", "部分适用资源未被当前规则集分析；请查看 skipped_resources。")]
        if status == "PARTIAL"
        else []
    )
    return _base_contract(
        status=status,
        total=total,
        scanned=len(analyzable_resources),
        skipped=skipped,
        findings=findings,
        diagnostics=diagnostics,
    )
