from pathlib import Path
from typing import Any

from scanner.parser import load_yaml_path
from scanner.pod_scanner import scan_pod_resources
from scanner.rbac_scanner import scan_rbac_resources
from scanner.service_scanner import scan_service_resources
from scanner.scoring import build_scan_summary, sort_risks_by_priority

YamlResource = dict[str,Any]
Risk = dict[str,Any]
ScanSummary = dict[str,Any]
ScanResult = dict[str,Any]

SCANNED_RESOURCE_KINDS = {
    "Pod",
    "Deployment",
    "Role",
    "ClusterRole",
    "RoleBinding",
    "ClusterRoleBinding",
    "Service",
    "Ingress",
}


"""
对已经解析好的 kubernetes resource 执行完整安全扫描
面向的调用者： website / desktop
web: 上传 YAML 后，先解析为resources再调用本函数
Desktop: 读取文件后，复用本函数
"""
def is_windows_workload(resource: YamlResource) -> bool:
    """判断当前支持的 Workload 是否显式声明为 Windows。"""
    kind = str(resource.get("kind", "")).strip()
    if kind == "Pod":
        pod_spec = resource.get("spec")
    elif kind == "Deployment":
        deployment_spec = resource.get("spec")
        template = deployment_spec.get("template") if isinstance(deployment_spec, dict) else None
        pod_spec = template.get("spec") if isinstance(template, dict) else None
    else:
        return False

    if not isinstance(pod_spec, dict):
        return False
    pod_os = pod_spec.get("os")
    return (
        isinstance(pod_os, dict)
        and str(pod_os.get("name", "")).strip().casefold() == "windows"
    )


def scan_resources(
    resources: list[YamlResource],
    *,
    skip_windows_workloads: bool = False,
) -> ScanResult:

    if not resources:
        raise ValueError("扫描输入中没有有效 Kubernetes 资源，无法判定扫描结果。")

    scanned_kinds = {
        str(resource.get("kind", "")).strip()
        for resource in resources
        if isinstance(resource, dict)
    }
    if not scanned_kinds.intersection(SCANNED_RESOURCE_KINDS):
        raise ValueError("扫描输入中没有当前扫描器支持的资源 Kind，无法判定扫描结果。")
    
    risks: list[Risk] = []

    workload_resources = resources
    if skip_windows_workloads:
        workload_resources = [
            resource
            for resource in resources
            if not is_windows_workload(resource)
        ]

    risks.extend(scan_pod_resources(workload_resources))
    risks.extend(scan_rbac_resources(resources))
    risks.extend(scan_service_resources(resources))

    sorted_risks = sort_risks_by_priority(risks)
    summary = build_scan_summary(sorted_risks)

    return {
        "resources": resources,
        "risks": sorted_risks,
        "summary": summary,
    }

"""
扫描指定 YAML 文件或目录
面向的调用者：CLI和报告命令
target_path 支持 单个.yaml 文件(.yml文件)/含 YAML 文件的目录
返回：
    - resources: 解析出的 Kubernetes 资源
    - risks: 排序后的风险列表
    - summary: 风险统计与整体评分
"""
def scan_path(target_path: str | Path) -> ScanResult:

    resources = load_yaml_path(target_path)

    return scan_resources(resources)


"""判断扫描结果中是否存在风险"""
def has_risks(scan_result: ScanResult) -> bool:

    risks = scan_result.get("risks") or {}

    return len(risks) > 0


"""从扫描结果中获取 resources """
def get_resources(scan_result: ScanResult) -> list[YamlResource]:
    
    resources = scan_result.get("resources") or []

    return resources if isinstance(resources, list) else []


"""从扫描结果中获取 risks """
def get_risks(scan_result: ScanResult) -> list[Risk]:
    
    risks = scan_result.get("risks") or []

    return risks if isinstance(risks, list) else []

"""从扫描结果中获取 summary """
def get_summary(scan_result: ScanResult) -> ScanSummary:

    summary = scan_result.get("summary") or {}

    return summary if isinstance(summary, dict) else {}
