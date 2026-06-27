from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Literal

import yaml

from scanner.parser import get_resource_identity
from scanner.scan_engine import get_resources, get_risks, scan_path


YamlResource = dict[str, Any]
Risk = dict[str, Any]
FixAction = dict[str, Any]
FixMode = Literal["safe", "strict"]


SAFE_FIX_RULES = {
    "KGL-POD-001",  # hostNetwork
    "KGL-POD-002",  # hostPID
    "KGL-POD-003",  # hostIPC
    "KGL-SEC-001",  # privileged
    "KGL-SEC-002",  # allowPrivilegeEscalation
    "KGL-SEC-005",  # seccompProfile
}

STRICT_FIX_RULES = {
    "KGL-SA-001",   # automountServiceAccountToken: true
    "KGL-SA-002",   # automountServiceAccountToken implicit
    "KGL-SEC-004",  # runAsNonRoot false / missing
    "KGL-SEC-006",  # readOnlyRootFilesystem missing / false
}

SUPPORTED_FIX_RULES = SAFE_FIX_RULES | STRICT_FIX_RULES


POD_SPEC_FIELD_RULE_MAP = {
    "hostNetwork": "KGL-POD-001",
    "hostPID": "KGL-POD-002",
    "hostIPC": "KGL-POD-003",
    "automountServiceAccountToken": "KGL-SA-002",
}


# -----------------------------------------------------------------------------
# Basic helpers
# -----------------------------------------------------------------------------


def normalize_mode(mode: str) -> FixMode:
    """标准化修复模式。"""
    normalized = mode.lower().strip()

    if normalized not in {"safe", "strict"}:
        raise ValueError("修复模式错误：只支持 safe 或 strict。")

    return normalized  # type: ignore[return-value]


def make_action(
    *,
    status: str,
    rule_id: str,
    resource: str,
    source_file: str,
    path: str,
    old_value: Any = "-",
    new_value: Any = "-",
    message: str = "",
) -> FixAction:
    """创建修复动作记录。"""
    return {
        "status": status,
        "rule_id": rule_id,
        "resource": resource,
        "source_file": source_file,
        "path": path,
        "old_value": old_value,
        "new_value": new_value,
        "message": message,
    }


def make_skip_action(
    *,
    risk: Risk,
    reason: str,
) -> FixAction:
    """记录未自动修复的风险。"""
    return make_action(
        status="skipped",
        rule_id=str(risk.get("rule_id", "-")),
        resource=str(risk.get("resource", "-")),
        source_file=str(risk.get("source_file", "-")),
        path=str(risk.get("path", "-")),
        old_value="-",
        new_value="-",
        message=reason,
    )


def get_resource_ref(resource: YamlResource) -> str:
    """生成修复动作中展示用的资源引用。"""
    identity = get_resource_identity(resource)
    return f"{identity['kind']}/{identity['name']}"


def get_resource_refs(resource: YamlResource) -> set[str]:
    """生成资源引用候选值，用于匹配 risk['resource']。"""
    identity = get_resource_identity(resource)

    kind = identity["kind"]
    name = identity["name"]
    namespace = identity["namespace"]

    refs = {
        name,
        f"{kind}/{name}",
        f"{kind}/{namespace}/{name}",
        f"{namespace}/{name}",
    }

    if namespace == "cluster-scope":
        refs.add(f"{kind}/{name}")
        refs.add(name)

    return refs


def same_source_file(risk: Risk, resource: YamlResource) -> bool:
    """判断风险和资源是否来自同一个源文件。"""
    risk_source = str(risk.get("source_file", "")).strip()
    resource_source = str(resource.get("_source_file", "")).strip()

    if not risk_source or risk_source == "-":
        return True

    if not resource_source or resource_source == "-":
        return True

    risk_path = Path(risk_source)
    resource_path = Path(resource_source)

    return (
        risk_source == resource_source
        or risk_path.name == resource_path.name
    )


def risk_matches_resource(risk: Risk, resource: YamlResource) -> bool:
    """判断某条风险是否属于当前资源。"""
    risk_resource = str(risk.get("resource", "")).strip()

    if risk_resource not in get_resource_refs(resource):
        return False

    return same_source_file(risk, resource)


# -----------------------------------------------------------------------------
# Kubernetes workload helpers
# -----------------------------------------------------------------------------


def get_pod_spec(resource: YamlResource) -> dict[str, Any] | None:
    """从 Pod 或 Deployment 中获取 PodSpec。"""
    kind = str(resource.get("kind", "")).strip()

    if kind == "Pod":
        spec = resource.get("spec")
        return spec if isinstance(spec, dict) else None

    if kind == "Deployment":
        spec = resource.get("spec")
        if not isinstance(spec, dict):
            return None

        template = spec.get("template")
        if not isinstance(template, dict):
            return None

        pod_spec = template.get("spec")
        return pod_spec if isinstance(pod_spec, dict) else None

    return None


def ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    """确保 parent[key] 是 dict，如果不存在或类型不对则创建。"""
    value = parent.get(key)

    if not isinstance(value, dict):
        value = {}
        parent[key] = value

    return value


def get_target_container_name(risk: Risk) -> str | None:
    """从风险对象中获取目标容器名。"""
    container = risk.get("container")

    if container is None:
        return None

    container_name = str(container).strip()

    if not container_name or container_name == "-":
        return None

    return container_name


def get_containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    """获取 containers 列表。"""
    containers = pod_spec.get("containers")

    if not isinstance(containers, list):
        return []

    return [
        container
        for container in containers
        if isinstance(container, dict)
    ]


def get_target_containers(
    pod_spec: dict[str, Any],
    risk: Risk,
) -> list[dict[str, Any]]:
    """根据风险中的 container 字段定位目标容器。"""
    containers = get_containers(pod_spec)
    target_name = get_target_container_name(risk)

    if target_name is None:
        return containers

    return [
        container
        for container in containers
        if str(container.get("name", "")).strip() == target_name
    ]


def get_pod_spec_field_path(resource: YamlResource, field_name: str) -> str:
    """根据资源类型生成 PodSpec 字段路径。"""
    kind = str(resource.get("kind", "")).strip()

    if kind == "Deployment":
        return f"spec.template.spec.{field_name}"

    return f"spec.{field_name}"


def get_container_security_path(
    resource: YamlResource,
    container_name: str,
    field_name: str,
) -> str:
    """根据资源类型生成 container.securityContext 字段路径。"""
    kind = str(resource.get("kind", "")).strip()

    if kind == "Deployment":
        return f"spec.template.spec.containers[{container_name}].securityContext.{field_name}"

    return f"spec.containers[{container_name}].securityContext.{field_name}"


def pod_spec_field_to_rule_id(field_name: str) -> str:
    """把 PodSpec 字段映射为规则 ID。"""
    return POD_SPEC_FIELD_RULE_MAP.get(field_name, "KGL-FIX-UNKNOWN")


# -----------------------------------------------------------------------------
# Field mutation functions
# -----------------------------------------------------------------------------


def set_pod_spec_boolean(
    *,
    pod_spec: dict[str, Any],
    field_name: str,
    new_value: bool,
    risk: Risk,
    resource: YamlResource,
) -> list[FixAction]:
    """修复 PodSpec 级别的布尔字段。"""
    old_value = pod_spec.get(field_name)

    if old_value == new_value:
        return []

    pod_spec[field_name] = new_value

    identity = get_resource_identity(resource)
    resource_ref = str(risk.get("resource") or get_resource_ref(resource))

    return [
        make_action(
            status="fixed",
            rule_id=str(risk.get("rule_id", pod_spec_field_to_rule_id(field_name))),
            resource=resource_ref,
            source_file=identity["source_file"],
            path=get_pod_spec_field_path(resource, field_name),
            old_value=old_value,
            new_value=new_value,
            message=f"Set {field_name} to {new_value}.",
        )
    ]


def set_container_security_boolean(
    *,
    pod_spec: dict[str, Any],
    field_name: str,
    new_value: bool,
    risk: Risk,
    resource: YamlResource,
) -> list[FixAction]:
    """修复 container.securityContext 下的布尔字段。"""
    actions: list[FixAction] = []
    containers = get_target_containers(pod_spec, risk)

    identity = get_resource_identity(resource)
    resource_ref = str(risk.get("resource") or get_resource_ref(resource))
    rule_id = str(risk.get("rule_id", "-"))

    for container in containers:
        container_name = str(container.get("name", "-"))
        security_context = ensure_dict(container, "securityContext")
        old_value = security_context.get(field_name)

        if old_value == new_value:
            continue

        security_context[field_name] = new_value

        actions.append(
            make_action(
                status="fixed",
                rule_id=rule_id,
                resource=resource_ref,
                source_file=identity["source_file"],
                path=get_container_security_path(resource, container_name, field_name),
                old_value=old_value,
                new_value=new_value,
                message=f"Set container {container_name} {field_name} to {new_value}.",
            )
        )

    return actions


def set_container_seccomp_runtime_default(
    *,
    pod_spec: dict[str, Any],
    risk: Risk,
    resource: YamlResource,
) -> list[FixAction]:
    """为容器设置 seccompProfile.type = RuntimeDefault。"""
    actions: list[FixAction] = []
    containers = get_target_containers(pod_spec, risk)

    identity = get_resource_identity(resource)
    resource_ref = str(risk.get("resource") or get_resource_ref(resource))
    rule_id = str(risk.get("rule_id", "-"))

    for container in containers:
        container_name = str(container.get("name", "-"))
        security_context = ensure_dict(container, "securityContext")
        seccomp_profile = ensure_dict(security_context, "seccompProfile")

        old_value = seccomp_profile.get("type")

        if old_value == "RuntimeDefault":
            continue

        seccomp_profile["type"] = "RuntimeDefault"

        actions.append(
            make_action(
                status="fixed",
                rule_id=rule_id,
                resource=resource_ref,
                source_file=identity["source_file"],
                path=get_container_security_path(
                    resource,
                    container_name,
                    "seccompProfile.type",
                ),
                old_value=old_value,
                new_value="RuntimeDefault",
                message=f"Set container {container_name} seccompProfile.type to RuntimeDefault.",
            )
        )

    return actions


# -----------------------------------------------------------------------------
# Risk-based fixes
# -----------------------------------------------------------------------------


def apply_supported_fix(
    *,
    resource: YamlResource,
    risk: Risk,
    mode: FixMode,
) -> list[FixAction]:
    """根据规则 ID 对资源应用自动修复。"""
    rule_id = str(risk.get("rule_id", "")).strip()

    if rule_id in STRICT_FIX_RULES and mode != "strict":
        return []

    pod_spec = get_pod_spec(resource)

    if pod_spec is None:
        return []

    if rule_id == "KGL-POD-001":
        return set_pod_spec_boolean(
            pod_spec=pod_spec,
            field_name="hostNetwork",
            new_value=False,
            risk=risk,
            resource=resource,
        )

    if rule_id == "KGL-POD-002":
        return set_pod_spec_boolean(
            pod_spec=pod_spec,
            field_name="hostPID",
            new_value=False,
            risk=risk,
            resource=resource,
        )

    if rule_id == "KGL-POD-003":
        return set_pod_spec_boolean(
            pod_spec=pod_spec,
            field_name="hostIPC",
            new_value=False,
            risk=risk,
            resource=resource,
        )

    if rule_id == "KGL-SEC-001":
        return set_container_security_boolean(
            pod_spec=pod_spec,
            field_name="privileged",
            new_value=False,
            risk=risk,
            resource=resource,
        )

    if rule_id == "KGL-SEC-002":
        return set_container_security_boolean(
            pod_spec=pod_spec,
            field_name="allowPrivilegeEscalation",
            new_value=False,
            risk=risk,
            resource=resource,
        )

    if rule_id == "KGL-SEC-005":
        return set_container_seccomp_runtime_default(
            pod_spec=pod_spec,
            risk=risk,
            resource=resource,
        )

    if rule_id in {"KGL-SA-001", "KGL-SA-002"}:
        return set_pod_spec_boolean(
            pod_spec=pod_spec,
            field_name="automountServiceAccountToken",
            new_value=False,
            risk=risk,
            resource=resource,
        )

    if rule_id == "KGL-SEC-004":
        return set_container_security_boolean(
            pod_spec=pod_spec,
            field_name="runAsNonRoot",
            new_value=True,
            risk=risk,
            resource=resource,
        )

    if rule_id == "KGL-SEC-006":
        return set_container_security_boolean(
            pod_spec=pod_spec,
            field_name="readOnlyRootFilesystem",
            new_value=True,
            risk=risk,
            resource=resource,
        )

    return []


def apply_fixes_to_resources(
    *,
    resources: list[YamlResource],
    risks: list[Risk],
    mode: FixMode,
) -> tuple[list[FixAction], list[FixAction]]:
    """对 resources 应用 risk-based 自动修复。"""
    fixed_actions: list[FixAction] = []
    skipped_actions: list[FixAction] = []

    for risk in risks:
        rule_id = str(risk.get("rule_id", "")).strip()

        if rule_id not in SUPPORTED_FIX_RULES:
            skipped_actions.append(
                make_skip_action(
                    risk=risk,
                    reason="该风险需要人工判断，当前不支持自动修复。",
                )
            )
            continue

        if rule_id in STRICT_FIX_RULES and mode != "strict":
            skipped_actions.append(
                make_skip_action(
                    risk=risk,
                    reason="该风险属于 strict 修复项，safe 模式下不会自动修改。",
                )
            )
            continue

        matched_resources = [
            resource
            for resource in resources
            if risk_matches_resource(risk, resource)
        ]

        if not matched_resources:
            skipped_actions.append(
                make_skip_action(
                    risk=risk,
                    reason="未能定位到风险对应的资源，跳过自动修复。",
                )
            )
            continue

        current_actions: list[FixAction] = []

        for resource in matched_resources:
            current_actions.extend(
                apply_supported_fix(
                    resource=resource,
                    risk=risk,
                    mode=mode,
                )
            )

        if current_actions:
            fixed_actions.extend(current_actions)
        else:
            skipped_actions.append(
                make_skip_action(
                    risk=risk,
                    reason="已匹配资源，但未找到可安全修改的字段，或字段已经是目标值。",
                )
            )

    return fixed_actions, skipped_actions


# -----------------------------------------------------------------------------
# Baseline hardening fixes
# -----------------------------------------------------------------------------


def apply_pod_spec_baseline_fixes(
    *,
    resources: list[YamlResource],
    mode: FixMode,
) -> list[FixAction]:
    """
    对 PodSpec 级别字段做兜底修复。

    这层不依赖 risk 匹配结果，直接检查 YAML 资源本身。
    用于避免 hostNetwork / hostPID / hostIPC 这类字段因 risk 匹配失败而漏修。
    """
    actions: list[FixAction] = []

    safe_pod_spec_fields = {
        "hostNetwork": False,
        "hostPID": False,
        "hostIPC": False,
    }

    strict_pod_spec_fields = {
        "automountServiceAccountToken": False,
    }

    for resource in resources:
        pod_spec = get_pod_spec(resource)

        if pod_spec is None:
            continue

        identity = get_resource_identity(resource)
        resource_ref = get_resource_ref(resource)

        for field_name, new_value in safe_pod_spec_fields.items():
            old_value = pod_spec.get(field_name)

            if old_value is not True:
                continue

            pod_spec[field_name] = new_value

            actions.append(
                make_action(
                    status="fixed",
                    rule_id=pod_spec_field_to_rule_id(field_name),
                    resource=resource_ref,
                    source_file=identity["source_file"],
                    path=get_pod_spec_field_path(resource, field_name),
                    old_value=old_value,
                    new_value=new_value,
                    message=f"Set {field_name} to {new_value}.",
                )
            )

        if mode != "strict":
            continue

        for field_name, new_value in strict_pod_spec_fields.items():
            old_value = pod_spec.get(field_name)

            if old_value is False:
                continue

            pod_spec[field_name] = new_value

            actions.append(
                make_action(
                    status="fixed",
                    rule_id=pod_spec_field_to_rule_id(field_name),
                    resource=resource_ref,
                    source_file=identity["source_file"],
                    path=get_pod_spec_field_path(resource, field_name),
                    old_value=old_value,
                    new_value=new_value,
                    message=f"Set {field_name} to {new_value}.",
                )
            )

    return actions


def action_key(action: FixAction) -> tuple[str, str, str, str]:
    """生成修复动作去重键。"""
    return (
        str(action.get("source_file", "")),
        str(action.get("resource", "")),
        str(action.get("path", "")),
        str(action.get("rule_id", "")),
    )


def merge_fix_actions(
    risk_based_actions: list[FixAction],
    baseline_actions: list[FixAction],
) -> list[FixAction]:
    """合并修复动作，并去重。"""
    merged: list[FixAction] = []
    seen: set[tuple[str, str, str, str]] = set()

    for action in risk_based_actions + baseline_actions:
        key = action_key(action)

        if key in seen:
            continue

        seen.add(key)
        merged.append(action)

    return merged


def normalize_text(value: Any) -> str:
    """用于修复动作去重和比较的宽松标准化。"""
    return str(value if value is not None else "").strip().lower().replace("\\", "/")


def normalize_rule_id(value: Any) -> str:
    """
    标准化规则 ID。

    这里额外兼容历史 typo：
    - KGI-POD-001 -> KGL-POD-001
    """
    rule_id = normalize_text(value).upper()

    rule_aliases = {
        "KGI-POD-001": "KGL-POD-001",
        "KGI-POD-002": "KGL-POD-002",
        "KGI-POD-003": "KGL-POD-003",
    }

    return rule_aliases.get(rule_id, rule_id)


def normalize_path(value: Any) -> str:
    """标准化风险路径，方便判断同一个字段是否已经修复。"""
    return normalize_text(value).replace("spec.template.", "")


def action_source_file_name(action: FixAction) -> str:
    """获取 action 的源文件名。"""
    return Path(str(action.get("source_file", ""))).name


def action_resource_name(action: FixAction) -> str:
    """获取 action 的资源名。"""
    return normalize_text(action.get("resource", ""))


def fixed_action_matches_skipped_action(
    *,
    fixed_action: FixAction,
    skipped_action: FixAction,
) -> bool:
    """
    判断 skipped action 是否已经被某条 fixed action 覆盖。

    匹配策略：
    1. 规则 ID 兼容历史 typo 后相同
    2. 源文件名相同
    3. 资源相同或路径指向同一类字段
    """
    fixed_rule_id = normalize_rule_id(fixed_action.get("rule_id", ""))
    skipped_rule_id = normalize_rule_id(skipped_action.get("rule_id", ""))

    if fixed_rule_id != skipped_rule_id:
        return False

    fixed_file_name = action_source_file_name(fixed_action)
    skipped_file_name = action_source_file_name(skipped_action)

    if fixed_file_name and skipped_file_name and fixed_file_name != skipped_file_name:
        return False

    fixed_resource = action_resource_name(fixed_action)
    skipped_resource = action_resource_name(skipped_action)

    if fixed_resource and skipped_resource and fixed_resource == skipped_resource:
        return True

    fixed_path = normalize_path(fixed_action.get("path", ""))
    skipped_path = normalize_path(skipped_action.get("path", ""))

    if fixed_path and skipped_path:
        if fixed_path == skipped_path:
            return True

        if fixed_path.endswith("hostnetwork") and skipped_path.endswith("hostnetwork"):
            return True

        if fixed_path.endswith("hostpid") and skipped_path.endswith("hostpid"):
            return True

        if fixed_path.endswith("hostipc") and skipped_path.endswith("hostipc"):
            return True

    return False


def remove_skipped_actions_that_were_fixed(
    *,
    skipped_actions: list[FixAction],
    fixed_actions: list[FixAction],
) -> list[FixAction]:
    """如果某个风险已经被修复，就不要再显示为 skipped。"""
    filtered: list[FixAction] = []

    for skipped_action in skipped_actions:
        already_fixed = any(
            fixed_action_matches_skipped_action(
                fixed_action=fixed_action,
                skipped_action=skipped_action,
            )
            for fixed_action in fixed_actions
        )

        if already_fixed:
            continue

        filtered.append(skipped_action)

    return filtered


# -----------------------------------------------------------------------------
# YAML output helpers
# -----------------------------------------------------------------------------


def strip_internal_fields(resource: YamlResource) -> YamlResource:
    """移除扫描器内部字段，避免写入 fixed YAML。"""
    clean_resource = deepcopy(resource)
    clean_resource.pop("_source_file", None)
    clean_resource.pop("_document_index", None)
    return clean_resource


def group_resources_by_source_file(
    resources: list[YamlResource],
) -> dict[str, list[YamlResource]]:
    """按照源文件对资源分组。"""
    grouped: dict[str, list[YamlResource]] = {}

    for resource in resources:
        source_file = str(resource.get("_source_file", "-"))
        grouped.setdefault(source_file, []).append(resource)

    for source_file in grouped:
        grouped[source_file].sort(
            key=lambda item: int(item.get("_document_index", 0))
        )

    return grouped


def build_output_file_path(
    *,
    source_file: str,
    target_path: Path,
    output_dir: Path,
) -> Path:
    """根据源文件路径生成 fixed 文件输出路径。"""
    source_path = Path(source_file)

    if target_path.is_dir():
        try:
            relative_path = source_path.resolve().relative_to(target_path.resolve())
        except ValueError:
            relative_path = Path(source_path.name)
    else:
        relative_path = Path(source_path.name)

    return output_dir / relative_path


def write_fixed_yaml_files(
    *,
    resources: list[YamlResource],
    target_path: Path,
    output_dir: Path,
    changed_source_files: set[str],
) -> list[str]:
    """把被修改过的 YAML 文件写入输出目录。"""
    output_dir.mkdir(parents=True, exist_ok=True)

    grouped_resources = group_resources_by_source_file(resources)
    written_files: list[str] = []

    for source_file, file_resources in grouped_resources.items():
        if source_file not in changed_source_files:
            continue

        output_file = build_output_file_path(
            source_file=source_file,
            target_path=target_path,
            output_dir=output_dir,
        )

        output_file.parent.mkdir(parents=True, exist_ok=True)

        documents = [
            strip_internal_fields(resource)
            for resource in file_resources
        ]

        content = yaml.safe_dump_all(
            documents,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )

        output_file.write_text(content, encoding="utf-8")
        written_files.append(str(output_file))

    return written_files


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def build_fix_summary(
    *,
    mode: FixMode,
    fixed_actions: list[FixAction],
    skipped_actions: list[FixAction],
    written_files: list[str],
) -> dict[str, Any]:
    """生成修复汇总信息。"""
    return {
        "mode": mode,
        "fixed_count": len(fixed_actions),
        "skipped_count": len(skipped_actions),
        "written_file_count": len(written_files),
        "written_files": written_files,
        "fixed_actions": fixed_actions,
        "skipped_actions": skipped_actions,
    }


def fix_path(
    *,
    target_path: str | Path,
    output_dir: str | Path,
    mode: str = "safe",
) -> dict[str, Any]:
    """
    扫描并修复指定 YAML 文件或目录。

    注意：
    - 不会覆盖原始 YAML
    - 只会把修复后的 YAML 写入 output_dir
    - safe 模式只修复相对安全的字段
    - strict 模式会额外启用可能影响业务行为的加固项
    """
    normalized_mode = normalize_mode(mode)

    target = Path(target_path)
    output = Path(output_dir)

    scan_result = scan_path(target)

    original_resources = get_resources(scan_result)
    risks = get_risks(scan_result)

    fixed_resources = deepcopy(original_resources)

    risk_based_fixed_actions, skipped_actions = apply_fixes_to_resources(
        resources=fixed_resources,
        risks=risks,
        mode=normalized_mode,
    )

    baseline_fixed_actions = apply_pod_spec_baseline_fixes(
        resources=fixed_resources,
        mode=normalized_mode,
    )

    fixed_actions = merge_fix_actions(
        risk_based_fixed_actions,
        baseline_fixed_actions,
    )

    skipped_actions = remove_skipped_actions_that_were_fixed(
        skipped_actions=skipped_actions,
        fixed_actions=fixed_actions,
    )

    changed_source_files = {
        str(action["source_file"])
        for action in fixed_actions
        if action.get("status") == "fixed"
    }

    written_files = write_fixed_yaml_files(
        resources=fixed_resources,
        target_path=target,
        output_dir=output,
        changed_source_files=changed_source_files,
    )

    summary = build_fix_summary(
        mode=normalized_mode,
        fixed_actions=fixed_actions,
        skipped_actions=skipped_actions,
        written_files=written_files,
    )

    return {
        "scan_result": scan_result,
        "fixed_resources": fixed_resources,
        "fix_summary": summary,
    }