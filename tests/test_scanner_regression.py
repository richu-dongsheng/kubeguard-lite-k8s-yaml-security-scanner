"""KubeGuard-Lite 核心扫描规则的真实 YAML 回归测试。"""

from __future__ import annotations

import unittest
from copy import deepcopy
from pathlib import Path

import yaml

from fixer.yaml_fixer import (
    POD_SPEC_FIELD_RULE_MAP,
    STRICT_FIX_RULES,
    apply_pod_spec_baseline_fixes,
    apply_fixes_to_resources,
    remove_skipped_actions_that_were_fixed,
)
from scanner.pod_scanner import get_effective_security_context
from scanner.scan_engine import scan_path, scan_resources


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ScannerRegressionTests(unittest.TestCase):
    """验证 YAML 解析、Workload 规则和既有 RBAC/Service 扫描入口。"""

    def scan_yaml(self, content: str) -> dict[str, object]:
        """解析内嵌 YAML 样例后调用真实扫描引擎。"""
        resources = [
            document
            for document in yaml.safe_load_all(content)
            if isinstance(document, dict)
        ]
        return scan_resources(resources)

    @staticmethod
    def risks_for_resource(result: dict[str, object], resource: str) -> list[dict[str, object]]:
        risks = result["risks"]
        return [risk for risk in risks if risk.get("resource") == resource]

    def test_workload_rules_trigger_with_expected_severity_and_paths(self) -> None:
        """不安全 Pod 和 Deployment 命中全部既有 Workload 规则并定位到原始 YAML。"""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: pod-risk
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  automountServiceAccountToken: true
  volumes:
    - name: config
      configMap:
        name: app-config
    - name: etc
      hostPath:
        path: /etc
        type: Directory
    - name: runtime
      hostPath:
        path: /var/run/docker.sock
        type: Socket
    - name: workspace
      hostPath:
        path: /workspace
    - name: missing-host-path
  containers:
    - name: safe-sidecar
      image: nginx:1.27
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        runAsUser: 1000
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: 512Mi
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 0
        runAsNonRoot: false
        readOnlyRootFilesystem: false
    - name: worker
      image: busybox
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deploy-risk
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      automountServiceAccountToken: true
      volumes:
        - name: runtime
          hostPath:
            path: /run/containerd/containerd.sock
            type: Socket
      containers:
        - name: safe-sidecar
          image: nginx:1.27
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            runAsUser: 1000
            runAsNonRoot: true
            seccompProfile:
              type: RuntimeDefault
            readOnlyRootFilesystem: true
          resources:
            limits:
              cpu: "1"
              memory: 512Mi
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            runAsUser: 0
            runAsNonRoot: false
            readOnlyRootFilesystem: false
        - name: worker
          image: busybox
"""
        result = self.scan_yaml(content)

        expected_levels = {
            "KGL-POD-001": "HIGH",
            "KGL-POD-002": "HIGH",
            "KGL-POD-003": "HIGH",
            "KGL-SA-001": "MEDIUM",
            "KGL-IMG-001": "MEDIUM",
            "KGL-SEC-000": "LOW",
            "KGL-SEC-001": "HIGH",
            "KGL-SEC-002": "MEDIUM",
            "KGL-SEC-003": "HIGH",
            "KGL-SEC-004": "MEDIUM",
            "KGL-SEC-005": "LOW",
            "KGL-SEC-006": "LOW",
            "KGL-SEC-008": "LOW",
            "KGL-RES-001": "MEDIUM",
        }

        for resource, pod_prefix in (
            ("Pod/pod-risk", "spec"),
            ("Deployment/deploy-risk", "spec.template.spec"),
        ):
            with self.subTest(resource=resource):
                risks = self.risks_for_resource(result, resource)
                by_rule: dict[str, list[dict[str, object]]] = {}
                for risk in risks:
                    by_rule.setdefault(str(risk["rule_id"]), []).append(risk)

                for rule_id, expected_level in expected_levels.items():
                    self.assertIn(rule_id, by_rule)
                    if rule_id == "KGL-SEC-004":
                        self.assertEqual(
                            {risk["level"] for risk in by_rule[rule_id]},
                            {"MEDIUM", "LOW"},
                        )
                        continue
                    self.assertTrue(
                        all(risk["level"] == expected_level for risk in by_rule[rule_id]),
                        f"{rule_id} 的风险等级应为 {expected_level}",
                    )

                self.assertEqual(
                    next(risk["path"] for risk in by_rule["KGL-POD-001"]),
                    f"{pod_prefix}.hostNetwork",
                )
                self.assertEqual(
                    next(risk["path"] for risk in by_rule["KGL-POD-002"]),
                    f"{pod_prefix}.hostPID",
                )
                self.assertEqual(
                    next(risk["path"] for risk in by_rule["KGL-POD-003"]),
                    f"{pod_prefix}.hostIPC",
                )
                self.assertEqual(
                    next(risk["path"] for risk in by_rule["KGL-SA-001"]),
                    f"{pod_prefix}.automountServiceAccountToken",
                )
                self.assertEqual(
                    next(risk["path"] for risk in by_rule["KGL-SEC-001"]),
                    f"{pod_prefix}.containers[1].securityContext.privileged",
                )
                expected_container_paths = {
                    "KGL-IMG-001": f"{pod_prefix}.containers[1].image",
                    "KGL-SEC-002": f"{pod_prefix}.containers[1].securityContext.allowPrivilegeEscalation",
                    "KGL-SEC-003": f"{pod_prefix}.containers[1].securityContext.runAsUser",
                    "KGL-SEC-004": f"{pod_prefix}.containers[1].securityContext.runAsNonRoot",
                    "KGL-SEC-005": f"{pod_prefix}.containers[1].securityContext.seccompProfile",
                    "KGL-SEC-006": f"{pod_prefix}.containers[1].securityContext.readOnlyRootFilesystem",
                    "KGL-SEC-008": f"{pod_prefix}.containers[1].securityContext.capabilities.drop",
                    "KGL-RES-001": f"{pod_prefix}.containers[1].resources.limits",
                }
                for rule_id, expected_path in expected_container_paths.items():
                    with self.subTest(resource=resource, rule_id=rule_id):
                        self.assertIn(expected_path, {risk["path"] for risk in by_rule[rule_id]})
                self.assertEqual(
                    next(risk["path"] for risk in by_rule["KGL-SEC-000"]),
                    f"{pod_prefix}.containers[2].securityContext",
                )

        pod_risks = self.risks_for_resource(result, "Pod/pod-risk")
        host_path_findings = [risk for risk in pod_risks if risk["rule_id"] == "KGL-VOL-001"]
        self.assertEqual(
            {(risk["path"], risk["level"]) for risk in host_path_findings},
            {
                ("spec.volumes[1].hostPath.path", "HIGH"),
                ("spec.volumes[2].hostPath.path", "HIGH"),
                ("spec.volumes[3].hostPath.path", "MEDIUM"),
            },
        )

        deployment_host_path = next(
            risk
            for risk in self.risks_for_resource(result, "Deployment/deploy-risk")
            if risk["rule_id"] == "KGL-VOL-001"
        )
        self.assertEqual(deployment_host_path["level"], "HIGH")
        self.assertEqual(
            deployment_host_path["path"],
            "spec.template.spec.volumes[0].hostPath.path",
        )

    def test_service_account_token_missing_and_disabled_conditions(self) -> None:
        """未显式设置仍命中低危规则，显式 false 则不命中，两种资源路径各自正确。"""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: token-default
spec:
  containers:
    - name: app
      image: nginx:1.27
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: token-default-deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.27
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: token-disabled
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: nginx:1.27
"""
        result = self.scan_yaml(content)

        missing_token_risks = self.risks_for_resource(result, "Pod/token-default")
        sa_risk = next(risk for risk in missing_token_risks if risk["rule_id"] == "KGL-SA-002")
        self.assertEqual(sa_risk["level"], "LOW")
        self.assertEqual(sa_risk["path"], "spec.automountServiceAccountToken")
        self.assertFalse(
            any(risk["rule_id"] in {"KGL-SA-001", "KG-SA-001"} for risk in missing_token_risks)
        )

        deployment_missing_token = self.risks_for_resource(
            result,
            "Deployment/token-default-deployment",
        )
        deployment_sa_risk = next(
            risk
            for risk in deployment_missing_token
            if risk["rule_id"] == "KGL-SA-002"
        )
        self.assertEqual(deployment_sa_risk["level"], "LOW")
        self.assertEqual(
            deployment_sa_risk["path"],
            "spec.template.spec.automountServiceAccountToken",
        )

        disabled_risks = self.risks_for_resource(result, "Deployment/token-disabled")
        self.assertFalse(
            any(risk["rule_id"] in {"KGL-SA-001", "KG-SA-001", "KGL-SA-002"} for risk in disabled_risks)
        )

    def test_security_context_inherited_field_points_to_pod_level(self) -> None:
        """Pod 级安全上下文触发的 root 风险定位到实际 PodSpec 字段。"""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: pod-context
spec:
  securityContext:
    runAsUser: 0
  containers:
    - name: app
      image: nginx:1.27
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deploy-context
spec:
  template:
    spec:
      securityContext:
        runAsUser: 0
      containers:
        - name: app
          image: nginx:1.27
"""
        result = self.scan_yaml(content)

        pod_risk = next(
            risk
            for risk in self.risks_for_resource(result, "Pod/pod-context")
            if risk["rule_id"] == "KGL-SEC-003"
        )
        deployment_risk = next(
            risk
            for risk in self.risks_for_resource(result, "Deployment/deploy-context")
            if risk["rule_id"] == "KGL-SEC-003"
        )
        self.assertEqual(pod_risk["path"], "spec.securityContext.runAsUser")
        self.assertEqual(
            deployment_risk["path"],
            "spec.template.spec.securityContext.runAsUser",
        )

    def test_security_context_field_scopes_and_container_overrides(self) -> None:
        """仅继承 Pod 级允许的默认字段，容器字段及覆盖值定位到实际来源。"""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: pod-context-scopes
spec:
  securityContext:
    runAsUser: 0
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
    privileged: true
    allowPrivilegeEscalation: true
    readOnlyRootFilesystem: true
  containers:
    - name: inherited
      image: nginx:1.27
    - name: overridden
      image: nginx:1.27
      securityContext:
        runAsUser: 1000
        runAsNonRoot: false
        seccompProfile:
          type: Localhost
          localhostProfile: profiles/custom.json
        privileged: false
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: 512Mi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deployment-context-scopes
spec:
  template:
    spec:
      securityContext:
        runAsUser: 0
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
        privileged: true
        allowPrivilegeEscalation: true
        readOnlyRootFilesystem: true
      containers:
        - name: inherited
          image: nginx:1.27
        - name: overridden
          image: nginx:1.27
          securityContext:
            runAsUser: 1000
            runAsNonRoot: false
            seccompProfile:
              type: Localhost
              localhostProfile: profiles/custom.json
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
          resources:
            limits:
              cpu: "1"
              memory: 512Mi
"""
        result = self.scan_yaml(content)

        expected_inherited_paths = {
            "Pod/pod-context-scopes": "spec.securityContext.runAsUser",
            "Deployment/deployment-context-scopes": (
                "spec.template.spec.securityContext.runAsUser"
            ),
        }
        expected_container_paths = {
            "Pod/pod-context-scopes": (
                "spec.containers[1].securityContext.runAsNonRoot"
            ),
            "Deployment/deployment-context-scopes": (
                "spec.template.spec.containers[1].securityContext.runAsNonRoot"
            ),
        }
        expected_inherited_container_paths = {
            "Pod/pod-context-scopes": (
                "spec.containers[0].securityContext.readOnlyRootFilesystem"
            ),
            "Deployment/deployment-context-scopes": (
                "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem"
            ),
        }

        for resource, inherited_path in expected_inherited_paths.items():
            with self.subTest(resource=resource):
                risks = self.risks_for_resource(result, resource)
                inherited_risks = [
                    risk for risk in risks
                    if risk.get("container") == "inherited"
                ]
                overridden_risks = [
                    risk for risk in risks
                    if risk.get("container") == "overridden"
                ]
                inherited_by_rule = {
                    risk["rule_id"]: risk for risk in inherited_risks
                }
                overridden_by_rule = {
                    risk["rule_id"]: risk for risk in overridden_risks
                }

                self.assertEqual(inherited_by_rule["KGL-SEC-003"]["level"], "HIGH")
                self.assertEqual(inherited_by_rule["KGL-SEC-003"]["path"], inherited_path)
                self.assertIn("KGL-SEC-006", inherited_by_rule)
                self.assertEqual(inherited_by_rule["KGL-SEC-006"]["level"], "LOW")
                self.assertEqual(
                    inherited_by_rule["KGL-SEC-006"]["path"],
                    expected_inherited_container_paths[resource],
                )
                inherited_privilege_escalation = next(
                    risk for risk in inherited_risks
                    if risk["rule_id"] == "KGL-SEC-002"
                )
                self.assertEqual(inherited_privilege_escalation["level"], "MEDIUM")
                self.assertEqual(
                    inherited_privilege_escalation["path"],
                    "spec.containers[0].securityContext.allowPrivilegeEscalation"
                    if resource.startswith("Pod/")
                    else "spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation",
                )
                self.assertIn("未显式禁止", inherited_privilege_escalation["message"])
                self.assertFalse(
                    any(
                        risk["rule_id"] in {"KGL-SEC-001", "KGL-SEC-004", "KGL-SEC-005"}
                        for risk in inherited_risks
                    )
                )

                self.assertFalse(
                    any(
                        risk["rule_id"]
                        in {
                            "KGL-SEC-001",
                            "KGL-SEC-002",
                            "KGL-SEC-003",
                            "KGL-SEC-005",
                            "KGL-SEC-006",
                        }
                        for risk in overridden_risks
                    )
                )
                self.assertEqual(overridden_by_rule["KGL-SEC-004"]["level"], "MEDIUM")
                self.assertEqual(
                    overridden_by_rule["KGL-SEC-004"]["path"],
                    expected_container_paths[resource],
                )

        # 已配置 seccompProfile 时不生成缺失风险，因此同时核对实际生效的配置值。
        pod_resource = next(
            resource for resource in result["resources"]
            if resource.get("kind") == "Pod"
        )
        pod_spec = pod_resource["spec"]
        inherited_container, _ = get_effective_security_context(
            pod_spec,
            pod_spec["containers"][0],
        )
        overridden_container, _ = get_effective_security_context(
            pod_spec,
            pod_spec["containers"][1],
        )
        self.assertEqual(inherited_container["runAsNonRoot"], True)
        self.assertEqual(inherited_container["seccompProfile"]["type"], "RuntimeDefault")
        self.assertEqual(overridden_container["runAsUser"], 1000)
        self.assertEqual(overridden_container["runAsNonRoot"], False)
        self.assertEqual(overridden_container["seccompProfile"]["type"], "Localhost")
        self.assertEqual(overridden_container["privileged"], False)
        self.assertEqual(overridden_container["allowPrivilegeEscalation"], False)
        self.assertEqual(overridden_container["readOnlyRootFilesystem"], True)
        self.assertNotIn("privileged", inherited_container)
        self.assertNotIn("allowPrivilegeEscalation", inherited_container)
        self.assertNotIn("readOnlyRootFilesystem", inherited_container)

        deployment_resource = next(
            resource for resource in result["resources"]
            if resource.get("kind") == "Deployment"
        )
        deployment_spec = deployment_resource["spec"]["template"]["spec"]
        deployment_inherited, _ = get_effective_security_context(
            deployment_spec,
            deployment_spec["containers"][0],
        )
        deployment_overridden, _ = get_effective_security_context(
            deployment_spec,
            deployment_spec["containers"][1],
        )
        self.assertEqual(deployment_inherited["seccompProfile"]["type"], "RuntimeDefault")
        self.assertEqual(deployment_overridden["seccompProfile"]["type"], "Localhost")
        self.assertEqual(deployment_overridden["privileged"], False)
        self.assertEqual(deployment_overridden["allowPrivilegeEscalation"], False)
        self.assertEqual(deployment_overridden["readOnlyRootFilesystem"], True)
        self.assertNotIn("privileged", deployment_inherited)
        self.assertNotIn("allowPrivilegeEscalation", deployment_inherited)
        self.assertNotIn("readOnlyRootFilesystem", deployment_inherited)

    def test_init_containers_scan_shared_rules_and_are_not_auto_fixed(self) -> None:
        """initContainers 复用容器规则、遵循 Pod 默认值，并隔离 Fixer 定位。"""
        result = self.scan_yaml(
            """apiVersion: v1
kind: Pod
metadata:
  name: init-rule-coverage
spec:
  securityContext:
    runAsUser: 0
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 1000
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
        readOnlyRootFilesystem: false
  initContainers:
    - name: init-inherited
      image: busybox:latest
    - name: init-overridden
      image: busybox:1.36
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 1000
        runAsNonRoot: false
        seccompProfile:
          type: Localhost
          localhostProfile: profiles/custom.json
        readOnlyRootFilesystem: false
---
apiVersion: v1
kind: Pod
metadata:
  name: init-seccomp-missing
spec:
  containers:
    - name: app
      image: nginx:1.27
  initContainers:
    - name: init-no-seccomp
      image: busybox:1.36
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        runAsUser: 1000
        runAsNonRoot: true
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: 128Mi
"""
        )
        risks = self.risks_for_resource(result, "Pod/init-rule-coverage")

        privileged_risks = [
            risk for risk in risks if risk["rule_id"] == "KGL-SEC-001"
        ]
        self.assertEqual(
            {
                (risk["container"], risk["level"], risk["path"])
                for risk in privileged_risks
            },
            {
                (
                    "app",
                    "HIGH",
                    "spec.containers[0].securityContext.privileged",
                ),
                (
                    "init-overridden",
                    "HIGH",
                    "spec.initContainers[1].securityContext.privileged",
                ),
            },
        )

        inherited_risks = [
            risk for risk in risks if risk["container"] == "init-inherited"
        ]
        inherited_by_rule = {risk["rule_id"]: risk for risk in inherited_risks}
        self.assertEqual(inherited_by_rule["KGL-SEC-003"]["level"], "HIGH")
        self.assertEqual(
            inherited_by_rule["KGL-SEC-003"]["path"],
            "spec.securityContext.runAsUser",
        )
        self.assertEqual(
            inherited_by_rule["KGL-IMG-001"]["path"],
            "spec.initContainers[0].image",
        )
        self.assertEqual(
            inherited_by_rule["KGL-SEC-000"]["path"],
            "spec.initContainers[0].securityContext",
        )
        self.assertEqual(
            inherited_by_rule["KGL-SEC-006"]["path"],
            "spec.initContainers[0].securityContext.readOnlyRootFilesystem",
        )
        self.assertEqual(
            inherited_by_rule["KGL-RES-001"]["path"],
            "spec.initContainers[0].resources.limits",
        )
        self.assertNotIn("KGL-SEC-004", inherited_by_rule)
        self.assertNotIn("KGL-SEC-005", inherited_by_rule)
        self.assertEqual(inherited_by_rule["KGL-SEC-002"]["level"], "MEDIUM")
        self.assertIn("未显式禁止", inherited_by_rule["KGL-SEC-002"]["message"])

        overridden_risks = [
            risk for risk in risks if risk["container"] == "init-overridden"
        ]
        overridden_by_rule = {risk["rule_id"]: risk for risk in overridden_risks}
        self.assertEqual(
            overridden_by_rule["KGL-SEC-002"]["path"],
            "spec.initContainers[1].securityContext.allowPrivilegeEscalation",
        )
        self.assertEqual(
            overridden_by_rule["KGL-SEC-004"]["level"],
            "MEDIUM",
        )
        self.assertEqual(
            overridden_by_rule["KGL-SEC-004"]["path"],
            "spec.initContainers[1].securityContext.runAsNonRoot",
        )
        self.assertEqual(
            overridden_by_rule["KGL-SEC-006"]["path"],
            "spec.initContainers[1].securityContext.readOnlyRootFilesystem",
        )
        self.assertEqual(
            overridden_by_rule["KGL-RES-001"]["path"],
            "spec.initContainers[1].resources.limits",
        )
        self.assertNotIn("KGL-SEC-003", overridden_by_rule)
        self.assertNotIn("KGL-SEC-005", overridden_by_rule)

        init_risks = [risk for risk in risks if risk.get("container_type") == "initContainer"]
        self.assertTrue(init_risks)
        self.assertTrue(all(risk["auto_fixable"] is False for risk in init_risks))

        pod_resource = result["resources"][0]
        effective_inherited, _ = get_effective_security_context(
            pod_resource["spec"],
            pod_resource["spec"]["initContainers"][0],
        )
        effective_overridden, _ = get_effective_security_context(
            pod_resource["spec"],
            pod_resource["spec"]["initContainers"][1],
        )
        self.assertEqual(effective_inherited["runAsUser"], 0)
        self.assertEqual(effective_inherited["runAsNonRoot"], True)
        self.assertEqual(effective_inherited["seccompProfile"]["type"], "RuntimeDefault")
        self.assertEqual(effective_overridden["runAsUser"], 1000)
        self.assertEqual(effective_overridden["runAsNonRoot"], False)
        self.assertEqual(effective_overridden["seccompProfile"]["type"], "Localhost")

        missing_seccomp_risks = self.risks_for_resource(
            result,
            "Pod/init-seccomp-missing",
        )
        missing_seccomp_risk = next(
            risk for risk in missing_seccomp_risks
            if risk["rule_id"] == "KGL-SEC-005"
            and risk["container"] == "init-no-seccomp"
        )
        self.assertEqual(missing_seccomp_risk["level"], "LOW")
        self.assertEqual(
            missing_seccomp_risk["path"],
            "spec.initContainers[0].securityContext.seccompProfile",
        )
        self.assertEqual(missing_seccomp_risk["container_type"], "initContainer")

        # 模拟不合法的同名普通容器，验证 Fixer 仍不会把 init 风险改到普通容器上。
        fix_resources = deepcopy(result["resources"])
        fix_resources[0]["spec"]["containers"][0]["name"] = "init-overridden"
        original_privileged = fix_resources[0]["spec"]["containers"][0]["securityContext"]["privileged"]
        fixed_actions, skipped_actions = apply_fixes_to_resources(
            resources=fix_resources,
            risks=[
                risk for risk in init_risks
                if risk["rule_id"] == "KGL-SEC-001"
                and risk["container"] == "init-overridden"
            ],
            mode="safe",
        )
        self.assertEqual(fixed_actions, [])
        self.assertEqual(len(skipped_actions), 1)
        self.assertIn("initContainer", skipped_actions[0]["message"])
        self.assertEqual(
            fix_resources[0]["spec"]["containers"][0]["securityContext"]["privileged"],
            original_privileged,
        )

    def test_fixer_obeys_auto_fixable_and_preserves_legacy_findings(self) -> None:
        """False 必须跳过，缺少标记的旧 Finding 仍按既有规则修复。"""
        result = self.scan_yaml(
            """apiVersion: v1
kind: Pod
metadata:
  name: fixer-auto-fix-contract
spec:
  automountServiceAccountToken: false
  containers:
    - name: shared
      image: nginx:1.27
      securityContext:
        privileged: true
        allowPrivilegeEscalation: false
        runAsUser: 1000
        runAsNonRoot: false
        seccompProfile:
          type: RuntimeDefault
        readOnlyRootFilesystem: false
      resources:
        limits:
          cpu: "1"
          memory: 128Mi
  initContainers:
    - name: shared
      image: busybox:1.36
      securityContext:
        privileged: true
        allowPrivilegeEscalation: false
        runAsUser: 1000
        runAsNonRoot: false
        seccompProfile:
          type: RuntimeDefault
        readOnlyRootFilesystem: false
      resources:
        limits:
          cpu: "1"
          memory: 128Mi
"""
        )
        risks = self.risks_for_resource(result, "Pod/fixer-auto-fix-contract")
        resources = result["resources"]

        def get_finding(rule_id: str, container_type: str | None) -> dict[str, object]:
            return deepcopy(next(
                risk for risk in risks
                if risk["rule_id"] == rule_id
                and risk["container"] == "shared"
                and risk.get("container_type") == container_type
            ))

        # 这两条规则分别覆盖 Safe 与 Strict 修复集合；False 必须在两种模式都阻止修改。
        for rule_id in ("KGL-SEC-001", "KGL-SEC-004"):
            ordinary_finding = get_finding(rule_id, None)
            self.assertIs(ordinary_finding["auto_fixable"], True)
            for mode in ("safe", "strict"):
                with self.subTest(rule_id=rule_id, mode=mode, case="explicit_false"):
                    finding = deepcopy(ordinary_finding)
                    finding["auto_fixable"] = False
                    fix_resources = deepcopy(resources)
                    original_resources = deepcopy(fix_resources)
                    fixed_actions, skipped_actions = apply_fixes_to_resources(
                        resources=fix_resources,
                        risks=[finding],
                        mode=mode,
                    )
                    self.assertEqual(fixed_actions, [])
                    self.assertEqual(len(skipped_actions), 1)
                    self.assertEqual(skipped_actions[0]["status"], "skipped")
                    self.assertIn("不可自动修复", skipped_actions[0]["message"])
                    self.assertEqual(fix_resources, original_resources)

        # initContainer 类型与路径保护继续优先于名称匹配，两种模式下都不能改同名普通容器。
        for rule_id in ("KGL-SEC-001", "KGL-SEC-004"):
            init_finding = get_finding(rule_id, "initContainer")
            for mode in ("safe", "strict"):
                with self.subTest(rule_id=rule_id, mode=mode, case="init_same_name"):
                    fix_resources = deepcopy(resources)
                    original_resources = deepcopy(fix_resources)
                    fixed_actions, skipped_actions = apply_fixes_to_resources(
                        resources=fix_resources,
                        risks=[init_finding],
                        mode=mode,
                    )
                    self.assertEqual(fixed_actions, [])
                    self.assertEqual(len(skipped_actions), 1)
                    self.assertEqual(skipped_actions[0]["status"], "skipped")
                    self.assertIn("initContainer", skipped_actions[0]["message"])
                    self.assertEqual(fix_resources, original_resources)

        # 普通与 init 风险同资源、同规则时，只修普通容器，init Finding 仍计为 skipped。
        normal_privileged = get_finding("KGL-SEC-001", None)
        init_privileged = get_finding("KGL-SEC-001", "initContainer")
        same_name_resources = deepcopy(resources)
        fixed_actions, skipped_actions = apply_fixes_to_resources(
            resources=same_name_resources,
            risks=[normal_privileged, init_privileged],
            mode="safe",
        )
        remaining_skipped = remove_skipped_actions_that_were_fixed(
            skipped_actions=skipped_actions,
            fixed_actions=fixed_actions,
        )
        self.assertEqual(len(fixed_actions), 1)
        self.assertEqual(same_name_resources[0]["spec"]["containers"][0]["securityContext"]["privileged"], False)
        self.assertEqual(same_name_resources[0]["spec"]["initContainers"][0]["securityContext"]["privileged"], True)
        self.assertEqual(len(remaining_skipped), 1)
        self.assertEqual(remaining_skipped[0]["auto_fixable"], False)

        # 显式允许的普通容器风险仍在原模式可修复；旧 Finding 缺字段也维持旧行为。
        fixable_cases = (
            ("KGL-SEC-001", "safe", "privileged", False),
            ("KGL-SEC-004", "strict", "runAsNonRoot", True),
        )
        for rule_id, mode, field_name, expected_value in fixable_cases:
            for remove_flag in (False, True):
                with self.subTest(rule_id=rule_id, mode=mode, legacy=remove_flag):
                    finding = get_finding(rule_id, None)
                    if remove_flag:
                        finding.pop("auto_fixable")
                    fix_resources = deepcopy(resources)
                    fixed_actions, skipped_actions = apply_fixes_to_resources(
                        resources=fix_resources,
                        risks=[finding],
                        mode=mode,
                    )
                    self.assertEqual(len(fixed_actions), 1)
                    self.assertEqual(fixed_actions[0]["status"], "fixed")
                    self.assertEqual(skipped_actions, [])
                    self.assertIs(
                        fix_resources[0]["spec"]["containers"][0]["securityContext"][field_name],
                        expected_value,
                    )

        # Strict-only 规则仍不能在 Safe 模式修复，即使 Finding 明确允许自动修复。
        safe_resources = deepcopy(resources)
        safe_before = deepcopy(safe_resources)
        safe_fixed, safe_skipped = apply_fixes_to_resources(
            resources=safe_resources,
            risks=[get_finding("KGL-SEC-004", None)],
            mode="safe",
        )
        self.assertEqual(safe_fixed, [])
        self.assertEqual(len(safe_skipped), 1)
        self.assertEqual(safe_resources, safe_before)

    def test_non_fixable_pod_findings_are_not_overridden_by_baseline(self) -> None:
        """Strict 基线不能越过 auto_fixable=False 的 ServiceAccount Finding。"""
        for token_setting in ("automountServiceAccountToken: true", ""):
            with self.subTest(token_setting=token_setting or "missing"):
                result = self.scan_yaml(
                    f"""apiVersion: v1
kind: Pod
metadata:
  name: non-fixable-token
spec:
  {token_setting}
  containers:
    - name: app
      image: nginx:1.27
"""
                )
                risks = self.risks_for_resource(result, "Pod/non-fixable-token")
                token_finding = next(
                    risk for risk in risks
                    if risk["rule_id"] in {"KGL-SA-001", "KGL-SA-002"}
                )
                self.assertIs(token_finding["auto_fixable"], False)

                fix_resources = deepcopy(result["resources"])
                original_resources = deepcopy(fix_resources)
                fixed_actions, skipped_actions = apply_fixes_to_resources(
                    resources=fix_resources,
                    risks=[token_finding],
                    mode="strict",
                )
                baseline_actions = apply_pod_spec_baseline_fixes(
                    resources=fix_resources,
                    mode="strict",
                    risks=risks,
                )

                self.assertEqual(fixed_actions, [])
                self.assertEqual(baseline_actions, [])
                self.assertEqual(len(skipped_actions), 1)
                self.assertEqual(skipped_actions[0]["status"], "skipped")
                self.assertEqual(fix_resources, original_resources)
                self.assertEqual(
                    remove_skipped_actions_that_were_fixed(
                        skipped_actions=skipped_actions,
                        fixed_actions=fixed_actions + baseline_actions,
                    ),
                    skipped_actions,
                )

    def test_init_container_deployment_paths_and_multiple_indices(self) -> None:
        """Deployment initContainer 使用 template 路径前缀和自身索引。"""
        result = self.scan_yaml(
            """apiVersion: apps/v1
kind: Deployment
metadata:
  name: deployment-init-paths
spec:
  template:
    spec:
      securityContext:
        runAsUser: 0
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: nginx:1.27
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            runAsUser: 1000
            runAsNonRoot: true
            seccompProfile:
              type: RuntimeDefault
            readOnlyRootFilesystem: true
          resources:
            limits:
              cpu: "1"
              memory: 512Mi
      initContainers:
        - name: init-overridden
          image: busybox:1.36
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            runAsUser: 1000
            runAsNonRoot: true
            seccompProfile:
              type: RuntimeDefault
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          resources:
            limits:
              cpu: "1"
              memory: 512Mi
        - name: init-risk
          image: busybox:latest
          securityContext:
            privileged: true
"""
        )
        risks = self.risks_for_resource(result, "Deployment/deployment-init-paths")
        init_risks = [
            risk for risk in risks if risk.get("container_type") == "initContainer"
        ]
        by_rule = {risk["rule_id"]: risk for risk in init_risks}

        self.assertEqual(
            by_rule["KGL-SEC-001"]["path"],
            "spec.template.spec.initContainers[1].securityContext.privileged",
        )
        self.assertEqual(by_rule["KGL-SEC-001"]["level"], "HIGH")
        self.assertEqual(
            by_rule["KGL-SEC-003"]["path"],
            "spec.template.spec.securityContext.runAsUser",
        )
        self.assertEqual(
            by_rule["KGL-IMG-001"]["path"],
            "spec.template.spec.initContainers[1].image",
        )
        self.assertEqual(
            by_rule["KGL-RES-001"]["path"],
            "spec.template.spec.initContainers[1].resources.limits",
        )
        self.assertNotIn("KGL-SEC-005", by_rule)
        self.assertFalse(
            any(
                risk["container"] == "init-overridden"
                for risk in init_risks
            )
        )

    def test_host_path_boundary_cases_and_missing_volume_fields(self) -> None:
        """只对实际 hostPath 对象报告，区分敏感路径、普通路径和 socket。"""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: host-path-boundaries
spec:
  volumes:
    - name: config
      configMap:
        name: app-config
    - name: no-host-path
    - name: etc
      hostPath:
        path: /etc
    - name: runtime
      hostPath:
        path: /run/containerd/containerd.sock
    - name: workspace
      hostPath:
        path: /workspace/data
  containers:
    - name: app
      image: nginx:1.27
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "1"
          memory: 512Mi
---
apiVersion: v1
kind: Pod
metadata:
  name: empty-volumes
spec:
  volumes: []
  containers:
    - name: app
      image: nginx:1.27
---
apiVersion: v1
kind: Pod
metadata:
  name: absent-volumes
spec:
  containers:
    - name: app
      image: nginx:1.27
"""
        result = self.scan_yaml(content)

        host_path_risks = [
            risk
            for risk in self.risks_for_resource(result, "Pod/host-path-boundaries")
            if risk["rule_id"] == "KGL-VOL-001"
        ]
        self.assertEqual(
            {(risk["path"], risk["level"]) for risk in host_path_risks},
            {
                ("spec.volumes[2].hostPath.path", "HIGH"),
                ("spec.volumes[3].hostPath.path", "HIGH"),
                ("spec.volumes[4].hostPath.path", "MEDIUM"),
            },
        )
        for resource in ("Pod/empty-volumes", "Pod/absent-volumes"):
            with self.subTest(resource=resource):
                self.assertFalse(
                    any(
                        risk["rule_id"] == "KGL-VOL-001"
                        for risk in self.risks_for_resource(result, resource)
                    )
                )

    def test_secure_pod_and_deployment_do_not_trigger_workload_rules(self) -> None:
        """安全配置应通过所有当前 Workload 规则的非触发边界。"""
        content = """
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  automountServiceAccountToken: false
  volumes: []
  containers:
    - name: app
      image: nginx:1.27
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        runAsUser: 1000
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
      resources:
        limits:
          cpu: "1"
          memory: 512Mi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-deployment
spec:
  template:
    spec:
      hostNetwork: false
      hostPID: false
      hostIPC: false
      automountServiceAccountToken: false
      containers:
        - name: app
          image: nginx:1.27
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            runAsUser: 1000
            runAsNonRoot: true
            seccompProfile:
              type: RuntimeDefault
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          resources:
            limits:
              cpu: "1"
              memory: 512Mi
"""
        result = self.scan_yaml(content)
        self.assertEqual(result["risks"], [])
        self.assertEqual(result["summary"]["grade"], "SAFE")

    def test_service_account_canonical_rule_id_matches_fixer_contract(self) -> None:
        """显式开启 Token 只输出标准规则 ID，修复器仍使用同一 ID 集合。"""
        result = self.scan_yaml(
            """apiVersion: v1
kind: Pod
metadata:
  name: token-enabled
spec:
  automountServiceAccountToken: true
  containers:
    - name: app
      image: nginx:1.27
"""
        )
        risks = self.risks_for_resource(result, "Pod/token-enabled")
        sa_risk = next(risk for risk in risks if risk["rule_id"] == "KGL-SA-001")
        self.assertEqual(sa_risk["level"], "MEDIUM")
        self.assertEqual(sa_risk["path"], "spec.automountServiceAccountToken")
        self.assertFalse(any(risk["rule_id"] == "KG-SA-001" for risk in risks))
        self.assertIn("KGL-SA-001", STRICT_FIX_RULES)
        self.assertNotIn("KG-SA-001", STRICT_FIX_RULES)
        self.assertEqual(POD_SPEC_FIELD_RULE_MAP["automountServiceAccountToken"], "KGL-SA-002")
        rule_document = (PROJECT_ROOT / "docs" / "rule-description.md").read_text(encoding="utf-8")
        self.assertIn("KGL-SA-001", rule_document)
        self.assertNotIn("KG-SA-001", rule_document)

    def test_multidocument_yaml_is_scanned_and_keeps_safe_zero_risk_result(self) -> None:
        """多文档输入逐个扫描，合法安全资源的零风险结果保持为成功。"""
        fixture = PROJECT_ROOT / "tests" / "fixtures" / "multidocument.yaml"
        result = scan_path(fixture)
        self.assertEqual(len(result["resources"]), 2)
        risks = self.risks_for_resource(result, "Pod/risky-document")
        host_network_risk = next(risk for risk in risks if risk["rule_id"] == "KGL-POD-001")
        self.assertEqual(host_network_risk["level"], "HIGH")
        self.assertEqual(host_network_risk["path"], "spec.hostNetwork")
        self.assertFalse(self.risks_for_resource(result, "Pod/safe-document"))

    def test_empty_invalid_and_unrecognized_inputs_are_not_reported_as_safe(self) -> None:
        """无资源、无效 YAML 和无法识别的文档均失败，不能生成 SAFE 零风险结论。"""
        fixtures = PROJECT_ROOT / "tests" / "fixtures"
        invalid_fixtures = (
            "empty-documents.yaml",
            "invalid-yaml.yaml",
            "scalar-document.yaml",
            "list-document.yaml",
            "missing-kind.yaml",
            "missing-api-version.yaml",
            "unsupported-kind.yaml",
        )
        for fixture in invalid_fixtures:
            with self.subTest(fixture=fixture):
                with self.assertRaises(ValueError):
                    scan_path(fixtures / fixture)

        with self.assertRaises(ValueError):
            scan_resources([])

    def test_capability_rules_classify_danger_and_drop_all_separately(self) -> None:
        """危险 add 按能力分级，普通能力不报；drop ALL 是独立 LOW 加固项。"""
        result = self.scan_yaml(
            """apiVersion: v1
kind: Pod
metadata:
  name: capabilities-pod
spec:
  containers:
    - name: ordinary-capability
      image: nginx:1.27
      securityContext:
        capabilities:
          add: [NET_BIND_SERVICE]
          drop: [ALL]
    - name: dangerous-capabilities
      image: nginx:1.27
      securityContext:
        capabilities:
          add: [CAP_SYS_ADMIN, NET_ADMIN]
          drop: [NET_RAW]
    - name: noncanonical-drop-all
      image: nginx:1.27
      securityContext:
        capabilities:
          drop: [all]
  initContainers:
    - name: init-dangerous-capability
      image: busybox:1.36
      securityContext:
        capabilities:
          add: [SYS_PTRACE]
          drop: [NET_BIND_SERVICE]
    - name: init-ordinary-capability
      image: busybox:1.36
      securityContext:
        capabilities:
          add: [NET_BIND_SERVICE]
          drop: [ALL]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: capabilities-deployment
spec:
  template:
    spec:
      containers:
        - name: deployment-dangerous-capability
          image: nginx:1.27
          securityContext:
            capabilities:
              add: [SYS_MODULE]
              drop: [ALL]
      initContainers:
        - name: deployment-init-dangerous-capability
          image: busybox:1.36
          securityContext:
            capabilities:
              add: [DAC_OVERRIDE]
              drop: [MKNOD]
"""
        )

        def rule_findings(resource: str, rule_id: str, container: str) -> list[dict[str, object]]:
            return [
                risk for risk in self.risks_for_resource(result, resource)
                if risk["rule_id"] == rule_id and risk["container"] == container
            ]

        pod_danger = rule_findings(
            "Pod/capabilities-pod", "KGL-SEC-007", "dangerous-capabilities"
        )
        self.assertEqual(
            [(risk["level"], risk["path"]) for risk in pod_danger],
            [
                (
                    "HIGH",
                    "spec.containers[1].securityContext.capabilities.add[0]",
                ),
                (
                    "MEDIUM",
                    "spec.containers[1].securityContext.capabilities.add[1]",
                ),
            ],
        )
        self.assertFalse(any(risk["auto_fixable"] for risk in pod_danger))
        self.assertEqual(
            rule_findings("Pod/capabilities-pod", "KGL-SEC-007", "ordinary-capability"),
            [],
        )
        self.assertEqual(
            rule_findings("Pod/capabilities-pod", "KGL-SEC-008", "ordinary-capability"),
            [],
        )
        noncanonical_drop = rule_findings(
            "Pod/capabilities-pod", "KGL-SEC-008", "noncanonical-drop-all"
        )[0]
        self.assertEqual(noncanonical_drop["level"], "LOW")
        self.assertEqual(
            noncanonical_drop["path"],
            "spec.containers[2].securityContext.capabilities.drop",
        )
        self.assertFalse(noncanonical_drop["auto_fixable"])

        pod_drop_finding = rule_findings(
            "Pod/capabilities-pod", "KGL-SEC-008", "dangerous-capabilities"
        )[0]
        self.assertEqual(pod_drop_finding["level"], "LOW")
        self.assertEqual(
            pod_drop_finding["path"],
            "spec.containers[1].securityContext.capabilities.drop",
        )
        self.assertFalse(pod_drop_finding["auto_fixable"])

        init_danger = rule_findings(
            "Pod/capabilities-pod", "KGL-SEC-007", "init-dangerous-capability"
        )[0]
        self.assertEqual(init_danger["level"], "HIGH")
        self.assertEqual(
            init_danger["path"],
            "spec.initContainers[0].securityContext.capabilities.add[0]",
        )
        self.assertEqual(init_danger["container_type"], "initContainer")
        self.assertFalse(init_danger["auto_fixable"])
        init_drop_finding = rule_findings(
            "Pod/capabilities-pod", "KGL-SEC-008", "init-dangerous-capability"
        )[0]
        self.assertEqual(init_drop_finding["level"], "LOW")
        self.assertEqual(
            init_drop_finding["path"],
            "spec.initContainers[0].securityContext.capabilities.drop",
        )
        self.assertEqual(init_drop_finding["container_type"], "initContainer")
        self.assertEqual(
            rule_findings(
                "Pod/capabilities-pod", "KGL-SEC-007", "init-ordinary-capability"
            ),
            [],
        )
        self.assertEqual(
            rule_findings(
                "Pod/capabilities-pod", "KGL-SEC-008", "init-ordinary-capability"
            ),
            [],
        )

        deployment_regular = rule_findings(
            "Deployment/capabilities-deployment",
            "KGL-SEC-007",
            "deployment-dangerous-capability",
        )[0]
        self.assertEqual(deployment_regular["level"], "HIGH")
        self.assertEqual(
            deployment_regular["path"],
            "spec.template.spec.containers[0].securityContext.capabilities.add[0]",
        )
        deployment_init = rule_findings(
            "Deployment/capabilities-deployment",
            "KGL-SEC-007",
            "deployment-init-dangerous-capability",
        )[0]
        self.assertEqual(deployment_init["level"], "MEDIUM")
        self.assertEqual(
            deployment_init["path"],
            "spec.template.spec.initContainers[0].securityContext.capabilities.add[0]",
        )
        self.assertEqual(deployment_init["container_type"], "initContainer")
        deployment_init_drop = rule_findings(
            "Deployment/capabilities-deployment",
            "KGL-SEC-008",
            "deployment-init-dangerous-capability",
        )[0]
        self.assertEqual(deployment_init_drop["level"], "LOW")
        self.assertEqual(
            deployment_init_drop["path"],
            "spec.template.spec.initContainers[0].securityContext.capabilities.drop",
        )
        for finding in (deployment_regular, deployment_init, deployment_init_drop):
            self.assertFalse(finding["auto_fixable"])

    def test_drop_all_satisfies_sec008_even_with_other_dropped_capabilities(self) -> None:
        """drop 列表含 ALL 即满足要求；只有其他能力、缺失或空列表才报告。"""
        result = self.scan_yaml(
            """apiVersion: v1
kind: Pod
metadata:
  name: drop-all-semantics
spec:
  containers:
    - name: all-only
      image: nginx:1.27
      securityContext:
        capabilities:
          drop: [ALL]
    - name: all-and-net-raw
      image: nginx:1.27
      securityContext:
        capabilities:
          drop: [ALL, NET_RAW]
    - name: net-raw-only
      image: nginx:1.27
      securityContext:
        capabilities:
          drop: [NET_RAW]
    - name: drop-missing
      image: nginx:1.27
      securityContext:
        capabilities:
          add: [NET_BIND_SERVICE]
    - name: drop-empty
      image: nginx:1.27
      securityContext:
        capabilities:
          drop: []
"""
        )
        risks = self.risks_for_resource(result, "Pod/drop-all-semantics")
        sec008_by_container = {
            risk["container"]: risk
            for risk in risks
            if risk["rule_id"] == "KGL-SEC-008"
        }

        self.assertNotIn("all-only", sec008_by_container)
        self.assertNotIn("all-and-net-raw", sec008_by_container)
        for index, container in enumerate(("net-raw-only", "drop-missing", "drop-empty"), start=2):
            with self.subTest(container=container):
                finding = sec008_by_container[container]
                self.assertEqual(finding["level"], "LOW")
                self.assertEqual(
                    finding["path"],
                    f"spec.containers[{index}].securityContext.capabilities.drop",
                )

    def test_seccomp_profiles_distinguish_missing_unconfined_and_confined(self) -> None:
        """只把 Unconfined 判为配置风险，区分缺失并遵守 Pod 默认与容器覆盖。"""
        result = self.scan_yaml(
            """apiVersion: v1
kind: Pod
metadata:
  name: seccomp-unconfined-pod
spec:
  securityContext:
    seccompProfile:
      type: Unconfined
  containers:
    - name: inherits-unconfined
      image: nginx:1.27
    - name: overrides-runtime-default
      image: nginx:1.27
      securityContext:
        seccompProfile:
          type: RuntimeDefault
    - name: explicitly-unconfined
      image: nginx:1.27
      securityContext:
        seccompProfile:
          type: Unconfined
  initContainers:
    - name: overrides-localhost
      image: busybox:1.36
      securityContext:
        seccompProfile:
          type: Localhost
          localhostProfile: profiles/custom.json
    - name: init-explicitly-unconfined
      image: busybox:1.36
      securityContext:
        seccompProfile:
          type: Unconfined
---
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-missing-pod
spec:
  containers:
    - name: missing-profile
      image: nginx:1.27
      securityContext: {}
  initContainers:
    - name: init-missing-profile
      image: busybox:1.36
      securityContext: {}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: seccomp-deployment
spec:
  template:
    spec:
      securityContext:
        seccompProfile:
          type: Localhost
          localhostProfile: profiles/deployment.json
      containers:
        - name: inherits-localhost
          image: nginx:1.27
      initContainers:
        - name: init-unconfined
          image: busybox:1.36
          securityContext:
            seccompProfile:
              type: Unconfined
"""
        )

        def rule_finding(resource: str, rule_id: str, container: str) -> dict[str, object]:
            return next(
                risk for risk in self.risks_for_resource(result, resource)
                if risk["rule_id"] == rule_id and risk["container"] == container
            )

        inherited_unconfined = rule_finding(
            "Pod/seccomp-unconfined-pod", "KGL-SEC-009", "inherits-unconfined"
        )
        self.assertEqual(inherited_unconfined["level"], "MEDIUM")
        self.assertEqual(
            inherited_unconfined["path"],
            "spec.securityContext.seccompProfile",
        )
        explicit_unconfined = rule_finding(
            "Pod/seccomp-unconfined-pod", "KGL-SEC-009", "explicitly-unconfined"
        )
        self.assertEqual(explicit_unconfined["level"], "MEDIUM")
        self.assertEqual(
            explicit_unconfined["path"],
            "spec.containers[2].securityContext.seccompProfile",
        )
        init_unconfined = rule_finding(
            "Pod/seccomp-unconfined-pod", "KGL-SEC-009", "init-explicitly-unconfined"
        )
        self.assertEqual(
            init_unconfined["path"],
            "spec.initContainers[1].securityContext.seccompProfile",
        )
        self.assertEqual(init_unconfined["container_type"], "initContainer")
        self.assertFalse(init_unconfined["auto_fixable"])

        unconfined_pod_risks = self.risks_for_resource(
            result, "Pod/seccomp-unconfined-pod"
        )
        self.assertFalse(
            any(
                risk["rule_id"] in {"KGL-SEC-005", "KGL-SEC-009"}
                and risk["container"] in {"overrides-runtime-default", "overrides-localhost"}
                for risk in unconfined_pod_risks
            )
        )
        self.assertFalse(
            any(
                risk["rule_id"] == "KGL-SEC-005"
                for risk in unconfined_pod_risks
            )
        )

        missing_regular = rule_finding(
            "Pod/seccomp-missing-pod", "KGL-SEC-005", "missing-profile"
        )
        self.assertEqual(missing_regular["level"], "LOW")
        self.assertEqual(
            missing_regular["path"],
            "spec.containers[0].securityContext.seccompProfile",
        )
        missing_init = rule_finding(
            "Pod/seccomp-missing-pod", "KGL-SEC-005", "init-missing-profile"
        )
        self.assertEqual(missing_init["level"], "LOW")
        self.assertEqual(
            missing_init["path"],
            "spec.initContainers[0].securityContext.seccompProfile",
        )
        self.assertEqual(missing_init["container_type"], "initContainer")
        self.assertFalse(
            any(
                risk["rule_id"] == "KGL-SEC-009"
                for risk in self.risks_for_resource(result, "Pod/seccomp-missing-pod")
            )
        )

        deployment_init = rule_finding(
            "Deployment/seccomp-deployment", "KGL-SEC-009", "init-unconfined"
        )
        self.assertEqual(deployment_init["level"], "MEDIUM")
        self.assertEqual(
            deployment_init["path"],
            "spec.template.spec.initContainers[0].securityContext.seccompProfile",
        )
        self.assertEqual(deployment_init["container_type"], "initContainer")
        deployment_localhost = next(
            resource for resource in result["resources"]
            if resource.get("kind") == "Deployment"
        )
        effective_localhost, _ = get_effective_security_context(
            deployment_localhost["spec"]["template"]["spec"],
            deployment_localhost["spec"]["template"]["spec"]["containers"][0],
        )
        self.assertEqual(effective_localhost["seccompProfile"]["type"], "Localhost")
        self.assertFalse(
            any(
                risk["rule_id"] in {"KGL-SEC-005", "KGL-SEC-009"}
                for risk in self.risks_for_resource(result, "Deployment/seccomp-deployment")
                if risk["container"] == "inherits-localhost"
            )
        )

    def test_privilege_and_nonroot_explicit_and_missing_semantics(self) -> None:
        """APE true/false/缺失与 runAsNonRoot 状态分开报告，缺失不冒充 root。"""
        result = self.scan_yaml(
            """apiVersion: v1
kind: Pod
metadata:
  name: security-defaults-pod
spec:
  containers:
    - name: explicitly-risky
      image: nginx:1.27
      securityContext:
        allowPrivilegeEscalation: true
        runAsUser: 1000
        runAsNonRoot: false
    - name: explicitly-safe
      image: nginx:1.27
      securityContext:
        allowPrivilegeEscalation: false
        runAsUser: 1000
        runAsNonRoot: true
    - name: omitted-settings
      image: nginx:1.27
      securityContext: {}
  initContainers:
    - name: init-omitted-settings
      image: busybox:1.36
      securityContext: {}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-defaults-deployment
spec:
  template:
    spec:
      securityContext:
        runAsUser: 1000
        runAsNonRoot: false
        allowPrivilegeEscalation: true
      containers:
        - name: inherited-nonroot-false
          image: nginx:1.27
          securityContext: {}
        - name: overrides-nonroot-safe
          image: nginx:1.27
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
      initContainers:
        - name: null-inherits-nonroot-false
          image: busybox:1.36
          securityContext:
            runAsNonRoot: null
"""
        )

        def rule_finding(resource: str, rule_id: str, container: str) -> dict[str, object]:
            return next(
                risk for risk in self.risks_for_resource(result, resource)
                if risk["rule_id"] == rule_id and risk["container"] == container
            )

        explicitly_risky_ape = rule_finding(
            "Pod/security-defaults-pod", "KGL-SEC-002", "explicitly-risky"
        )
        self.assertEqual(explicitly_risky_ape["level"], "MEDIUM")
        self.assertEqual(
            explicitly_risky_ape["path"],
            "spec.containers[0].securityContext.allowPrivilegeEscalation",
        )
        explicitly_risky_nonroot = rule_finding(
            "Pod/security-defaults-pod", "KGL-SEC-004", "explicitly-risky"
        )
        self.assertEqual(explicitly_risky_nonroot["level"], "MEDIUM")
        self.assertEqual(
            explicitly_risky_nonroot["path"],
            "spec.containers[0].securityContext.runAsNonRoot",
        )
        self.assertFalse(
            any(
                risk["rule_id"] in {"KGL-SEC-002", "KGL-SEC-004"}
                for risk in self.risks_for_resource(result, "Pod/security-defaults-pod")
                if risk["container"] == "explicitly-safe"
            )
        )

        omitted_ape = rule_finding(
            "Pod/security-defaults-pod", "KGL-SEC-002", "omitted-settings"
        )
        self.assertEqual(omitted_ape["level"], "MEDIUM")
        self.assertEqual(
            omitted_ape["path"],
            "spec.containers[2].securityContext.allowPrivilegeEscalation",
        )
        self.assertIn("未显式禁止", omitted_ape["message"])
        omitted_nonroot = rule_finding(
            "Pod/security-defaults-pod", "KGL-SEC-004", "omitted-settings"
        )
        self.assertEqual(omitted_nonroot["level"], "LOW")
        self.assertEqual(
            omitted_nonroot["path"],
            "spec.containers[2].securityContext.runAsNonRoot",
        )
        self.assertIn("未显式强制", omitted_nonroot["message"])
        self.assertNotIn("以 root 用户运行", omitted_nonroot["message"])
        self.assertFalse(
            any(
                risk["rule_id"] == "KGL-SEC-003"
                for risk in self.risks_for_resource(result, "Pod/security-defaults-pod")
                if risk["container"] == "omitted-settings"
            )
        )

        init_ape = rule_finding(
            "Pod/security-defaults-pod", "KGL-SEC-002", "init-omitted-settings"
        )
        init_nonroot = rule_finding(
            "Pod/security-defaults-pod", "KGL-SEC-004", "init-omitted-settings"
        )
        self.assertEqual(init_ape["level"], "MEDIUM")
        self.assertEqual(
            init_ape["path"],
            "spec.initContainers[0].securityContext.allowPrivilegeEscalation",
        )
        self.assertEqual(init_nonroot["level"], "LOW")
        self.assertEqual(
            init_nonroot["path"],
            "spec.initContainers[0].securityContext.runAsNonRoot",
        )
        self.assertEqual(init_nonroot["container_type"], "initContainer")

        inherited_nonroot = rule_finding(
            "Deployment/security-defaults-deployment",
            "KGL-SEC-004",
            "inherited-nonroot-false",
        )
        self.assertEqual(inherited_nonroot["level"], "MEDIUM")
        self.assertEqual(
            inherited_nonroot["path"],
            "spec.template.spec.securityContext.runAsNonRoot",
        )
        inherited_ape = rule_finding(
            "Deployment/security-defaults-deployment",
            "KGL-SEC-002",
            "inherited-nonroot-false",
        )
        self.assertEqual(inherited_ape["level"], "MEDIUM")
        self.assertEqual(
            inherited_ape["path"],
            "spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation",
        )
        null_inherited_nonroot = rule_finding(
            "Deployment/security-defaults-deployment",
            "KGL-SEC-004",
            "null-inherits-nonroot-false",
        )
        self.assertEqual(null_inherited_nonroot["level"], "MEDIUM")
        self.assertEqual(
            null_inherited_nonroot["path"],
            "spec.template.spec.securityContext.runAsNonRoot",
        )
        self.assertEqual(null_inherited_nonroot["container_type"], "initContainer")
        self.assertFalse(
            any(
                risk["rule_id"] in {"KGL-SEC-002", "KGL-SEC-004"}
                for risk in self.risks_for_resource(
                    result, "Deployment/security-defaults-deployment"
                )
                if risk["container"] == "overrides-nonroot-safe"
            )
        )

    def test_new_rules_matrix_and_fixer_skip_in_both_modes(self) -> None:
        """新规则在两种 Kind/容器位置保留身份，且 Safe/Strict 均不越权修复。"""
        capabilities = {
            "SYS_ADMIN": "HIGH", "SYS_MODULE": "HIGH", "SYS_RAWIO": "HIGH",
            "SYS_PTRACE": "HIGH", "NET_ADMIN": "MEDIUM", "NET_RAW": "MEDIUM",
            "DAC_OVERRIDE": "MEDIUM", "DAC_READ_SEARCH": "MEDIUM",
        }
        for kind in ("Pod", "Deployment"):
            for container_field in ("containers", "initContainers"):
                with self.subTest(kind=kind, container_field=container_field):
                    pod_spec = {
                        "securityContext": {
                            "seccompProfile": {"type": "Unconfined"},
                            # 非法 Pod 字段不能变成有效的容器能力。
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "containers": [],
                        container_field: [{
                            "name": "app", "image": "nginx:1.27",
                            "securityContext": {
                                "seccompProfile": None,
                                "capabilities": {"add": list(capabilities)},
                            },
                        }],
                    }
                    resource = {
                        "apiVersion": "v1" if kind == "Pod" else "apps/v1",
                        "kind": kind, "metadata": {"name": "matrix"},
                        "spec": pod_spec if kind == "Pod" else {"template": {"spec": pod_spec}},
                    }
                    result = self.scan_yaml(yaml.safe_dump(resource))
                    findings = [r for r in result["risks"] if r["rule_id"] in {
                        "KGL-SEC-007", "KGL-SEC-008", "KGL-SEC-009",
                    }]
                    prefix = "spec" if kind == "Pod" else "spec.template.spec"
                    added = [r for r in findings if r["rule_id"] == "KGL-SEC-007"]
                    self.assertEqual(len(added), len(capabilities))
                    by_path = {r["path"]: r for r in added}
                    for index, (capability, level) in enumerate(capabilities.items()):
                        finding = by_path[
                            f"{prefix}.{container_field}[0].securityContext.capabilities.add[{index}]"
                        ]
                        self.assertEqual(finding["level"], level)
                        self.assertIn(capability, finding["message"])
                    drop = next(r for r in findings if r["rule_id"] == "KGL-SEC-008")
                    self.assertEqual(drop["level"], "LOW")
                    self.assertEqual(drop["path"], f"{prefix}.{container_field}[0].securityContext.capabilities.drop")
                    seccomp = next(r for r in findings if r["rule_id"] == "KGL-SEC-009")
                    self.assertEqual(seccomp["level"], "MEDIUM")
                    self.assertEqual(seccomp["path"], f"{prefix}.securityContext.seccompProfile")
                    for finding in findings:
                        self.assertEqual(finding["resource"], f"{kind}/matrix")
                        self.assertEqual(finding["container"], "app")
                        self.assertEqual(
                            finding.get("container_type"),
                            "initContainer" if container_field == "initContainers" else None,
                        )
                        self.assertIs(finding["auto_fixable"], False)
                    for mode in ("safe", "strict"):
                        with self.subTest(mode=mode):
                            resources = deepcopy(result["resources"])
                            original = deepcopy(resources)
                            fixed, skipped = apply_fixes_to_resources(
                                resources=resources, risks=findings, mode=mode,
                            )
                            self.assertEqual(fixed, [])
                            self.assertEqual(len(skipped), len(findings))
                            self.assertTrue(all(r["status"] == "skipped" for r in skipped))
                            self.assertEqual(resources, original)

    def test_existing_rbac_service_and_ingress_examples_smoke(self) -> None:
        """既有 RBAC、Service、Ingress 示例继续产生稳定规则、等级和路径。"""
        result = scan_path(PROJECT_ROOT / "examples" / "insecure")
        risks = result["risks"]

        expected_findings = {
            ("KGL-RBAC-001", "HIGH", "ClusterRoleBinding/dangerous-cluster-admin-binding", "roleRef.name"),
            ("KGL-RBAC-004", "HIGH", "ClusterRole/secret-reader", "rules[0].resources"),
            ("KGL-SVC-001", "MEDIUM", "Service/public-nodeport-service", "spec.type"),
            ("KGL-SVC-002", "HIGH", "Service/public-loadbalancer-service", "spec.type"),
            ("KGL-ING-001", "MEDIUM", "Ingress/risky-ingress", "spec.tls"),
            (
                "KGL-ING-003",
                "HIGH",
                "Ingress/risky-ingress",
                "metadata.annotations.nginx.ingress.kubernetes.io/server-snippet",
            ),
        }
        actual_findings = {
            (risk["rule_id"], risk["level"], risk["resource"], risk["path"])
            for risk in risks
        }
        self.assertTrue(expected_findings.issubset(actual_findings))


if __name__ == "__main__":
    unittest.main()
