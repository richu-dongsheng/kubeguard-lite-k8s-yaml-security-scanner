from typing import Any

from scanner.parser import get_resource_identity

YamlResource = dict[str,Any] #单个k8s资源字典
Risk = dict[str,Any]    #扫描出来的一条风险记录

#宿主机挂载路径黑名单
SENSITIVE_HOST_PATHS = [
    "/",
    "/etc",
    "/root",
    "/var/lib/kubelet",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
]

# Kubernetes v1.35 中，当前规则涉及且可由 PodSecurityContext 默认到容器的字段。
POD_INHERITABLE_SECURITY_CONTEXT_FIELDS = frozenset({
    "runAsUser",
    "runAsNonRoot",
    "seccompProfile",
})
# 当前规则涉及的容器专属字段，不采纳同名 Pod 级字段。
CONTAINER_SECURITY_CONTEXT_FIELDS = frozenset({
    "privileged",
    "allowPrivilegeEscalation",
    "readOnlyRootFilesystem",
    "capabilities",
})

# 仅挑选明确扩大系统、进程或网络攻击面的能力；一般性 add 不会命中。
# SYS_ADMIN / SYS_MODULE / SYS_RAWIO / SYS_PTRACE 影响面较广，列为 HIGH。
# NET_ADMIN / NET_RAW / DAC_OVERRIDE / DAC_READ_SEARCH 的风险通常受 namespace
# 和挂载范围限制，列为 MEDIUM。该列表是启发式高风险集合，不等同于 PSS 全量校验。
DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN": ("HIGH", "允许广泛系统管理操作，可能削弱 namespace 隔离并访问高权限内核接口。"),
    "SYS_MODULE": ("HIGH", "允许加载或卸载内核模块，可能影响节点内核及其上运行的工作负载。"),
    "SYS_RAWIO": ("HIGH", "允许低层 I/O 操作，可能访问硬件或绕过常规设备访问边界。"),
    "SYS_PTRACE": ("HIGH", "允许检查或操纵其他进程，可能读取进程内存中的凭据或篡改进程行为。"),
    "NET_ADMIN": ("MEDIUM", "允许修改适用网络 namespace 中的接口、路由或过滤配置。"),
    "NET_RAW": ("MEDIUM", "允许构造或发送原始网络报文，扩大探测、伪造报文等网络攻击面。"),
    "DAC_OVERRIDE": ("MEDIUM", "允许绕过常规文件读写权限检查，影响容器可访问的文件系统范围。"),
    "DAC_READ_SEARCH": ("MEDIUM", "允许绕过常规文件读取或目录搜索权限检查，影响容器可访问的文件系统范围。"),
}


def normalize_capability(value: Any) -> str:
    """规范化 Linux capability 名称，兼容可选的 CAP_ 前缀。"""
    name = str(value).strip().upper()
    return name[4:] if name.startswith("CAP_") else name

"""统一生成风险记录"""
def make_risk(
    *,
    level: str,
    rule_id: str,
    resource: str,
    namespace: str,
    source_file: str,
    message: str,
    reason: str,
    suggestion: str,
    path: str,
    container: str | None = None,
    container_type: str | None = None,
    auto_fixable: bool = False,    
) -> Risk:
    risk = {
        "level": level,
        "rule_id": rule_id,
        "resource": resource,
        "namespace": namespace,
        "container": container or "-",
        "path": path,
        "message": message,
        "reason": reason,
        "suggestion": suggestion,
        "source_file": source_file,
        "auto_fixable": auto_fixable,
    }
    if container_type is not None:
        risk["container_type"] = container_type
    return risk

"""从kubernetes资源中提取podSpec"""
def get_pod_spec(resource: YamlResource) -> dict[str,Any] | None:
    kind = resource.get("kind")

    if kind == "Pod":   #情况一：pod的pod.spec就在spec里面
        spec = resource.get("spec") or {}
        return spec if isinstance(spec, dict) else None
    
    if kind == "Deployment": #情况二：deployment的pod.spec路径是resource.spec.template.spec
        spec = (
            resource
            .get("spec",{})
            .get("template",{})
            .get("spec",{})
        )
        return spec if isinstance(spec,dict) else None
    return None 


def get_pod_spec_path(resource: YamlResource) -> str:
    """返回 PodSpec 在原始资源中的字段路径。"""
    if resource.get("kind") == "Deployment":
        return "spec.template.spec"
    return "spec"

"""返回资源标识信息：resource_ref,namespace,source_file,kind"""
def get_resource_ref(resource: YamlResource) -> tuple[str,str,str,str]:
    identity = get_resource_identity(resource)
    kind = identity["kind"]
    name = identity["name"]
    namespace = identity["namespace"]
    source_file = identity["source_file"]

    resource_ref = f"{kind}/{name}"
    return resource_ref,namespace,source_file,kind


"""风险检测1：判断 hostpath 是否属于敏感宿主机路径"""
def is_sensitive_host_path(path: str) -> bool:
    if path == "/":  #直接挂载根目录，直接高危（linux系统里 / 表示根目录）
        return True
    
    for(sensitive_path) in SENSITIVE_HOST_PATHS:
        if sensitive_path == "/":
            continue                #根目录刚才算过了，排除在外，这么做主要是下面判断会变成检测//）
        if  path == sensitive_path or path.startswith(sensitive_path + "/"):
            return True   
        
    return False

"""风险检测2：判断镜像是否为未固定版本"""
def is_unpinned_image(image: str) -> bool:
    if not image:
        return True
    #带sha256摘要（一种哈希算法，只要镜像稍有改变，字符串马上大变，绝对固定、安全
    if "@" in image:
        return False
    """非官方公共镜像，如仓库里的镜像路径会带有/，为了统一化，我们按照 / 进行分割，最后一部分一定是
        镜像名。image.split("/")会得到各部分组成的列表，[-1]表示取最后一部分，python中-n表示取倒数第n个
    """
    image_name = image.split("/")[-1]
    #没有tag:绝对不安全
    if ":" not in image_name:
        return True
    tag = image_name.split(":")[-1] #按 ：划分，最后一部分一定是tag

    return tag == "latest" #如果是latest,返回true,反之返回false

"""只合并可由 Pod 级默认的字段，并让容器级配置优先。"""
def get_effective_security_context(pod_spec:dict[str,Any], container:dict[str,Any]) -> tuple[dict[str,Any],bool]:
    pod_security_context = pod_spec.get("securityContext") or {}
    container_security_context = container.get("securityContext")

    has_container_security_context = isinstance(container_security_context,dict)

    effective_security_context = {}

    # 只有 Kubernetes PodSecurityContext 中可继承到容器的字段才使用 Pod 默认值。
    if isinstance(pod_security_context,dict):
        for field_name in POD_INHERITABLE_SECURITY_CONTEXT_FIELDS:
            if field_name in pod_security_context and pod_security_context[field_name] is not None:
                effective_security_context[field_name] = pod_security_context[field_name]

    # 仅采纳本扫描器实际识别的容器字段；Pod 级非法字段不会成为容器配置。
    if isinstance(container_security_context,dict):
        for field_name in (
            POD_INHERITABLE_SECURITY_CONTEXT_FIELDS
            | CONTAINER_SECURITY_CONTEXT_FIELDS
        ):
            if field_name in container_security_context and container_security_context[field_name] is not None:
                effective_security_context[field_name] = container_security_context[field_name]
    
    return effective_security_context,has_container_security_context

"""扫描函数1：扫描Pod全局配置风险"""
def scan_pod_level_risks(
        pod_spec:dict[str,Any],
        *,
        resource:str,
        namespace:str,
        source_file:str,
        pod_spec_path: str,
) -> list[Risk]:
    risks: list[Risk] = []

    if pod_spec.get("hostNetwork") is True:
        risks.append(make_risk(
            level = "HIGH",
            rule_id = "KGL-POD-001",
            resource = resource,
            namespace = namespace,
            source_file = source_file,
            path = f"{pod_spec_path}.hostNetwork",
            message = "Pod 启用了hostNetwork",
            reason = "hostNetwork 会让pod共享宿主机网络命名空间，削弱网络隔离边界",
            suggestion = "删除hostNetwork: true,除非该工作负载确实需要宿主机网络",
            auto_fixable = True,
        ))

    if pod_spec.get("hostPID") is True:
        risks.append(make_risk(
            level = "HIGH",
            rule_id = "KGL-POD-002",
            resource = resource,
            namespace = namespace,
            source_file = source_file,
            path = f"{pod_spec_path}.hostPID",
            message = "Pod 启用了 hostPID",
            reason = "hostPID 会让 Pod 共享宿主机进程命名空间，可能暴露宿主机进程信息。",
            suggestion = "删除hostPID: true,避免业务容器访问宿主机进程空间",
            auto_fixable = True,
        ))

    if pod_spec.get("hostIPC") is True:
        risks.append(make_risk(
            level = "HIGH",
            rule_id = "KGL-POD-003",
            resource = resource,
            namespace = namespace,
            source_file = source_file,
            path = f"{pod_spec_path}.hostIPC",
            message = "Pod 启用了 hostIPC",
            reason = "hostIPC会让 pod 共享宿主机IPC命名空间，削弱进程间通信隔离",
            suggestion = "删除 hostIPC: true,除非有明确的系统级组件需求",
            auto_fixable = True,
        ))
    
    if pod_spec.get("automountServiceAccountToken") is True:
        risks.append(make_risk(
            level = "MEDIUM",
            rule_id = "KGL-SA-001",
            resource = resource,
            namespace = namespace,
            source_file = source_file,
            path = f"{pod_spec_path}.automountServiceAccountToken",
            message = "Pod 显式开启了 automountServiceAccountToken",
            reason = "容器被攻击后，攻击者可能读取ServiceAccount token 并访问 kubernetes API。",
            suggestion = "如果业务不需要访问 kubernetes API,设置 automountServiceAccountToken: false。",
            auto_fixable = False,
        ))
    elif pod_spec.get("automountServiceAccountToken") is None:
        risks.append(make_risk(
            level = "LOW",
            rule_id = "KGL-SA-002",
            resource = resource,
            namespace = namespace,
            source_file = source_file,
            path = f"{pod_spec_path}.automountServiceAccountToken",
            message = "Pod未显式关闭 automountServiceAccountToken",
            reason = "未显式关闭时，Pod可能自动挂载 ServiceAccount token",
            suggestion = "如果业务不需要访问 kubernetes API,建议显式设置 automountServiceAccountToken: false。",
            auto_fixable = False,
        ))

    return risks

"""扫描函数2：扫描volume中的 hostPath 风险"""
def scan_volume_risks(
    pod_spec: dict[str,Any],
    *,
    resource: str,
    namespace: str,
    source_file: str,
    pod_spec_path: str,
) -> list[Risk]:
    risks:list[Risk] = []

    volumes = pod_spec.get("volumes") or []

    if not isinstance(volumes,list):
        return risks
    for index,volume in enumerate(volumes):
        if not isinstance(volume,dict):
            continue

        host_path = volume.get("hostPath")

        if not isinstance(host_path,dict):
            continue

        path_value = str(host_path.get("path",""))

        level = "HIGH" if is_sensitive_host_path(path_value) else "MEDIUM"

        risks.append(make_risk(
            level = level,
            rule_id = "KGL-VOL-001",
            resource = resource,
            namespace = namespace,
            source_file = source_file,
            path = f"{pod_spec_path}.volumes[{index}].hostPath.path",
            message = f"Pod 使用了 hostPath 挂载：{path_value}",
            reason = "hostPath 会把宿主机路径暴露给容器，可能导致宿主机文件泄露、篡改或攻击面扩大。",
            suggestion = "避免业务容器使用 hostpath,优先使用 PVC、configMap、Secret等更受控的挂载方式。",
            auto_fixable = False,
        ))

    return risks

"""使用同一套规则扫描普通容器和 initContainers。"""
def scan_container_risks(
    pod_spec: dict[str,Any],
    *,
    resource: str,
    namespace: str,
    source_file: str,
    pod_spec_path: str,
) -> list[Risk]:
    risks:list[Risk] = []

    # initContainers 虽按顺序运行，但镜像、安全上下文和资源限制仍需逐容器审查。
    for container_field in ("containers", "initContainers"):
        containers = pod_spec.get(container_field) or []

        if not isinstance(containers, list):
            continue

        is_init_container = container_field == "initContainers"

        for index,container in enumerate(containers):
            if not isinstance(container,dict):
                continue

            risk_start = len(risks)
            container_name = str(container.get("name",f"container-{index}"))
            container_path = f"{pod_spec_path}.{container_field}[{index}]"

            image = str(container.get("image",""))

            if is_unpinned_image(image):
                risks.append(make_risk(
                    level = "MEDIUM",
                    rule_id = "KGL-IMG-001",
                    resource = resource,
                    namespace = namespace,
                    source_file = source_file,
                    container = container_name,
                    path = f"{container_path}.image",
                    message = f"容器{container_name}使用了 latest 或未固定的镜像标签，",
                    reason = "latest或缺失tag会导致部署结果不可复现，增加供应链和回滚风险",
                    suggestion = "使用明确版本标签，例如nginx:1.25.4,或使用镜像 digest。",
                    auto_fixable = False,
                ))

            security_context,has_container_security_context = get_effective_security_context(
                pod_spec,
                container,
            )

            pod_security_context = pod_spec.get("securityContext") or {}
            container_security_context = container.get("securityContext")

            def security_context_path(field_name: str) -> str:
                """定位字段实际配置处；缺失字段沿用容器级建议路径。"""
                if (
                    isinstance(container_security_context, dict)
                    and field_name in container_security_context
                    and container_security_context[field_name] is not None
                ):
                    return f"{container_path}.securityContext.{field_name}"
                if (
                    field_name in POD_INHERITABLE_SECURITY_CONTEXT_FIELDS
                    and isinstance(pod_security_context, dict)
                    and field_name in pod_security_context
                    and pod_security_context[field_name] is not None
                ):
                    return f"{pod_spec_path}.securityContext.{field_name}"
                return f"{container_path}.securityContext.{field_name}"

            if not has_container_security_context:
                risks.append(make_risk(
                    level="LOW",
                    rule_id="KGL-SEC-000",
                    resource=resource,
                    namespace=namespace,
                    source_file=source_file,
                    container=container_name,
                    path=f"{container_path}.securityContext",
                    message=f"容器 {container_name} 未显式声明 securityContext",
                    reason="缺少 securityContext 会导致容器安全约束不明确，不利于最小权限配置。",
                    suggestion="为容器添加 securityContext，并显式声明权限约束。",
                    auto_fixable=True,
                ))

            if security_context.get("privileged") is True:
                risks.append(make_risk(
                    level="HIGH",
                    rule_id="KGL-SEC-001",
                    resource=resource,
                    namespace=namespace,
                    source_file=source_file,
                    container=container_name,
                    path=security_context_path("privileged"),
                    message=f"容器 {container_name} 启用了 privileged",
                    reason="特权容器会显著削弱容器与宿主机之间的隔离边界。",
                    suggestion="删除 privileged: true，除非该容器确实是受信任的系统级组件。",
                    auto_fixable=True,
                ))

            allow_privilege_escalation = security_context.get("allowPrivilegeEscalation")
            if allow_privilege_escalation is True or allow_privilege_escalation is None:
                missing_allow_privilege_escalation = allow_privilege_escalation is None
                risks.append(make_risk(
                    level="MEDIUM",
                    rule_id="KGL-SEC-002",
                    resource=resource,
                    namespace=namespace,
                    source_file=source_file,
                    container=container_name,
                    path=security_context_path("allowPrivilegeEscalation"),
                    message=(
                        f"容器 {container_name} 未显式禁止权限提升"
                        if missing_allow_privilege_escalation
                        else f"容器 {container_name} 允许权限提升"
                    ),
                    reason=(
                        "字段缺失时不会强制设置 no_new_privs，Kubernetes 通常允许权限提升；privileged 或 SYS_ADMIN 场景始终允许。此项表示配置缺口，不证明进程已经提升权限。"
                        if missing_allow_privilege_escalation
                        else "allowPrivilegeEscalation: true 允许进程尝试获得高于父进程的权限。"
                    ),
                    suggestion="设置 allowPrivilegeEscalation: false。",
                    auto_fixable=True,
                ))

            if security_context.get("runAsUser") == 0:
                risks.append(make_risk(
                    level="HIGH",
                    rule_id="KGL-SEC-003",
                    resource=resource,
                    namespace=namespace,
                    source_file=source_file,
                    container=container_name,
                    path=security_context_path("runAsUser"),
                    message=f"容器 {container_name} 显式以 root 用户运行",
                    reason="runAsUser: 0 表示容器进程以 root 身份运行，可能扩大攻击影响。",
                    suggestion="设置 runAsUser 为非 0 用户，例如 1000，并配合 runAsNonRoot: true。",
                    auto_fixable=False,
                ))

            if security_context.get("runAsNonRoot") is False:
                risks.append(make_risk(
                    level="MEDIUM",
                    rule_id="KGL-SEC-004",
                    resource=resource,
                    namespace=namespace,
                    source_file=source_file,
                    container=container_name,
                    path=security_context_path("runAsNonRoot"),
                    message=f"容器 {container_name} 未要求以非 root 用户运行",
                    reason="runAsNonRoot: false 明确未要求使用非 root 身份，但不能据此断定容器当前进程实际以 root 运行。",
                    suggestion="设置 runAsNonRoot: true。",
                    auto_fixable=True,
                ))
            elif "runAsNonRoot" not in security_context:
                risks.append(make_risk(
                    level="LOW",
                    rule_id="KGL-SEC-004",
                    resource=resource,
                    namespace=namespace,
                    source_file=source_file,
                    container=container_name,
                    path=security_context_path("runAsNonRoot"),
                    message=f"容器 {container_name} 未显式强制以非 root 用户运行",
                    reason="未设置 runAsNonRoot 不代表当前进程必然以 root 运行，但 Kubernetes 不会据此拒绝 root 用户。",
                    suggestion="确认镜像运行用户后，按业务兼容性设置 runAsNonRoot: true。",
                    auto_fixable=True,
                ))

            seccomp_profile = security_context.get("seccompProfile")
            seccomp_type = (
                seccomp_profile.get("type")
                if isinstance(seccomp_profile, dict)
                else None
            )

            if seccomp_type is None:
                risks.append(make_risk(
                    level="LOW",
                    rule_id="KGL-SEC-005",
                    resource=resource,
                    namespace=namespace,
                    source_file=source_file,
                    container=container_name,
                    path=security_context_path("seccompProfile"),
                    message=f"容器 {container_name} 未配置 seccompProfile",
                    reason="这里只检查清单是否显式声明 profile；字段缺失不证明运行时未应用 seccomp，节点或运行时可能提供默认策略。",
                    suggestion="设置 seccompProfile.type: RuntimeDefault。",
                    auto_fixable=True,
                ))
            elif seccomp_type == "Unconfined":
                risks.append(make_risk(
                    level="MEDIUM",
                    rule_id="KGL-SEC-009",
                    resource=resource,
                    namespace=namespace,
                    source_file=source_file,
                    container=container_name,
                    path=security_context_path("seccompProfile"),
                    message=f"容器 {container_name} 显式使用 seccomp Unconfined",
                    reason="Unconfined 不应用 seccomp 系统调用过滤；这是攻击面配置风险，不代表已发生利用。",
                    suggestion="评估应用兼容性后使用 RuntimeDefault，或使用节点上存在且受控的 Localhost profile。",
                    auto_fixable=False,
                ))

            container_capabilities = (
                container_security_context.get("capabilities")
                if isinstance(container_security_context, dict)
                else None
            )
            if not isinstance(container_capabilities, dict):
                container_capabilities = {}

            added_capabilities = container_capabilities.get("add") or []
            if isinstance(added_capabilities, list):
                for capability_index, capability_value in enumerate(added_capabilities):
                    capability_name = normalize_capability(capability_value)
                    capability_risk = DANGEROUS_CAPABILITIES.get(capability_name)
                    if capability_risk is None:
                        continue

                    capability_level, capability_reason = capability_risk
                    risks.append(make_risk(
                        level=capability_level,
                        rule_id="KGL-SEC-007",
                        resource=resource,
                        namespace=namespace,
                        source_file=source_file,
                        container=container_name,
                        path=f"{container_path}.securityContext.capabilities.add[{capability_index}]",
                        message=f"容器 {container_name} 显式添加高风险 Linux capability {capability_name}",
                        reason=capability_reason,
                        suggestion="移除不必要的 capability；如确有需求，仅授予完成任务所需的最小能力。",
                        auto_fixable=False,
                    ))

            dropped_capabilities = container_capabilities.get("drop") or []
            drops_all = (
                isinstance(dropped_capabilities, list)
                and any(value == "ALL" for value in dropped_capabilities)
            )
            if not drops_all:
                risks.append(make_risk(
                    level="LOW",
                    rule_id="KGL-SEC-008",
                    resource=resource,
                    namespace=namespace,
                    source_file=source_file,
                    container=container_name,
                    path=f"{container_path}.securityContext.capabilities.drop",
                    message=f"容器 {container_name} 未显式 drop ALL capabilities",
                    reason="这是减少默认 capability 集合的加固缺口，不表示容器已经拥有某个新增危险 capability。",
                    suggestion="根据 Kubernetes Restricted 策略要求评估 drop: [ALL]，再按最小权限添加确有需要的能力。",
                    auto_fixable=False,
                ))

            if security_context.get("readOnlyRootFilesystem") is not True:
                risks.append(make_risk(
                    level="LOW",
                    rule_id="KGL-SEC-006",
                    resource=resource,
                    namespace=namespace,
                    source_file=source_file,
                    container=container_name,
                    path=security_context_path("readOnlyRootFilesystem"),
                    message=f"容器 {container_name} 未开启只读根文件系统",
                    reason="只读根文件系统可以降低攻击者在容器内写入恶意文件的风险。",
                    suggestion="在确认业务不依赖写入根文件系统后，设置 readOnlyRootFilesystem: true。",
                    auto_fixable=True,
                ))

            resources = container.get("resources") or {}

            if not isinstance(resources,dict):
                resources = {}

            limits = resources.get("limits") or {}

            if not isinstance(limits, dict) or not limits:
                risks.append(make_risk(
                    level="MEDIUM",
                    rule_id="KGL-RES-001",
                    resource=resource,
                    namespace=namespace,
                    source_file=source_file,
                    container=container_name,
                    path=f"{container_path}.resources.limits",
                    message=f"容器 {container_name} 没有设置 resources.limits",
                    reason="缺少资源限制可能导致容器异常占用 CPU 或内存，影响节点和其他工作负载稳定性。",
                    suggestion="为容器添加 CPU 和 memory 的 resources.limits。",
                    auto_fixable=False,
                ))

            if is_init_container:
                # 现有 Fixer 只按 containers 名称定位；init Finding 禁止使用其修复策略。
                for risk in risks[risk_start:]:
                    risk["container_type"] = "initContainer"
                    risk["auto_fixable"] = False

    return risks



"""单个文件扫描函数入口：扫描单个kubernetes工作负载资源"""
def scan_workload(resource: YamlResource) -> list[Risk]:
    pod_spec = get_pod_spec(resource)

    if pod_spec is None:
        return []
    resource_ref,namespace,source_file,_kind = get_resource_ref(resource)
    pod_spec_path = get_pod_spec_path(resource)

    risks: list[Risk] = []
    #传入四个信息确认身份，然后对该k8s资源进行pod层面的检查，风险加入到risks列表中，后面同理
    #extend:列表中追加多条，append只能当为整体追加这一条，所以选extend
    risks.extend(scan_pod_level_risks(
        pod_spec,
        resource = resource_ref,
        namespace = namespace,
        source_file = source_file,
        pod_spec_path = pod_spec_path,
    ))
    risks.extend(scan_volume_risks(
        pod_spec,
        resource = resource_ref,
        namespace = namespace,
        source_file = source_file, 
        pod_spec_path = pod_spec_path,
    ))

    risks.extend(scan_container_risks(
        pod_spec,
        resource = resource_ref,
        namespace = namespace,
        source_file = source_file,
        pod_spec_path = pod_spec_path,
    ))

    return risks



"""文件（夹）扫描总入口"""
def scan_pod_resources(resources: list[YamlResource]) -> list[Risk]:
    all_risks: list[Risk] = []

    for resource in resources:
        all_risks.extend(scan_workload(resource))

    return all_risks
