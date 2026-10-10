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
})

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
    auto_fixable: bool = False,    
) -> Risk:
    return {
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
            if field_name in pod_security_context:
                effective_security_context[field_name] = pod_security_context[field_name]

    # 仅采纳本扫描器实际识别的容器字段；Pod 级非法字段不会成为容器配置。
    if isinstance(container_security_context,dict):
        for field_name in (
            POD_INHERITABLE_SECURITY_CONTEXT_FIELDS
            | CONTAINER_SECURITY_CONTEXT_FIELDS
        ):
            if field_name in container_security_context:
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

"""扫描函数3：扫描 containers中的安全风险"""
def scan_container_risks(
    pod_spec: dict[str,Any],
    *,
    resource: str,
    namespace: str,
    source_file: str,
    pod_spec_path: str,
) -> list[Risk]:
    risks:list[Risk] = []
    
    containers = pod_spec.get("containers") or []

    if not isinstance(containers,list):
        return risks
        
    for index,container in enumerate(containers):
        if not isinstance(container,dict):
            continue

        container_name = str(container.get("name",f"container-{index}"))
        container_path = f"{pod_spec_path}.containers[{index}]"

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
            ):
                return f"{container_path}.securityContext.{field_name}"
            if (
                field_name in POD_INHERITABLE_SECURITY_CONTEXT_FIELDS
                and isinstance(pod_security_context, dict)
                and field_name in pod_security_context
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

        if security_context.get("allowPrivilegeEscalation") is True:
            risks.append(make_risk(
                level="MEDIUM",
                rule_id="KGL-SEC-002",
                resource=resource,
                namespace=namespace,
                source_file=source_file,
                container=container_name,
                path=security_context_path("allowPrivilegeEscalation"),
                message=f"容器 {container_name} 允许权限提升",
                reason="allowPrivilegeEscalation: true 可能让容器内进程获得额外权限。",
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
                reason="runAsNonRoot: false 可能允许容器以 root 身份运行。",
                suggestion="设置 runAsNonRoot: true。",
                auto_fixable=True,
            ))

        if "seccompProfile" not in security_context:
            risks.append(make_risk(
                level="LOW",
                rule_id="KGL-SEC-005",
                resource=resource,
                namespace=namespace,
                source_file=source_file,
                container=container_name,
                path=security_context_path("seccompProfile"),
                message=f"容器 {container_name} 未配置 seccompProfile",
                reason="seccomp 可以限制容器进程可使用的系统调用，减少内核攻击面。",
                suggestion="设置 seccompProfile.type: RuntimeDefault。",
                auto_fixable=True,
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
