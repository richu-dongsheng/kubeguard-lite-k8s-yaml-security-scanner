from typing import Any

from scanner.parser import get_resource_identity

YamlResource = dict[str, Any]
Risk = dict[str,Any]
RoleKey = tuple[str,str,str] #用元组作为字典索引，唯一定位一个Role(资源类型，命名空间，名称)，作为字典key

RBAC_API_GROUP = "rbac.authorization.k8s.io" #RBAC的专属API组
RBAC_RESOURCES = {
    "roles",
    "rolebindings",
    "clusterroles",
    "clusterrolebindings",
}       #RBAC的四大研究对象

READ_VERBS = {"get","list","watch"} #读的操作
WRITE_VERBS = {"create","update","patch","delete","deletecollection"} #写的操作
PRIVILEGE_ESCALATION_VERBS = {"bind","escalate","impersonate"} #扩大权限的操作


"""把 RBAC rule 中的字段统一转化为字符串列表，理论上kubernetes RBAC中
   apiGroups/resources/verbs 都是list,但是要防止不规范的输入（手写会出现非list格式），提升鲁棒性"""

def normalize_to_list(value : Any) -> list[str]:
    if value is None:
        return []                           #传入空值，返回空列表
    if isinstance(value,list):
        return [str(item) for item in value]    #已经是列表，就要确保每一项都是字符串
    
    return [str(value)]             #本来不是列表，直接转化为字符串列表



""" k8s RBAC规则中：
    出现通配符"*"，代表拥有全部权限，判定为高危；
    出现黑名单中的危险动词和资源，视情况判定。
    下面第一个函数检测是否出现黑名单上的内容，第二个函数检测是否出现某一个内容，
    作为功能函数，二者功能不一样的
"""

"""判断 values 中是否包含 targets 任意元素（通过将二者转化为集合然后看交集的方式实现） 或 通配符 "*" """
def contains_any(values:list[str],targets:set[str]) -> bool:
    return "*" in  values or bool(set(values) & targets) #set(value 将value字符串列表转化为集合，& 取交集)

"""判断 values 中是否包含某个值，或包含通配符"""
def contains_value(values:list[str],target:str) -> bool:
    return "*" in values or target in values

"""像之前检测pod_spec层面一样，我们需要先创建统一 RBAC 风险对象。
     字段尽量与 pod_scanner.py 中的 Risk 保持兼容：
    - container 默认为 "-"
    - auto_fixable 默认为 False"""
def make_rbac_risk(
    *,
    level: str,
    rule_id: str,
    resource: str,
    namespace: str,
    source_file: str,
    path: str,
    message: str,
    reason: str,
    suggestion: str,
    subject: str = "-",
    binding: str = "-",
) -> Risk:

    return {
        "level": level,
        "rule_id": rule_id,
        "category": "RBAC",
        "resource": resource,
        "namespace": namespace,
        "container": "-",
        "subject": subject,
        "binding": binding,
        "path": path,
        "message": message,
        "reason": reason,
        "suggestion": suggestion,
        "source_file": source_file,
        "auto_fixable": False,
    }

"""我们依然要先获取资源标识，还是那四项,但是这次需要根据名字划分作用域"""
def get_resource_ref(resource:YamlResource) -> tuple[str,str,str,str]:
    identity = get_resource_identity(resource)

    kind = identity["kind"]
    name = identity["name"]
    source_file = identity["source_file"]

    if kind in {"ClusterRole","ClusterRoleBinding"}:
        namespace = "cluster-scope"                    #作用域为全局
    else:
        namespace = identity["namespace"]              #作用域为指定命名空间

    resource_ref = f"{kind}/{name}" #资源介绍统一为种类/名称

    return resource_ref,namespace,source_file,kind

"""为Role/ClusterRole 生成索引key
    Role key:("Role",namespace,name)
    
    ClusterRole key:("ClusterRole","cluster-scope",name)"""
def get_role_key(resource: YamlResource) -> RoleKey | None:

    kind = str(resource.get("kind", "")).strip()

    metadata = resource.get("metadata") or {}
    name = str(metadata.get("name", "unknown")).strip()

    if kind == "Role":
        namespace = str(metadata.get("namespace","default")).strip() or "default"
        return ("Role",namespace,name)
    
    if kind == "ClusterRole":
        return("ClusterRole","cluster-scope",name)

    return None

#把当前扫描范围内定义的Role、clusterRole收集起来(使用字典将key和对应的yaml资源映射起来)
def build_role_index(resources:list[YamlResource]) -> dict[RoleKey,YamlResource]:
    role_index: dict[RoleKey,YamlResource] = {}

    for resource in resources:
        role_key = get_role_key(resource)

        if role_key is not None:
            role_index[role_key] = resource

    return role_index

"""把 RoleBinding / ClusterRoleBinding 的 subject 转化为可读字符串"""
def subject_to_string(subject: dict[str, Any]) -> str:
    kind = str(subject.get("kind", "Unknown")).strip()
    name = str(subject.get("name", "unknown")).strip()
    namespace = subject.get("namespace")

    if namespace:
        return f"{kind}/{str(namespace).strip()}/{name}"

    return f"{kind}/{name}"

"""提取Binding绑定主体列表"""
def get_binding_subjects(binding: YamlResource) -> list[str]:

    subjects = binding.get("subjects") or {}

    if not isinstance(subjects,list):
        return []
    result: list[str] = []

    for subject in subjects:
        if isinstance(subject,dict):
            result.append(subject_to_string(subject))

    return result


"""提取Binding 信息,返回：
    - binding_ref: RoleBinding/name 或 ClusterRoleBinding/name
    - binding_namespace: namespace 或 cluster-scope
    - role_ref_kind: Role / ClusterRole
    - role_ref_name: 被引用角色名
"""
def get_binding_ref(binding: YamlResource) -> tuple[str,str,str,str]:

    metadata = binding.get("metadata") or {}
    role_ref = binding.get("roleRef") or {}
    kind = str(binding.get("kind","Unknown")).strip()
    name = str(metadata.get("name","unknown")).strip()

    if kind == "ClusterRoleBinding":
        binding_namespace = "cluster-scope"
    else:
        binding_namespace = str(metadata.get("namespace","default"))

    binding_ref = f"{kind}/{name}"
    role_ref_kind = str(role_ref.get("kind","Unknown")).strip()
    role_ref_name = str(role_ref.get("name","unknown")).strip()

    return binding_ref,binding_namespace,role_ref_kind,role_ref_name 


"""根据Binding中的roleRef,去role_index中查找对应的Role/ClusterRole
    找到就返回它的权限规则"""
def resolve_role_ref(
        binding: YamlResource,
        role_index: dict[RoleKey,YamlResource],
) -> YamlResource | None:
    binding_ref,binding_namespace,role_ref_kind,role_ref_name = get_binding_ref(binding)

    if role_ref_kind == "Role":
        return role_index.get(("Role",binding_namespace,role_ref_name))
    
    if role_ref_kind == "ClusterRole":
        return role_index.get(("ClusterRole","cluster-scope",role_ref_name))
    
    return None

"""从 Role / ClusterRole 中提取 rules"""
def get_rules(resource:YamlResource) -> list[dict[str,Any]]:
    rules = resource.get("rules") or {}

    if not isinstance(rules,list):
        return []
    return [rule for rule in rules if isinstance(rule,dict)]

"""检查单条 RBAC rules 中的风险
   返回findings,不直接生成完整 Risk,
   使 Role 直扫和 Binding 关联分析都可以复用"""
def detect_rule_findings(rule: dict[str, Any],rule_index:int) -> list[dict[str,str]]:
    findings: list[dict[str,str]] = []

    api_groups = normalize_to_list(rule.get("apiGroups"))
    resources = normalize_to_list(rule.get("resources"))
    verbs = normalize_to_list(rule.get("verbs"))

    rule_path = f"rules[{rule_index}]"

    if "*" in api_groups or "*" in resources or "*" in verbs:
        findings.append({
            "level": "HIGH",
            "rule_id": "KGL-RBAC-003",
            "path": rule_path,
            "message": "RBAC 规则使用了通配符权限",
            "reason": "通配符 * 可能代表所有 API 组、所有资源或所有操作，通常违背最小权限原则。",
            "suggestion": "避免使用 * ，改为只授予业务确实需要的 apiGroups、resources、verbs。",
        })
    if contains_value(resources, "secrets") and contains_any(verbs, READ_VERBS):
        findings.append({
            "level": "HIGH",
            "rule_id": "KGL-RBAC-004",
            "path": f"{rule_path}.resources",
            "message": "RBAC 规则允许读取 secrets",
            "reason": "Secret 中可能包含密码、token、证书、镜像仓库凭据等敏感信息。",
            "suggestion": "避免普通业务主体读取 secrets；如必须使用，应限制到最小命名空间和最少动词。",
        })

    if contains_value(resources, "pods/exec") and contains_any(verbs, {"create"}):
        findings.append({
            "level": "HIGH",
            "rule_id": "KGL-RBAC-005",
            "path": f"{rule_path}.resources",
            "message": "RBAC 规则允许 pods/exec",
            "reason": "pods/exec 允许进入 Pod 执行命令，可能被攻击者用于进入其他工作负载容器。",
            "suggestion": "避免给普通业务主体授予 pods/exec 权限。",
        })

    if contains_value(resources, "pods") and contains_any(verbs, {"create"}):
        findings.append({
            "level": "MEDIUM",
            "rule_id": "KGL-RBAC-006",
            "path": f"{rule_path}.resources",
            "message": "RBAC 规则允许创建 pods",
            "reason": "创建 Pod 权限可能被攻击者用于部署恶意容器；若缺少 Pod 安全限制，影响会扩大。",
            "suggestion": "谨慎授予 pods/create 权限，并配合 Pod 安全策略、准入控制和最小权限原则。",
        })
    if (
        contains_any(api_groups, {RBAC_API_GROUP})
        and contains_any(resources, RBAC_RESOURCES)
        and contains_any(verbs, WRITE_VERBS)
    ):
        findings.append({
            "level": "HIGH",
            "rule_id": "KGL-RBAC-007",
            "path": rule_path,
            "message": "RBAC 规则允许修改 RBAC 资源",
            "reason": "允许创建或修改 RoleBinding / ClusterRoleBinding 可能导致权限提升。",
            "suggestion": "普通业务主体不应拥有修改 RBAC 资源的权限。",
        })

    if contains_any(verbs, PRIVILEGE_ESCALATION_VERBS):
        findings.append({
            "level": "HIGH",
            "rule_id": "KGL-RBAC-008",
            "path": f"{rule_path}.verbs",
            "message": "RBAC 规则包含权限提升相关动词",
            "reason": "bind、escalate、impersonate 与权限绑定、权限升级或身份冒充相关，风险较高。",
            "suggestion": "避免给普通主体授予 bind、escalate、impersonate 权限。",
        })

    return findings


def scan_role_rules(resource: YamlResource) -> list[Risk]:
    """直接扫描 Role / ClusterRole 自身定义的危险 rules。"""
    kind = resource.get("kind")

    if kind not in {"Role", "ClusterRole"}:
        return []

    resource_ref, namespace, source_file, _kind = get_resource_ref(resource)
    risks: list[Risk] = []

    for index, rule in enumerate(get_rules(resource)):
        findings = detect_rule_findings(rule, index)

        for finding in findings:
            risks.append(make_rbac_risk(
                level=finding["level"],
                rule_id=finding["rule_id"],
                resource=resource_ref,
                namespace=namespace,
                source_file=source_file,
                path=finding["path"],
                message=finding["message"],
                reason=finding["reason"],
                suggestion=finding["suggestion"],
            ))

    return risks

"""检测 RoleBinding / clusterRoleBinding 是否直接绑定 cluster-admin"""
def scan_cluster_admin_binding(binding: YamlResource) -> list[Risk]:
    kind = str(binding.get("kind", "")).strip()
   
    if kind not in {"RoleBinding","ClusterRoleBinding"}:
        return []
    
    role_ref = binding.get("roleRef") or {}
    role_ref_kind = str(role_ref.get("kind","Unknown")).strip()
    role_ref_name = str(role_ref.get("name","unknown")).strip()
    

    if role_ref_kind != "ClusterRole" or role_ref_name != "cluster-admin":
        return []
    binding_ref,binding_namespace,_role_ref_kind,_role_ref_name = get_binding_ref(binding)
    _resource_ref,_namespace,source_file,_kind = get_resource_ref(binding)

    subjects = get_binding_subjects(binding)
    subject_text = ", ".join(subjects) if subjects else "-"

    if kind == "ClusterRoleBinding":
        return [make_rbac_risk(
            level="HIGH",
            rule_id="KGL-RBAC-001",
            resource=binding_ref,
            namespace="cluster-scope",
            source_file=source_file,
            subject=subject_text,
            binding=binding_ref,
            path="roleRef.name",
            message="ClusterRoleBinding 绑定了 cluster-admin",
            reason="cluster-admin 通常代表集群最高权限，普通 ServiceAccount 不应被授予该权限。",
            suggestion="移除该 ClusterRoleBinding，或改为绑定最小权限 ClusterRole。",
        )]

    return [make_rbac_risk(
        level="HIGH",
        rule_id="KGL-RBAC-002",
        resource=binding_ref,
        namespace=binding_namespace,
        source_file=source_file,
        subject=subject_text,
        binding=binding_ref,
        path="roleRef.name",
        message="RoleBinding 绑定了 cluster-admin",
        reason="RoleBinding 引用 cluster-admin 时，虽然通常只在该命名空间生效，但仍然会授予极高权限。",
        suggestion="避免在普通命名空间通过 RoleBinding 引用 cluster-admin，改为最小权限 Role。",
    )]

"""关联分析Binding 引用的 Role / ClusterRole
   如果被引用的角色在当前扫描范围内：
   展开其rules,生成“某主体获得危险权限”的风险
   如果被引用角色不在当前扫描范围内,生成低危提示，说明无法静态展开"""
def scan_binding_expanded_permissions(
        binding: YamlResource,
        role_index: dict[RoleKey,YamlResource],
) -> list[Risk]:
    kind = binding.get("kind")

    if kind not in {"RoleBinding","ClusterRoleBinding"}:
        return []
    
    binding_ref, binding_namespace, role_ref_kind, role_ref_name = get_binding_ref(binding)
    _resource_ref, _namespace, source_file, _kind = get_resource_ref(binding) #_+变量名：接收占位

    if role_ref_kind == "ClusterRole" and role_ref_name == "cluster-admin":
        return []     #已检测过
    subjects = get_binding_subjects(binding)
    subject_text = ", ".join(subjects) if subjects else "-" #多个对象拼接为一个字符串，无则输出-是为了不输出空白

    referenced_role = resolve_role_ref(binding,role_index) #根据binding中的roleRef信息去索引字典里查找对应权限包

    if referenced_role is None:     #情况一：找不到对应的权限包
        return [make_rbac_risk(
            level="LOW",
            rule_id="KGL-RBAC-009",
            resource=binding_ref,
            namespace=binding_namespace,
            source_file=source_file,
            subject=subject_text,
            binding=binding_ref,
            path="roleRef",
            message="Binding 引用了当前扫描范围内未定义的角色",
            reason="静态扫描无法展开当前目录之外已有的 Role / ClusterRole 权限，可能存在未识别的权限风险。",
            suggestion="请结合真实集群中的 RBAC 配置进一步确认该 roleRef 的实际权限。",
        )]
    referenced_ref, _referenced_namespace, _referenced_source, _referenced_kind = get_resource_ref(
        referenced_role
    ) #提取被引用role的标识
    risks: list[Risk] = []

    #遍历权限包的所有权限规则，生成风险报告
    for index,rule in enumerate(get_rules(referenced_role)):
        findings = detect_rule_findings(rule,index)

        for finding in findings:
            risks.append(make_rbac_risk(
                level=finding["level"],
                rule_id=finding["rule_id"],
                resource=referenced_ref,
                namespace=binding_namespace,
                source_file=source_file,
                subject=subject_text,
                binding=binding_ref,
                path=f"{binding_ref} -> {referenced_ref}.{finding['path']}",
                message=f"{subject_text} 会通过 {binding_ref} 获得危险权限：{finding['message']}",
                reason=finding["reason"],
                suggestion=finding["suggestion"],
            ))

    return risks
    
    
"""总入口：扫描资源列表中的全部RBAC风险"""
def scan_rbac_resources(resources: list[YamlResource]) -> list[Risk]:
    risks: list[Risk] = []
    role_index = build_role_index(resources)
    
    for resource in resources:
        kind = str(resource.get("kind", "")).strip()
        
        if kind in {"Role","ClusterRole"}:
            risks.extend(scan_role_rules(resource))
        
        if kind in {"RoleBinding","ClusterRoleBinding"}:
            risks.extend(scan_cluster_admin_binding(resource))
            risks.extend(scan_binding_expanded_permissions(resource,role_index))

    return risks