from typing import Any

from scanner.parser import get_resource_identity

YamlResource = dict[str,Any]
Risk = dict[str,Any]

SENSITIVE_PORTS: dict[int,str] = {
    22: "SSH 远程登录端口",
    2375: "Docker API 明文端口",
    2376: "Docker API TLS 端口",
    2379: "etcd 客户端端口",
    2380: "etcd 节点通信端口",
    3306: "MySQL 数据库端口",
    5432: "PostgreSQL 数据库端口",
    6379: "Redis 数据库端口",
    6443: "Kubernetes API Server 端口",
    9200: "Elasticsearch HTTP 端口",
    9300: "Elasticsearch 集群通信端口",
    10250: "kubelet API 端口",
    10255: "kubelet 只读端口",
    11211: "Memcached 端口",
    27017: "MongoDB 数据库端口",
}

DANGEROUS_INGRESS_ANNOTATIONS = {
    "nginx.ingress.kubernetes.io/configuration-snippet",
    "nginx.ingress.kubernetes.io/server-snippet",
    "nginx.ingress.kubernetes.io/auth-snippet",
    "nginx.ingress.kubernetes.io/modsecurity-snippet",
}


"""创建统一的 service / Ingress 风险对象"""
def make_service_risk(
    *,
    level:str,
    rule_id: str,
    resource: str,
    namespace: str,
    source_file: str,
    path: str,
    message: str,
    reason: str,
    suggestion: str,
    port: str = "-",
    auto_fixable: bool = False,
) -> Risk:
    return {
        "level": level,
        "rule_id": rule_id,
        "category": "Service",
        "resource": resource,
        "namespace": namespace,
        "container": "-",
        "subject": "-",
        "binding": "-",
        "port": port,
        "path": path,
        "message": message,
        "reason": reason,
        "suggestion": suggestion,
        "source_file": source_file,
        "auto_fixable": auto_fixable,
    }

"""提取资源标识"""
def get_resource_ref(resource:YamlResource) -> tuple[str,str,str,str]:

    identity = get_resource_identity(resource)

    kind = identity["kind"]
    name = identity["name"]
    namespace = identity["namespace"]
    source_file = identity["source_file"]

    resource_ref = f"{kind}/{name}"

    return resource_ref,namespace,source_file,kind

"""把端口号转为int型"""
def normalize_int(value: Any) -> int | None:
   
    if isinstance(value,bool):  #兼容yaml不规范写法，要这么写是因为如果写了True，py语法会解析为1
        return None
    
    if isinstance(value,int):
        return value
    
    if isinstance(value,str) and value.isdigit(): #数字型字符串，直接转int
        return int(value)
    return None

"""获取Service类型，默认ClusterIP"""
def get_service_type(service: YamlResource) -> str:
    spec = service.get("spec")

    if not isinstance(spec, dict):
        return "ClusterIP"

    service_type = spec.get("type", "ClusterIP")

    return str(service_type).strip() or "ClusterIP"

"""获取 service Ports 列表"""
def get_service_ports(service: YamlResource) -> list[dict[str,Any]]:
    spec = service.get("spec") or {}
    ports = spec.get("ports") or {}

    if not isinstance(ports,list):
        return []
    
    return [port for port in ports if isinstance(port,dict)]

"""获取service selector"""
def get_service_selector(service: YamlResource) -> dict[str,str]:
    spec = service.get("spec") or {}
    selector = spec.get("selector") or {}

    if not isinstance(selector,dict):
        return {}
    
    return {str(key): str(value) for key,value in selector.items()}

"""从 metadata 中提取 labels """
def get_labels_from_metadata(metadata: Any) -> dict[str,str]:
    if not isinstance(metadata, dict):
        return {}

    labels = metadata.get("labels") or {}

    if not isinstance(labels, dict):
        return {}

    return {str(key): str(value) for key, value in labels.items()}


"""提取工作负载最终 pod 会携带的 labels
    支持：
    - Pod: metadata.labels
    - Deployment / DaemonSet / StatefulSet / ReplicaSet: spec.template.metadata.labels
    - Job: spec.template.metadata.labels
    - CronJob: spec.jobTemplate.spec.template.metadata.labels"""

def get_workload_pod_labels(resource: YamlResource) -> dict[str,str]:
    kind = resource.get("kind")

    if kind == "Pod":
        metadata = resource.get("metadata") or {}
        return get_labels_from_metadata(metadata)
    
    if kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet"}:
        metadata = (
            resource
            .get("spec", {})
            .get("template", {})
            .get("metadata", {})
        )
        return get_labels_from_metadata(metadata)

    if kind == "Job":
        metadata = (
            resource
            .get("spec", {})
            .get("template", {})
            .get("metadata", {})
        )
        return get_labels_from_metadata(metadata)

    if kind == "CronJob":
        metadata = (
            resource
            .get("spec", {})
            .get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("metadata", {})
        )
        return get_labels_from_metadata(metadata)

    return {}
    
"""建立工作负载 labels 索引，用于判断 service selector 在当前扫描范围内是否能匹配到工作负载"""
def build_workload_label_index(resources: list[YamlResource]) -> list[dict[str,Any]]:
    index: list[dict[str,Any]] = []

    for resource in resources:
        resource_ref,namespace,source_file,kind = get_resource_ref(resource)
        labels = get_workload_pod_labels(resource)

        if not labels:
            continue

        index.append({
            "resource": resource_ref,
            "namespace": namespace,
            "source_file": source_file,
            "kind": kind,
            "labels": labels,
        })

    return index
    
"""判断 selector 是否匹配 labels"""
def selector_matches_labels(selector: dict[str,str],labels: dict[str,str]) ->bool:
    if not selector:
        return False
    
    for key, value in selector.items():
        if labels.get(key) != value:
            return False
        
    return True

"""判断 service selector 是否能在当前扫描范围内匹配到工作负载"""
def service_selector_matches_any_workload(
        service: YamlResource,
        workload_label_index: list[dict[str,Any]],
) -> bool:
    selector = get_service_selector(service)
    _resource_ref,namespace, _source_file, _kind = get_resource_ref(service)

    if not selector:
        return False
    
    for workload in workload_label_index:
        if workload["namespace"] != namespace:
            continue
        if selector_matches_labels(selector,workload["labels"]):
            return True
        
    return False

def scan_service_exposure_risks(
    service: YamlResource,
    workload_label_index: list[dict[str, Any]],
) -> list[Risk]:
    """扫描 Service 暴露面风险。"""
    if service.get("kind") != "Service":
        return []

    resource_ref, namespace, source_file, _kind = get_resource_ref(service)
    service_type = get_service_type(service)

    spec = service.get("spec") or {}
    risks: list[Risk] = []

    if service_type == "NodePort":
        risks.append(make_service_risk(
            level="MEDIUM",
            rule_id="KGL-SVC-001",
            resource=resource_ref,
            namespace=namespace,
            source_file=source_file,
            path="spec.type",
            message="Service 使用了 NodePort 暴露方式",
            reason="NodePort 会在每个节点上开放端口，可能扩大服务暴露面。",
            suggestion="如无必要，优先使用 ClusterIP；如必须使用 NodePort，应限制节点访问来源并配合防火墙策略。",
        ))

    if service_type == "LoadBalancer":
        risks.append(make_service_risk(
            level="HIGH",
            rule_id="KGL-SVC-002",
            resource=resource_ref,
            namespace=namespace,
            source_file=source_file,
            path="spec.type",
            message="Service 使用了 LoadBalancer 暴露方式",
            reason="在云环境中，LoadBalancer 可能创建外部负载均衡入口，导致服务暴露到集群外部。",
            suggestion="确认是否确实需要外部暴露；如需要，应配置访问控制、来源限制和认证机制。",
        ))

        load_balancer_source_ranges = spec.get("loadBalancerSourceRanges")

        if not load_balancer_source_ranges:
            risks.append(make_service_risk(
                level="MEDIUM",
                rule_id="KGL-SVC-008",
                resource=resource_ref,
                namespace=namespace,
                source_file=source_file,
                path="spec.loadBalancerSourceRanges",
                message="LoadBalancer 未限制访问来源",
                reason="缺少 loadBalancerSourceRanges 时，外部访问来源可能过宽，增加暴露面。",
                suggestion="为 LoadBalancer 设置 loadBalancerSourceRanges，只允许可信来源访问。",
            ))

    if service_type == "ExternalName":
        external_name = str(spec.get("externalName", "unknown"))

        risks.append(make_service_risk(
            level="MEDIUM",
            rule_id="KGL-SVC-009",
            resource=resource_ref,
            namespace=namespace,
            source_file=source_file,
            path="spec.externalName",
            message=f"Service 使用 ExternalName 指向外部域名：{external_name}",
            reason="ExternalName 会把集群内服务名映射到外部域名，可能引入外部依赖、DNS 劫持或供应链风险。",
            suggestion="确认 externalName 指向可信域名，并避免业务核心链路依赖不受控外部域名。",
        ))

    external_ips = spec.get("externalIPs") or []

    if isinstance(external_ips, list) and external_ips:
        risks.append(make_service_risk(
            level="HIGH",
            rule_id="KGL-SVC-003",
            resource=resource_ref,
            namespace=namespace,
            source_file=source_file,
            path="spec.externalIPs",
            message="Service 配置了 externalIPs",
            reason="externalIPs 可能让服务通过指定外部 IP 暴露，若配置不当会绕过预期网络边界。",
            suggestion="避免随意使用 externalIPs；如必须使用，应确认 IP 归属、路由策略和访问控制。",
        ))

    ports = get_service_ports(service)

    for index, port_item in enumerate(ports):
        port = normalize_int(port_item.get("port"))
        target_port = normalize_int(port_item.get("targetPort"))
        node_port = normalize_int(port_item.get("nodePort"))

        exposed_ports = [
            ("port", port),
            ("targetPort", target_port),
            ("nodePort", node_port),
        ]

        for field_name, port_value in exposed_ports:
            if port_value is None:
                continue

            if port_value in SENSITIVE_PORTS:
                risks.append(make_service_risk(
                    level="HIGH",
                    rule_id="KGL-SVC-004",
                    resource=resource_ref,
                    namespace=namespace,
                    source_file=source_file,
                    path=f"spec.ports[{index}].{field_name}",
                    port=str(port_value),
                    message=f"Service 暴露敏感端口 {port_value}",
                    reason=f"{port_value} 是 {SENSITIVE_PORTS[port_value]}，暴露后可能造成高风险访问入口。",
                    suggestion="避免通过 Service 暴露敏感管理端口；如必须暴露，应限制访问来源并开启认证、审计和网络隔离。",
                ))

        if node_port is not None and not 30000 <= node_port <= 32767:
            risks.append(make_service_risk(
                level="MEDIUM",
                rule_id="KGL-SVC-007",
                resource=resource_ref,
                namespace=namespace,
                source_file=source_file,
                path=f"spec.ports[{index}].nodePort",
                port=str(node_port),
                message=f"Service nodePort {node_port} 不在默认 NodePort 范围内",
                reason="Kubernetes 默认 NodePort 范围通常是 30000-32767，异常端口可能表示配置错误或非标准集群设置。",
                suggestion="确认 apiserver 的 service-node-port-range 配置；如无特殊需求，使用默认 NodePort 范围。",
            ))

    selector = get_service_selector(service)

    if service_type != "ExternalName" and not selector:
        risks.append(make_service_risk(
            level="LOW",
            rule_id="KGL-SVC-005",
            resource=resource_ref,
            namespace=namespace,
            source_file=source_file,
            path="spec.selector",
            message="Service 没有配置 selector",
            reason="缺少 selector 的 Service 可能依赖手动 Endpoints 或 EndpointSlice，流量指向不够直观，容易造成误配置。",
            suggestion="确认该 Service 是否确实需要无 selector；普通业务服务建议显式配置 selector。",
        ))

    if selector and not service_selector_matches_any_workload(service, workload_label_index):
        risks.append(make_service_risk(
            level="LOW",
            rule_id="KGL-SVC-006",
            resource=resource_ref,
            namespace=namespace,
            source_file=source_file,
            path="spec.selector",
            message="Service selector 在当前扫描范围内没有匹配到工作负载",
            reason="Service selector 如果无法匹配 Pod labels，可能导致服务无后端；但静态扫描范围可能不完整，因此仅作为提示。",
            suggestion="检查 Service selector 是否与目标 Pod / Deployment template labels 一致。",
        ))

    return risks

"""提取metadata.annotations"""
def get_annotations(resource: YamlResource) -> dict[str,str]:
    metadata = resource.get("metadata") or {}

    annotations = metadata.get("annotations") or {}

    if not isinstance(annotations, dict):
        return {}

    return {str(key): str(value) for key, value in annotations.items()}

"""获取Ingress rules"""
def get_ingress_rules(ingress: YamlResource) -> list[dict[str, Any]]:
    spec = ingress.get("spec") or {}
    rules = spec.get("rules") or []

    if not isinstance(rules, list):
        return []

    return [rule for rule in rules if isinstance(rule, dict)]

"""判断 Ingress 是否配置 TLS"""
def ingress_has_tls(ingress: YamlResource) -> bool:

    spec = ingress.get("spec") or {}
    tls = spec.get("tls") or []

    return isinstance(tls, list) and len(tls) > 0

"""扫描 Ingress 暴露风险"""
def scan_ingress_risks(ingress:YamlResource) -> list[Risk]:
    
    if ingress.get("kind") != "Ingress":
        return []
    resource_ref,namespace,source_file,_kind = get_resource_ref(ingress)
    risks: list[Risk] = []

    annotations = get_annotations(ingress)

    for annotation_key in annotations:
        if annotation_key in DANGEROUS_INGRESS_ANNOTATIONS:
            risks.append(make_service_risk(
                level="HIGH",
                rule_id="KGL-ING-003",
                resource=resource_ref,
                namespace=namespace,
                source_file=source_file,
                path=f"metadata.annotations.{annotation_key}",
                message=f"Ingress 使用了高风险 Nginx 注解：{annotation_key}",
                reason="snippet 类注解可能向 Nginx 配置中注入自定义片段，若被滥用可能绕过安全边界或引入配置注入风险。",
                suggestion="避免在普通业务 Ingress 中使用 snippet 类注解；如必须使用，应经过严格审查。",
            ))

    rules = get_ingress_rules(ingress)
    has_tls = ingress_has_tls(ingress)

    if rules and not has_tls:
        risks.append(make_service_risk(
            level="MEDIUM",
            rule_id="KGL-ING-001",
            resource=resource_ref,
            namespace=namespace,
            source_file=source_file,
            path="spec.tls",
            message="Ingress 未配置 TLS",
            reason="未配置 TLS 可能导致外部访问使用明文 HTTP，存在流量窃听和篡改风险。",
            suggestion="为 Ingress 配置 TLS，并使用可信证书。",
        ))

    for index, rule in enumerate(rules):
        host = str(rule.get("host", "")).strip()

        if not host:
            risks.append(make_service_risk(
                level="LOW",
                rule_id="KGL-ING-004",
                resource=resource_ref,
                namespace=namespace,
                source_file=source_file,
                path=f"spec.rules[{index}].host",
                message="Ingress rule 未显式配置 host",
                reason="未配置 host 的 Ingress 可能匹配较宽的流量范围，增加误暴露风险。",
                suggestion="为 Ingress rule 显式配置业务域名。",
            ))

        if host.startswith("*.") or host == "*":
            risks.append(make_service_risk(
                level="MEDIUM",
                rule_id="KGL-ING-002",
                resource=resource_ref,
                namespace=namespace,
                source_file=source_file,
                path=f"spec.rules[{index}].host",
                message=f"Ingress 使用了通配符 host：{host}",
                reason="通配符域名会扩大 Ingress 匹配范围，可能导致非预期子域名流量进入服务。",
                suggestion="避免使用过宽的通配符域名，优先配置明确业务域名。",
            ))

    return risks

"""扫描全部 Service / Ingress 暴露风险"""
def scan_service_resources(resources: list[YamlResource]) -> list[Risk]:

    risks: list[Risk] = []
    workload_label_index = build_workload_label_index(resources)

    for resource in resources:
        kind = resource.get("kind")

        if kind == "Service":
            risks.extend(scan_service_exposure_risks(resource, workload_label_index))

        if kind == "Ingress":
            risks.extend(scan_ingress_risks(resource))

    return risks