from typing import Any

Risk = dict[str,Any]
ScanSummary = dict[str,Any]

LEVEL_WEIGHTS = {           #风险系数贡献数
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 1,
}

PRIORITY_RULE_BONUS = {   #高危风险额外增加风险系数（这样区分普通高危和致命高危）

    #workload 高危
    "KGL-SEC-001": 5,    #privileged：容器有特权
    "KGL-POD-001": 4,    #hostNetwork
    "KGL-POD-002": 4,    #hostPID
    "KGL-POD-003": 4,    #hostPIC
    "KGL-SEC-003": 4,    #runAsUser: 0

    #RBAC 高危
    "KGL-RBAC-001": 8,   #ClusterRoleBinding Cluster-admin
    "KGL-RBAC-002": 6,   #RoleBinding Cluster-admin
    "KGL-RBAC-004": 5,   #secrets read
    "KGL-RBAC-005": 5,   #pods/exec
    "KGL-RBAC-007": 5,   #modify RBAC
    "KGL-RBAC-008": 5,   #bind/escalate/impersonate

    #service / Ingress 高危
    "KGL-SVC-002": 4,    #LoadBalancer
    "KGL-SVC-003": 4,    #externalLIPs
    "KGL-SVC-004": 4,    #sensitve ports
    "KGL-ING-003": 4,    #dangerous nginx snippet
}

CATEGORY_BONUS = {                #不同类别额外增加不同风险系数（RBAC类风险往往比workload、service更严重）
    "RBAC": 2,
    "Workload": 1,
    "Service": 1,
}

GRADE_THRESHOLDS = [            #grade_threshold 分级阈值
    (180,"CRITICAL","极高风险","存在大量高危配置，建议立即阻断上线并先修复 HIGH 风险"), #元组，定义后不可修改
    (100, "HIGH", "高风险", "存在明显高危配置，建议上线前完成关键风险整改。"),
    (50, "MEDIUM", "中风险", "存在多项中低危配置问题，建议进行安全加固后再上线。"),
    (1, "LOW", "低风险", "发现少量低危或加固建议，可按优先级逐步优化。"),
    (0, "SAFE", "未发现明显风险", "当前扫描范围内未发现已配置的风险规则。"),
]

"""标准化风险等级"""
def normalize_level(level: Any) -> str:
    normalized = str(level or "LOW").upper().strip() #防止手写YAML文件时最后多出空格导致后面的字段匹配失败

    if normalized not in LEVEL_WEIGHTS:
        return "LOW"
    
    return normalized

"""获取风险等级"""
def get_risk_level(risk: Risk) -> str:
    return str(risk.get("level"))

"""获取风险类别"""
def get_risk_category(risk:Risk) -> str:
    return str(risk.get("category","Workload")).strip() or "UNKNOWN"

"""获取规则ID"""
def get_rule_id(risk: Risk) -> str:
    return str(risk.get("rule_id","UNKNOWN")).strip() or "UNKNOWN"

"""计算单条风险优先级分数
   分数 == 基础分 + 特定高危加分 + 类别加权"""
def calculate_single_risk_score(risk: Risk) -> int:
    level = get_risk_level(risk)
    category = get_risk_category(risk)
    rule_id = get_rule_id(risk)

    base_score = LEVEL_WEIGHTS[level]
    rule_bonus = PRIORITY_RULE_BONUS.get(rule_id,0)
    category_bonus = CATEGORY_BONUS.get(category,0)

    return base_score + rule_bonus + category_bonus

"""根据单条风险分数生成修复优先级。

    P0: 立即修复
    P1: 优先修复
    P2: 计划修复
    P3: 加固建议                 
    """
def get_fix_priority(risk: Risk) -> str:

    level = get_risk_level(risk)
    score = calculate_single_risk_score(risk)

    if level == "HIGH" and score >= 17:
        return "P0"
    if level == "HIGH":
        return "P1"
    
    if level == "MEDIUM":
        return "P2"
    
    return "P3"

"""给风险对象补充评分字段(不修改原risk，而是返回一个新的dict,防止影响scanner输出)"""
def enrich_risk(risk: Risk) -> Risk:
    enriched = dict(risk)

    enriched["level"] = get_risk_level(risk)
    enriched["category"] = get_risk_category(risk)
    enriched["risk_score"] = calculate_single_risk_score(risk)
    enriched["fix_priority"] = get_fix_priority(risk)

    return enriched

"""批量补充风险评分字段"""
def enrich_risks(risks: list[Risk]) -> list[Risk]:
    return [enrich_risk(risk) for risk in risks]

"""按修复优先级排序风险
    排序依据：
    1. P0 / P1 / P2 / P3
    2. 单条风险分数
    3. HIGH / MEDIUM / LOW
    """
def sort_risks_by_priority(risks: list[Risk]) -> list[Risk]:
    enriched_risks = enrich_risks(risks)

    priority_order = {
        "P0": 0,
        "P1": 1,
        "P2": 2,
        "P3": 3,
    }

    level_order = {
        "HIGH": 0,
        "MEDIUM": 1,
        "LOW": 2,
    }

    return sorted(
        enriched_risks,
        key = lambda risk:(  #使用匿名函数进行排序，按照四个指标
            priority_order.get(str(risk.get("fix_priority")),99), #按优先级排序，数字越小越紧急，排名越靠前，如果出现异常则为99，排最后
            -int(risk.get("risk_score",0)), #要实现同优先级分数越高越靠前，就要加负号，毕竟sort按照从小到大排列
            level_order.get(str(risk.get("level")),99), #根据等级进行划分
            str(risk.get("rule_id","")),
        ),
    )

"""按风险等级进行统计"""
def count_by_level(risks: list[Risk]) -> dict[str,int]:

    result = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for risk in risks:
        level = get_risk_level(risk)
        result[level] += 1

    return result

"""按风险类别进行统计"""
def count_by_category(risks: list[Risk]) -> dict[str,int]:

    result = {
        "Workload": 0,
        "RBAC": 0,
        "Service": 0,
    }
    
    for risk in risks:
        category = get_risk_category(risk)
        result[category] = result.get(category,0) + 1

    return result

"""统计可自动修复风险的数量"""
def count_auto_fixable(risks: list[Risk]) -> int:
    return sum(1 for risk in risks if risk.get("auto_fixable") is True)

"""计算总风险分"""
def calculate_total_score(risks: list[Risk]) -> int:
    return sum(calculate_single_risk_score(risk) for risk in risks)

"""根据总风险分数计算整体评级(暴力匹配)"""
def calculate_grade(total_score: int) -> dict[str,str]:
    
    for threshold,grade,label,description in  GRADE_THRESHOLDS:
        if total_score >= threshold:
            return {
                "grade":grade,
                "label":label,
                "description":description,
            }    
    
    return {
        "grade": "SAFE",
        "label": "未发现明显风险",
        "description": "当前扫描范围内未发现已配置的风险规则。"
    }

"""获取最高优先级风险"""
def get_top_risks(risks: list[Risk], limit: int = 5) -> list[Risk]:
    
    return sort_risks_by_priority(risks)[:limit]

"""根据统计结果生成总体修复建议"""
def build_recommendations(level_counts: dict[str,int], category_counts: dict[str,int]) -> list[str]:

    recommendations:list[str] = []

    if level_counts.get("HIGH", 0) > 0:
        recommendations.append("优先修复 HIGH 风险，尤其是 privileged、cluster-admin、secrets 读取、LoadBalancer 暴露等问题。")

    if category_counts.get("RBAC", 0) > 0:
        recommendations.append("检查 RBAC 权限是否遵循最小权限原则，重点关注 ServiceAccount、RoleBinding 和 ClusterRoleBinding。")

    if category_counts.get("Workload", 0) > 0:
        recommendations.append("检查 Pod / Deployment 的容器安全上下文、镜像标签、资源限制和 ServiceAccount token 挂载配置。")

    if category_counts.get("Service", 0) > 0:
        recommendations.append("检查 Service / Ingress 暴露面，限制 NodePort、LoadBalancer、externalIPs 和敏感端口。")

    if not recommendations:
        recommendations.append("当前扫描范围内未发现明显风险，可继续保持最小权限和最小暴露面原则。")

    return recommendations


"""构建完整的扫描评分摘要"""
def build_scan_summary(risks: list[Risk]) -> ScanSummary:
    
    enriched_risks = enrich_risks(risks)

    level_counts = count_by_level(enriched_risks)
    category_counts = count_by_category(enriched_risks)
    total_score = calculate_total_score(enriched_risks)
    grade_info = calculate_grade(total_score)

    return{
        "total_risks": len(enriched_risks),
        "level_counts": level_counts,
        "category_counts": category_counts,
        "auto_fixable_count": count_auto_fixable(enriched_risks),
        "total_score": total_score,
        "grade": grade_info["grade"],
        "grade_label": grade_info["label"],
        "grade_description": grade_info["description"],
        "top_risks": get_top_risks(enriched_risks, limit=5),
        "recommendations": build_recommendations(level_counts, category_counts),
    }
