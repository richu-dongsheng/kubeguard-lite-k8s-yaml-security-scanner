from datetime import datetime
from typing import Any

from scanner.parser import get_resource_identity

YamlResource = dict[str,Any]
Risk = dict[str,Any]
ScanSummary = dict[str,Any]



"""
转义 Markdown 表格中的特殊字符
Markdown 表格用竖线 | 分割单元格。
如果风险描述里自带 | 符号，表格会直接裂开、排版错乱。
同时把换行符 \n 替换成 HTML 换行 <br>，保证单元格内换行正常显示。
"""
def md_escape(value: Any) -> str:
    text = str(value if value is not None else "-")
    return text.replace("|","\\|").replace("\n","<br>")



"""获得风险关联主体：RBAC 使用 subject, workload 使用 container。"""
def get_actor(risk: Risk) -> str:
    return str(risk.get("subject") or risk.get("container") or "-")


"""不同等级进行区分"""
def get_level_badge(level: Any) -> str:

    level_text = str(level).upper()

    if level_text == "HIGH":
        return "🔴 HIGH"
    
    if level_text == "MEDIUM":
        return "🟡 MEDIUM"
    
    if level_text == "LOW":
        return "🔵 LOW"
    
    return level_text



"""渲染 Markdown 表格"""
def render_markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines: list[str] = []

    lines.append("| " + "| ".join(headers) + " |")
    lines.append("| " + "| ".join(["---"] * len(headers)) + " |")

    for row in rows:
        lines.append("| " + "| ".join(md_escape(item) for item in row) + " |")

    return lines


"""总入口：生成 Markdown 安全扫描报告"""
def generate_markdown_report(
    *,
    resources: list[YamlResource],
    risks: list[Risk],
    summary: ScanSummary,
    target_path: str = "-",
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    level_counts = summary.get("level_counts", {})
    category_counts = summary.get("category_counts", {})
    recommendations = summary.get("recommendations", [])
    top_risks = summary.get("top_risks", [])

    #提前筛选出可以直接修复的风险
    auto_fixable_risks = [
        risk for risk in risks if risk.get("auto_fixable") is True
    ]
    
    #罗列出行，然后拼接
    lines: list[str] = []

    lines.append("# kubeguard-Lite Kubernetes YAML 安全扫描报告")
    lines.append("")
    lines.append("## 1. 报告概览")
    lines.append("")

    lines.extend(render_markdown_table(
        ["项目", "结果"],
        [
            ["扫描目标", target_path],
            ["生成时间", now],
            ["Kubernetes 资源数", len(resources)],
            ["风险总数", summary.get("total_risks", 0)],
            ["整体危险系数", summary.get("total_score", 0)],
            ["整体评级", f"{summary.get('grade', '-')} ({summary.get('grade_label', '-')})"],
            ["评级说明", summary.get("grade_description", "-")],
            ["可自动修复风险数", summary.get("auto_fixable_count", 0)],
        ],
    ))

    lines.append("")
    lines.append("## 2.风险等级统计")
    lines.append("")
    lines.extend(render_markdown_table(
        ["等级", "数量"],
        [
            ["HIGH", level_counts.get("HIGH", 0)],
            ["MEDIUM", level_counts.get("MEDIUM", 0)],
            ["LOW", level_counts.get("LOW", 0)],
        ],
    ))

    lines.append("")
    lines.append("## 3. 风险类别统计")
    lines.append("")

    category_rows = [
        [category,count] for category, count in category_counts.items()
    ]
    lines.extend(render_markdown_table(["类别","数量"],category_rows))

    lines.append("")
    lines.append("## 4. Top 高优先级风险")
    lines.append("")

    if top_risks:
        top_rows = []
        for index, risk in enumerate(top_risks, start=1):
            top_rows.append([
                index,
                risk.get("risk_score", "-"),
                get_level_badge(risk.get("level", "-")),
                risk.get("category", "-"),
                risk.get("rule_id", "-"),
                risk.get("resource", "-"),
                get_actor(risk),
                risk.get("message", "-"),
            ])

        lines.extend(render_markdown_table(
            ["序号", "危险系数", "等级", "类别", "规则", "资源", "主体/容器", "风险说明"],
            top_rows,
        ))
    else:
        lines.append("未发现高优先级风险。")

    lines.append("")
    lines.append("## 5. 完整风险清单")
    lines.append("")

    if risks:
        for index, risk in enumerate(risks, start=1):
            lines.append(f"### {index}. {risk.get('rule_id', '-')}: {risk.get('message', '-')}")
            lines.append("")
            lines.extend(render_markdown_table(
                ["字段", "内容"],
                [
                    ["危险系数", risk.get("risk_score", "-")],
                    ["等级", get_level_badge(risk.get("level", "-"))],
                    ["类别", risk.get("category", "-")],
                    ["资源", risk.get("resource", "-")],
                    ["命名空间", risk.get("namespace", "-")],
                    ["主体/容器", get_actor(risk)],
                    ["来源文件", risk.get("source_file", "-")],
                    ["风险路径", risk.get("path", "-")],
                    ["风险原因", risk.get("reason", "-")],
                    ["修复建议", risk.get("suggestion", "-")],
                    ["是否可自动修复", "YES" if risk.get("auto_fixable") is True else "NO"],
                ],
            ))
            lines.append("")
    else:
        lines.append("未发现已配置规则覆盖的风险。")

    lines.append("")
    lines.append("## 6. 可自动修复风险摘要")
    lines.append("")

    if auto_fixable_risks:
        auto_fix_rows = []
        for index, risk in enumerate(auto_fixable_risks, start=1):
            auto_fix_rows.append([
                index,
                risk.get("rule_id", "-"),
                risk.get("resource", "-"),
                risk.get("message", "-"),
                risk.get("suggestion", "-"),
            ])

        lines.extend(render_markdown_table(
            ["序号", "规则", "资源", "风险说明", "修复建议"],
            auto_fix_rows,
        ))
    else:
        lines.append("当前没有可自动修复的风险。")

    lines.append("")
    lines.append("## 7. 资源清单")
    lines.append("")

    resource_rows = []
    for index, resource in enumerate(resources, start=1):
        identity = get_resource_identity(resource)

        resource_rows.append([
            index,
            identity["kind"],
            identity["name"],
            identity["namespace"],
            identity["source_file"],
        ])

    lines.extend(render_markdown_table(
        ["序号", "Kind", "Name", "Namespace", "Source File"],
        resource_rows,
    ))

    lines.append("")
    lines.append("## 8. 总体修复建议")
    lines.append("")

    if recommendations:
        for recommendation in recommendations:
            lines.append(f"- {recommendation}")
    else:
        lines.append("- 当前扫描范围内未生成额外修复建议。")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Generated by kubeguard-Lite.")

    return "\n".join(lines)
