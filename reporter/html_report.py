from datetime import datetime
from html import escape
from typing import Any

from scanner.parser import get_resource_identity

YamlResource = dict[str, Any]
Risk = dict[str, Any]
ScanSummary = dict[str, Any]


def h(value: Any) -> str:
    """HTML 转义。"""
    return escape(str(value if value is not None else "-"))


def get_actor(risk: Risk) -> str:
    return str(risk.get("subject") or risk.get("container") or "-")


def level_class(level: Any) -> str:
    level_text = str(level).upper()

    if level_text == "HIGH":
        return "level-high"

    if level_text == "MEDIUM":
        return "level-medium"

    if level_text == "LOW":
        return "level-low"

    return ""


def render_table(headers: list[str], rows: list[list[Any]]) -> str:
    thead = "".join(f"<th>{h(header)}</th>" for header in headers)

    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{h(cell)}</td>" for cell in row)
        body_rows.append(f"<tr>{cells}</tr>")

    tbody = "\n".join(body_rows)

    return f"""
<table>
  <thead>
    <tr>{thead}</tr>
  </thead>
  <tbody>
    {tbody}
  </tbody>
</table>
"""

def render_risk_card(index: int,risk: Risk) -> str:
    level = str(risk.get("level","-"))
    css_class = level_class(level)

    return f"""
<section class="risk-card {css_class}">
  <h3>{index}. {h(risk.get("rule_id", "-"))}: {h(risk.get("message", "-"))}</h3>
  <div class="risk-meta">
    <span>危险系数：<strong>{h(risk.get("risk_score", "-"))}</strong></span>
    <span>等级：<strong>{h(level)}</strong></span>
    <span>类别：<strong>{h(risk.get("category", "-"))}</strong></span>
    <span>资源：<strong>{h(risk.get("resource", "-"))}</strong></span>
    <span>主体/容器：<strong>{h(get_actor(risk))}</strong></span>
  </div>
  <p><strong>来源文件：</strong>{h(risk.get("source_file", "-"))}</p>
  <p><strong>风险路径：</strong>{h(risk.get("path", "-"))}</p>
  <p><strong>风险原因：</strong>{h(risk.get("reason", "-"))}</p>
  <p><strong>修复建议：</strong>{h(risk.get("suggestion", "-"))}</p>
  <p><strong>可自动修复：</strong>{'YES' if risk.get("auto_fixable") is True else 'NO'}</p>
</section>
"""

"""生成 HTML 安全报告"""
def generate_html_report(
    *,
    resources: list[YamlResource],
    risks: list[Risk],
    summary: ScanSummary,
    target_path: str = "-"
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    level_counts = summary.get("level_counts", {})
    category_counts = summary.get("category_counts", {})
    recommendations = summary.get("recommendations", [])
    top_risks = summary.get("top_risks", [])

    auto_fixable_risks = [
        risk for risk in risks
        if risk.get("auto_fixable") is True
    ]

    overview_table = render_table(
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
    )

    level_table = render_table(
        ["等级", "数量"],
        [
            ["HIGH", level_counts.get("HIGH", 0)],
            ["MEDIUM", level_counts.get("MEDIUM", 0)],
            ["LOW", level_counts.get("LOW", 0)],
        ],
    )

    category_table = render_table(
        ["类别", "数量"],
        [[category, count] for category, count in category_counts.items()],
    )

    top_risk_table = render_table(
        ["序号", "危险系数", "等级", "类别", "规则", "资源", "主体/容器", "风险说明"],
        [
            [
                index,
                risk.get("risk_score", "-"),
                risk.get("level", "-"),
                risk.get("category", "-"),
                risk.get("rule_id", "-"),
                risk.get("resource", "-"),
                get_actor(risk),
                risk.get("message", "-"),
            ]
            for index, risk in enumerate(top_risks, start=1)
        ],
    )

    resource_table = render_table(
        ["序号", "Kind", "Name", "Namespace", "Source File"],
        [
            [
                index,
                get_resource_identity(resource)["kind"],
                get_resource_identity(resource)["name"],
                get_resource_identity(resource)["namespace"],
                get_resource_identity(resource)["source_file"],
            ]
            for index, resource in enumerate(resources, start=1)
        ],
    )

    auto_fix_table = render_table(
        ["序号", "规则", "资源", "风险说明", "修复建议"],
        [
            [
                index,
                risk.get("rule_id", "-"),
                risk.get("resource", "-"),
                risk.get("message", "-"),
                risk.get("suggestion", "-"),
            ]
            for index, risk in enumerate(auto_fixable_risks, start=1)
        ],
    ) if auto_fixable_risks else "<p>当前没有可自动修复的风险。</p>"

    risk_cards = "\n".join(
        render_risk_card(index, risk)
        for index, risk in enumerate(risks, start=1)
    ) or "<p>未发现已配置规则覆盖的风险。</p>"

    recommendation_items = "\n".join(
        f"<li>{h(recommendation)}</li>"
        for recommendation in recommendations
    ) or "<li>当前扫描范围内未生成额外修复建议。</li>"

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>kubeguard-Lite 安全扫描报告</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
      margin: 0;
      background: #f5f7fb;
      color: #1f2937;
      line-height: 1.6;
    }}

    header {{
      background: #111827;
      color: white;
      padding: 32px 48px;
    }}

    header h1 {{
      margin: 0;
      font-size: 28px;
    }}

    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 32px 24px 64px;
    }}

    section {{
      background: white;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06);
    }}

    h2 {{
      margin-top: 0;
      border-left: 5px solid #2563eb;
      padding-left: 12px;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      font-size: 14px;
    }}

    th, td {{
      border: 1px solid #e5e7eb;
      padding: 10px 12px;
      text-align: left;
      vertical-align: top;
    }}

    th {{
      background: #f3f4f6;
      font-weight: 700;
    }}

    tr:nth-child(even) td {{
      background: #fafafa;
    }}

    .grade-box {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-top: 16px;
    }}

    .metric {{
      background: #f9fafb;
      border: 1px solid #e5e7eb;
      border-radius: 10px;
      padding: 16px;
    }}

    .metric strong {{
      display: block;
      font-size: 24px;
      margin-top: 4px;
    }}

    .risk-card {{
      border-left: 6px solid #9ca3af;
    }}

    .risk-card h3 {{
      margin-top: 0;
    }}

    .risk-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 12px;
    }}

    .risk-meta span {{
      background: #f3f4f6;
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 13px;
    }}

    .level-high {{
      border-left-color: #dc2626;
    }}

    .level-medium {{
      border-left-color: #d97706;
    }}

    .level-low {{
      border-left-color: #2563eb;
    }}

    footer {{
      text-align: center;
      color: #6b7280;
      padding: 24px;
      font-size: 13px;
    }}
  </style>
</head>
<body>
<header>
  <h1>kubeguard-Lite Kubernetes YAML 安全扫描报告</h1>
  <p>Generated at {h(now)}</p>
</header>

<main>
  <section>
    <h2>1. 报告概览</h2>
    <div class="grade-box">
      <div class="metric">风险总数<strong>{h(summary.get("total_risks", 0))}</strong></div>
      <div class="metric">整体危险系数<strong>{h(summary.get("total_score", 0))}</strong></div>
      <div class="metric">整体评级<strong>{h(summary.get("grade", "-"))}</strong></div>
      <div class="metric">可自动修复<strong>{h(summary.get("auto_fixable_count", 0))}</strong></div>
    </div>
    {overview_table}
  </section>

  <section>
    <h2>2. 风险等级统计</h2>
    {level_table}
  </section>

  <section>
    <h2>3. 风险类别统计</h2>
    {category_table}
  </section>

  <section>
    <h2>4. Top 高优先级风险</h2>
    {top_risk_table}
  </section>

  <section>
    <h2>5. 完整风险清单</h2>
    {risk_cards}
  </section>

  <section>
    <h2>6. 可自动修复风险摘要</h2>
    {auto_fix_table}
  </section>

  <section>
    <h2>7. 资源清单</h2>
    {resource_table}
  </section>

  <section>
    <h2>8. 总体修复建议</h2>
    <ul>
      {recommendation_items}
    </ul>
  </section>
</main>

<footer>
  Generated by kubeguard-Lite.
</footer>
</body>
</html>
"""