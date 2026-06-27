from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any

from scanner.scan_engine import get_resources, get_risks, get_summary


ScanResult = dict[str, Any]
FixSummary = dict[str, Any]
FixAction = dict[str, Any]
ScanSummary = dict[str, Any]


# -----------------------------------------------------------------------------
# Common helpers
# -----------------------------------------------------------------------------


def value_to_text(value: Any) -> str:
    """把任意值转成报告展示文本。"""
    if value is None:
        return "-"

    if isinstance(value, bool):
        return "true" if value else "false"

    return str(value)


def md_escape(value: Any) -> str:
    """转义 Markdown 表格特殊字符。"""
    text = value_to_text(value)
    return text.replace("|", "\\|").replace("\n", "<br>")


def h(value: Any) -> str:
    """HTML 转义。"""
    return escape(value_to_text(value))


def render_markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    """渲染 Markdown 表格。"""
    lines: list[str] = []

    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

    for row in rows:
        lines.append("| " + " | ".join(md_escape(item) for item in row) + " |")

    return lines


def render_html_table(headers: list[str], rows: list[list[Any]]) -> str:
    """渲染 HTML 表格。"""
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


def get_level_count(summary: ScanSummary, level: str) -> int:
    """安全获取风险等级数量。"""
    level_counts = summary.get("level_counts", {})

    if not isinstance(level_counts, dict):
        return 0

    return int(level_counts.get(level, 0))


def get_summary_value(summary: ScanSummary, key: str, default: Any = "-") -> Any:
    """安全获取 summary 字段。"""
    return summary.get(key, default)


def calculate_delta(before: Any, after: Any) -> int:
    """计算修复前后差值。"""
    try:
        return int(after) - int(before)
    except (TypeError, ValueError):
        return 0


def format_delta(delta: int) -> str:
    """格式化差值。"""
    if delta > 0:
        return f"+{delta}"

    return str(delta)


# -----------------------------------------------------------------------------
# Row builders
# -----------------------------------------------------------------------------


def build_overview_rows(
    *,
    target_path: str,
    output_dir: str,
    fix_summary: FixSummary,
    original_scan_result: ScanResult,
    fixed_scan_result: ScanResult,
    generated_at: str,
) -> list[list[Any]]:
    """构建修复报告概览行。"""
    original_resources = get_resources(original_scan_result)
    fixed_resources = get_resources(fixed_scan_result)

    original_summary = get_summary(original_scan_result)
    fixed_summary = get_summary(fixed_scan_result)

    return [
        ["修复目标", target_path],
        ["输出目录", output_dir],
        ["生成时间", generated_at],
        ["修复模式", fix_summary.get("mode", "-")],
        ["修复前资源数", len(original_resources)],
        ["修复后资源数", len(fixed_resources)],
        ["已自动修复动作数", fix_summary.get("fixed_count", 0)],
        ["未自动修复风险数", fix_summary.get("skipped_count", 0)],
        ["写入文件数", fix_summary.get("written_file_count", 0)],
        ["修复前风险总数", original_summary.get("total_risks", 0)],
        ["修复后风险总数", fixed_summary.get("total_risks", 0)],
        ["修复前整体危险系数", original_summary.get("total_score", 0)],
        ["修复后整体危险系数", fixed_summary.get("total_score", 0)],
        ["修复前评级", f"{original_summary.get('grade', '-')} ({original_summary.get('grade_label', '-')})"],
        ["修复后评级", f"{fixed_summary.get('grade', '-')} ({fixed_summary.get('grade_label', '-')})"],
    ]


def build_level_comparison_rows(
    *,
    original_scan_result: ScanResult,
    fixed_scan_result: ScanResult,
) -> list[list[Any]]:
    """构建风险等级修复前后对比行。"""
    original_summary = get_summary(original_scan_result)
    fixed_summary = get_summary(fixed_scan_result)

    rows: list[list[Any]] = []

    for level in ["HIGH", "MEDIUM", "LOW"]:
        before = get_level_count(original_summary, level)
        after = get_level_count(fixed_summary, level)
        delta = calculate_delta(before, after)

        rows.append([
            level,
            before,
            after,
            format_delta(delta),
        ])

    before_total = int(original_summary.get("total_risks", 0))
    after_total = int(fixed_summary.get("total_risks", 0))

    rows.append([
        "TOTAL",
        before_total,
        after_total,
        format_delta(calculate_delta(before_total, after_total)),
    ])

    return rows


def build_score_comparison_rows(
    *,
    original_scan_result: ScanResult,
    fixed_scan_result: ScanResult,
) -> list[list[Any]]:
    """构建整体评分修复前后对比行。"""
    original_summary = get_summary(original_scan_result)
    fixed_summary = get_summary(fixed_scan_result)

    before_score = int(original_summary.get("total_score", 0))
    after_score = int(fixed_summary.get("total_score", 0))

    return [
        [
            "整体危险系数",
            before_score,
            after_score,
            format_delta(calculate_delta(before_score, after_score)),
        ],
        [
            "整体评级",
            original_summary.get("grade", "-"),
            fixed_summary.get("grade", "-"),
            "-",
        ],
        [
            "评级说明",
            original_summary.get("grade_description", "-"),
            fixed_summary.get("grade_description", "-"),
            "-",
        ],
    ]


def build_fix_action_rows(actions: list[FixAction]) -> list[list[Any]]:
    """构建已修复动作表格行。"""
    rows: list[list[Any]] = []

    for index, action in enumerate(actions, start=1):
        rows.append([
            index,
            action.get("rule_id", "-"),
            action.get("resource", "-"),
            action.get("source_file", "-"),
            action.get("path", "-"),
            action.get("old_value", "-"),
            action.get("new_value", "-"),
            action.get("message", "-"),
        ])

    return rows


def build_skipped_action_rows(actions: list[FixAction]) -> list[list[Any]]:
    """构建未自动修复风险表格行。"""
    rows: list[list[Any]] = []

    for index, action in enumerate(actions, start=1):
        rows.append([
            index,
            action.get("rule_id", "-"),
            action.get("resource", "-"),
            action.get("source_file", "-"),
            action.get("path", "-"),
            action.get("message", "-"),
        ])

    return rows


def build_written_file_rows(written_files: list[Any]) -> list[list[Any]]:
    """构建输出文件清单行。"""
    rows: list[list[Any]] = []

    for index, file_path in enumerate(written_files, start=1):
        rows.append([index, file_path])

    return rows


def build_residual_risk_rows(fixed_scan_result: ScanResult, limit: int = 10) -> list[list[Any]]:
    """构建修复后残余风险行。"""
    risks = get_risks(fixed_scan_result)

    rows: list[list[Any]] = []

    for index, risk in enumerate(risks[:limit], start=1):
        rows.append([
            index,
            risk.get("risk_score", "-"),
            risk.get("level", "-"),
            risk.get("category", "-"),
            risk.get("rule_id", "-"),
            risk.get("resource", "-"),
            risk.get("message", "-"),
        ])

    return rows


def build_fix_recommendations(
    *,
    fix_summary: FixSummary,
    fixed_scan_result: ScanResult,
    output_dir: str,
) -> list[str]:
    """生成修复后建议。"""
    fixed_summary = get_summary(fixed_scan_result)
    fixed_high = get_level_count(fixed_summary, "HIGH")
    fixed_total = int(fixed_summary.get("total_risks", 0))

    recommendations: list[str] = []

    recommendations.append(f"请人工 review 输出目录 `{output_dir}` 中的修复后 YAML，确认不会影响业务行为。")
    recommendations.append("建议使用 Git diff 或其他对比工具检查字段变更，尤其是 PodSpec 与 container.securityContext。")

    if fixed_high > 0:
        recommendations.append("修复后仍存在 HIGH 风险，建议不要直接部署，应优先人工处理残余高危项。")
    else:
        recommendations.append("修复后 HIGH 风险已清零，可以继续处理 MEDIUM / LOW 风险并进行业务验证。")

    if fixed_total > 0:
        recommendations.append("镜像版本、资源限制、RBAC、Service、Ingress 等风险通常需要结合业务场景人工修复。")

    if fix_summary.get("mode") == "safe":
        recommendations.append("当前使用 safe 模式，未自动修改可能影响业务行为的 strict 项。需要更强加固时可使用 strict 模式重新生成修复结果。")

    recommendations.append("部署修复后的 YAML 前，建议先在测试环境执行 dry-run 或临时命名空间验证。")

    return recommendations


# -----------------------------------------------------------------------------
# Markdown report
# -----------------------------------------------------------------------------


def generate_fix_markdown_report(
    *,
    fix_summary: FixSummary,
    original_scan_result: ScanResult,
    fixed_scan_result: ScanResult,
    target_path: str = "-",
    output_dir: str = "-",
) -> str:
    """生成 Markdown 自动修复报告。"""
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    fixed_actions = fix_summary.get("fixed_actions", [])
    skipped_actions = fix_summary.get("skipped_actions", [])
    written_files = fix_summary.get("written_files", [])

    if not isinstance(fixed_actions, list):
        fixed_actions = []

    if not isinstance(skipped_actions, list):
        skipped_actions = []

    if not isinstance(written_files, list):
        written_files = []

    recommendations = build_fix_recommendations(
        fix_summary=fix_summary,
        fixed_scan_result=fixed_scan_result,
        output_dir=output_dir,
    )

    lines: list[str] = []

    lines.append("# kubeguard-Lite YAML 自动修复报告")
    lines.append("")
    lines.append("## 1. 修复概览")
    lines.append("")
    lines.extend(render_markdown_table(
        ["项目", "结果"],
        build_overview_rows(
            target_path=target_path,
            output_dir=output_dir,
            fix_summary=fix_summary,
            original_scan_result=original_scan_result,
            fixed_scan_result=fixed_scan_result,
            generated_at=generated_at,
        ),
    ))

    lines.append("")
    lines.append("## 2. 修复前后风险等级对比")
    lines.append("")
    lines.extend(render_markdown_table(
        ["等级", "修复前", "修复后", "变化"],
        build_level_comparison_rows(
            original_scan_result=original_scan_result,
            fixed_scan_result=fixed_scan_result,
        ),
    ))

    lines.append("")
    lines.append("## 3. 修复前后整体评分对比")
    lines.append("")
    lines.extend(render_markdown_table(
        ["项目", "修复前", "修复后", "变化"],
        build_score_comparison_rows(
            original_scan_result=original_scan_result,
            fixed_scan_result=fixed_scan_result,
        ),
    ))

    lines.append("")
    lines.append("## 4. 已自动修复动作清单")
    lines.append("")

    if fixed_actions:
        lines.extend(render_markdown_table(
            ["序号", "规则", "资源", "来源文件", "路径", "旧值", "新值", "说明"],
            build_fix_action_rows(fixed_actions),
        ))
    else:
        lines.append("本次没有执行自动修复动作。")

    lines.append("")
    lines.append("## 5. 未自动修复风险清单")
    lines.append("")

    if skipped_actions:
        lines.extend(render_markdown_table(
            ["序号", "规则", "资源", "来源文件", "路径", "跳过原因"],
            build_skipped_action_rows(skipped_actions),
        ))
    else:
        lines.append("本次没有未自动修复风险。")

    lines.append("")
    lines.append("## 6. 输出文件清单")
    lines.append("")

    if written_files:
        lines.extend(render_markdown_table(
            ["序号", "文件路径"],
            build_written_file_rows(written_files),
        ))
    else:
        lines.append("本次没有写入修复后的 YAML 文件。")

    lines.append("")
    lines.append("## 7. 修复后残余风险 Top 10")
    lines.append("")

    residual_rows = build_residual_risk_rows(fixed_scan_result, limit=10)

    if residual_rows:
        lines.extend(render_markdown_table(
            ["序号", "危险系数", "等级", "类别", "规则", "资源", "风险说明"],
            residual_rows,
        ))
    else:
        lines.append("修复后未发现已配置规则覆盖的残余风险。")

    lines.append("")
    lines.append("## 8. 后续建议")
    lines.append("")

    for recommendation in recommendations:
        lines.append(f"- {recommendation}")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Generated by kubeguard-Lite.")

    return "\n".join(lines)


# -----------------------------------------------------------------------------
# HTML report
# -----------------------------------------------------------------------------


def generate_fix_html_report(
    *,
    fix_summary: FixSummary,
    original_scan_result: ScanResult,
    fixed_scan_result: ScanResult,
    target_path: str = "-",
    output_dir: str = "-",
) -> str:
    """生成 HTML 自动修复报告。"""
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    original_summary = get_summary(original_scan_result)
    fixed_summary = get_summary(fixed_scan_result)

    fixed_actions = fix_summary.get("fixed_actions", [])
    skipped_actions = fix_summary.get("skipped_actions", [])
    written_files = fix_summary.get("written_files", [])

    if not isinstance(fixed_actions, list):
        fixed_actions = []

    if not isinstance(skipped_actions, list):
        skipped_actions = []

    if not isinstance(written_files, list):
        written_files = []

    recommendations = build_fix_recommendations(
        fix_summary=fix_summary,
        fixed_scan_result=fixed_scan_result,
        output_dir=output_dir,
    )

    overview_table = render_html_table(
        ["项目", "结果"],
        build_overview_rows(
            target_path=target_path,
            output_dir=output_dir,
            fix_summary=fix_summary,
            original_scan_result=original_scan_result,
            fixed_scan_result=fixed_scan_result,
            generated_at=generated_at,
        ),
    )

    level_table = render_html_table(
        ["等级", "修复前", "修复后", "变化"],
        build_level_comparison_rows(
            original_scan_result=original_scan_result,
            fixed_scan_result=fixed_scan_result,
        ),
    )

    score_table = render_html_table(
        ["项目", "修复前", "修复后", "变化"],
        build_score_comparison_rows(
            original_scan_result=original_scan_result,
            fixed_scan_result=fixed_scan_result,
        ),
    )

    fixed_action_table = (
        render_html_table(
            ["序号", "规则", "资源", "来源文件", "路径", "旧值", "新值", "说明"],
            build_fix_action_rows(fixed_actions),
        )
        if fixed_actions
        else "<p>本次没有执行自动修复动作。</p>"
    )

    skipped_action_table = (
        render_html_table(
            ["序号", "规则", "资源", "来源文件", "路径", "跳过原因"],
            build_skipped_action_rows(skipped_actions),
        )
        if skipped_actions
        else "<p>本次没有未自动修复风险。</p>"
    )

    written_file_table = (
        render_html_table(
            ["序号", "文件路径"],
            build_written_file_rows(written_files),
        )
        if written_files
        else "<p>本次没有写入修复后的 YAML 文件。</p>"
    )

    residual_rows = build_residual_risk_rows(fixed_scan_result, limit=10)

    residual_table = (
        render_html_table(
            ["序号", "危险系数", "等级", "类别", "规则", "资源", "风险说明"],
            residual_rows,
        )
        if residual_rows
        else "<p>修复后未发现已配置规则覆盖的残余风险。</p>"
    )

    recommendation_items = "\n".join(
        f"<li>{h(recommendation)}</li>"
        for recommendation in recommendations
    )

    before_score = original_summary.get("total_score", 0)
    after_score = fixed_summary.get("total_score", 0)
    before_total = original_summary.get("total_risks", 0)
    after_total = fixed_summary.get("total_risks", 0)

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>kubeguard-Lite 自动修复报告</title>
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
      border-left: 5px solid #16a34a;
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

    .metric-grid {{
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

    .metric span {{
      color: #6b7280;
      font-size: 13px;
    }}

    .metric strong {{
      display: block;
      font-size: 24px;
      margin-top: 4px;
    }}

    .good {{
      color: #16a34a;
    }}

    .warn {{
      color: #d97706;
    }}

    .bad {{
      color: #dc2626;
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
  <h1>kubeguard-Lite YAML 自动修复报告</h1>
  <p>Generated at {h(generated_at)}</p>
</header>

<main>
  <section>
    <h2>1. 修复概览</h2>

    <div class="metric-grid">
      <div class="metric">
        <span>修复模式</span>
        <strong>{h(fix_summary.get("mode", "-"))}</strong>
      </div>
      <div class="metric">
        <span>已自动修复动作数</span>
        <strong class="good">{h(fix_summary.get("fixed_count", 0))}</strong>
      </div>
      <div class="metric">
        <span>修复前风险总数</span>
        <strong>{h(before_total)}</strong>
      </div>
      <div class="metric">
        <span>修复后风险总数</span>
        <strong>{h(after_total)}</strong>
      </div>
      <div class="metric">
        <span>修复前危险系数</span>
        <strong>{h(before_score)}</strong>
      </div>
      <div class="metric">
        <span>修复后危险系数</span>
        <strong class="good">{h(after_score)}</strong>
      </div>
    </div>

    {overview_table}
  </section>

  <section>
    <h2>2. 修复前后风险等级对比</h2>
    {level_table}
  </section>

  <section>
    <h2>3. 修复前后整体评分对比</h2>
    {score_table}
  </section>

  <section>
    <h2>4. 已自动修复动作清单</h2>
    {fixed_action_table}
  </section>

  <section>
    <h2>5. 未自动修复风险清单</h2>
    {skipped_action_table}
  </section>

  <section>
    <h2>6. 输出文件清单</h2>
    {written_file_table}
  </section>

  <section>
    <h2>7. 修复后残余风险 Top 10</h2>
    {residual_table}
  </section>

  <section>
    <h2>8. 后续建议</h2>
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