from pathlib import Path
from typing import Any
import json

import typer
from rich.console import Console
from rich.table import Table

from scanner.parser import get_resource_identity
from scanner.scan_engine import scan_path, get_resources, get_risks, get_summary
from scanner.json_contract import scan_path_contract

from reporter.markdown_report import generate_markdown_report
from reporter.html_report import generate_html_report

from fixer.yaml_fixer import fix_path
from fixer.fix_report import generate_fix_markdown_report, generate_fix_html_report

YamlResource = dict[str, Any]
Risk = dict[str, Any]
ScanSummary = dict[str, Any]


cli = typer.Typer(
    help="kubeguard-Lite: Kubernetes YAML 静态配置安全扫描工具",
    no_args_is_help=True,
)

console = Console()


@cli.callback()
def main():
    """kubeguard-Lite 命令行入口。"""
    pass


def render_resource_table(resources: list[YamlResource]) -> None:
    """渲染 Kubernetes 资源识别结果表。"""
    resource_table = Table(
        title="kubeguard-Lite 资源识别结果",
        show_lines=True,
    )

    resource_table.add_column("序号", justify="right", no_wrap=True)
    resource_table.add_column("Kind", no_wrap=True)
    resource_table.add_column("Name")
    resource_table.add_column("Namespace", no_wrap=True)
    resource_table.add_column("Source File")

    for index, resource in enumerate(resources, start=1):
        identity = get_resource_identity(resource)

        resource_table.add_row(
            str(index),
            identity["kind"],
            identity["name"],
            identity["namespace"],
            identity["source_file"],
        )

    console.print(resource_table)
    console.print(f"[green]发现 Kubernetes 资源数：{len(resources)}[/green]")


def render_risk_table(risks: list[Risk]) -> None:
    """渲染风险扫描结果简表。"""
    risk_table = Table(
        title="kubeguard-Lite 风险扫描结果",
        show_lines=True,
    )

    risk_table.add_column("序号", justify="right", no_wrap=True)
    risk_table.add_column("危险系数", justify="right", no_wrap=True)
    risk_table.add_column("类别", no_wrap=True)
    risk_table.add_column("等级", no_wrap=True)
    risk_table.add_column("规则", no_wrap=True)
    risk_table.add_column("资源")
    risk_table.add_column("风险说明")

    for index, risk in enumerate(risks, start=1):
        risk_table.add_row(
            str(index),
            str(risk.get("risk_score", "-")),
            str(risk.get("category", "Workload")),
            str(risk.get("level", "-")),
            str(risk.get("rule_id", "-")),
            str(risk.get("resource", "-")),
            str(risk.get("message", "-")),
        )

    console.print(risk_table)


def render_level_and_category_summary(summary: ScanSummary) -> None:
    """渲染风险等级统计和类别统计。"""
    level_counts = summary["level_counts"]
    category_counts = summary["category_counts"]

    console.print("[bold]风险统计：[/bold]")
    console.print(f"[red]HIGH = {level_counts['HIGH']}[/red]")
    console.print(f"[yellow]MEDIUM = {level_counts['MEDIUM']}[/yellow]")
    console.print(f"[blue]LOW = {level_counts['LOW']}[/blue]")
    console.print(f"[magenta]TOTAL = {summary['total_risks']}[/magenta]")

    console.print()
    console.print("[bold]类别统计：[/bold]")

    for category, count in category_counts.items():
        console.print(f"{category} = {count}")


def render_score_summary(summary: ScanSummary) -> None:
    """渲染整体危险系数和风险评级。"""
    console.print()
    console.print("[bold]整体危险系数：[/bold]")
    console.print(f"Score = {summary['total_score']}")
    console.print(f"Grade = {summary['grade']} ({summary['grade_label']})")
    console.print(summary["grade_description"])


def render_auto_fix_summary(risks: list[Risk], limit: int = 10) -> None:
    """渲染可自动修复风险摘要。"""
    auto_fixable_risks = [
        risk for risk in risks
        if risk.get("auto_fixable") is True
    ]

    console.print()
    console.print("[bold]自动修复能力：[/bold]")
    console.print(f"可自动修复风险数 = {len(auto_fixable_risks)}")

    if not auto_fixable_risks:
        console.print("[yellow]当前没有可自动修复的风险。[/yellow]")
        return

    auto_fix_table = Table(
        title="可自动修复风险摘要",
        show_lines=True,
    )

    auto_fix_table.add_column("序号", justify="right", no_wrap=True)
    auto_fix_table.add_column("规则", no_wrap=True)
    auto_fix_table.add_column("资源")
    auto_fix_table.add_column("风险说明")

    for index, risk in enumerate(auto_fixable_risks[:limit], start=1):
        auto_fix_table.add_row(
            str(index),
            str(risk.get("rule_id", "-")),
            str(risk.get("resource", "-")),
            str(risk.get("message", "-")),
        )

    console.print(auto_fix_table)

    if len(auto_fixable_risks) > limit:
        console.print(
            f"[yellow]仅展示前 {limit} 条，可自动修复风险总数为 {len(auto_fixable_risks)}。[/yellow]"
        )


def render_recommendations(summary: ScanSummary) -> None:
    """渲染总体修复建议。"""
    console.print()
    console.print("[bold]修复建议：[/bold]")

    for recommendation in summary["recommendations"]:
        console.print(f"- {recommendation}")

    console.print()

def render_fix_actions_table(actions: list[dict[str, object]], title: str, limit: int = 20) -> None:
    """渲染修复动作表。"""
    if not actions:
        console.print(f"[yellow]{title}：无[/yellow]")
        return

    table = Table(
        title=title,
        show_lines=True,
    )

    table.add_column("序号", justify="right", no_wrap=True)
    table.add_column("状态", no_wrap=True)
    table.add_column("规则", no_wrap=True)
    table.add_column("资源")
    table.add_column("路径")
    table.add_column("旧值")
    table.add_column("新值")
    table.add_column("说明")

    for index, action in enumerate(actions[:limit], start=1):
        table.add_row(
            str(index),
            str(action.get("status", "-")),
            str(action.get("rule_id", "-")),
            str(action.get("resource", "-")),
            str(action.get("path", "-")),
            str(action.get("old_value", "-")),
            str(action.get("new_value", "-")),
            str(action.get("message", "-")),
        )

    console.print(table)

    if len(actions) > limit:
        console.print(
            f"[yellow]仅展示前 {limit} 条，实际共有 {len(actions)} 条。[/yellow]"
        )


def render_fix_summary(fix_summary: dict[str, object]) -> None:
    """渲染自动修复汇总结果。"""
    fixed_actions = fix_summary.get("fixed_actions", [])
    skipped_actions = fix_summary.get("skipped_actions", [])
    written_files = fix_summary.get("written_files", [])

    if not isinstance(fixed_actions, list):
        fixed_actions = []

    if not isinstance(skipped_actions, list):
        skipped_actions = []

    if not isinstance(written_files, list):
        written_files = []

    console.print()
    console.print("[bold]自动修复汇总：[/bold]")
    console.print(f"修复模式 = {fix_summary.get('mode', '-')}")
    console.print(f"[green]已修复动作数 = {fix_summary.get('fixed_count', 0)}[/green]")
    console.print(f"[yellow]跳过风险数 = {fix_summary.get('skipped_count', 0)}[/yellow]")
    console.print(f"写入文件数 = {fix_summary.get('written_file_count', 0)}")

    console.print()
    console.print("[bold]输出文件：[/bold]")

    if written_files:
        for file_path in written_files:
            console.print(f"- {file_path}")
    else:
        console.print("[yellow]没有生成修复后的 YAML 文件。[/yellow]")

    console.print()
    render_fix_actions_table(
        fixed_actions,
        title="已自动修复动作",
        limit=20,
    )

    console.print()
    render_fix_actions_table(
        skipped_actions,
        title="未自动修复风险摘要",
        limit=20,
    )




@cli.command()
def scan(path: str):
    """扫描指定目录或 YAML 文件中的 Kubernetes 配置风险。"""
    target = Path(path)

    try:
        scan_result = scan_path(target)
    except Exception as exc:
        console.print(f"[red]扫描失败：{exc}[/red]")
        raise typer.Exit(code=1)

    resources = get_resources(scan_result)
    risks = get_risks(scan_result)
    summary = get_summary(scan_result)

    render_resource_table(resources)

    if not risks:
        console.print("[green]未发现已配置规则覆盖的 Kubernetes YAML 风险。[/green]")
        return

    render_risk_table(risks)
    render_level_and_category_summary(summary)
    render_score_summary(summary)
    render_auto_fix_summary(risks)
    render_recommendations(summary)


@cli.command("scan-json")
def scan_json(path: str):
    """以 JSON Contract v1 扫描 YAML；不执行修复或写入输入文件。"""
    contract = scan_path_contract(path)
    # 使用 ASCII 转义，避免 Windows 控制台编码影响 Go Adapter 读取 JSON。
    typer.echo(json.dumps(contract, ensure_ascii=True, sort_keys=True, separators=(",", ":")))

    for diagnostic in contract["diagnostics"]:
        typer.echo(
            f"{diagnostic['code']}: {diagnostic['message']}",
            err=True,
        )

    if contract["status"] == "FAILED":
        raise typer.Exit(code=1)



"""生成 kubernetes YANL 安全扫描报告"""
@cli.command()
def report(
    path: str,          #路径参数
    report_format: str = typer.Option(
        "md",
        "--format",
        "-f",
        help = "报告格式: md 或 html",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help = "报告输出路径，例如 reports/report.md"
    ),
):
    target = Path(path)

    try:
        scan_result = scan_path(target)
    except Exception as exc:
        console.print(f"[red]报告生成失败：{exc}[/red]")
        raise typer.Exit(code=1)
    
    resources = get_resources(scan_result)
    risks = get_risks(scan_result)
    summary = get_summary(scan_result)

    normalized_format = report_format.lower().strip()

    if normalized_format not in {"md","html"}:
        console.print("[red]报告格式错误：只支持 md 或 html.[/red]")
        raise typer.Exit(code=1)
    
    if output is None:  #默认路径
        output_path = Path("reports") / f"kubeguard-report.{normalized_format}"
    else:               #自选路径
        output_path = Path(output)

    #自动递归创建输出文件所在全部目录，目录存在也不会报错，parents=True为递归创建各级目录，exist_ok为即使目录存在也不报错
    output_path.parent.mkdir(parents=True,exist_ok=True)

    if normalized_format == "md":
        content = generate_markdown_report(
            resources = resources,
            risks = risks,
            summary = summary,
            target_path = str(target)
        )
    else:
        content = generate_html_report(
            resources=resources,
            risks=risks,
            summary=summary,
            target_path=str(target)
        )

    output_path.write_text(content,encoding="utf-8")

    console.print(f"[green]报告生成成功：{output_path}[/green]")
    console.print(f"[green]风险总数：{summary.get('total_risks',0)}[/green]")
    console.print(f"[green]整体评级：{summary.get('grade','-')}({summary.get('grade_label','-')})[/green]")


@cli.command()
def fix(
    path: str,
    output: str = typer.Option(
        "fixed",
        "--output",
        "-o",
        help="修复后 YAML 的输出目录，默认 fixed",
    ),
    mode: str = typer.Option(
        "safe",
        "--mode",
        "-m",
        help="修复模式：safe 或 strict",
    ),
    fix_report_format: str = typer.Option(
        "md",
        "--fix-report-format",
        help="自动修复报告格式：md 或 html",
    ),
    fix_report_output: str | None = typer.Option(
        None,
        "--fix-report",
        help="自动修复报告输出路径，例如 reports/fix-report.md",
    ),
):
    """自动修复 Kubernetes YAML 中的部分安全风险。"""
    target = Path(path)

    try:
        result = fix_path(
            target_path=target,
            output_dir=output,
            mode=mode,
        )
    except Exception as exc:
        console.print(f"[red]自动修复失败：{exc}[/red]")
        raise typer.Exit(code=1)

    fix_summary = result["fix_summary"]

    console.print("[green]自动修复流程完成。[/green]")
    render_fix_summary(fix_summary)

    original_scan_result = result["scan_result"]
    fixed_scan_result = result["fixed_scan_result"]

    normalized_report_format = fix_report_format.lower().strip()

    if normalized_report_format not in {"md", "html"}:
        console.print("[red]自动修复报告格式错误：只支持 md 或 html。[/red]")
        raise typer.Exit(code=1)

    if fix_report_output is None:
        report_output_path = Path("reports") / f"fix-report.{normalized_report_format}"
    else:
        report_output_path = Path(fix_report_output)

    report_output_path.parent.mkdir(parents=True, exist_ok=True)

    if normalized_report_format == "md":
        report_content = generate_fix_markdown_report(
            fix_summary=fix_summary,
            original_scan_result=original_scan_result,
            fixed_scan_result=fixed_scan_result,
            target_path=str(target),
            output_dir=str(output),
        )
    else:
        report_content = generate_fix_html_report(
            fix_summary=fix_summary,
            original_scan_result=original_scan_result,
            fixed_scan_result=fixed_scan_result,
            target_path=str(target),
            output_dir=str(output),
        )

    report_output_path.write_text(report_content, encoding="utf-8")

    console.print()
    console.print(f"[green]自动修复报告已生成：{report_output_path}[/green]")

    console.print()
    console.print("[bold]后续建议：[/bold]")
    console.print(f"- 请人工检查输出目录：{output}")
    console.print(f"- 建议重新扫描修复结果：python cli.py scan {output}")
    console.print("- 对 RBAC、Service、Ingress、镜像版本等风险，请结合业务场景人工处理。")

if __name__ == "__main__":
    cli()
