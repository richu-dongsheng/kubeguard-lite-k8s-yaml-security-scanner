from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from scanner.parser import get_resource_identity
from scanner.scan_engine import scan_path, get_resources, get_risks, get_summary


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


if __name__ == "__main__":
    cli()