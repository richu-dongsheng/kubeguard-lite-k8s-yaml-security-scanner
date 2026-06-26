from pathlib import Path      #导入路径工具

import typer      #快速做命令行工具的库
from rich.console import Console #终端美化库，console用于在终端打印彩色文字和格式化内容
from rich.table import Table  #生成终端里整齐的表格

from scanner.parser import get_resource_identity,load_yaml_path
from scanner.pod_scanner import scan_pod_resources
from scanner.rbac_scanner import scan_rbac_resources
from scanner.service_scanner import scan_service_resources
from scanner.scoring import build_scan_summary, sort_risks_by_priority

#创建typer实例，名为app，help为工具的全局说明
cli = typer.Typer(
    help="kubeguard-Lite: kubernetes YAML静态配置安全扫描工具",
    no_args_is_help = True,
                  )

#实例化控制台输出对象来统一管理彩色打印
console = Console() 

@cli.callback()
def main():
    """命令行入口"""
    pass

#装饰器：后接的函数是一条可以在终端里执行的子命令
@cli.command()
def scan(path: str):  #字符串参数作为路径
    """扫描指定目录下的kubernetes文件"""
    target = Path(path)

    try:
        resources = load_yaml_path(target)
    except Exception as exc:
        console.print(f"[red]扫描失败：{exc}[/red]")

        raise typer.Exit(code=1)
    
    resource_table = Table(title="kubeguard-Lite 资源识别结果",
                        show_lines=True,
                        )

    resource_table.add_column("序号",justify="right")
    resource_table.add_column("kind")
    resource_table.add_column("Name")            
    resource_table.add_column("Namespace")
    resource_table.add_column("source File")

    for index,resource in enumerate(resources,start=1):
        identity = get_resource_identity(resource)

        resource_table.add_row(
            str(index),
            identity["kind"],
            identity["name"],
            identity["namespace"],
            identity["source_file"],
        ) 

    console.print(resource_table)
    console.print(f"[green]发现 kubernetes 资源数：{len(resources)}[/green]")

    risks = []
    risks.extend(scan_pod_resources(resources))
    risks.extend(scan_rbac_resources(resources))
    risks.extend(scan_service_resources(resources))
    
    risks = sort_risks_by_priority(risks)
    summary = build_scan_summary(risks)

    if not risks:
        console.print("[green]未发现已配置规则覆盖的 Kubernetes YAML 风险。[/green]")
        return 

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
            str(risk["level"]),
            str(risk["rule_id"]),
            str(risk["resource"]),
            str(risk["message"]),
        )

    console.print(risk_table)

    auto_fixable_risks = [
        risk for risk in risks
        if risk.get("auto_fixable") is True
    ]

    console.print()
    console.print("[bold]自动修复能力：[/bold]")
    console.print(f"可自动修复风险数 = {len(auto_fixable_risks)}")

    if auto_fixable_risks:
        auto_fix_table = Table(
            title="可自动修复风险摘要",
            show_lines=True,
            
        )
    auto_fix_table.add_column("序号", justify="right", no_wrap=True)
    auto_fix_table.add_column("规则", no_wrap=True)
    auto_fix_table.add_column("资源")
    auto_fix_table.add_column("风险说明")

    for index, risk in enumerate(auto_fixable_risks[:10], start=1):
        auto_fix_table.add_row(
            str(index),
            str(risk.get("rule_id", "-")),
            str(risk.get("resource", "-")),
            str(risk.get("message", "-")),
        )

    console.print(auto_fix_table)

    if len(auto_fixable_risks) > 10:
        console.print(f"[yellow]仅展示前 10 条，可自动修复风险总数为 {len(auto_fixable_risks)}。[/yellow]")

    #三等风险数统计
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

    console.print()
    console.print("[bold]整体危险系数：[/bold]")
    console.print(f"Score = {summary['total_score']}")
    console.print(f"Grade = {summary['grade']} ({summary['grade_label']})")
    console.print(summary["grade_description"])

    console.print()
    console.print("[bold]修复建议：[/bold]")

    for recommendation in summary["recommendations"]:
        console.print(f"- {recommendation}")
    
    console.print()


if __name__=="__main__":
    cli()