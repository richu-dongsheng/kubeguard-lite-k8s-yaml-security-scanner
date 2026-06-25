from pathlib import Path      #导入路径工具

import typer      #快速做命令行工具的库
from rich.console import Console #终端美化库，console用于在终端打印彩色文字和格式化内容
from rich.table import Table  #生成终端里整齐的表格

from scanner.parser import get_resource_identity,load_yaml_path
from scanner.pod_scanner import scan_pod_resources
from scanner.rbac_scanner import scan_rbac_resources

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
    
    resource_table = Table(title="kubeguard-Lite 资源识别结果")

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


    if not risks:
        console.print("[green]未发现 Pod / Deployment 配置风险。[/green]")
        return 

    risk_table = Table(title = "kubeguard-Lite 风险扫描结果")
    risk_table.add_column("序号",justify = "right")
    risk_table.add_column("类别")
    risk_table.add_column("等级")
    risk_table.add_column("规则")
    risk_table.add_column("资源")
    risk_table.add_column("主体/容器")
    risk_table.add_column("风险说明")
    risk_table.add_column("可自动修复")

    for index,risk in enumerate(risks,start = 1):
        actor = risk.get("subject") or risk.get("container") or "-"

        risk_table.add_row(
            str(index),
            risk.get("category", "Workload"),
            risk["level"],
            risk["rule_id"],
            risk["resource"],
            risk["container"],
            actor,
            risk["message"],
            "YES" if risk["auto_fixable"] else "NO",
        )

    console.print(risk_table)

    #三等风险数统计
    high_count = sum(1 for risk in risks if risk["level"] == "HIGH")
    medium_count = sum(1 for risk in risks if risk["level"] == 'MEDIUM')
    low_count = sum(1 for risk in risks if risk["level"] == "LOW")

    console.print(
    f"[bold]风险统计：[/bold]\n\n"
    f"[red] HIGH = {high_count}[/red]\n\n"
    f"[yellow] MEDIUM = {medium_count}[/yellow]\n\n"
    f"[blue] LOW = {low_count}[/blue]\n\n"
    f"[purple] TOTAL = {len(risks)}[/purple]\n\n"
)



if __name__=="__main__":
    cli()