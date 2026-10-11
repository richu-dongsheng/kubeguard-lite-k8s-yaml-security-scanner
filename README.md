# KubeGuard-Lite

**语言 / Language：** **简体中文** | [English](README_EN.md)

**KubeGuard-Lite** 是 Kubernetes YAML 静态配置安全扫描器，也提供可由其他程序调用的 Python 扫描引擎。它在部署前分析清单中的常见安全配置和暴露面风险，并保留规则、资源位置与覆盖状态供开发者或集成平台审查。

项目定位为静态扫描组件，不是完整云安全平台、准入控制器或 Kubernetes 策略合规认证工具。

## Core Features / 核心功能

- **Workload 配置检查**：当前支持 Pod 和 Deployment，扫描普通容器与 `initContainers`。检查 privileged、host namespace、hostPath、SecurityContext、ServiceAccount Token、镜像引用、资源限制等配置。
- **容器安全配置**：检查 privilege escalation、runAsUser/runAsNonRoot、只读根文件系统、seccomp、Linux Capabilities；区分显式危险配置与加固缺口。
- **RBAC 静态风险**：检查角色绑定、宽泛权限、敏感资源读取和高风险动词等。
- **Service / Ingress 配置**：检查外部暴露方式、敏感端口、TLS、Host 和高风险注解等。
- **CLI 与报告**：提供人类可读 CLI、Markdown/HTML 扫描报告，以及 Safe/Strict 两种现有自动修复模式。
- **机器接口**：提供稳定版本化的 JSON Contract v1，包含结构化 Finding、资源覆盖状态和诊断。

规则清单与实际边界见 [规则说明](docs/rule-description.md) 和 [JSON Contract v1](docs/json-contract-v1.md)。当前工作负载范围主要是 Pod/Deployment；其他资源的处理会在 JSON 接口中标为跳过或范围外。

## Quick Start / 快速上手

机器扫描依赖已在 **Python 3.13.11、Windows x64** 环境验证。使用独立虚拟环境安装最小扫描依赖；无需 Streamlit、PySide6、Kubernetes 集群或管理员权限。

Windows PowerShell：

```powershell
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-scan.txt
.venv\Scripts\python.exe cli.py scan examples/insecure
```

Linux / macOS：

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements-scan.txt
.venv/bin/python cli.py scan examples/insecure
```

依赖锁在 Python 3.13.11 Windows x64 验证；Linux/macOS 也可尝试使用该清单，但本项目未在这些平台验证锁文件。完整 Web/Desktop 开发依赖见 `requirements.txt`。

生成 Markdown 或 HTML 报告：

```bash
python cli.py report examples/insecure --format md --output reports/scan-report.md
python cli.py report examples/insecure --format html --output reports/scan-report.html
```

现有 `fix` 命令会将修复后的 YAML 写入指定输出目录，并默认生成 `reports/fix-report.md`；扫描本身不会自动触发修复。请审阅输出 YAML 和修复报告：

```bash
python cli.py fix examples/insecure --mode safe --output fixed
```

## JSON API / 机器接口

程序集成使用：

```bash
python cli.py scan-json examples/insecure
```

该命令只读扫描输入，stdout 输出 JSON，stderr 可输出诊断摘要；不会连接集群或调用 Fixer。协议字段和状态定义见 [docs/json-contract-v1.md](docs/json-contract-v1.md)。

真实示例扫描返回的 JSON 选定字段如下（不代表完整响应对象）：

```json
{
  "schema_version": "1.0",
  "scanner_version": "0.2.0",
  "status": "COMPLETED",
  "resource_counts": {"total": 12, "scanned": 11, "skipped": 1},
  "finding_counts": {"HIGH": 16, "MEDIUM": 13, "LOW": 12, "UNKNOWN": 0, "total": 41}
}
```

其中一条实际 Finding 的字段片段：

```json
{
  "rule_id": "KGL-RBAC-004",
  "severity": "HIGH",
  "resource": {"kind": "ClusterRole", "namespace": null, "name": "secret-reader"},
  "path": "ClusterRoleBinding/bind-secret-reader -> ClusterRole/secret-reader.rules[0].resources",
  "auto_fixable": false
}
```

`schema_version` 为 `1.0`，扫描器软件版本 `scanner_version` 为 `0.2.0`。`COMPLETED` 表示本次声明范围内可适用目标已分析；发现风险仍是成功处理请求，退出码为 `0`。`PARTIAL` 表示存在已分析目标，也有未覆盖的适用资源；即使 Findings 为空，也不能据此解释为安全。`FAILED` 表示无有效分析结果或扫描失败，退出码为 `1`。`skipped_resources` 区分 `UNSUPPORTED_KIND`、Windows Linux 规则不适用和 `OUT_OF_SCOPE` 等原因。

## Integration / 平台集成

Go、Python 或其他语言的安全平台可以将 `scan-json` 作为外部静态分析组件，解析 stdout JSON、检查退出码并根据 `status` 决定后续流程。KubeGuard Fusion 计划复用该扫描引擎；其 Go Adapter 尚未在本仓库或本版本中交付。

`auto_fixable` 是扫描器给出的修复能力元数据，不构成调用方执行修改的授权。集成方必须使用自身的权限策略和审批流程决定是否执行后续操作。

## Limitations / 已知限制

- 规则是针对已列字段和值的静态启发式检查，不代表完整 Kubernetes Schema 校验或完整 Pod Security Standards（PSS）合规。
- 不执行镜像漏洞扫描、集群有效权限分析、Admission 决策或运行时行为验证。
- Linux 是主要安全检查目标。JSON 接口会跳过显式声明为 Windows 的 Pod/Deployment 并反映为覆盖状态；旧人类可读 `scan` 命令不提供完整 Windows 适用性过滤。不要把这些结果解释为 Windows 安全基线。
- 本轮覆盖的 Workload Kind 是 Pod 和 Deployment。其他适用但未支持的 Kind 会被标记未覆盖；范围外资源与未支持资源不是同一种状态。
- 自动修复只覆盖有限规则，不能替代独立授权、代码审查、业务验证和对最终 YAML 的复查。

## Releases / 版本说明

- **v0.2.0 — 源码/API 集成发行版(已发布)**：扫描器版本为 `0.2.0`，JSON Contract 仍为 `1.0`。本次发行内容面向源码运行和机器集成；本仓库没有为 v0.2.0 发布新的桌面二进制文件。
- **v0.1.0 — 历史桌面版**：此前发布的桌面工具、人工 CLI、安全扫描与报告版本。Windows x86_64 旧资产名为 `kubeguard-lite-desktop-windows-x86_64.exe`，Linux x86_64 旧资产名为 `kubeguard-lite-desktop-linux-x86_64.AppImage`。请从 [v0.1.0 Release 页面](https://github.com/richu-dongsheng/kubeguard-lite-k8s-yaml-security-scanner/releases/tag/v0.1.0) 下载历史资产，不要将这些二进制文件当作 v0.2.0。

查看[所有 GitHub Releases](https://github.com/richu-dongsheng/kubeguard-lite-k8s-yaml-security-scanner/releases)及 [CHANGELOG](CHANGELOG.md)。

## License

本项目使用 MIT License，详见 [LICENSE](LICENSE)。
