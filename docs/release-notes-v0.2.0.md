## KubeGuard-Lite v0.2.0 — 源码/API 集成版

KubeGuard-Lite v0.2.0 将项目升级为可供其他平台调用的 Kubernetes YAML 静态扫描引擎，并保留现有人工 CLI 与报告能力。本发行面向源码运行和机器集成；不包含新的 v0.2.0 桌面二进制资产。

### 主要变化

- 修复 `hostPath` 识别、Workload 风险定位、ServiceAccount Rule ID，以及 Pod/容器 `SecurityContext` 字段作用域和继承处理。
- Workload 现有容器级规则同时扫描 `containers` 和 `initContainers`，Finding 保留容器类型、索引与配置路径。
- 增加分级高风险 Linux Capabilities 检查、`drop: [ALL]` 加固缺口检查和显式 seccomp `Unconfined` 检测。
- Fixer 在 Safe/Strict 模式下遵守 `auto_fixable: false`，避免将不可修复 Finding 当作可执行修复。
- 提供 JSON Contract v1：`schema_version` 为 `1.0`，`scanner_version` 为 `0.2.0`。使用 `python cli.py scan-json <target>` 获取 JSON。
- 明确 `COMPLETED`、`PARTIAL` 和 `FAILED` 的扫描覆盖语义；未支持 Kind、Windows Workload 和范围外资源会带有明确的跳过原因。
- 补充真实扫描回归测试和最小扫描依赖锁 `requirements-scan.txt`。

### 运行

```bash
python -m venv .venv
python -m pip install -r requirements-scan.txt
python cli.py scan-json examples/insecure
```

扫描发现风险时，命令仍以退出码 `0` 表示请求已处理。调用方必须检查 JSON `status`；`PARTIAL` 即使没有 Finding 也不代表安全，只有 `FAILED` 使用非零退出码。

### 已知限制

本版本不是完整 Kubernetes Schema 或 Pod Security Standards（PSS）合规工具，不执行镜像漏洞扫描、集群有效权限分析或运行时验证。安全检查主要面向 Linux，Workload 覆盖范围为 Pod/Deployment。自动修复仅适用于明确支持的规则，`auto_fixable` 元数据本身不是授权。

完整规则和字段语义见 `docs/rule-description.md` 与 `docs/json-contract-v1.md`。
