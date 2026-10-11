# KubeGuard-Lite JSON Contract v1

机器入口使用 `python cli.py scan-json <YAML 文件或目录>`。该入口只扫描并把结果写到 stdout；诊断摘要写到 stderr。stderr 文本用于终端显示，编码可能遵循 Windows 当前控制台代码页；机器调用方应从 stdout JSON 的 `diagnostics` 读取结构化诊断。它不会调用 Fixer、修改输入文件或连接 Kubernetes。风险发现本身仍以退出码 `0` 表示扫描请求已处理；只有 `FAILED` 返回非零退出码。`PARTIAL` 返回 `0`，调用方必须检查 JSON 中的 `status`。

旧入口 `python cli.py scan <YAML 文件或目录>` 保持原有人类可读输出和退出码行为。

## 顶层对象

所有字段均为必填，字段顺序不构成协议语义。JSON 入口当前按稳定排序输出对象键、Findings 和跳过资源；stdout 使用 ASCII Unicode 转义，避免控制台编码影响机器解析。

| 字段 | 类型 | 定义 |
| --- | --- | --- |
| `schema_version` | string | JSON 协议版本，当前为 `1.0`，与扫描器发行版本分开管理。 |
| `scanner_version` | string | 扫描器软件发行版本，当前源码值为 `0.2.0`；由 `scanner/json_contract.py` 中的 `SCANNER_VERSION` 作为唯一来源。它与 JSON Contract 的 `schema_version` 独立演进。 |
| `status` | enum | `COMPLETED`、`PARTIAL` 或 `FAILED`。 |
| `resource_counts` | object | `total` 为解析出的 Kubernetes 资源文档数；`scanned` 为完成适用规则分析的资源数；`skipped` 为 `skipped_resources` 数量。 |
| `finding_counts` | object | `HIGH`、`MEDIUM`、`LOW`、`UNKNOWN` 和 `total`。当前扫描器产生前三种 Severity；`UNKNOWN` 为未识别等级的保留计数。 |
| `findings` | array | 规范化风险列表。成功扫描可以是空列表。 |
| `skipped_resources` | array | 未完整执行当前 Workload/RBAC/Service 扫描的资源及原因。OUT_OF_SCOPE 资源也计入 skipped。 |
| `diagnostics` | array | 可安全输出的机器诊断；仅包含稳定代码和通用消息，不回显异常文本或输入路径。 |

### Finding

每条 Finding 包含以下必填字段：

| 字段 | 类型 | 来源与语义 |
| --- | --- | --- |
| `rule_id` | string | 扫描器实际结果的 `rule_id`，例如 `KGL-SEC-001`。 |
| `severity` | enum | 原始 `level` 规范化为大写 `HIGH`、`MEDIUM`、`LOW`；无法识别时为 `UNKNOWN`。 |
| `category` | string | 原始 `category`；Workload 规则缺省时按扫描器现有默认值 `Workload`。 |
| `message` | string | 扫描器原始 `message`。 |
| `reason` | string | 扫描器原始 `reason`。 |
| `suggestion` | string | 扫描器原始 `suggestion`。 |
| `resource` | object | `{kind, namespace, name}`，由扫描器 `resource` 和 `namespace` 字段映射；无法解析的成员为 `null`。当前扫描器把未声明 namespace 的资源按 `default` 标记，此协议保留该来源值。 |
| `path` | string or null | 扫描器 Finding 的 YAML 字段路径，例如 `spec.template.spec.initContainers[0].securityContext.privileged`。它不是输入文件路径。 |
| `container` | object or null | 适用时包含 `{name, type, index}`。容器类型为 `container` 或 `initContainer`；索引从 Finding 路径读取。不能可靠提取的成员为 `null`。 |
| `auto_fixable` | boolean or null | 原 Finding 的自动修复标记；缺少或非布尔值时为 `null`。此字段不代表 JSON 入口会执行修复。 |

扫描器原始结果中的 `source_file`、评分字段及原始资源 YAML 不会进入 Contract。没有稳定来源信息的字段不猜测、不补造。

`auto_fixable` 仅是扫描器给出的能力元数据，不能作为 Fusion 的操作授权。Adapter 必须使用自身权限、策略和人工批准流程决定是否执行后续操作；JSON 扫描入口不会触发 Fixer。

已有 RBAC 权限展开结果的 `resource` 可能指向被引用的 Role，而 `path` 是 Binding → Role 的关联说明，不是可以直接写回单个资源的纯 YAML 路径。本协议保留该真实行为，不能把这些关联 Finding 用作自动写回定位。当前结果也没有可靠的文档索引来源；重复资源文档保留多个 Finding，不进行猜测性去重。容器继承 Pod 级字段时，`path` 位于 Pod 级，容器索引无法从路径读取，因此为 `null`；普通容器的类型没有显式来源时也为 `null`。

### 跳过原因与诊断代码

`skipped_resources[].reason` 取值：

- `UNSUPPORTED_KIND`：当前检测范围内但未覆盖的工作负载控制器（如 DaemonSet、StatefulSet、Job、CronJob、ReplicaSet、ReplicationController）或尚未展开的 Kubernetes `List`。
- `WINDOWS_LINUX_RULES_UNSUPPORTED`：Pod/Deployment 显式声明 `spec.os.name: windows`。该资源不执行 Workload 规则，因此 Linux 专属结果不会被当作 Windows 的安全结论。
- `OUT_OF_SCOPE`：不属于当前检测目标的资源，例如 ConfigMap。此类资源被明确列出，但不影响 `COMPLETED`。
- `SCAN_FAILED`：扫描引擎异常导致原本可扫描的资源未能完成分析。

诊断 `code` 取值：`INPUT_NOT_FOUND`、`INPUT_READ_FAILED`、`INPUT_INVALID`、`EMPTY_INPUT`、`NO_ANALYZABLE_TARGET`、`SCAN_FAILED`、`PARTIAL_COVERAGE`。消息为通用文本，不包含绝对路径、异常原文或 YAML 内容。

## 状态判定

- `COMPLETED`：至少一个当前支持的非 Windows 目标完成分析，且没有未覆盖的适用目标。可以有零条或多条 Finding。仅有 `OUT_OF_SCOPE` 资源不会降级状态。
- `PARTIAL`：至少一个目标完成分析，同时存在 `UNSUPPORTED_KIND` 或 `WINDOWS_LINUX_RULES_UNSUPPORTED` 资源。即使 Finding 为零，也不能据此判定整体安全。
- `FAILED`：输入为空或无效、扫描未完成，或没有任何可分析目标完成必要分析。仅有 Windows、未覆盖控制器或 OUT_OF_SCOPE 资源时为 `FAILED`；失败不会用空 Findings 冒充成功。若批量扫描引擎中断，则不保留不完整 Findings，并把未完成目标标记为 `SCAN_FAILED`。

`resource_counts.total = scanned + skipped`。扫描成功且混有 OUT_OF_SCOPE 文档时，`skipped` 可以大于零而状态仍为 `COMPLETED`，因为该状态只保证请求中声明为适用的扫描目标已分析。

JSON 入口为 Windows Pod/Deployment 跳过 Workload 扫描；完整资源集仍用于 RBAC/Service 扫描上下文，确保 Service selector 检查不会因过滤 Windows Pod 而产生虚假的“无匹配工作负载”结论。当前仍不具备 Windows 安全基线。

## 版本兼容规则

`schema_version` 使用 `主版本.次版本`。相同主版本内只允许增加可选字段或枚举值；消费者应忽略未知可选字段，并对未知枚举采取保守处理。移除或重命名必填字段、改变字段含义或既有枚举语义时必须升级主版本。`scanner_version` 独立演进，不代表 Contract 结构变化。

## 覆盖边界

本协议表达当前 scanner 的扫描覆盖，不宣称完整 Kubernetes Schema 校验、完整 Pod Security Standards 合规、集群有效权限或运行时安全结论。扫描规则仍以 [规则说明](rule-description.md) 中列出的真实能力为准。

## 机器扫描环境与发行复现

仓库 `requirements.txt` 同时包含 Web/Desktop 依赖。仅运行 scanner/CLI 的环境使用根目录 `requirements-scan.txt`，其中固定 PyYAML、Typer、Rich 及其传递依赖版本，不安装 Streamlit、PySide6 或 ruamel.yaml。Windows PowerShell 可在无需管理员权限、无需 Kubernetes 集群的情况下创建独立环境：

```powershell
py -3.13 -m venv venv
venv\Scripts\python.exe -m pip install -r requirements-scan.txt
venv\Scripts\python.exe cli.py scan-json <YAML 文件或目录>
```

该依赖锁在 Python 3.13.11 Windows x64 环境验证；`py -3.13` 只选择 3.13 系列，发行复现时还必须确认 `python --version` 精确为 3.13.11，必要时使用该解释器的绝对路径。升级 Python 或任一依赖时，应重新运行完整 unittest、JSON CLI Contract Tests 和真实 YAML 扫描，并将解析后的全部直接/传递依赖版本固定回 `requirements-scan.txt`。输入文件只读解析，JSON 入口不会改写 YAML。

源码准备版本为 `0.2.0`。历史桌面版 `v0.1.0` 与本扫描器版本并存，不应将旧版桌面二进制标记为 `v0.2.0`。审核后的发行必须记录完整 Git Commit SHA、精确 Python 版本和 `requirements-scan.txt` 的 SHA-256（Windows PowerShell 可用 `Get-FileHash requirements-scan.txt -Algorithm SHA256` 计算）。Adapter 可同时校验 `schema_version` 与 `scanner_version`。协议结构升级按上一节规则单独提升 `schema_version`。
