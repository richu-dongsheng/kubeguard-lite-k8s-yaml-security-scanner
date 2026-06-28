# kubeguard-Lite 设计说明

## 一、项目背景

Kubernetes 已经成为云原生应用部署的重要基础设施。大量业务系统通过 YAML 文件定义 Pod、Deployment、Service、Ingress、RBAC 等资源，并通过这些配置描述应用的运行方式、网络暴露方式和权限模型。

在实际使用中，很多 Kubernetes 安全问题并不一定来自程序漏洞，而是来自错误配置。例如：

* 容器开启 privileged 模式
* Pod 使用 hostNetwork、hostPID、hostIPC
* 容器以 root 用户运行
* ServiceAccount 权限过大
* RBAC 绑定 cluster-admin
* Service 使用 NodePort、LoadBalancer 或 externalIPs 暴露服务
* Ingress 使用高风险 Nginx snippet 注解
* 镜像使用 latest 标签
* 容器缺失资源限制

这些问题通常在 YAML 文件中就能提前发现。因此，在资源部署到集群之前，对 Kubernetes YAML 进行静态配置风险扫描具有现实意义。

kubeguard-Lite 正是围绕这一目标设计：通过轻量级静态分析，在部署前发现 Kubernetes 配置风险，并对部分明确危险配置提供自动修复能力。

---

## 二、设计目标

本项目的核心设计目标如下：

### 1. 部署前风险识别

工具不依赖真实 Kubernetes 集群，而是直接分析本地 YAML 文件，在资源进入集群之前发现潜在安全风险。

### 2. 聚焦配置错误

项目重点关注 Kubernetes YAML 中常见的错误配置，而不是容器镜像漏洞扫描、运行时攻击检测或集群合规审计。

### 3. 轻量化与可解释

扫描结果需要可读、可解释，能够展示规则编号、风险等级、危险系数、资源名称、字段路径、风险原因和修复建议。

### 4. 支持报告输出

工具需要支持 Markdown 和 HTML 报告，方便用于课程报告、项目展示、安全审计记录和答辩说明。

### 5. 保守自动修复

自动修复功能不追求“修复所有问题”，而是只自动修改相对明确、较少依赖业务上下文的危险配置。

### 6. 多入口使用

工具同时支持 CLI、Web Demo 和桌面端，使其既能用于开发调试，也能用于图形化展示。

---

## 三、整体架构

kubeguard-Lite 采用分层设计：

```text
输入层
  YAML 文件 / YAML 目录

解析层
  解析多文档 YAML
  标记来源文件和文档编号

扫描层
  Workload Scanner
  RBAC Scanner
  Service / Ingress Scanner

评分层
  风险等级归一化
  危险系数计算
  风险类别统计
  整体评级生成

修复层
  risk-based fix
  baseline hardening fix
  修复动作记录
  fixed YAML 输出

报告层
  Markdown 扫描报告
  HTML 扫描报告
  Markdown 修复报告
  HTML 修复报告

交互层
  CLI
  Streamlit Web Demo
  PySide6 Desktop App
```

这种结构使扫描规则、评分逻辑、修复逻辑和界面展示相互解耦。CLI、Web 和桌面端都复用同一套后端扫描与修复能力。

---

## 四、核心扫描流程

扫描流程如下：

```text
输入 YAML 路径
  ↓
load_yaml_path()
  ↓
资源列表 resources
  ↓
scan_pod_resources()
scan_rbac_resources()
scan_service_resources()
  ↓
风险列表 risks
  ↓
sort_risks_by_priority()
build_scan_summary()
  ↓
CLI / Web / Desktop / Report 输出
```

解析器会为每个 YAML 资源补充内部字段，例如：

* `_source_file`
* `_document_index`

这些字段用于追踪风险来源和修复输出，但在写入修复后的 YAML 时会被移除，避免污染用户配置文件。

---

## 五、Workload 扫描设计

Workload 扫描器主要处理：

* Pod
* Deployment

对于 Pod，扫描器读取：

```text
spec
```

对于 Deployment，扫描器读取：

```text
spec.template.spec
```

这样可以统一提取 PodSpec，再检查以下风险字段：

* `hostNetwork`
* `hostPID`
* `hostIPC`
* `automountServiceAccountToken`
* 容器镜像 tag
* `securityContext`
* `privileged`
* `allowPrivilegeEscalation`
* `runAsUser`
* `runAsNonRoot`
* `seccompProfile`
* `readOnlyRootFilesystem`
* `resources.limits`

Workload 规则的核心目标是识别容器运行时隔离边界被削弱、容器权限过高、镜像不可追踪和资源隔离不足等问题。

---

## 六、RBAC 扫描设计

RBAC 是 Kubernetes 权限控制的核心。攻击者一旦进入某个 Pod，常见后续攻击路径之一就是利用 Pod 中挂载的 ServiceAccount Token 访问 Kubernetes API。

因此，ServiceAccount 对应的 RBAC 权限越大，攻击者在集群中的横向移动能力越强。

RBAC 扫描器处理以下资源：

* Role
* ClusterRole
* RoleBinding
* ClusterRoleBinding

扫描逻辑分为两部分：

### 1. 直接扫描 Role / ClusterRole

识别规则中是否存在：

* 通配符权限
* 读取 secrets
* pods/exec
* 创建 pods
* 修改 RBAC 资源
* bind / escalate / impersonate

### 2. Binding 关联分析

工具会建立 Role / ClusterRole 索引，然后分析 RoleBinding / ClusterRoleBinding 的 `roleRef`，把绑定关系与实际权限关联起来。

示例流程：

```text
RoleBinding / ClusterRoleBinding
  ↓
roleRef
  ↓
Role / ClusterRole
  ↓
rules
  ↓
危险权限识别
  ↓
主体 subject 风险输出
```

这种设计可以让工具发现“某个 ServiceAccount 通过 Binding 获得危险权限”的攻击路径，而不是只孤立地扫描单个资源。

---

## 七、Service 与 Ingress 扫描设计

Service 和 Ingress 决定了工作负载如何被访问，是 Kubernetes 暴露面管理的关键配置。

Service 扫描器关注：

* NodePort
* LoadBalancer
* externalIPs
* ExternalName
* 敏感端口
* 缺失 selector
* selector 无法匹配当前扫描范围内的工作负载
* LoadBalancer 未配置来源限制

Ingress 扫描器关注：

* 未配置 TLS
* 通配符 Host
* 缺失 Host
* 高风险 Nginx snippet 注解

Service 扫描器还会尝试根据 Service selector 与 Workload labels 做关联，判断 Service 是否能匹配当前扫描范围内的工作负载。

---

## 八、危险系数设计

项目中的风险评分不是简单地把 HIGH、MEDIUM、LOW 直接展示，而是进一步计算“危险系数”。

危险系数主要由三部分组成：

1. **风险等级基础分**

   * HIGH 风险基础分较高
   * MEDIUM 风险基础分居中
   * LOW 风险基础分较低

2. **规则优先级加权**

   * cluster-admin
   * privileged
   * hostNetwork / hostPID / hostIPC
   * secrets read
   * pods/exec
   * RBAC 资源修改
     这类风险会额外加权。

3. **风险类别加权**
   RBAC 风险可能导致集群级权限提升，因此在评分中具有更高优先级。

最终工具会计算：

* 单条风险危险系数
* 总危险系数
* HIGH / MEDIUM / LOW 统计
* Workload / RBAC / Service 类别统计
* 整体评级

整体评级包括：

| 等级       | 含义         |
| -------- | ---------- |
| CRITICAL | 极高风险       |
| HIGH     | 高风险        |
| MEDIUM   | 中风险        |
| LOW      | 低风险        |
| SAFE     | 未发现已覆盖规则风险 |

---

## 九、自动修复设计

自动修复采用保守策略。工具不会盲目修改所有风险，而是将风险分成三类。

### 1. safe 自动修复项

safe 模式只修复相对明确、较少依赖业务上下文的危险配置，例如：

* `hostNetwork: true` → `false`
* `hostPID: true` → `false`
* `hostIPC: true` → `false`
* `privileged: true` → `false`
* `allowPrivilegeEscalation: true` → `false`
* 缺失 `seccompProfile` 时补充 `RuntimeDefault`

### 2. strict 自动修复项

strict 模式执行更强硬的安全加固，例如：

* `automountServiceAccountToken: false`
* `runAsNonRoot: true`
* `readOnlyRootFilesystem: true`

这些配置有安全收益，但可能影响业务行为，因此不在 safe 模式中默认修改。

### 3. manual-only 风险

以下风险必须结合业务场景判断，不适合自动修改：

* 镜像版本应该固定为哪个 tag
* resources.limits 应该设置为多少
* RBAC 权限应该收缩到什么范围
* Service 是否应该改为 ClusterIP
* Ingress TLS 使用哪个证书
* hostPath 是否可以删除或替换

工具会记录这些未自动修复项，并在报告中给出原因和后续建议。

---

## 十、接口设计思路

项目将核心扫描能力封装在 `scanner/scan_engine.py` 中，提供统一接口：

```text
scan_path()
scan_resources()
get_resources()
get_risks()
get_summary()
```

这样 CLI、Web、Desktop、Report 模块都可以复用统一的扫描结果。

自动修复模块同样提供统一入口：

```text
fix_path()
```

返回内容包括：

* 原始扫描结果
* 修复后资源
* 修复后扫描结果
* 修复摘要
* 已修复动作
* 未修复风险
* 写入文件列表

这种设计避免了每个前端入口重复实现业务逻辑。

---

## 十一、多入口设计说明

kubeguard-Lite 提供三种使用入口：

| 入口          | 文件           | 定位                           |
| ----------- | ------------ | ---------------------------- |
| CLI         | `cli.py`     | 面向命令行使用、脚本调用和后续 DevSecOps 集成 |
| Web Demo    | `website.py` | 面向本地快速演示、上传 YAML 扫描和报告下载     |
| Desktop App | `desktop.py` | 面向普通用户的图形化桌面工具，是当前主要发布形态     |

三种入口复用同一套后端能力：

```text
scanner/scan_engine.py
fixer/yaml_fixer.py
fixer/fix_report.py
reporter/markdown_report.py
reporter/html_report.py
```

因此，CLI、Web Demo 和 Desktop App 并不是三套独立实现，而是共享扫描、评分、修复和报告模块。

Web Demo 使用 Streamlit 实现，主要用于本地展示和功能验证。它可以快速展示 YAML 扫描、自动修复、修复前后对比和报告下载能力，但不是当前项目的主发布形态。

Desktop App 使用 PySide6 实现，支持 Windows exe 和 Linux AppImage 打包，是当前更完整的用户交付形态。

## 依赖分层设计

项目依赖分为两类：

1. `requirements.txt`
   用于源码运行，包含 CLI、Web Demo 和 Desktop App 所需的直接依赖。

2. `requirements-build.txt`
   用于桌面端打包，主要包含 PyInstaller。

这种拆分可以避免把打包工具和大量平台相关依赖混入普通运行依赖中，也能减少用户安装失败的概率。





## 十二、项目局限性

当前版本仍有一些限制：

1. 只进行静态 YAML 分析，不连接真实集群。
2. 无法判断运行时状态。
3. 只能分析当前输入目录中的资源，跨目录、跨仓库的关联能力有限。
4. 自动修复只覆盖部分明确危险字段。
5. 对 RBAC 最小权限、Service 暴露策略、资源限制数值等问题仍依赖人工判断。
6. 当前不是完整的合规平台，不能替代 CIS Benchmark 工具、Admission Controller 或运行时安全系统。

---

## 十三、后续规划

后续可以考虑继续扩展：

* 增加更多 Kubernetes 资源类型支持
* 映射 Pod Security Standards
* 映射 CIS Kubernetes Benchmark 部分配置项
* 增加 SARIF 输出，接入 DevSecOps 工具链
* 增加 GitHub Actions 扫描能力
* 增加修复前后 diff 预览
* 优化 Linux AppImage 体积
* 增加英文 README 或中英双语文档

---

## 十四、总结

kubeguard-Lite 的核心价值是：在资源部署前，通过静态分析 Kubernetes YAML 文件，提前识别云原生配置错误带来的攻击面，并对部分明确危险配置进行自动修复。

它不是完整云原生安全平台，而是一个轻量级、可解释、可扩展的配置风险扫描工具，适合用于云原生安全学习、课程项目展示和部署前配置审计。
