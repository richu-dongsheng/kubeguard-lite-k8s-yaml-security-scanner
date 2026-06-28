

# kubeguard-Lite

**kubeguard-Lite** 是一款面向 Kubernetes 场景的 YAML 静态配置风险扫描与自动修复工具。

本项目通过静态分析 Kubernetes YAML 文件，在资源部署前识别潜在配置风险，例如 privileged 容器、hostNetwork、ServiceAccount Token 自动挂载、RBAC 过权、Service 暴露面过大、Ingress 高风险注解、latest 镜像标签等问题，并提供风险评分、报告导出和部分配置自动修复能力。

> 本项目定位为教学式云原生安全前置项目，重点关注 Kubernetes 配置错误带来的攻击面暴露问题，适合用于云原生安全学习、课程实践、部署前配置审计和安全工具开发入门。

---

## 一、项目特点

* 支持 Kubernetes YAML 静态配置风险扫描
* 支持 Pod / Deployment 等 Workload 安全检查
* 支持 RBAC 权限风险识别与 Binding → Role / ClusterRole 关联分析
* 支持 Service / Ingress 暴露面风险识别
* 支持风险等级、危险系数和整体评分
* 支持 Markdown / HTML 扫描报告导出
* 支持 YAML 自动修复
* 支持 Markdown / HTML 自动修复报告导出
* 支持 CLI、Streamlit Web Demo、PySide6 桌面端
* 支持 Windows exe 与 Linux AppImage 桌面版发布
* 内置使用指南、规则细则和设计说明

---

## 二、工具适用场景

kubeguard-Lite 适用于以下场景：

1. **Kubernetes YAML 部署前检查**
   在资源进入集群之前，对 YAML 文件进行配置风险扫描。

2. **云原生安全学习**
   通过具体 YAML 风险样例理解 Kubernetes 配置安全问题。

3. **课程项目 / 实践项目展示**
   展示从规则设计、扫描引擎、评分系统、报告生成到桌面端打包的完整开发流程。

4. **轻量级配置审计**
   对本地 YAML 文件或目录进行安全基线检查。

5. **DevSecOps 前置能力探索**
   可作为后续 CI/CD 安全门禁、策略扫描、供应链安全项目的基础模块。

---

## 三、当前支持的风险类别

| 类别             | 典型风险                                                                           |
| -------------- | ------------------------------------------------------------------------------ |
| Workload 安全    | privileged 容器、hostNetwork、hostPID、hostIPC、root 用户运行、缺失 seccompProfile          |
| 镜像安全           | 使用 latest 标签、镜像未固定版本                                                           |
| 资源治理           | 缺失 resources.limits                                                            |
| ServiceAccount | automountServiceAccountToken 未显式关闭                                             |
| RBAC 权限        | cluster-admin 绑定、读取 secrets、pods/exec、修改 RBAC 资源、bind / escalate / impersonate |
| Service 暴露     | NodePort、LoadBalancer、externalIPs、敏感端口暴露                                       |
| Ingress 安全     | 未配置 TLS、通配符 Host、高风险 Nginx snippet 注解                                          |

---

## 四、桌面版下载

请前往 GitHub Releases 页面下载桌面版程序。

当前提供：

* Windows x86_64：`kubeguard-lite-desktop-windows-x86_64.exe`
* Linux x86_64：`kubeguard-lite-desktop-linux-x86_64.AppImage`

Linux 用户首次运行 AppImage 时需要赋予执行权限：

```bash
chmod +x kubeguard-lite-desktop-linux-x86_64.AppImage
./kubeguard-lite-desktop-linux-x86_64.AppImage
```

---

## 五、CLI 快速开始

克隆项目：

```bash
git clone https://github.com/richu-dongsheng/kubeguard-lite-k8s-yaml-security-scanner.git
cd kubeguard-lite-k8s-yaml-security-scanner
```

创建虚拟环境：

```bash
python -m venv .venv
source .venv/bin/activate
```

安装最小依赖：

```bash
pip install PyYAML typer rich PySide6 pyinstaller
```

扫描示例 YAML：

```bash
python cli.py scan examples/insecure
```

自动修复：

```bash
python cli.py fix examples/insecure --mode safe --output fixed
```

导出扫描报告：

```bash
python cli.py report examples/insecure --format html --output reports/scan-report.html
```

导出自动修复报告：

```bash
python cli.py fix examples/insecure --mode safe --output fixed --fix-report-format html --fix-report reports/fix-report.html
```

---

## 六、自动修复模式

kubeguard-Lite 提供两种自动修复模式。

### 1. safe 模式

`safe` 是默认推荐模式，只修复相对明确、较少依赖业务上下文的危险配置，例如：

* `hostNetwork: true` → `false`
* `hostPID: true` → `false`
* `hostIPC: true` → `false`
* `privileged: true` → `false`
* `allowPrivilegeEscalation: true` → `false`
* 补充 `seccompProfile.type: RuntimeDefault`

### 2. strict 模式

`strict` 模式会执行更强的安全加固，但可能影响业务行为，例如：

* 禁用 ServiceAccount Token 自动挂载
* 设置 `runAsNonRoot: true`
* 设置 `readOnlyRootFilesystem: true`

strict 模式适合安全要求更高的场景，但修复后必须进行业务验证。

---

## 七、报告能力

kubeguard-Lite 支持两类报告：

| 报告类型   | 支持格式            |
| ------ | --------------- |
| 扫描报告   | Markdown / HTML |
| 自动修复报告 | Markdown / HTML |

报告内容包括：

* 扫描目标
* Kubernetes 资源数量
* 风险数量
* HIGH / MEDIUM / LOW 风险统计
* Workload / RBAC / Service 风险类别统计
* 整体危险系数
* 整体评级
* 风险清单
* 已自动修复动作
* 未自动修复风险
* 修复后残余风险
* 后续处理建议

---

## 八、项目结构

```text
kubeguard-lite/
├── cli.py
├── desktop.py
├── desktop_help.py
├── website.py
├── scanner/
│   ├── parser.py
│   ├── pod_scanner.py
│   ├── rbac_scanner.py
│   ├── service_scanner.py
│   ├── scoring.py
│   └── scan_engine.py
├── fixer/
│   ├── yaml_fixer.py
│   └── fix_report.py
├── reporter/
│   ├── markdown_report.py
│   └── html_report.py
├── examples/
│   └── insecure/
└── docs/
    ├── design.md
    ├── practice-report.md
    └── rule-description.md
```

---

## 九、文档说明

更多说明见 `docs/` 目录：

* `docs/design.md`：项目设计说明、架构设计和规则设计依据
* `docs/rule-description.md`：扫描规则、危险系数和自动修复支持情况
* `docs/practice-report.md`：项目实践报告和开发过程总结

---

## 十、注意事项

* 本工具是静态分析工具，不会连接真实 Kubernetes 集群。
* 自动修复不会覆盖原始 YAML 文件，而是写入新的输出目录。
* RBAC 权限收缩、镜像版本选择、资源限制数值、Service 暴露方式、Ingress TLS 证书等问题需要结合业务场景人工判断。
* 本工具不能替代 Kubernetes Admission Controller、运行时安全监控或完整的云原生安全平台。
* 本项目主要用于学习、研究、课程实践和轻量级部署前配置审计。

---

## License

本项目当前用于教学、学习和研究场景。
