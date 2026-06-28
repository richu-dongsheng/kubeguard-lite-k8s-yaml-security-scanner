# kubeguard-Lite 实践报告

## 一、项目概述

kubeguard-Lite 是一个面向 Kubernetes 场景的 YAML 静态配置风险扫描与自动修复工具。项目以部署前配置审计为核心目标，通过解析 Kubernetes YAML 文件，识别 Workload、RBAC、Service、Ingress 等资源中的常见配置风险，并输出风险等级、危险系数、修复建议和审计报告。

本项目属于云原生安全方向的前置实践项目，主要用于理解 Kubernetes 配置风险、静态扫描工具设计、自动修复策略和桌面端安全工具打包发布流程。

---

## 二、实践目标

本次实践主要目标包括：

1. 掌握 Kubernetes YAML 常见资源结构。
2. 理解 PodSpec、container.securityContext、RBAC、Service、Ingress 等配置中的安全风险。
3. 设计并实现静态 YAML 解析器。
4. 设计并实现多类 Kubernetes 风险扫描规则。
5. 构建风险评分与整体评级机制。
6. 实现 Markdown / HTML 报告导出。
7. 实现保守型 YAML 自动修复能力。
8. 实现 CLI、Web Demo 和 PySide6 桌面端。
9. 完成 Windows exe 和 Linux AppImage 打包发布。

---

## 三、项目开发过程

### 1. YAML 解析模块

项目首先实现 YAML 解析能力，支持单个 YAML 文件和目录递归扫描。解析器能够处理多文档 YAML，并为每个资源补充来源文件和文档编号，方便后续风险定位和修复输出。

### 2. Workload 扫描模块

Workload 扫描模块主要针对 Pod 和 Deployment。通过统一提取 PodSpec，扫描 hostNetwork、hostPID、hostIPC、privileged、allowPrivilegeEscalation、seccompProfile、resources.limits 等字段。

该模块帮助理解容器权限、命名空间隔离、安全上下文和资源限制等 Kubernetes 安全基础概念。

### 3. RBAC 扫描模块

RBAC 模块实现了 Role、ClusterRole、RoleBinding、ClusterRoleBinding 的扫描，并支持 Binding 到 Role / ClusterRole 的关联分析。

该模块不仅识别单个权限规则中的危险权限，还尝试分析 ServiceAccount 通过绑定关系获得的实际权限，从而更接近真实攻击路径分析。

### 4. Service 与 Ingress 扫描模块

Service 模块识别 NodePort、LoadBalancer、externalIPs、敏感端口暴露等风险，并尝试将 Service selector 与 Workload labels 进行匹配。

Ingress 模块识别未配置 TLS、通配符 Host、高风险 Nginx snippet 注解等问题。

### 5. 风险评分模块

项目设计了风险评分机制，对不同风险赋予危险系数，并根据 HIGH / MEDIUM / LOW 风险数量、风险类别和规则优先级生成整体评级。

这种方式比单纯输出风险列表更直观，便于用户判断当前 YAML 配置的整体危险程度。

### 6. 报告模块

项目实现 Markdown 和 HTML 两类报告。扫描报告用于记录资源识别结果、风险统计、完整风险清单和修复建议。自动修复报告用于记录修复前后对比、已修复动作、未修复风险和残余风险。

报告能力提升了工具的可交付性，也方便用于课程报告、审计记录和项目展示。

### 7. 自动修复模块

自动修复模块采用保守策略，区分 safe 和 strict 两种模式。

safe 模式只修复相对明确的危险配置，例如 hostNetwork、privileged、allowPrivilegeEscalation 和 seccompProfile。

strict 模式会进一步处理 automountServiceAccountToken、runAsNonRoot、readOnlyRootFilesystem 等可能影响业务行为的加固项。

### 8. 桌面端与发布

项目最后使用 PySide6 实现桌面端图形界面，支持扫描、修复、报告导出和内置帮助文档。桌面端采用紫黑色安全工具风格，并实现 Windows exe 与 Linux AppImage 打包。

---

## 四、实践成果

本次实践完成了以下成果：

1. Kubernetes YAML 静态配置扫描器。
2. Workload / RBAC / Service / Ingress 多类别风险规则。
3. 风险危险系数评分机制。
4. Markdown / HTML 扫描报告。
5. YAML 自动修复能力。
6. Markdown / HTML 自动修复报告。
7. CLI 命令行工具。
8. Streamlit Web Demo。
9. PySide6 桌面端工具。
10. Windows exe 和 Linux AppImage Release 发布。

---

## 五、项目收获

通过本项目实践，加深了以下方面的理解：

1. Kubernetes YAML 资源结构。
2. PodSpec 与 container.securityContext 安全配置。
3. ServiceAccount 与 RBAC 权限模型。
4. Service / Ingress 暴露面风险。
5. 静态扫描工具的规则设计方法。
6. 自动修复功能需要保守处理业务上下文。
7. 安全工具需要可解释输出和审计报告。
8. 桌面端工具打包发布涉及不同操作系统环境差异。

---

## 六、存在不足

当前项目仍存在一些不足：

1. 规则覆盖范围有限。
2. 未连接真实 Kubernetes 集群。
3. 不能验证运行时状态。
4. 自动修复能力只覆盖部分字段。
5. AppImage 体积较大。
6. 尚未接入 CI/CD 扫描流程。
7. 尚未映射 Pod Security Standards 或 CIS Benchmark。

---

## 七、后续改进方向

后续可以考虑：

1. 扩展更多 Kubernetes 资源类型。
2. 增加 Pod Security Standards 映射。
3. 增加 CIS Kubernetes Benchmark 相关检查。
4. 支持 SARIF 输出，接入代码扫描平台。
5. 支持 GitHub Actions 自动扫描。
6. 增加修复前后 YAML diff 预览。
7. 优化 Linux AppImage 体积。
8. 增加英文 README 或中英双语文档。

---

## 八、总结

kubeguard-Lite 从一个 YAML 静态扫描工具出发，逐步扩展到风险评分、报告生成、自动修复、Web 展示和桌面端发布，形成了较完整的云原生安全配置扫描工具链。

虽然它还不是完整的企业级云原生安全平台，但作为前置项目，它已经覆盖了 Kubernetes 配置风险识别、自动化处理和工具产品化发布的核心流程，为后续深入学习云安全、云原生安全和 DevSecOps 打下了基础。