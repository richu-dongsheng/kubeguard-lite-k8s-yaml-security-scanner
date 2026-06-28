# kubeguard-Lite 规则说明

本文档列出 kubeguard-Lite 当前版本支持的扫描规则、风险类别、默认危险系数和自动修复支持情况。

危险系数由评分引擎根据风险等级、规则优先级和风险类别加权计算得到。后续版本如果调整评分策略，具体数值可能发生变化。

---

## 一、Workload 配置风险规则

| Rule ID     | 风险项                                | 类别       | 默认危险系数 |
| ----------- | ---------------------------------- | -------- | -----: |
| KGL-POD-001 | PodSpec 启用 hostNetwork             | Workload |     15 |
| KGL-POD-002 | PodSpec 启用 hostPID                 | Workload |     15 |
| KGL-POD-003 | PodSpec 启用 hostIPC                 | Workload |     15 |
| KGL-SA-001  | 显式开启 automountServiceAccountToken  | Workload |      2 |
| KGL-SA-002  | 未显式关闭 automountServiceAccountToken | Workload |      2 |
| KGL-IMG-001 | 镜像使用 latest 或未固定版本标签               | Workload |      6 |
| KGL-SEC-000 | 容器缺失 securityContext               | Workload |      2 |
| KGL-SEC-001 | 容器启用 privileged                    | Workload |     16 |
| KGL-SEC-002 | 容器允许 allowPrivilegeEscalation      | Workload |      6 |
| KGL-SEC-003 | 容器使用 root 用户运行                     | Workload |     15 |
| KGL-SEC-004 | 容器未启用 runAsNonRoot                 | Workload |      6 |
| KGL-SEC-005 | 容器缺失 seccompProfile                | Workload |      2 |
| KGL-SEC-006 | 容器未启用 readOnlyRootFilesystem       | Workload |      2 |
| KGL-RES-001 | 容器缺失 resources.limits              | Workload |      6 |
| KGL-VOL-001 | 挂载敏感 hostPath 路径                   | Workload |     11 |

---

## 二、RBAC 权限风险规则

| Rule ID      | 风险项                                       | 类别   | 默认危险系数 |
| ------------ | ----------------------------------------- | ---- | -----: |
| KGL-RBAC-001 | ClusterRoleBinding 绑定 cluster-admin       | RBAC |     20 |
| KGL-RBAC-002 | RoleBinding 绑定 cluster-admin              | RBAC |     18 |
| KGL-RBAC-003 | RBAC 规则包含通配符权限                            | RBAC |     12 |
| KGL-RBAC-004 | RBAC 规则允许读取 secrets                       | RBAC |     17 |
| KGL-RBAC-005 | RBAC 规则允许 pods/exec                       | RBAC |     17 |
| KGL-RBAC-006 | RBAC 规则允许创建 pods                          | RBAC |      7 |
| KGL-RBAC-007 | RBAC 规则允许修改 RBAC 资源                       | RBAC |     17 |
| KGL-RBAC-008 | RBAC 规则包含 bind、escalate 或 impersonate     | RBAC |     17 |
| KGL-RBAC-009 | Binding 引用了当前扫描范围内不存在的 Role 或 ClusterRole | RBAC |      3 |

---

## 三、Service 暴露风险规则

| Rule ID     | 风险项                                       | 类别      | 默认危险系数 |
| ----------- | ----------------------------------------- | ------- | -----: |
| KGL-SVC-001 | Service 使用 NodePort 暴露方式                  | Service |      6 |
| KGL-SVC-002 | Service 使用 LoadBalancer 暴露方式              | Service |     15 |
| KGL-SVC-003 | Service 配置 externalIPs                    | Service |     15 |
| KGL-SVC-004 | Service 暴露敏感端口                            | Service |     15 |
| KGL-SVC-005 | Service 未配置 selector                      | Service |      2 |
| KGL-SVC-006 | Service selector 未匹配到当前扫描范围内的工作负载         | Service |      2 |
| KGL-SVC-007 | NodePort 不在默认端口范围内                        | Service |      6 |
| KGL-SVC-008 | LoadBalancer 未配置 loadBalancerSourceRanges | Service |      6 |
| KGL-SVC-009 | Service 使用 ExternalName                   | Service |      6 |

---

## 四、Ingress 风险规则

| Rule ID     | 风险项                            | 类别      | 默认危险系数 |
| ----------- | ------------------------------ | ------- | -----: |
| KGL-ING-001 | Ingress 未配置 TLS                | Service |      6 |
| KGL-ING-002 | Ingress 使用通配符 Host             | Service |      6 |
| KGL-ING-003 | Ingress 使用高风险 Nginx snippet 注解 | Service |     15 |
| KGL-ING-004 | Ingress 未配置 Host               | Service |      2 |

---

## 五、自动修复支持情况

| Rule ID     | 修复模式   | 修复策略                                     |
| ----------- | ------ | ---------------------------------------- |
| KGL-POD-001 | safe   | 将 hostNetwork 设置为 false                  |
| KGL-POD-002 | safe   | 将 hostPID 设置为 false                      |
| KGL-POD-003 | safe   | 将 hostIPC 设置为 false                      |
| KGL-SEC-001 | safe   | 将 privileged 设置为 false                   |
| KGL-SEC-002 | safe   | 将 allowPrivilegeEscalation 设置为 false     |
| KGL-SEC-005 | safe   | 设置 seccompProfile.type 为 RuntimeDefault  |
| KGL-SA-001  | strict | 将 automountServiceAccountToken 设置为 false |
| KGL-SA-002  | strict | 将 automountServiceAccountToken 设置为 false |
| KGL-SEC-004 | strict | 将 runAsNonRoot 设置为 true                  |
| KGL-SEC-006 | strict | 将 readOnlyRootFilesystem 设置为 true        |

---

## 六、暂不自动修复的风险

以下风险需要结合业务场景判断，因此当前版本只进行识别和提示，不默认自动修改。

| 风险类型                            | 暂不自动修复原因                   |
| ------------------------------- | -------------------------- |
| 镜像 latest / 未固定 tag             | 工具无法判断应该替换为哪个业务版本          |
| resources.limits 缺失             | 工具无法判断 CPU / Memory 应设置为多少 |
| RBAC 过权                         | 最小权限范围依赖业务访问需求             |
| Service NodePort / LoadBalancer | 暴露方式可能是业务设计要求              |
| externalIPs                     | 需要结合网络架构判断                 |
| Ingress TLS 缺失                  | 证书和域名配置依赖实际环境              |
| Ingress snippet 注解              | 需要判断注解是否被业务依赖              |
| hostPath 挂载                     | 需要判断是否存在替代方案或业务依赖          |

---

## 七、危险系数参考

| 危险系数区间 | 参考含义               |
| ------ | ------------------ |
| 15 及以上 | 高优先级风险，建议优先处理      |
| 6 到 14 | 中等风险，需要结合业务场景判断    |
| 1 到 5  | 低风险或提示类风险，建议纳入基线治理 |

---

# docs/practice_report.md
