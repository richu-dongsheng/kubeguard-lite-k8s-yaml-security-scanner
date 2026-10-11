# Changelog

本文件记录面向用户的重要版本变化。JSON Contract 协议版本与扫描器软件版本分别管理。

## v0.2.0 — 源码/API 集成发行版准备中

- 修复 `hostPath` 字段识别和 Workload 风险字段路径，统一 ServiceAccount Token 规则的 canonical Rule ID，并改进容器/volume 索引定位。
- 修正 Pod 与容器 `SecurityContext` 字段作用域及继承/覆盖处理；容器专属字段不再从 Pod 级配置误继承。
- 将适用的现有容器规则扩展到 `initContainers`，保留容器身份和 YAML 路径；不支持的 initContainer 自动修复仍会安全跳过。
- 增加分级的高风险 Linux Capabilities 检查、`capabilities.drop` 未包含 `ALL` 的低风险加固提示，以及对显式 seccomp `Unconfined` 的检测。
- 强化 Fixer 对 `auto_fixable: false` 的遵守：Safe 和 Strict 模式均跳过该 Finding，并将其记入 skipped。
- 新增 JSON Contract v1（`schema_version: 1.0`），通过 `python cli.py scan-json <target>` 输出机器可读结果；明确 `COMPLETED`、`PARTIAL`、`FAILED`、`OUT_OF_SCOPE` 和 `UNSUPPORTED_KIND` 语义，并为不适用的 Windows Workload 和未覆盖资源报告状态。
- 增加基于真实扫描逻辑的 unittest 回归基线，提供固定版本的 `requirements-scan.txt`，用于安装不包含 Web/Desktop 框架的扫描依赖。
- `scanner_version` 更新为 `0.2.0`；JSON `schema_version` 保持 `1.0`。

已知限制：此版本不实现完整 Kubernetes Schema 或 PSS 合规，不扫描镜像漏洞，不分析集群有效权限或运行时行为；安全规则主要面向 Linux，Workload 规则覆盖 Pod/Deployment。自动修复仅支持部分规则，不能作为执行授权。

## v0.1.0 — 2026-06 历史桌面版

此前发布的桌面工具版本，以人工 CLI、安全扫描和报告为主，并提供 Windows x86_64 与 Linux x86_64 桌面发行资产。历史二进制仍保留在 [v0.1.0 GitHub Release](https://github.com/richu-dongsheng/kubeguard-lite-k8s-yaml-security-scanner/releases/tag/v0.1.0)；不应将这些资产标记为 v0.2.0。