from pathlib import Path
from typing import Any

import yaml


YamlResource = dict[str, Any]

YAML_SUFFIXES = {".yaml", ".yml"}


def is_yaml_file(path: Path) -> bool:
    """判断一个路径是否是 YAML 文件。"""
    return path.is_file() and path.suffix.lower() in YAML_SUFFIXES


def iter_yaml_files(target_path: str | Path) -> list[Path]:
    """
    根据输入路径收集 YAML 文件。

    支持两种输入：
    1. 单个 YAML 文件
    2. 一个目录，递归查找其中所有 .yaml / .yml 文件
    """
    target = Path(target_path)

    if not target.exists():
        raise FileNotFoundError(f"路径不存在：{target}")

    if target.is_file():
        if not is_yaml_file(target):
            raise ValueError(f"不是 YAML 文件：{target}")
        return [target]

    if target.is_dir():
        return sorted(
            path for path in target.rglob("*")
            if is_yaml_file(path)
        )

    raise ValueError(f"不支持的路径类型：{target}")


def load_yaml_file(file_path: str | Path) -> list[YamlResource]:
    """
    读取单个 YAML 文件，返回其中包含的 Kubernetes 资源列表。

    支持多文档 YAML，例如：
    ---
    kind: Pod
    ---
    kind: Deployment
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"YAML 文件不存在：{path}")

    if not is_yaml_file(path):
        raise ValueError(f"不是 YAML 文件：{path}")

    resources: list[YamlResource] = []

    try:
        with path.open("r", encoding="utf-8") as file:
            documents = yaml.safe_load_all(file)

            for document_index, document in enumerate(documents, start=1):
                # 空文档，例如只有 ---，解析结果是 None
                if document is None:
                    continue

                if not isinstance(document, dict):
                    raise ValueError(
                        f"无法识别 YAML 文档：{path} 第 {document_index} 个文档顶层必须是 Kubernetes 资源对象"
                    )

                api_version = document.get("apiVersion")
                kind = document.get("kind")
                if not isinstance(api_version, str) or not api_version.strip():
                    raise ValueError(
                        f"无法识别 Kubernetes 资源：{path} 第 {document_index} 个文档缺少有效 apiVersion"
                    )
                if not isinstance(kind, str) or not kind.strip():
                    raise ValueError(
                        f"无法识别 Kubernetes 资源：{path} 第 {document_index} 个文档缺少有效 kind"
                    )

                metadata = document.get("metadata")
                if metadata is not None and not isinstance(metadata, dict):
                    raise ValueError(
                        f"无法识别 Kubernetes 资源：{path} 第 {document_index} 个文档的 metadata 必须是对象"
                    )

                # 给资源附加来源信息，方便后续报告和自动修复定位
                document["_source_file"] = str(path)
                document["_document_index"] = document_index

                resources.append(document)

    except yaml.YAMLError as exc:
        raise ValueError(f"YAML 解析失败：{path}，原因：{exc}") from exc

    return resources


def load_yaml_directory(directory_path: str | Path) -> list[YamlResource]:
    """
    读取目录下所有 YAML 文件，并返回全部 Kubernetes 资源。

    这个函数保留，是为了语义清晰；
    实际项目入口更推荐使用 load_yaml_path()。
    """
    directory = Path(directory_path)

    if not directory.exists():
        raise FileNotFoundError(f"目录不存在：{directory}")

    if not directory.is_dir():
        raise NotADirectoryError(f"不是目录：{directory}")

    all_resources: list[YamlResource] = []

    for yaml_file in iter_yaml_files(directory):
        all_resources.extend(load_yaml_file(yaml_file))

    return all_resources


def load_yaml_path(target_path: str | Path) -> list[YamlResource]:
    """
    读取一个路径中的 Kubernetes YAML 资源。

    target_path 可以是：
    - 单个 .yaml / .yml 文件
    - 一个目录
    """
    all_resources: list[YamlResource] = []

    for yaml_file in iter_yaml_files(target_path):
        all_resources.extend(load_yaml_file(yaml_file))

    return all_resources


def get_resource_identity(resource: YamlResource) -> dict[str, str]:
    """标准化提取 Kubernetes 资源的基本身份信息。"""
    metadata = resource.get("metadata") or {}
    
    CLUSTER_SCOPED_KINDS = {
        "Namespace",
        "Node",
        "PersistentVolume",
        "ClusterRole",
        "ClusterRoleBinding",
    }
    
    kind = str(resource.get("kind", "Unknown"))

    if kind in CLUSTER_SCOPED_KINDS:
        namespace = "cluster-scope"
    else:
        namespace = str(metadata.get("namespace", "default"))



    return {
        "apiVersion": str(resource.get("apiVersion", "unknown")),
        "kind": str(resource.get("kind", "Unknown")),
        "name": str(metadata.get("name", "unknown")),
        "namespace":str(namespace),
        "source_file": str(resource.get("_source_file", "unknown")),
        "document_index": str(resource.get("_document_index", "unknown")),
    }
