from pathlib import Path
import tempfile
from typing import Any

import streamlit as st

from scanner.scan_engine import scan_path, get_resources, get_risks, get_summary
from scanner.parser import get_resource_identity
from reporter.markdown_report import generate_markdown_report
from reporter.html_report import generate_html_report


Risk = dict[str, Any]
YamlResource = dict[str, Any]
ScanSummary = dict[str, Any]


st.set_page_config(
    page_title="kubeguard-Lite",
    page_icon="🛡️",
    layout="wide",
)


def resource_rows(resources: list[YamlResource]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for index, resource in enumerate(resources, start=1):
        identity = get_resource_identity(resource)

        rows.append({
            "序号": index,
            "Kind": identity["kind"],
            "Name": identity["name"],
            "Namespace": identity["namespace"],
            "Source File": identity["source_file"],
        })

    return rows


def risk_rows(risks: list[Risk]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for index, risk in enumerate(risks, start=1):
        actor = risk.get("subject") or risk.get("container") or "-"

        rows.append({
            "序号": index,
            "危险系数": risk.get("risk_score", "-"),
            "类别": risk.get("category", "-"),
            "等级": risk.get("level", "-"),
            "规则": risk.get("rule_id", "-"),
            "资源": risk.get("resource", "-"),
            "主体/容器": actor,
            "风险说明": risk.get("message", "-"),
            "可自动修复": "YES" if risk.get("auto_fixable") is True else "NO",
        })

    return rows


def auto_fix_rows(risks: list[Risk]) -> list[dict[str, Any]]:
    auto_fixable_risks = [
        risk for risk in risks
        if risk.get("auto_fixable") is True
    ]

    rows: list[dict[str, Any]] = []

    for index, risk in enumerate(auto_fixable_risks, start=1):
        rows.append({
            "序号": index,
            "规则": risk.get("rule_id", "-"),
            "资源": risk.get("resource", "-"),
            "风险说明": risk.get("message", "-"),
            "修复建议": risk.get("suggestion", "-"),
        })

    return rows


def render_summary(summary: ScanSummary) -> None:
    level_counts = summary.get("level_counts", {})
    category_counts = summary.get("category_counts", {})

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("风险总数", summary.get("total_risks", 0))
    col2.metric("整体危险系数", summary.get("total_score", 0))
    col3.metric("整体评级", summary.get("grade", "-"))
    col4.metric("可自动修复", summary.get("auto_fixable_count", 0))

    st.info(summary.get("grade_description", "-"))

    st.subheader("风险等级统计")
    st.dataframe(
        [
            {"等级": "HIGH", "数量": level_counts.get("HIGH", 0)},
            {"等级": "MEDIUM", "数量": level_counts.get("MEDIUM", 0)},
            {"等级": "LOW", "数量": level_counts.get("LOW", 0)},
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("风险类别统计")
    st.dataframe(
        [
            {"类别": category, "数量": count}
            for category, count in category_counts.items()
        ],
        use_container_width=True,
        hide_index=True,
    )


def render_scan_result(scan_result: dict[str, Any], target_path: str) -> None:
    resources = get_resources(scan_result)
    risks = get_risks(scan_result)
    summary = get_summary(scan_result)

    st.success("扫描完成")

    render_summary(summary)

    st.divider()

    st.subheader("Kubernetes 资源识别结果")
    st.dataframe(
        resource_rows(resources),
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    st.subheader("风险扫描结果")

    if risks:
        st.dataframe(
            risk_rows(risks),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("未发现已配置规则覆盖的 Kubernetes YAML 风险。")

    st.divider()

    st.subheader("可自动修复风险摘要")

    auto_rows = auto_fix_rows(risks)

    if auto_rows:
        st.dataframe(
            auto_rows,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("当前没有可自动修复风险。")

    st.divider()

    st.subheader("修复建议")

    for recommendation in summary.get("recommendations", []):
        st.write(f"- {recommendation}")

    st.divider()

    st.subheader("导出报告")

    markdown_report = generate_markdown_report(
        resources=resources,
        risks=risks,
        summary=summary,
        target_path=target_path,
    )

    html_report = generate_html_report(
        resources=resources,
        risks=risks,
        summary=summary,
        target_path=target_path,
    )

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            label="下载 Markdown 报告",
            data=markdown_report,
            file_name="kubeguard-report.md",
            mime="text/markdown",
        )

    with col2:
        st.download_button(
            label="下载 HTML 报告",
            data=html_report,
            file_name="kubeguard-report.html",
            mime="text/html",
        )


def scan_local_path_ui() -> None:
    st.subheader("方式一：扫描本地路径")

    path = st.text_input(
        "输入 YAML 文件或目录路径",
        value="examples",
        help="支持单个 .yaml/.yml 文件，也支持目录递归扫描。",
    )

    if st.button("开始扫描本地路径", type="primary"):
        try:
            scan_result = scan_path(Path(path))
            st.session_state["scan_result"] = scan_result
            st.session_state["target_path"] = path
        except Exception as exc:
            st.error(f"扫描失败：{exc}")


def scan_uploaded_files_ui() -> None:
    st.subheader("方式二：上传 YAML 文件")

    uploaded_files = st.file_uploader(
        "上传一个或多个 Kubernetes YAML 文件",
        type=["yaml", "yml"],
        accept_multiple_files=True,
    )

    if st.button("开始扫描上传文件", type="primary"):
        if not uploaded_files:
            st.warning("请先上传 YAML 文件。")
            return

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                for uploaded_file in uploaded_files:
                    file_path = temp_path / uploaded_file.name
                    file_path.write_bytes(uploaded_file.getvalue())

                scan_result = scan_path(temp_path)
                st.session_state["scan_result"] = scan_result
                st.session_state["target_path"] = "uploaded-files"

        except Exception as exc:
            st.error(f"扫描失败：{exc}")


def main() -> None:
    st.title("🛡️ kubeguard-Lite")
    st.caption("Kubernetes YAML 静态配置安全扫描工具")

    st.write(
        "本页面用于快速演示 kubeguard-Lite 的 Web 可视化能力。"
        "核心扫描逻辑仍然复用 scan_engine、scanner、scoring 和 reporter 模块。"
    )

    tab1, tab2 = st.tabs(["本地路径扫描", "上传文件扫描"])

    with tab1:
        scan_local_path_ui()

    with tab2:
        scan_uploaded_files_ui()

    if "scan_result" in st.session_state:
        st.divider()
        render_scan_result(
            st.session_state["scan_result"],
            st.session_state.get("target_path", "-"),
        )


if __name__ == "__main__":
    main()