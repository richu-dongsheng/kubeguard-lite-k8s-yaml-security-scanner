from __future__ import annotations

from io import BytesIO
from pathlib import Path
import tempfile
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

import streamlit as st

from fixer.fix_report import generate_fix_html_report, generate_fix_markdown_report
from fixer.yaml_fixer import fix_path
from reporter.html_report import generate_html_report
from reporter.markdown_report import generate_markdown_report
from scanner.parser import get_resource_identity
from scanner.scan_engine import get_resources, get_risks, get_summary, scan_path


Risk = dict[str, Any]
YamlResource = dict[str, Any]
ScanSummary = dict[str, Any]
ScanResult = dict[str, Any]
FixSummary = dict[str, Any]


st.set_page_config(
    page_title="kubeguard-Lite",
    page_icon="🛡️",
    layout="wide",
)


# -----------------------------------------------------------------------------
# Row builders
# -----------------------------------------------------------------------------


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


def fix_action_rows(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for index, action in enumerate(actions, start=1):
        rows.append({
            "序号": index,
            "状态": action.get("status", "-"),
            "规则": action.get("rule_id", "-"),
            "资源": action.get("resource", "-"),
            "路径": action.get("path", "-"),
            "旧值": action.get("old_value", "-"),
            "新值": action.get("new_value", "-"),
            "说明": action.get("message", "-"),
        })

    return rows


def skipped_action_rows(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for index, action in enumerate(actions, start=1):
        rows.append({
            "序号": index,
            "状态": action.get("status", "-"),
            "规则": action.get("rule_id", "-"),
            "资源": action.get("resource", "-"),
            "路径": action.get("path", "-"),
            "原因": action.get("message", "-"),
        })

    return rows


def written_file_rows(written_files: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for index, file_path in enumerate(written_files, start=1):
        rows.append({
            "序号": index,
            "文件路径": str(file_path),
        })

    return rows


# -----------------------------------------------------------------------------
# Utility helpers
# -----------------------------------------------------------------------------


def write_uploaded_files(uploaded_files: list[Any], target_dir: Path) -> None:
    """把 Streamlit 上传文件写入临时目录。"""
    target_dir.mkdir(parents=True, exist_ok=True)

    for uploaded_file in uploaded_files:
        safe_name = Path(uploaded_file.name).name
        file_path = target_dir / safe_name
        file_path.write_bytes(uploaded_file.getvalue())


def build_zip_bytes(directory: Path) -> bytes:
    """把目录打包成 zip bytes，用于 Streamlit 下载。"""
    buffer = BytesIO()

    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as zip_file:
        for file_path in directory.rglob("*"):
            if file_path.is_file():
                arcname = file_path.relative_to(directory)
                zip_file.write(file_path, arcname=str(arcname))

    return buffer.getvalue()


def get_fix_lists(fix_summary: FixSummary) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[Any]]:
    fixed_actions = fix_summary.get("fixed_actions", [])
    skipped_actions = fix_summary.get("skipped_actions", [])
    written_files = fix_summary.get("written_files", [])

    if not isinstance(fixed_actions, list):
        fixed_actions = []

    if not isinstance(skipped_actions, list):
        skipped_actions = []

    if not isinstance(written_files, list):
        written_files = []

    return fixed_actions, skipped_actions, written_files


# -----------------------------------------------------------------------------
# Render scan result
# -----------------------------------------------------------------------------


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


def render_scan_result(scan_result: ScanResult, target_path: str) -> None:
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

    st.subheader("导出扫描报告")

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
            label="下载 Markdown 扫描报告",
            data=markdown_report,
            file_name="kubeguard-scan-report.md",
            mime="text/markdown",
        )

    with col2:
        st.download_button(
            label="下载 HTML 扫描报告",
            data=html_report,
            file_name="kubeguard-scan-report.html",
            mime="text/html",
        )


# -----------------------------------------------------------------------------
# Render fix result
# -----------------------------------------------------------------------------


def render_fix_comparison(original_scan_result: ScanResult, fixed_scan_result: ScanResult) -> None:
    original_summary = get_summary(original_scan_result)
    fixed_summary = get_summary(fixed_scan_result)

    before_level_counts = original_summary.get("level_counts", {})
    after_level_counts = fixed_summary.get("level_counts", {})

    st.subheader("修复前后对比")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "风险总数",
        fixed_summary.get("total_risks", 0),
        delta=int(fixed_summary.get("total_risks", 0)) - int(original_summary.get("total_risks", 0)),
    )
    col2.metric(
        "整体危险系数",
        fixed_summary.get("total_score", 0),
        delta=int(fixed_summary.get("total_score", 0)) - int(original_summary.get("total_score", 0)),
    )
    col3.metric(
        "整体评级",
        fixed_summary.get("grade", "-"),
    )
    col4.metric(
        "HIGH 风险",
        after_level_counts.get("HIGH", 0),
        delta=int(after_level_counts.get("HIGH", 0)) - int(before_level_counts.get("HIGH", 0)),
    )

    comparison_rows = [
        {
            "等级": "HIGH",
            "修复前": before_level_counts.get("HIGH", 0),
            "修复后": after_level_counts.get("HIGH", 0),
            "变化": int(after_level_counts.get("HIGH", 0)) - int(before_level_counts.get("HIGH", 0)),
        },
        {
            "等级": "MEDIUM",
            "修复前": before_level_counts.get("MEDIUM", 0),
            "修复后": after_level_counts.get("MEDIUM", 0),
            "变化": int(after_level_counts.get("MEDIUM", 0)) - int(before_level_counts.get("MEDIUM", 0)),
        },
        {
            "等级": "LOW",
            "修复前": before_level_counts.get("LOW", 0),
            "修复后": after_level_counts.get("LOW", 0),
            "变化": int(after_level_counts.get("LOW", 0)) - int(before_level_counts.get("LOW", 0)),
        },
        {
            "等级": "TOTAL",
            "修复前": original_summary.get("total_risks", 0),
            "修复后": fixed_summary.get("total_risks", 0),
            "变化": int(fixed_summary.get("total_risks", 0)) - int(original_summary.get("total_risks", 0)),
        },
    ]

    st.dataframe(
        comparison_rows,
        use_container_width=True,
        hide_index=True,
    )


def render_fix_result(fix_result: dict[str, Any], target_path: str, output_dir: str) -> None:
    fix_summary = fix_result["fix_summary"]
    original_scan_result = fix_result["scan_result"]
    fixed_scan_result = fix_result["fixed_scan_result"]

    fixed_actions, skipped_actions, written_files = get_fix_lists(fix_summary)

    st.success("自动修复完成")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("修复模式", fix_summary.get("mode", "-"))
    col2.metric("已修复动作数", fix_summary.get("fixed_count", 0))
    col3.metric("未自动修复风险数", fix_summary.get("skipped_count", 0))
    col4.metric("写入文件数", fix_summary.get("written_file_count", 0))

    st.divider()

    render_fix_comparison(original_scan_result, fixed_scan_result)

    st.divider()

    st.subheader("已自动修复动作")

    if fixed_actions:
        st.dataframe(
            fix_action_rows(fixed_actions),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("本次没有执行自动修复动作。")

    st.divider()

    st.subheader("未自动修复风险")

    if skipped_actions:
        st.dataframe(
            skipped_action_rows(skipped_actions),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("本次没有未自动修复风险。")

    st.divider()

    st.subheader("输出文件")

    if written_files:
        st.dataframe(
            written_file_rows(written_files),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("本次没有写入修复后的 YAML 文件。")

    st.divider()

    st.subheader("修复后残余风险")

    fixed_risks = get_risks(fixed_scan_result)

    if fixed_risks:
        st.dataframe(
            risk_rows(fixed_risks),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("修复后未发现已配置规则覆盖的残余风险。")

    st.divider()

    st.subheader("下载自动修复报告")

    fix_markdown_report = generate_fix_markdown_report(
        fix_summary=fix_summary,
        original_scan_result=original_scan_result,
        fixed_scan_result=fixed_scan_result,
        target_path=target_path,
        output_dir=output_dir,
    )

    fix_html_report = generate_fix_html_report(
        fix_summary=fix_summary,
        original_scan_result=original_scan_result,
        fixed_scan_result=fixed_scan_result,
        target_path=target_path,
        output_dir=output_dir,
    )

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            label="下载 Markdown 自动修复报告",
            data=fix_markdown_report,
            file_name="kubeguard-fix-report.md",
            mime="text/markdown",
        )

    with col2:
        st.download_button(
            label="下载 HTML 自动修复报告",
            data=fix_html_report,
            file_name="kubeguard-fix-report.html",
            mime="text/html",
        )

    fixed_zip_data = st.session_state.get("fixed_zip_data")

    if fixed_zip_data:
        st.download_button(
            label="下载修复后的 YAML ZIP",
            data=fixed_zip_data,
            file_name="kubeguard-fixed-yaml.zip",
            mime="application/zip",
        )


# -----------------------------------------------------------------------------
# Scan UI
# -----------------------------------------------------------------------------


def scan_local_path_ui() -> None:
    st.subheader("方式一：扫描本地路径")

    path = st.text_input(
        "输入 YAML 文件或目录路径",
        value="examples/insecure",
        help="支持单个 .yaml/.yml 文件，也支持目录递归扫描。",
        key="scan_local_path",
    )

    if st.button("开始扫描本地路径", type="primary"):
        try:
            scan_result = scan_path(Path(path))
            st.session_state["scan_result"] = scan_result
            st.session_state["scan_target_path"] = path
        except Exception as exc:
            st.error(f"扫描失败：{exc}")


def scan_uploaded_files_ui() -> None:
    st.subheader("方式二：上传 YAML 文件扫描")

    uploaded_files = st.file_uploader(
        "上传一个或多个 Kubernetes YAML 文件",
        type=["yaml", "yml"],
        accept_multiple_files=True,
        key="scan_uploaded_files",
    )

    if st.button("开始扫描上传文件", type="primary"):
        if not uploaded_files:
            st.warning("请先上传 YAML 文件。")
            return

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                write_uploaded_files(uploaded_files, temp_path)

                scan_result = scan_path(temp_path)

                st.session_state["scan_result"] = scan_result
                st.session_state["scan_target_path"] = "uploaded-files"

        except Exception as exc:
            st.error(f"扫描失败：{exc}")


# -----------------------------------------------------------------------------
# Fix UI
# -----------------------------------------------------------------------------


def fix_local_path_ui() -> None:
    st.subheader("方式一：修复本地路径")

    path = st.text_input(
        "输入 YAML 文件或目录路径",
        value="examples/insecure",
        help="支持单个 .yaml/.yml 文件，也支持目录递归修复。",
        key="fix_local_path",
    )

    output_dir = st.text_input(
        "修复后 YAML 输出目录",
        value="fixed",
        key="fix_local_output",
    )

    mode = st.radio(
        "修复模式",
        options=["safe", "strict"],
        index=0,
        horizontal=True,
        key="fix_local_mode",
        help="safe 模式更保守；strict 模式会额外修改可能影响业务行为的字段。",
    )

    if st.button("开始自动修复本地路径", type="primary"):
        try:
            fix_result = fix_path(
                target_path=Path(path),
                output_dir=Path(output_dir),
                mode=mode,
            )

            st.session_state["fix_result"] = fix_result
            st.session_state["fix_target_path"] = path
            st.session_state["fix_output_dir"] = output_dir
            st.session_state["fixed_zip_data"] = None

        except Exception as exc:
            st.error(f"自动修复失败：{exc}")


def fix_uploaded_files_ui() -> None:
    st.subheader("方式二：上传 YAML 文件修复")

    uploaded_files = st.file_uploader(
        "上传一个或多个 Kubernetes YAML 文件",
        type=["yaml", "yml"],
        accept_multiple_files=True,
        key="fix_uploaded_files",
    )

    mode = st.radio(
        "修复模式",
        options=["safe", "strict"],
        index=0,
        horizontal=True,
        key="fix_uploaded_mode",
        help="safe 模式更保守；strict 模式会额外修改可能影响业务行为的字段。",
    )

    if st.button("开始自动修复上传文件", type="primary"):
        if not uploaded_files:
            st.warning("请先上传 YAML 文件。")
            return

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_root = Path(temp_dir)
                input_dir = temp_root / "input"
                output_dir = temp_root / "fixed"

                write_uploaded_files(uploaded_files, input_dir)

                fix_result = fix_path(
                    target_path=input_dir,
                    output_dir=output_dir,
                    mode=mode,
                )

                fixed_zip_data = build_zip_bytes(output_dir)

                st.session_state["fix_result"] = fix_result
                st.session_state["fix_target_path"] = "uploaded-files"
                st.session_state["fix_output_dir"] = "fixed-uploaded-files"
                st.session_state["fixed_zip_data"] = fixed_zip_data

        except Exception as exc:
            st.error(f"自动修复失败：{exc}")


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------


def main() -> None:
    st.title("🛡️ kubeguard-Lite")
    st.caption("Kubernetes YAML 静态配置安全扫描与自动修复工具")

    st.write(
        "本页面用于快速演示 kubeguard-Lite 的 Web 可视化能力。"
        "核心扫描、评分、报告和修复逻辑均复用项目后端模块。"
    )

    scan_tab, fix_tab = st.tabs(["安全扫描", "自动修复"])

    with scan_tab:
        scan_mode_tab1, scan_mode_tab2 = st.tabs(["本地路径扫描", "上传文件扫描"])

        with scan_mode_tab1:
            scan_local_path_ui()

        with scan_mode_tab2:
            scan_uploaded_files_ui()

        if "scan_result" in st.session_state:
            st.divider()
            render_scan_result(
                st.session_state["scan_result"],
                st.session_state.get("scan_target_path", "-"),
            )

    with fix_tab:
        fix_mode_tab1, fix_mode_tab2 = st.tabs(["本地路径修复", "上传文件修复"])

        with fix_mode_tab1:
            fix_local_path_ui()

        with fix_mode_tab2:
            fix_uploaded_files_ui()

        if "fix_result" in st.session_state:
            st.divider()
            render_fix_result(
                st.session_state["fix_result"],
                st.session_state.get("fix_target_path", "-"),
                st.session_state.get("fix_output_dir", "-"),
            )


if __name__ == "__main__":
    main()