from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from PySide6.QtCore import QEvent,QObject,Qt, QThread, Signal,QPoint
from PySide6.QtGui import QAction, QMouseEvent

from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QPushButton,
    QComboBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QGroupBox
)

from fixer.fix_report import generate_fix_html_report, generate_fix_markdown_report
from fixer.yaml_fixer import fix_path
from reporter.html_report import generate_html_report
from reporter.markdown_report import generate_markdown_report
from scanner.parser import get_resource_identity
from scanner.scan_engine import get_resources, get_risks, get_summary, scan_path

from desktop_help import (
    HelpDocumentDialog,
    get_design_notes_html,
    get_rule_details_html,
    get_usage_guide_html,
)

ScanResult = dict[str, Any]
FixResult = dict[str, Any]
Risk = dict[str, Any]
YamlResource = dict[str, Any]


class ScanWorker(QThread):
    """后台扫描线程，避免界面卡死。"""

    success = Signal(dict)
    failed = Signal(str)

    def __init__(self, target_path: str):
        super().__init__()
        self.target_path = target_path

    def run(self) -> None:
        try:
            result = scan_path(Path(self.target_path))
            self.success.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class FixWorker(QThread):
    """后台修复线程，避免界面卡死。"""

    success = Signal(dict)
    failed = Signal(str)

    def __init__(self, target_path: str, output_dir: str, mode: str):
        super().__init__()
        self.target_path = target_path
        self.output_dir = output_dir
        self.mode = mode

    def run(self) -> None:
        try:
            result = fix_path(
                target_path=Path(self.target_path),
                output_dir=Path(self.output_dir),
                mode=self.mode,
            )
            self.success.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class KubeguardDesktop(QMainWindow):
    """kubeguard-Lite 桌面端主窗口。"""

    def __init__(self) -> None:
        super().__init__()

        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint)

        self.drag_position = QPoint()
        self.is_dragging = False

        self.scan_result: ScanResult | None = None
        self.fix_result: FixResult | None = None

        self.scan_worker: ScanWorker | None = None
        self.fix_worker: FixWorker | None = None

        self.setWindowTitle("kubeguard-Lite 云原生 YAML 安全扫描与自动修复工具")
        self.resize(1280, 820)

        self.apply_dark_theme()
        self.init_menu()
        self.init_ui()

    # -------------------------------------------------------------------------
    # UI initialization
    # -------------------------------------------------------------------------

    def init_menu(self) -> None:
        """初始化自定义标题栏和中文菜单栏。"""
        header_widget = QWidget()
        header_widget.setObjectName("appHeader")

        header_layout = QVBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(0)

        self.title_bar = QFrame()
        self.title_bar.setObjectName("appTitleBar")
        self.title_bar.setFixedHeight(46)

        title_layout = QHBoxLayout(self.title_bar)
        title_layout.setContentsMargins(16, 0, 10, 0)
        title_layout.setSpacing(10)

        self.title_label = QLabel("🛡️ kubeguard-Lite 云原生 YAML 安全扫描与自动修复工具")
        self.title_label.setObjectName("appTitleLabel")

        title_layout.addWidget(self.title_label)
        title_layout.addStretch()

        self.minimize_button = QPushButton("—")
        self.minimize_button.setObjectName("windowControlButton")
        self.minimize_button.setFixedSize(38, 30)
        self.minimize_button.clicked.connect(self.showMinimized)

        self.maximize_button = QPushButton("□")
        self.maximize_button.setObjectName("windowControlButton")
        self.maximize_button.setFixedSize(38, 30)
        self.maximize_button.clicked.connect(self.toggle_maximize_restore)

        self.close_button = QPushButton("✕")
        self.close_button.setObjectName("windowCloseButton")
        self.close_button.setFixedSize(38, 30)
        self.close_button.clicked.connect(self.close)

        title_layout.addWidget(self.minimize_button)
        title_layout.addWidget(self.maximize_button)
        title_layout.addWidget(self.close_button)

        self.title_bar.installEventFilter(self)
        self.title_label.installEventFilter(self)

        header_layout.addWidget(self.title_bar)

        menu_bar = QMenuBar()
        menu_bar.setObjectName("appMenuBar")

        exit_menu = menu_bar.addMenu("退出")

        exit_action = QAction("退出程序", self)
        exit_action.triggered.connect(self.close)
        exit_menu.addAction(exit_action)

        help_menu = menu_bar.addMenu("帮助")

        usage_action = QAction("使用指南", self)
        usage_action.triggered.connect(self.show_usage_guide)
        help_menu.addAction(usage_action)

        rule_action = QAction("规则细则", self)
        rule_action.triggered.connect(self.show_rule_details)
        help_menu.addAction(rule_action)

        design_action = QAction("设计说明", self)
        design_action.triggered.connect(self.show_design_notes)
        help_menu.addAction(design_action)

        about_menu = menu_bar.addMenu("关于")

        about_action = QAction("关于项目", self)
        about_action.triggered.connect(self.show_about)
        about_menu.addAction(about_action)

        header_layout.addWidget(menu_bar)

        self.setMenuWidget(header_widget)

    
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        """处理自定义标题栏拖动和双击最大化。"""
        title_widgets = {
            getattr(self, "title_bar", None),
            getattr(self, "title_label", None),
        }

        if watched in title_widgets and isinstance(event, QMouseEvent):
            if event.type() == QEvent.Type.MouseButtonDblClick:
                if event.button() == Qt.MouseButton.LeftButton:
                    self.toggle_maximize_restore()
                    return True

            if event.type() == QEvent.Type.MouseButtonPress:
                if event.button() == Qt.MouseButton.LeftButton:
                    self.is_dragging = True
                    self.drag_position = (
                        event.globalPosition().toPoint()
                        - self.frameGeometry().topLeft()
                    )
                    return True

            if event.type() == QEvent.Type.MouseMove:
                if self.is_dragging and event.buttons() & Qt.MouseButton.LeftButton:
                    if not self.isMaximized():
                        self.move(event.globalPosition().toPoint() - self.drag_position)
                    return True

            if event.type() == QEvent.Type.MouseButtonRelease:
                self.is_dragging = False
                self.drag_position = QPoint()
                return True

        return super().eventFilter(watched, event)


    def toggle_maximize_restore(self) -> None:
        """最大化 / 还原主窗口。"""
        if self.isMaximized():
            self.showNormal()
            self.maximize_button.setText("□")
        else:
            self.showMaximized()
            self.maximize_button.setText("❐")


    def changeEvent(self, event: QEvent) -> None:
        """同步最大化按钮状态。"""
        super().changeEvent(event)

        if event.type() == QEvent.Type.WindowStateChange:
            if hasattr(self, "maximize_button"):
                self.maximize_button.setText("❐" if self.isMaximized() else "□")


    def apply_dark_theme(self) -> None:
        """应用紫黑色桌面端主题。"""
        self.setStyleSheet("""
        QMainWindow {
            background-color: #12081f;
        }

        QWidget {
            background-color: #12081f;
            color: #e9ddff;
            font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
            font-size: 14px;
        }

         QWidget#appHeader {
            background-color: #12081f;
        }

        QFrame#appTitleBar {
            background-color: #0b0613;
            border-bottom: 1px solid #3b2463;
        }

        QLabel#appTitleLabel {
            color: #f5f3ff;
            font-size: 15px;
            font-weight: 700;
            letter-spacing: 0.5px;
        }

        QPushButton#windowControlButton {
            background-color: transparent;
            color: #ddd6fe;
            border: 1px solid transparent;
            border-radius: 7px;
            font-size: 15px;
            font-weight: 700;
        }

        QPushButton#windowControlButton:hover {
            background-color: #312e81;
            color: #ffffff;
            border: 1px solid #6d28d9;
        }

        QPushButton#windowControlButton:pressed {
            background-color: #4c1d95;
        }

        QPushButton#windowCloseButton {
            background-color: transparent;
            color: #fecaca;
            border: 1px solid transparent;
            border-radius: 7px;
            font-size: 15px;
            font-weight: 700;
        }

        QPushButton#windowCloseButton:hover {
            background-color: #dc2626;
            color: #ffffff;
            border: 1px solid #ef4444;
        }

        QPushButton#windowCloseButton:pressed {
            background-color: #991b1b;
        }                  
                           

        QMenuBar {
            background-color: #160a27;
            color: #f1e7ff;
            padding: 5px 12px;
            border-bottom: 1px solid #3b2463;
        }
        QMenuBar::item {
            background: transparent;
            padding: 6px 14px;
            border-radius: 6px;
        }

        QMenuBar::item:selected {
            background-color: #6d28d9;
            color: #ffffff;
        }

        QMenu {
            background-color: #211138;
            color: #f1e7ff;
            border: 1px solid #5b21b6;
            padding: 6px;
        }

        QMenu::item {
            padding: 8px 24px;
            border-radius: 6px;
        }

        QMenu::item:selected {
            background-color: #7c3aed;
            color: #ffffff;
        }

        QTabWidget::pane {
            border: 1px solid #3b2463;
            border-radius: 10px;
            background-color: #170b28;
            margin-top: 6px;
        }

        QTabBar::tab {
            background-color: #211138;
            color: #c4b5fd;
            padding: 9px 18px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            margin-right: 4px;
        }

        QTabBar::tab:selected {
            background-color: #7c3aed;
            color: #ffffff;
            font-weight: 700;
        }

        QTabBar::tab:hover {
            background-color: #5b21b6;
            color: #ffffff;
        }

        QGroupBox {
            background-color: #1a0d2e;
            border: 1px solid #4c1d95;
            border-radius: 12px;
            margin-top: 14px;
            padding: 14px;
            color: #f5f3ff;
            font-weight: 700;
        }

        QGroupBox::title {
            subcontrol-origin: margin;
            left: 14px;
            padding: 0 8px;
            color: #c084fc;
        }

        QLabel {
            color: #ddd6fe;
            font-weight: 600;
        }

        QLineEdit {
            background-color: #0f172a;
            color: #f8fafc;
            border: 1px solid #6d28d9;
            border-radius: 8px;
            padding: 8px 10px;
            selection-background-color: #7c3aed;
        }

        QLineEdit:focus {
            border: 1px solid #c084fc;
            background-color: #111827;
        }

        QTextEdit {
            background-color: #0f172a;
            color: #e0f2fe;
            border: 1px solid #4c1d95;
            border-radius: 10px;
            padding: 10px;
            selection-background-color: #7c3aed;
        }

        QPushButton {
            background-color: #6d28d9;
            color: #ffffff;
            border: none;
            border-radius: 8px;
            padding: 8px 14px;
            font-weight: 700;
        }

        QPushButton:hover {
            background-color: #7c3aed;
        }

        QPushButton:pressed {
            background-color: #4c1d95;
        }

        QPushButton:disabled {
            background-color: #334155;
            color: #94a3b8;
        }

        QComboBox {
            background-color: #0f172a;
            color: #f8fafc;
            border: 1px solid #6d28d9;
            border-radius: 8px;
            padding: 7px 10px;
        }

        QComboBox:hover {
            border: 1px solid #c084fc;
        }

        QComboBox QAbstractItemView {
            background-color: #1e1b4b;
            color: #f8fafc;
            selection-background-color: #7c3aed;
        }

        QTableWidget {
            background-color: #0f172a;
            alternate-background-color: #151b32;
            color: #e5e7eb;
            gridline-color: #334155;
            border: 1px solid #4c1d95;
            border-radius: 10px;
            selection-background-color: #7c3aed;
            selection-color: #ffffff;
        }

        QHeaderView::section {
            background-color: #312e81;
            color: #ffffff;
            padding: 8px;
            border: 1px solid #4338ca;
            font-weight: 700;
        }

        QTableCornerButton::section {
            background-color: #312e81;
            border: 1px solid #4338ca;
        }

        QScrollBar:vertical {
            background-color: #12081f;
            width: 12px;
            margin: 0;
        }

        QScrollBar::handle:vertical {
            background-color: #6d28d9;
            min-height: 24px;
            border-radius: 6px;
        }

        QScrollBar::handle:vertical:hover {
            background-color: #8b5cf6;
        }

        QScrollBar:horizontal {
            background-color: #12081f;
            height: 12px;
            margin: 0;
        }

        QScrollBar::handle:horizontal {
            background-color: #6d28d9;
            min-width: 24px;
            border-radius: 6px;
        }

        QScrollBar::handle:horizontal:hover {
            background-color: #8b5cf6;
        }

        QStatusBar {
            background-color: #1b0f2e;
            color: #c4b5fd;
            border-top: 1px solid #3b2463;
        }

        QMessageBox {
            background-color: #12081f;
            color: #f5f3ff;
        }

        QMessageBox QLabel {
            color: #f5f3ff;
            font-size: 14px;
            font-weight: 500;
        }
    """)

    def init_ui(self) -> None:
        tabs = QTabWidget()

        tabs.addTab(self.build_scan_tab(), "安全扫描")
        tabs.addTab(self.build_fix_tab(), "自动修复")

        self.setCentralWidget(tabs)

    def build_scan_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        path_group = QGroupBox("扫描目标")
        path_layout = QHBoxLayout(path_group)

        self.scan_path_input = QLineEdit()
        self.scan_path_input.setPlaceholderText("选择 Kubernetes YAML 文件或目录，例如 examples/insecure")
        self.scan_path_input.setText("examples/insecure")

        choose_file_btn = QPushButton("选择文件")
        choose_file_btn.clicked.connect(self.choose_scan_file)

        choose_dir_btn = QPushButton("选择目录")
        choose_dir_btn.clicked.connect(self.choose_scan_dir)

        scan_btn = QPushButton("开始扫描")
        scan_btn.clicked.connect(self.start_scan)

        path_layout.addWidget(QLabel("路径："))
        path_layout.addWidget(self.scan_path_input, stretch=1)
        path_layout.addWidget(choose_file_btn)
        path_layout.addWidget(choose_dir_btn)
        path_layout.addWidget(scan_btn)

        layout.addWidget(path_group)

        self.scan_summary_text = QTextEdit()
        self.scan_summary_text.setReadOnly(True)
        self.scan_summary_text.setMaximumHeight(130)
        self.scan_summary_text.setPlaceholderText("扫描摘要将在这里显示。")
        layout.addWidget(self.scan_summary_text)

        self.scan_tables = QTabWidget()

        self.resource_table = QTableWidget()
        self.risk_table = QTableWidget()
        self.auto_fixable_table = QTableWidget()

        self.scan_tables.addTab(self.resource_table, "资源识别结果")
        self.scan_tables.addTab(self.risk_table, "风险扫描结果")
        self.scan_tables.addTab(self.auto_fixable_table, "可自动修复风险")

        layout.addWidget(self.scan_tables, stretch=1)

        export_group = QGroupBox("导出扫描报告")
        export_layout = QHBoxLayout(export_group)

        export_md_btn = QPushButton("导出 Markdown 扫描报告")
        export_md_btn.clicked.connect(self.export_scan_markdown)

        export_html_btn = QPushButton("导出 HTML 扫描报告")
        export_html_btn.clicked.connect(self.export_scan_html)

        export_layout.addWidget(export_md_btn)
        export_layout.addWidget(export_html_btn)
        export_layout.addStretch()

        layout.addWidget(export_group)

        return page

    def build_fix_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        input_group = QGroupBox("修复目标")
        input_layout = QHBoxLayout(input_group)

        self.fix_path_input = QLineEdit()
        self.fix_path_input.setPlaceholderText("选择 Kubernetes YAML 文件或目录，例如 examples/insecure")
        self.fix_path_input.setText("examples/insecure")

        choose_file_btn = QPushButton("选择文件")
        choose_file_btn.clicked.connect(self.choose_fix_file)

        choose_dir_btn = QPushButton("选择目录")
        choose_dir_btn.clicked.connect(self.choose_fix_dir)

        input_layout.addWidget(QLabel("路径："))
        input_layout.addWidget(self.fix_path_input, stretch=1)
        input_layout.addWidget(choose_file_btn)
        input_layout.addWidget(choose_dir_btn)

        layout.addWidget(input_group)

        config_group = QGroupBox("修复配置")
        config_layout = QHBoxLayout(config_group)

        self.fix_output_input = QLineEdit()
        self.fix_output_input.setText("fixed")
        self.fix_output_input.setPlaceholderText("选择修复后 YAML 输出目录")

        choose_output_btn = QPushButton("选择输出目录")
        choose_output_btn.clicked.connect(self.choose_fix_output_dir)

        self.fix_mode_combo = QComboBox()
        self.fix_mode_combo.addItems(["safe", "strict"])

        fix_btn = QPushButton("开始自动修复")
        fix_btn.clicked.connect(self.start_fix)

        config_layout.addWidget(QLabel("输出目录："))
        config_layout.addWidget(self.fix_output_input, stretch=1)
        config_layout.addWidget(choose_output_btn)
        config_layout.addWidget(QLabel("模式："))
        config_layout.addWidget(self.fix_mode_combo)
        config_layout.addWidget(fix_btn)

        layout.addWidget(config_group)

        self.fix_summary_text = QTextEdit()
        self.fix_summary_text.setReadOnly(True)
        self.fix_summary_text.setMaximumHeight(150)
        self.fix_summary_text.setPlaceholderText("自动修复摘要将在这里显示。")
        layout.addWidget(self.fix_summary_text)

        self.fix_tables = QTabWidget()

        self.fix_comparison_table = QTableWidget()
        self.fixed_action_table = QTableWidget()
        self.skipped_action_table = QTableWidget()
        self.fixed_residual_risk_table = QTableWidget()

        self.fix_tables.addTab(self.fix_comparison_table, "修复前后对比")
        self.fix_tables.addTab(self.fixed_action_table, "已自动修复动作")
        self.fix_tables.addTab(self.skipped_action_table, "未自动修复风险")
        self.fix_tables.addTab(self.fixed_residual_risk_table, "修复后残余风险")

        layout.addWidget(self.fix_tables, stretch=1)

        export_group = QGroupBox("导出自动修复报告")
        export_layout = QHBoxLayout(export_group)

        export_fix_md_btn = QPushButton("导出 Markdown 修复报告")
        export_fix_md_btn.clicked.connect(self.export_fix_markdown)

        export_fix_html_btn = QPushButton("导出 HTML 修复报告")
        export_fix_html_btn.clicked.connect(self.export_fix_html)

        export_layout.addWidget(export_fix_md_btn)
        export_layout.addWidget(export_fix_html_btn)
        export_layout.addStretch()

        layout.addWidget(export_group)

        return page

    # -------------------------------------------------------------------------
    # File chooser
    # -------------------------------------------------------------------------

    def choose_scan_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择 YAML 文件",
            "",
            "YAML Files (*.yaml *.yml);;All Files (*)",
        )

        if file_path:
            self.scan_path_input.setText(file_path)

    def choose_scan_dir(self) -> None:
        dir_path = QFileDialog.getExistingDirectory(self, "选择 YAML 目录")

        if dir_path:
            self.scan_path_input.setText(dir_path)

    def choose_fix_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择 YAML 文件",
            "",
            "YAML Files (*.yaml *.yml);;All Files (*)",
        )

        if file_path:
            self.fix_path_input.setText(file_path)

    def choose_fix_dir(self) -> None:
        dir_path = QFileDialog.getExistingDirectory(self, "选择 YAML 目录")

        if dir_path:
            self.fix_path_input.setText(dir_path)

    def choose_fix_output_dir(self) -> None:
        dir_path = QFileDialog.getExistingDirectory(self, "选择修复输出目录")

        if dir_path:
            self.fix_output_input.setText(dir_path)

    # -------------------------------------------------------------------------
    # Scan workflow
    # -------------------------------------------------------------------------

    def start_scan(self) -> None:
        target_path = self.scan_path_input.text().strip()

        if not target_path:
            self.show_warning("请输入扫描路径。")
            return

        self.scan_summary_text.setPlainText("正在扫描，请稍候...")
        self.statusBar().showMessage("正在扫描...")

        self.scan_worker = ScanWorker(target_path)
        self.scan_worker.success.connect(self.on_scan_success)
        self.scan_worker.failed.connect(self.on_scan_failed)
        self.scan_worker.start()

    def on_scan_success(self, result: ScanResult) -> None:
        self.scan_result = result

        self.render_scan_summary(result)
        self.render_resource_table(get_resources(result))
        self.render_risk_table(get_risks(result))
        self.render_auto_fixable_table(get_risks(result))

        self.statusBar().showMessage("扫描完成。")
        self.show_info("扫描完成。")

    def on_scan_failed(self, error_message: str) -> None:
        self.statusBar().showMessage("扫描失败。")
        self.scan_summary_text.setPlainText(f"扫描失败：{error_message}")
        self.show_error(f"扫描失败：{error_message}")

    def render_scan_summary(self, result: ScanResult) -> None:
        resources = get_resources(result)
        risks = get_risks(result)
        summary = get_summary(result)
        level_counts = summary.get("level_counts", {})
        category_counts = summary.get("category_counts", {})

        lines = [
            "kubeguard-Lite 扫描摘要",
            "",
            f"Kubernetes 资源数：{len(resources)}",
            f"风险总数：{summary.get('total_risks', len(risks))}",
            f"整体危险系数：{summary.get('total_score', 0)}",
            f"整体评级：{summary.get('grade', '-')} ({summary.get('grade_label', '-')})",
            f"评级说明：{summary.get('grade_description', '-')}",
            "",
            f"HIGH：{level_counts.get('HIGH', 0)}    MEDIUM：{level_counts.get('MEDIUM', 0)}    LOW：{level_counts.get('LOW', 0)}",
            "类别统计：" + ", ".join(
                f"{category}={count}"
                for category, count in category_counts.items()
            ),
        ]

        self.scan_summary_text.setPlainText("\n".join(lines))

    # -------------------------------------------------------------------------
    # Fix workflow
    # -------------------------------------------------------------------------

    def start_fix(self) -> None:
        target_path = self.fix_path_input.text().strip()
        output_dir = self.fix_output_input.text().strip()
        mode = self.fix_mode_combo.currentText().strip()

        if not target_path:
            self.show_warning("请输入修复目标路径。")
            return

        if not output_dir:
            self.show_warning("请输入修复输出目录。")
            return

        self.fix_summary_text.setPlainText("正在执行自动修复，请稍候...")
        self.statusBar().showMessage("正在自动修复...")

        self.fix_worker = FixWorker(target_path, output_dir, mode)
        self.fix_worker.success.connect(self.on_fix_success)
        self.fix_worker.failed.connect(self.on_fix_failed)
        self.fix_worker.start()

    def on_fix_success(self, result: FixResult) -> None:
        self.fix_result = result

        self.render_fix_summary(result)
        self.render_fix_comparison_table(result)
        self.render_fixed_action_table(result)
        self.render_skipped_action_table(result)
        self.render_fixed_residual_risk_table(result)

        self.statusBar().showMessage("自动修复完成。")
        self.show_info("自动修复完成。")

    def on_fix_failed(self, error_message: str) -> None:
        self.statusBar().showMessage("自动修复失败。")
        self.fix_summary_text.setPlainText(f"自动修复失败：{error_message}")
        self.show_error(f"自动修复失败：{error_message}")

    def render_fix_summary(self, result: FixResult) -> None:
        fix_summary = result["fix_summary"]
        original_scan_result = result["scan_result"]
        fixed_scan_result = result["fixed_scan_result"]

        original_summary = get_summary(original_scan_result)
        fixed_summary = get_summary(fixed_scan_result)

        lines = [
            "kubeguard-Lite 自动修复摘要",
            "",
            f"修复模式：{fix_summary.get('mode', '-')}",
            f"已自动修复动作数：{fix_summary.get('fixed_count', 0)}",
            f"未自动修复风险数：{fix_summary.get('skipped_count', 0)}",
            f"写入文件数：{fix_summary.get('written_file_count', 0)}",
            "",
            f"修复前风险总数：{original_summary.get('total_risks', 0)}",
            f"修复后风险总数：{fixed_summary.get('total_risks', 0)}",
            f"修复前危险系数：{original_summary.get('total_score', 0)}",
            f"修复后危险系数：{fixed_summary.get('total_score', 0)}",
            f"修复前评级：{original_summary.get('grade', '-')}",
            f"修复后评级：{fixed_summary.get('grade', '-')}",
            "",
            "输出文件：",
        ]

        written_files = fix_summary.get("written_files", [])

        if isinstance(written_files, list) and written_files:
            lines.extend(f"- {file_path}" for file_path in written_files)
        else:
            lines.append("- 无")

        self.fix_summary_text.setPlainText("\n".join(lines))

    # -------------------------------------------------------------------------
    # Table render helpers
    # -------------------------------------------------------------------------

    def setup_table(self, table: QTableWidget, headers: list[str], rows: list[list[Any]]) -> None:
        table.clear()
        table.setRowCount(len(rows))
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(False)

        for row_index, row in enumerate(rows):
            for col_index, value in enumerate(row):
                item = QTableWidgetItem(self.value_to_text(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(row_index, col_index, item)

        table.resizeColumnsToContents()

    def render_resource_table(self, resources: list[YamlResource]) -> None:
        headers = ["序号", "Kind", "Name", "Namespace", "Source File"]
        rows: list[list[Any]] = []

        for index, resource in enumerate(resources, start=1):
            identity = get_resource_identity(resource)

            rows.append([
                index,
                identity["kind"],
                identity["name"],
                identity["namespace"],
                identity["source_file"],
            ])

        self.setup_table(self.resource_table, headers, rows)

    def render_risk_table(self, risks: list[Risk]) -> None:
        headers = ["序号", "危险系数", "类别", "等级", "规则", "资源", "主体/容器", "风险说明"]
        rows: list[list[Any]] = []

        for index, risk in enumerate(risks, start=1):
            actor = risk.get("subject") or risk.get("container") or "-"

            rows.append([
                index,
                risk.get("risk_score", "-"),
                risk.get("category", "-"),
                risk.get("level", "-"),
                risk.get("rule_id", "-"),
                risk.get("resource", "-"),
                actor,
                risk.get("message", "-"),
            ])

        self.setup_table(self.risk_table, headers, rows)

    def render_auto_fixable_table(self, risks: list[Risk]) -> None:
        headers = ["序号", "规则", "资源", "风险说明", "修复建议"]
        rows: list[list[Any]] = []

        auto_fixable_risks = [
            risk for risk in risks
            if risk.get("auto_fixable") is True
        ]

        for index, risk in enumerate(auto_fixable_risks, start=1):
            rows.append([
                index,
                risk.get("rule_id", "-"),
                risk.get("resource", "-"),
                risk.get("message", "-"),
                risk.get("suggestion", "-"),
            ])

        self.setup_table(self.auto_fixable_table, headers, rows)

    def render_fix_comparison_table(self, result: FixResult) -> None:
        original_summary = get_summary(result["scan_result"])
        fixed_summary = get_summary(result["fixed_scan_result"])

        before_levels = original_summary.get("level_counts", {})
        after_levels = fixed_summary.get("level_counts", {})

        headers = ["项目", "修复前", "修复后", "变化"]
        rows = [
            [
                "HIGH",
                before_levels.get("HIGH", 0),
                after_levels.get("HIGH", 0),
                int(after_levels.get("HIGH", 0)) - int(before_levels.get("HIGH", 0)),
            ],
            [
                "MEDIUM",
                before_levels.get("MEDIUM", 0),
                after_levels.get("MEDIUM", 0),
                int(after_levels.get("MEDIUM", 0)) - int(before_levels.get("MEDIUM", 0)),
            ],
            [
                "LOW",
                before_levels.get("LOW", 0),
                after_levels.get("LOW", 0),
                int(after_levels.get("LOW", 0)) - int(before_levels.get("LOW", 0)),
            ],
            [
                "TOTAL",
                original_summary.get("total_risks", 0),
                fixed_summary.get("total_risks", 0),
                int(fixed_summary.get("total_risks", 0)) - int(original_summary.get("total_risks", 0)),
            ],
            [
                "Score",
                original_summary.get("total_score", 0),
                fixed_summary.get("total_score", 0),
                int(fixed_summary.get("total_score", 0)) - int(original_summary.get("total_score", 0)),
            ],
            [
                "Grade",
                original_summary.get("grade", "-"),
                fixed_summary.get("grade", "-"),
                "-",
            ],
        ]

        self.setup_table(self.fix_comparison_table, headers, rows)

    def render_fixed_action_table(self, result: FixResult) -> None:
        fix_summary = result["fix_summary"]
        actions = fix_summary.get("fixed_actions", [])

        if not isinstance(actions, list):
            actions = []

        headers = ["序号", "规则", "资源", "路径", "旧值", "新值", "说明"]
        rows: list[list[Any]] = []

        for index, action in enumerate(actions, start=1):
            rows.append([
                index,
                action.get("rule_id", "-"),
                action.get("resource", "-"),
                action.get("path", "-"),
                action.get("old_value", "-"),
                action.get("new_value", "-"),
                action.get("message", "-"),
            ])

        self.setup_table(self.fixed_action_table, headers, rows)

    def render_skipped_action_table(self, result: FixResult) -> None:
        fix_summary = result["fix_summary"]
        actions = fix_summary.get("skipped_actions", [])

        if not isinstance(actions, list):
            actions = []

        headers = ["序号", "规则", "资源", "路径", "原因"]
        rows: list[list[Any]] = []

        for index, action in enumerate(actions, start=1):
            rows.append([
                index,
                action.get("rule_id", "-"),
                action.get("resource", "-"),
                action.get("path", "-"),
                action.get("message", "-"),
            ])

        self.setup_table(self.skipped_action_table, headers, rows)

    def render_fixed_residual_risk_table(self, result: FixResult) -> None:
        fixed_scan_result = result["fixed_scan_result"]
        risks = get_risks(fixed_scan_result)

        headers = ["序号", "危险系数", "类别", "等级", "规则", "资源", "风险说明"]
        rows: list[list[Any]] = []

        for index, risk in enumerate(risks, start=1):
            rows.append([
                index,
                risk.get("risk_score", "-"),
                risk.get("category", "-"),
                risk.get("level", "-"),
                risk.get("rule_id", "-"),
                risk.get("resource", "-"),
                risk.get("message", "-"),
            ])

        self.setup_table(self.fixed_residual_risk_table, headers, rows)

    # -------------------------------------------------------------------------
    # Export scan reports
    # -------------------------------------------------------------------------

    def export_scan_markdown(self) -> None:
        if self.scan_result is None:
            self.show_warning("请先执行扫描。")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "保存 Markdown 扫描报告",
            "kubeguard-scan-report.md",
            "Markdown Files (*.md);;All Files (*)",
        )

        if not file_path:
            return

        resources = get_resources(self.scan_result)
        risks = get_risks(self.scan_result)
        summary = get_summary(self.scan_result)

        content = generate_markdown_report(
            resources=resources,
            risks=risks,
            summary=summary,
            target_path=self.scan_path_input.text().strip(),
        )

        self.write_text_file(file_path, content)

    def export_scan_html(self) -> None:
        if self.scan_result is None:
            self.show_warning("请先执行扫描。")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "保存 HTML 扫描报告",
            "kubeguard-scan-report.html",
            "HTML Files (*.html);;All Files (*)",
        )

        if not file_path:
            return

        resources = get_resources(self.scan_result)
        risks = get_risks(self.scan_result)
        summary = get_summary(self.scan_result)

        content = generate_html_report(
            resources=resources,
            risks=risks,
            summary=summary,
            target_path=self.scan_path_input.text().strip(),
        )

        self.write_text_file(file_path, content)

    # -------------------------------------------------------------------------
    # Export fix reports
    # -------------------------------------------------------------------------

    def export_fix_markdown(self) -> None:
        if self.fix_result is None:
            self.show_warning("请先执行自动修复。")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "保存 Markdown 自动修复报告",
            "kubeguard-fix-report.md",
            "Markdown Files (*.md);;All Files (*)",
        )

        if not file_path:
            return

        content = generate_fix_markdown_report(
            fix_summary=self.fix_result["fix_summary"],
            original_scan_result=self.fix_result["scan_result"],
            fixed_scan_result=self.fix_result["fixed_scan_result"],
            target_path=self.fix_path_input.text().strip(),
            output_dir=self.fix_output_input.text().strip(),
        )

        self.write_text_file(file_path, content)

    def export_fix_html(self) -> None:
        if self.fix_result is None:
            self.show_warning("请先执行自动修复。")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "保存 HTML 自动修复报告",
            "kubeguard-fix-report.html",
            "HTML Files (*.html);;All Files (*)",
        )

        if not file_path:
            return

        content = generate_fix_html_report(
            fix_summary=self.fix_result["fix_summary"],
            original_scan_result=self.fix_result["scan_result"],
            fixed_scan_result=self.fix_result["fixed_scan_result"],
            target_path=self.fix_path_input.text().strip(),
            output_dir=self.fix_output_input.text().strip(),
        )

        self.write_text_file(file_path, content)

    # -------------------------------------------------------------------------
    # Misc helpers
    # -------------------------------------------------------------------------

    def write_text_file(self, file_path: str, content: str) -> None:
        try:
            Path(file_path).write_text(content, encoding="utf-8")
            self.show_info(f"文件已保存：{file_path}")
        except Exception as exc:
            self.show_error(f"保存失败：{exc}")

    def value_to_text(self, value: Any) -> str:
        if value is None:
            return "-"

        if isinstance(value, bool):
            return "true" if value else "false"

        return str(value)

    def show_info(self, message: str) -> None:
        QMessageBox.information(self, "kubeguard-Lite", message)

    def show_warning(self, message: str) -> None:
        QMessageBox.warning(self, "kubeguard-Lite", message)

    def show_error(self, message: str) -> None:
        QMessageBox.critical(self, "kubeguard-Lite", message)

    def show_about(self) -> None:
        QMessageBox.information(
            self,
            "关于 kubeguard-Lite",
            "kubeguard-Lite Desktop\n\n"
            "Kubernetes YAML 静态配置安全扫描与自动修复工具。\n\n"
            "本项目属于教学式云原生环境下的配置风险扫描工具。\n\n"
            "在 Kubernetes 场景中，大量安全风险来自错误配置，例如 "
            "privileged 容器、hostPath 挂载、ServiceAccount 过权、latest 镜像等。\n\n"
            "该工具通过静态分析 Kubernetes YAML 文件，在资源部署前识别潜在攻击面，"
            "并自动修改部分危险配置，属于面向云原生环境的安全检测工具。"
        )

    def show_help_document(self, title: str, html: str) -> None:
        dialog = HelpDocumentDialog(title, html, self)
        dialog.exec()


    def show_usage_guide(self) -> None:
        self.show_help_document(
            "使用指南",
            get_usage_guide_html(),
        )


    def show_rule_details(self) -> None:
        self.show_help_document(
            "规则细则",
            get_rule_details_html(),
        )


    def show_design_notes(self) -> None:
        self.show_help_document(
            "设计说明",
            get_design_notes_html(),
        )

def main() -> None:
    app = QApplication(sys.argv)

    window = KubeguardDesktop()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()