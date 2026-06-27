from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from PySide6.QtCore import Qt, QPoint
from PySide6.QtWidgets import (
    QDialog, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextBrowser, QFrame
)


def build_help_html(title: str, subtitle: str, content: str) -> str:
    """生成统一风格的帮助文档 HTML。"""
    return f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<style>
    body {{
        background-color: #10071c;
        color: #efe9ff;
        font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
        font-size: 14px;
        line-height: 1.75;
        margin: 0;
        padding: 0;
    }}

    .page {{
        padding: 28px 34px 42px 34px;
    }}

    .hero {{
        background-color: #1f1035;
        border: 1px solid #6d28d9;
        border-radius: 14px;
        padding: 24px 28px;
        margin-bottom: 24px;
    }}

    h1 {{
        color: #ffffff;
        font-size: 28px;
        margin: 0 0 8px 0;
    }}

    .subtitle {{
        color: #c4b5fd;
        font-size: 15px;
        margin-top: 6px;
    }}

    h2 {{
        color: #d8b4fe;
        font-size: 22px;
        border-left: 5px solid #8b5cf6;
        padding-left: 12px;
        margin-top: 30px;
        margin-bottom: 14px;
    }}

    h3 {{
        color: #93c5fd;
        font-size: 18px;
        margin-top: 22px;
        margin-bottom: 10px;
    }}

    p {{
        margin: 8px 0;
    }}

    ul, ol {{
        margin-top: 8px;
        margin-bottom: 14px;
        padding-left: 28px;
    }}

    li {{
        margin: 6px 0;
    }}

    table {{
        border-collapse: collapse;
        width: 100%;
        margin: 14px 0 22px 0;
        background-color: #0f172a;
        color: #e5e7eb;
        font-size: 13px;
    }}

    th {{
        background-color: #312e81;
        color: #ffffff;
        font-weight: 700;
        padding: 9px 10px;
        border: 1px solid #4c1d95;
    }}

    td {{
        padding: 8px 10px;
        border: 1px solid #334155;
        vertical-align: top;
    }}

    tr:nth-child(even) td {{
        background-color: #151b32;
    }}

    code {{
        background-color: #1e1b4b;
        color: #fef08a;
        padding: 2px 6px;
        border-radius: 5px;
        font-family: Consolas, "Courier New", monospace;
    }}

    .note {{
        background-color: #172554;
        border-left: 5px solid #60a5fa;
        padding: 12px 16px;
        border-radius: 8px;
        margin: 16px 0;
        color: #dbeafe;
    }}

    .warning {{
        background-color: #451a03;
        border-left: 5px solid #f59e0b;
        padding: 12px 16px;
        border-radius: 8px;
        margin: 16px 0;
        color: #ffedd5;
    }}

    .danger {{
        color: #fca5a5;
        font-weight: 700;
    }}

    .medium {{
        color: #fde68a;
        font-weight: 700;
    }}

    .low {{
        color: #bfdbfe;
        font-weight: 700;
    }}
</style>
</head>
<body>
<div class="page">
    <div class="hero">
        <h1>{title}</h1>
        <div class="subtitle">{subtitle}</div>
    </div>

    {content}
</div>
</body>
</html>
"""


class HelpDocumentDialog(QDialog):
    def __init__(self, title: str, html: str, parent=None) -> None:
        super().__init__(parent)

        self.drag_position = QPoint()

        # 去掉系统白色边框和标题栏
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

        self.setModal(True)
        self.resize(1100, 760)

        # ===== 最外层布局（透明背景 + 留边距）=====
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(14, 14, 14, 14)
        outer_layout.setSpacing(0)

        # ===== 主容器 =====
        self.container = QFrame()
        self.container.setObjectName("helpContainer")
        outer_layout.addWidget(self.container)

        container_layout = QVBoxLayout(self.container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)

        # ===== 自定义标题栏 =====
        self.title_bar = QFrame()
        self.title_bar.setObjectName("helpTitleBar")
        title_layout = QHBoxLayout(self.title_bar)
        title_layout.setContentsMargins(18, 12, 12, 12)
        title_layout.setSpacing(10)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("helpTitleLabel")

        title_layout.addWidget(self.title_label)
        title_layout.addStretch()

        self.close_button = QPushButton("✕")
        self.close_button.setObjectName("helpCloseButton")
        self.close_button.setFixedSize(36, 36)
        self.close_button.clicked.connect(self.close)
        title_layout.addWidget(self.close_button)

        container_layout.addWidget(self.title_bar)

        # ===== 文档显示区 =====
        self.browser = QTextBrowser()
        self.browser.setObjectName("helpBrowser")
        self.browser.setOpenExternalLinks(True)
        self.browser.setHtml(html)
        container_layout.addWidget(self.browser)

        # ===== 样式 =====
        self.setStyleSheet("""
            QFrame#helpContainer {
                background-color: #12051f;
                border: 2px solid #7b2cff;
                border-radius: 16px;
            }

            QFrame#helpTitleBar {
                background-color: #24103d;
                border-top-left-radius: 16px;
                border-top-right-radius: 16px;
                border-bottom: 1px solid #7b2cff;
            }

            QLabel#helpTitleLabel {
                color: #f5ecff;
                font-size: 22px;
                font-weight: 700;
            }

            QPushButton#helpCloseButton {
                background-color: transparent;
                color: #f5ecff;
                border: 1px solid #8b5cf6;
                border-radius: 8px;
                font-size: 18px;
                font-weight: bold;
            }

            QPushButton#helpCloseButton:hover {
                background-color: #7b2cff;
                color: white;
            }

            QTextBrowser#helpBrowser {
                background-color: #140022;
                color: #f3e8ff;
                border: none;
                padding: 18px;
                font-size: 15px;
                line-height: 1.8;
                selection-background-color: #7b2cff;
                selection-color: white;
            }

            QTextBrowser#helpBrowser QScrollBar:vertical {
                background: #1c0d2e;
                width: 12px;
                margin: 8px 4px 8px 0;
                border-radius: 6px;
            }

            QTextBrowser#helpBrowser QScrollBar::handle:vertical {
                background: #7b2cff;
                min-height: 30px;
                border-radius: 6px;
            }

            QTextBrowser#helpBrowser QScrollBar::handle:vertical:hover {
                background: #9d5cff;
            }

            QTextBrowser#helpBrowser QScrollBar::add-line:vertical,
            QTextBrowser#helpBrowser QScrollBar::sub-line:vertical {
                height: 0px;
            }

            QTextBrowser#helpBrowser QScrollBar::add-page:vertical,
            QTextBrowser#helpBrowser QScrollBar::sub-page:vertical {
                background: transparent;
            }
        """)
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            if self.title_bar.geometry().contains(event.position().toPoint()):
                self.drag_position = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
                event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.MouseButton.LeftButton and not self.drag_position.isNull():
            self.move(event.globalPosition().toPoint() - self.drag_position)
            event.accept()

    def mouseReleaseEvent(self, event):
        self.drag_position = QPoint()
        event.accept()



def get_usage_guide_html() -> str:
    content = """
<h2>一、工具定位</h2>
<p>
kubeguard-Lite 是一款面向 Kubernetes 场景的 YAML 静态配置风险扫描与自动修复工具。
它的主要目标是在资源部署前，对 Kubernetes YAML 文件进行安全检查，提前发现常见错误配置。
</p>

<div class="note">
本工具适合本地开发、课程项目展示、云原生安全学习、部署前配置审计等场景。
</div>

<h2>二、基本使用流程</h2>

<h3>1. 安全扫描</h3>
<ol>
    <li>打开桌面程序，进入 <code>安全扫描</code> 页面。</li>
    <li>在路径输入框中输入 YAML 文件或目录路径。</li>
    <li>也可以点击 <code>选择文件</code> 选择单个 YAML 文件。</li>
    <li>也可以点击 <code>选择目录</code> 选择包含多个 YAML 文件的目录。</li>
    <li>点击 <code>开始扫描</code>。</li>
    <li>扫描完成后查看资源识别结果、风险扫描结果和可自动修复风险列表。</li>
</ol>

<p>扫描结果包括：</p>
<ul>
    <li>Kubernetes 资源数量</li>
    <li>风险总数</li>
    <li>整体危险系数</li>
    <li>整体评级</li>
    <li>HIGH / MEDIUM / LOW 风险数量</li>
    <li>Workload / RBAC / Service 等类别统计</li>
</ul>

<h3>2. 导出扫描报告</h3>
<p>
扫描完成后，可以导出 Markdown 或 HTML 扫描报告。
Markdown 适合写入课程文档、GitHub README 或实验报告。
HTML 适合直接在浏览器中查看，也适合截图和答辩展示。
</p>

<h2>三、自动修复</h2>

<ol>
    <li>进入 <code>自动修复</code> 页面。</li>
    <li>输入需要修复的 YAML 文件或目录。</li>
    <li>选择修复后 YAML 的输出目录。</li>
    <li>选择修复模式。</li>
    <li>点击 <code>开始自动修复</code>。</li>
</ol>

<div class="warning">
自动修复不会覆盖原始 YAML 文件，而是将修复后的 YAML 写入指定输出目录。
建议修复前确保原始文件已经纳入 Git 管理或完成备份。
</div>

<h2>四、修复模式说明</h2>

<h3>1. safe 模式</h3>
<p>safe 模式是默认推荐模式，只修改相对明确、较少依赖业务上下文的危险配置。</p>

<ul>
    <li><code>hostNetwork: true</code> 修改为 <code>false</code></li>
    <li><code>hostPID: true</code> 修改为 <code>false</code></li>
    <li><code>hostIPC: true</code> 修改为 <code>false</code></li>
    <li><code>privileged: true</code> 修改为 <code>false</code></li>
    <li><code>allowPrivilegeEscalation: true</code> 修改为 <code>false</code></li>
    <li>为容器补充 <code>seccompProfile.type: RuntimeDefault</code></li>
</ul>

<h3>2. strict 模式</h3>
<p>strict 模式比 safe 模式更强硬，会额外修改一些可能影响业务行为的字段。</p>

<ul>
    <li>禁用 ServiceAccount Token 自动挂载</li>
    <li>设置 <code>runAsNonRoot: true</code></li>
    <li>设置 <code>readOnlyRootFilesystem: true</code></li>
</ul>

<div class="warning">
strict 模式适合安全要求更高的场景，但修改后必须进行业务验证。
</div>

<h2>五、自动修复报告</h2>
<p>自动修复完成后，可以导出自动修复报告。报告包括：</p>

<ul>
    <li>修复概览</li>
    <li>修复前后风险等级对比</li>
    <li>修复前后整体危险系数对比</li>
    <li>已自动修复动作清单</li>
    <li>未自动修复风险清单</li>
    <li>输出文件清单</li>
    <li>修复后残余风险</li>
    <li>后续处理建议</li>
</ul>

<h2>六、使用建议</h2>
<ol>
    <li>首次使用时，建议先扫描 <code>examples/insecure</code> 示例目录。</li>
    <li>自动修复前，建议确认 YAML 已备份或纳入 Git 管理。</li>
    <li>自动修复后，不建议直接部署，应先检查修复后的 YAML。</li>
    <li>对 RBAC、Service、Ingress、镜像版本和资源限制类风险，应结合业务场景人工判断。</li>
    <li>部署前建议先在测试环境验证，再进入生产环境。</li>
</ol>
"""
    return build_help_html(
        "kubeguard-Lite 使用指南",
        "面向新手用户的桌面端操作说明",
        content,
    )


def get_rule_details_html() -> str:
    content = """
<h2>一、说明</h2>
<p>
本节只列出当前版本扫描规则与默认危险系数，不展开解释规则设计原因。
危险系数由风险等级、规则优先级和风险类别加权计算得出。
</p>

<h2>二、Workload 配置风险规则</h2>
<table>
<tr><th>Rule ID</th><th>风险项</th><th>默认危险系数</th></tr>
<tr><td>KGL-POD-001</td><td>PodSpec 启用 hostNetwork</td><td class="danger">15</td></tr>
<tr><td>KGL-POD-002</td><td>PodSpec 启用 hostPID</td><td class="danger">15</td></tr>
<tr><td>KGL-POD-003</td><td>PodSpec 启用 hostIPC</td><td class="danger">15</td></tr>
<tr><td>KGL-SA-001</td><td>显式开启 automountServiceAccountToken</td><td class="low">2</td></tr>
<tr><td>KGL-SA-002</td><td>未显式关闭 automountServiceAccountToken</td><td class="low">2</td></tr>
<tr><td>KGL-IMG-001</td><td>镜像使用 latest 或未固定版本标签</td><td class="medium">6</td></tr>
<tr><td>KGL-SEC-000</td><td>容器缺失 securityContext</td><td class="low">2</td></tr>
<tr><td>KGL-SEC-001</td><td>容器启用 privileged</td><td class="danger">16</td></tr>
<tr><td>KGL-SEC-002</td><td>容器允许 allowPrivilegeEscalation</td><td class="medium">6</td></tr>
<tr><td>KGL-SEC-003</td><td>容器使用 root 用户运行</td><td class="danger">15</td></tr>
<tr><td>KGL-SEC-004</td><td>容器未启用 runAsNonRoot</td><td class="medium">6</td></tr>
<tr><td>KGL-SEC-005</td><td>容器缺失 seccompProfile</td><td class="low">2</td></tr>
<tr><td>KGL-SEC-006</td><td>容器未启用 readOnlyRootFilesystem</td><td class="low">2</td></tr>
<tr><td>KGL-RES-001</td><td>容器缺失 resources.limits</td><td class="medium">6</td></tr>
<tr><td>KGL-VOL-001</td><td>挂载敏感 hostPath 路径</td><td class="medium">11</td></tr>
</table>

<h2>三、RBAC 权限风险规则</h2>
<table>
<tr><th>Rule ID</th><th>风险项</th><th>默认危险系数</th></tr>
<tr><td>KGL-RBAC-001</td><td>ClusterRoleBinding 绑定 cluster-admin</td><td class="danger">20</td></tr>
<tr><td>KGL-RBAC-002</td><td>RoleBinding 绑定 cluster-admin</td><td class="danger">18</td></tr>
<tr><td>KGL-RBAC-003</td><td>RBAC 规则包含通配符权限</td><td class="medium">12</td></tr>
<tr><td>KGL-RBAC-004</td><td>RBAC 规则允许读取 secrets</td><td class="danger">17</td></tr>
<tr><td>KGL-RBAC-005</td><td>RBAC 规则允许 pods/exec</td><td class="danger">17</td></tr>
<tr><td>KGL-RBAC-006</td><td>RBAC 规则允许创建 pods</td><td class="medium">7</td></tr>
<tr><td>KGL-RBAC-007</td><td>RBAC 规则允许修改 RBAC 资源</td><td class="danger">17</td></tr>
<tr><td>KGL-RBAC-008</td><td>RBAC 规则包含 bind、escalate 或 impersonate</td><td class="danger">17</td></tr>
<tr><td>KGL-RBAC-009</td><td>Binding 引用了当前扫描范围内不存在的 Role 或 ClusterRole</td><td class="low">3</td></tr>
</table>

<h2>四、Service 暴露风险规则</h2>
<table>
<tr><th>Rule ID</th><th>风险项</th><th>默认危险系数</th></tr>
<tr><td>KGL-SVC-001</td><td>Service 使用 NodePort 暴露方式</td><td class="medium">6</td></tr>
<tr><td>KGL-SVC-002</td><td>Service 使用 LoadBalancer 暴露方式</td><td class="danger">15</td></tr>
<tr><td>KGL-SVC-003</td><td>Service 配置 externalIPs</td><td class="danger">15</td></tr>
<tr><td>KGL-SVC-004</td><td>Service 暴露敏感端口</td><td class="danger">15</td></tr>
<tr><td>KGL-SVC-005</td><td>Service 未配置 selector</td><td class="low">2</td></tr>
<tr><td>KGL-SVC-006</td><td>Service selector 未匹配到当前扫描范围内的工作负载</td><td class="low">2</td></tr>
<tr><td>KGL-SVC-007</td><td>NodePort 不在默认端口范围内</td><td class="medium">6</td></tr>
<tr><td>KGL-SVC-008</td><td>LoadBalancer 未配置 loadBalancerSourceRanges</td><td class="medium">6</td></tr>
<tr><td>KGL-SVC-009</td><td>Service 使用 ExternalName</td><td class="medium">6</td></tr>
</table>

<h2>五、Ingress 风险规则</h2>
<table>
<tr><th>Rule ID</th><th>风险项</th><th>默认危险系数</th></tr>
<tr><td>KGL-ING-001</td><td>Ingress 未配置 TLS</td><td class="medium">6</td></tr>
<tr><td>KGL-ING-002</td><td>Ingress 使用通配符 Host</td><td class="medium">6</td></tr>
<tr><td>KGL-ING-003</td><td>Ingress 使用高风险 Nginx snippet 注解</td><td class="danger">15</td></tr>
<tr><td>KGL-ING-004</td><td>Ingress 未配置 Host</td><td class="low">2</td></tr>
</table>

<h2>六、危险系数参考</h2>
<table>
<tr><th>危险系数区间</th><th>参考含义</th></tr>
<tr><td class="danger">15 及以上</td><td>高优先级风险，建议优先处理</td></tr>
<tr><td class="medium">6 到 14</td><td>中等风险，需要结合业务场景判断</td></tr>
<tr><td class="low">1 到 5</td><td>低风险或提示类风险，建议纳入基线治理</td></tr>
</table>
"""
    return build_help_html(
        "kubeguard-Lite 规则细则",
        "当前版本扫描规则与默认危险系数速查表",
        content,
    )


def get_design_notes_html() -> str:
    content = """
<h2>一、设计目标</h2>
<p>
kubeguard-Lite 的设计目标不是替代完整的 Kubernetes 安全平台，而是面向教学、实验和部署前检查场景，
提供一个轻量级 Kubernetes YAML 静态配置风险扫描工具。
</p>

<p>
本工具重点关注部署前配置风险。也就是说，在资源真正进入集群之前，通过分析 YAML 文件发现潜在攻击面。
</p>

<ul>
    <li>不需要连接 Kubernetes 集群。</li>
    <li>不需要部署 Agent。</li>
    <li>不依赖运行时流量或日志。</li>
</ul>

<h2>二、为什么关注 YAML 静态配置</h2>
<p>
Kubernetes 的很多安全问题并不是漏洞本身导致的，而是由错误配置引起的。
这些问题在 YAML 文件中就可以提前发现，因此静态扫描具有现实意义。
</p>

<h2>三、Workload 规则设计说明</h2>

<h3>1. hostNetwork</h3>
<p>
<code>hostNetwork: true</code> 会让 Pod 使用宿主机网络命名空间。
这意味着容器内进程可能直接接触宿主机网络环境，网络隔离能力下降。
因此，本工具将 hostNetwork 识别为高风险配置。
</p>

<h3>2. hostPID 与 hostIPC</h3>
<p>
<code>hostPID: true</code> 会让 Pod 共享宿主机进程命名空间。
<code>hostIPC: true</code> 会让 Pod 共享宿主机 IPC 命名空间。
这类配置会削弱容器隔离边界，因此被识别为高风险配置。
</p>

<h3>3. privileged 容器</h3>
<p>
<code>privileged: true</code> 是容器安全中非常危险的配置。
它会显著提升容器权限，使容器拥有更多 Linux capabilities，并可能访问宿主机设备资源。
若结合 hostPath、宿主机命名空间共享或内核接口暴露，可能形成容器逃逸或节点破坏风险。
</p>

<h3>4. allowPrivilegeEscalation</h3>
<p>
<code>allowPrivilegeEscalation: true</code> 允许进程获得比父进程更高的权限。
在容器环境中，这会增加提权风险。
</p>

<h3>5. runAsUser 与 runAsNonRoot</h3>
<p>
容器以 root 用户运行会增加攻击后的破坏能力。
即使容器内 root 不完全等同于宿主机 root，但在错误挂载、过高权限或内核攻击面存在时，root 身份会放大风险。
</p>

<h3>6. seccompProfile</h3>
<p>
seccomp 可以限制容器进程可调用的系统调用。
缺失 seccompProfile 意味着容器缺少一层系统调用级别限制。
<code>RuntimeDefault</code> 是较常见的安全基线选择，因此工具支持自动补充。
</p>

<h3>7. readOnlyRootFilesystem</h3>
<p>
只读根文件系统可以减少攻击者在容器内部写入恶意文件、落地工具或篡改运行环境的机会。
但部分业务确实需要写入文件系统，因此 safe 模式下不强制修改。
</p>

<h3>8. resources.limits</h3>
<p>
缺失资源限制可能导致单个容器占用过多 CPU 或内存，影响同节点其他工作负载。
这类问题偏向可用性和资源隔离风险，因此归为中等风险。
</p>

<h2>四、RBAC 规则设计说明</h2>
<p>
RBAC 是 Kubernetes 权限控制核心。攻击者进入 Pod 后，常见横向移动路径之一就是利用 Pod 中挂载的 ServiceAccount Token 访问 Kubernetes API。
因此，ServiceAccount 对应的 RBAC 权限越大，攻击者在集群中的后续操作能力越强。
</p>

<h3>1. cluster-admin</h3>
<p>
cluster-admin 是集群级最高权限角色。一旦普通 ServiceAccount 或用户被绑定到 cluster-admin，
该身份可能拥有完整集群控制能力，因此被识别为最高优先级 RBAC 风险。
</p>

<h3>2. secrets 读取权限</h3>
<p>
Secret 中可能包含数据库密码、镜像仓库凭据、TLS 私钥、Token 等敏感信息。
如果某个身份拥有读取 secrets 的权限，一旦身份被利用，可能造成凭据泄露和进一步横向移动。
</p>

<h3>3. pods/exec 权限</h3>
<p>
pods/exec 允许进入正在运行的 Pod 执行命令。
该权限可能被用于进入业务容器、读取环境变量、访问挂载文件或探测内部网络，因此被识别为高风险。
</p>

<h3>4. 修改 RBAC 资源</h3>
<p>
如果某个身份可以修改 Role、ClusterRole、RoleBinding 或 ClusterRoleBinding，
它可能进一步扩大自身或其他身份的权限，形成权限提升路径。
</p>

<h3>5. bind、escalate、impersonate</h3>
<p>
这些权限与 Kubernetes 权限提升高度相关。
bind 可能允许绑定高权限角色，escalate 可能允许创建超出自身权限的角色，impersonate 可能允许冒充其他用户或 ServiceAccount。
</p>

<h2>五、Service 与 Ingress 规则设计说明</h2>

<h3>1. NodePort</h3>
<p>
NodePort 会在节点端口上暴露服务。如果节点网络边界控制不严格，攻击者可能直接访问 NodePort 暴露的服务。
</p>

<h3>2. LoadBalancer</h3>
<p>
LoadBalancer 通常意味着服务可能被暴露到集群外部网络。在云环境中，它可能对应公网负载均衡器。
如果没有来源限制或额外访问控制，攻击面会明显扩大。
</p>

<h3>3. externalIPs</h3>
<p>
externalIPs 会让 Service 绑定外部 IP。错误使用 externalIPs 可能导致流量暴露、流量劫持或网络边界绕过。
</p>

<h3>4. 敏感端口</h3>
<p>
某些端口通常对应敏感服务，例如 SSH、etcd、MySQL、PostgreSQL、Redis、Kubernetes API Server、Kubelet 等。
如果这些端口通过 Service 暴露，可能导致内部基础设施组件或数据库被访问。
</p>

<h3>5. Ingress TLS</h3>
<p>
Ingress 未配置 TLS 时，外部访问链路可能缺少传输层加密。
虽然是否必须启用 TLS 取决于业务和部署环境，但多数 Web 服务场景下，缺失 TLS 是需要关注的配置问题。
</p>

<h3>6. Nginx snippet 注解</h3>
<p>
某些 Nginx Ingress snippet 注解允许用户注入额外 Nginx 配置。
这类能力灵活但风险较高，可能引入请求转发、头部改写、访问控制绕过等问题。
</p>

<h2>六、自动修复设计说明</h2>
<p>自动修复功能采用保守策略，不会盲目修改所有风险。</p>

<h3>1. safe 自动修复项</h3>
<ul>
    <li>hostNetwork true 改为 false</li>
    <li>privileged true 改为 false</li>
    <li>allowPrivilegeEscalation true 改为 false</li>
    <li>补充 seccompProfile RuntimeDefault</li>
</ul>

<h3>2. strict 自动修复项</h3>
<ul>
    <li>禁用 ServiceAccount Token 自动挂载</li>
    <li>启用 runAsNonRoot</li>
    <li>启用 readOnlyRootFilesystem</li>
</ul>

<h3>3. manual only 项</h3>
<p>镜像版本、资源限制、RBAC 权限收缩、Service 暴露方式、Ingress TLS 证书等问题需要结合业务场景判断，因此工具只提示不强改。</p>

<h2>七、总结</h2>
<p>kubeguard-Lite 的设计原则是：</p>
<ol>
    <li>在部署前发现配置风险。</li>
    <li>优先识别云原生场景中的高危错误配置。</li>
    <li>对明确危险项提供自动修复。</li>
    <li>对依赖业务上下文的风险保持保守，只提示不强改。</li>
    <li>通过报告输出保留扫描和修复证据。</li>
</ol>
"""
    return build_help_html(
        "kubeguard-Lite 设计说明",
        "扫描规则与自动修复策略的设计依据",
        content,
    )