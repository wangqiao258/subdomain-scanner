import os
from PySide6.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout,
                               QLabel, QLineEdit, QPushButton, QCheckBox,
                               QSpinBox, QGroupBox, QFileDialog, QGridLayout,
                               QComboBox, QScrollArea, QFrame, QSizePolicy)
from PySide6.QtCore import Qt
from PySide6.QtGui import QIntValidator


PASSIVE_SOURCES = [
    "crt.sh",
    "AlienVault OTX",
    "HackerTarget",
    "RapidDNS",
    "Anubis",
    "Wayback Machine",
    "CertSpotter",
    "URLScan.io",
    "VirusTotal",
    "SecurityTrails",
]

API_KEY_SOURCES = {
    "URLScan.io": "urlscan",
    "VirusTotal": "virustotal",
    "SecurityTrails": "securitytrails",
}


class ScanPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.domain_file = ""
        self.source_checks = {}
        self.api_key_inputs = {}
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 0, 16, 8)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("目标域名:"))
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com (多个域名逗号分隔)")
        self.domain_input.setFixedHeight(32)
        self.domain_input.setMaximumWidth(400)
        row1.addWidget(self.domain_input)
        self.import_domain_btn = QPushButton("导入列表")
        self.import_domain_btn.setFixedHeight(32)
        self.import_domain_btn.clicked.connect(self.import_domains)
        row1.addWidget(self.import_domain_btn)
        row1.addStretch()
        self.scan_btn = QPushButton("开始扫描")
        self.scan_btn.setObjectName("scanBtn")
        self.scan_btn.setFixedSize(120, 36)
        row1.addWidget(self.scan_btn)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("字典:"))
        self.wordlist_path = QLineEdit()
        self.wordlist_path.setReadOnly(True)
        self.wordlist_path.setPlaceholderText("内置字典")
        self.wordlist_path.setFixedHeight(32)
        self.wordlist_path.setMaximumWidth(400)
        row2.addWidget(self.wordlist_path)
        self.browse_btn = QPushButton("浏览")
        self.browse_btn.setFixedHeight(32)
        self.browse_btn.clicked.connect(self.browse_wordlist)
        row2.addWidget(self.browse_btn)
        row2.addStretch()
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setFixedSize(120, 36)
        row2.addWidget(self.stop_btn)
        layout.addLayout(row2)

        top_row = QHBoxLayout()

        modules_group = QGroupBox("扫描模块")
        modules_layout = QHBoxLayout(modules_group)
        modules_layout.setContentsMargins(8, 6, 8, 6)

        self.passive_cb = QCheckBox("被动收集")
        self.passive_cb.setChecked(True)
        self.passive_cb.stateChanged.connect(self._toggle_passive_options)
        modules_layout.addWidget(self.passive_cb)

        self.brute_cb = QCheckBox("DNS枚举")
        self.brute_cb.setChecked(True)
        modules_layout.addWidget(self.brute_cb)

        self.http_cb = QCheckBox("HTTP探测")
        self.http_cb.setChecked(True)
        modules_layout.addWidget(self.http_cb)

        self.port_cb = QCheckBox("端口扫描")
        self.port_cb.setChecked(False)
        self.port_cb.stateChanged.connect(self._toggle_port_options)
        modules_layout.addWidget(self.port_cb)

        top_row.addWidget(modules_group, 2)

        # ==================== 参数区域 ====================
        # 创建一个带标题的分组框，标题显示"参数"
        params_group = QGroupBox("参数")
        # 创建水平布局，用于横向排列控件
        params_layout = QHBoxLayout(params_group)
        # 设置布局内边距：左8、上6、右8、下6 像素
        params_layout.setContentsMargins(8, 6, 8, 6)
        # 设置控件之间的间距为0像素
        params_layout.setSpacing(0)

        # --- 第一块：线程 ---
        # 创建容器
        thread_widget = QWidget()
        thread_layout = QHBoxLayout(thread_widget)
        thread_layout.setContentsMargins(0, 0, 0, 0)
        thread_layout.setSpacing(2)
        # 添加"线程:"文字标签
        thread_layout.addWidget(QLabel("线程:"))
        # 创建文本输入框
        self.threads_input = QLineEdit("50")
        # 设置验证器，只允许输入5-200的整数
        self.threads_input.setValidator(QIntValidator(5, 200))
        # 设置固定宽度为40像素
        self.threads_input.setFixedWidth(40)
        # 设置固定高度为24像素
        self.threads_input.setFixedHeight(24)
        # 将输入框添加到布局
        thread_layout.addWidget(self.threads_input)
        # 设置容器大小策略为固定大小
        thread_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        # 将第一块添加到参数布局（靠左）
        params_layout.addWidget(thread_widget)

        # 添加弹性空间（第一块和第二块之间）
        params_layout.addStretch()

        # --- 第二块：超时 ---
        # 创建容器
        timeout_widget = QWidget()
        timeout_layout = QHBoxLayout(timeout_widget)
        timeout_layout.setContentsMargins(0, 0, 0, 0)
        timeout_layout.setSpacing(2)
        # 添加"超时:"文字标签
        timeout_layout.addWidget(QLabel("超时:"))
        # 创建文本输入框
        self.timeout_input = QLineEdit("5")
        # 设置验证器，只允许输入1-30的整数
        self.timeout_input.setValidator(QIntValidator(1, 30))
        # 设置固定宽度为40像素
        self.timeout_input.setFixedWidth(40)
        # 设置固定高度为24像素
        self.timeout_input.setFixedHeight(24)
        # 将输入框添加到布局
        timeout_layout.addWidget(self.timeout_input)
        # 设置容器大小策略为固定大小
        timeout_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        # 将第二块添加到参数布局
        params_layout.addWidget(timeout_widget)

        # 添加弹性空间，把控件推到左边
        params_layout.addStretch()

        # 将参数区域添加到顶部行，stretch=1表示占据1份空间
        top_row.addWidget(params_group, 1)

        # ==================== 端口扫描区域 ====================
        # 创建一个带标题的分组框，标题显示"端口扫描"
        self.port_params_group = QGroupBox("端口扫描")
        # 默认禁用（灰色状态），需要勾选端口扫描才启用
        self.port_params_group.setEnabled(False)
        # 创建水平布局
        port_params_layout = QHBoxLayout(self.port_params_group)
        # 设置布局内边距：左8、上6、右8、下6 像素
        port_params_layout.setContentsMargins(8, 6, 8, 6)
        # 设置控件之间的间距为0像素
        port_params_layout.setSpacing(0)

        # --- 第一块：范围 ---
        # 创建容器
        range_widget = QWidget()
        range_layout = QHBoxLayout(range_widget)
        range_layout.setContentsMargins(0, 0, 0, 0)
        range_layout.setSpacing(2)
        # 添加"范围:"文字标签
        range_layout.addWidget(QLabel("范围:"))
        # 创建下拉选择框
        self.port_mode_combo = QComboBox()
        # 添加选项：常见端口、Top1000、自定义范围
        self.port_mode_combo.addItems(["常见(~300)", "Top1000", "自定义"])
        # 当选项改变时触发_toggle_port_range方法
        self.port_mode_combo.currentTextChanged.connect(self._toggle_port_range)
        # 设置下拉框固定宽度为95像素
        self.port_mode_combo.setFixedWidth(95)
        # 将下拉框添加到布局
        range_layout.addWidget(self.port_mode_combo)
        # 设置容器大小策略为固定大小
        range_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        # 将第一块添加到端口扫描布局（靠左）
        port_params_layout.addWidget(range_widget)

        # 创建自定义端口范围输入框（直接添加到端口扫描布局，不嵌套）
        self.port_range_input = QLineEdit()
        # 设置占位符文字
        self.port_range_input.setPlaceholderText("80,443,8080")
        # 默认隐藏
        self.port_range_input.setVisible(False)
        # 设置固定宽度为120像素
        self.port_range_input.setFixedWidth(120)
        # 设置固定高度为28像素
        self.port_range_input.setFixedHeight(28)
        # 确保可编辑
        self.port_range_input.setReadOnly(False)
        # 确保可接收焦点
        self.port_range_input.setFocusPolicy(Qt.StrongFocus)
        # 将输入框添加到端口扫描布局
        port_params_layout.addWidget(self.port_range_input)

        # 添加弹性空间（第一块和第二块之间）
        port_params_layout.addStretch()

        # --- 第二块：线程 ---
        # 创建容器
        port_thread_widget = QWidget()
        port_thread_layout = QHBoxLayout(port_thread_widget)
        port_thread_layout.setContentsMargins(0, 0, 0, 0)
        port_thread_layout.setSpacing(2)
        # 添加"线程:"文字标签
        port_thread_layout.addWidget(QLabel("线程:"))
        # 创建文本输入框
        self.port_threads_input = QLineEdit("100")
        # 设置验证器，只允许输入10-500的整数
        self.port_threads_input.setValidator(QIntValidator(10, 500))
        # 设置固定宽度为40像素
        self.port_threads_input.setFixedWidth(40)
        # 设置固定高度为24像素
        self.port_threads_input.setFixedHeight(24)
        # 将输入框添加到布局
        port_thread_layout.addWidget(self.port_threads_input)
        # 设置容器大小策略为固定大小
        port_thread_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        # 将第二块添加到端口扫描布局
        port_params_layout.addWidget(port_thread_widget)

        # 添加弹性空间（第二块和第三块之间）
        port_params_layout.addStretch()

        # --- 第三块：超时 ---
        # 创建容器
        port_timeout_widget = QWidget()
        port_timeout_layout = QHBoxLayout(port_timeout_widget)
        port_timeout_layout.setContentsMargins(0, 0, 0, 0)
        port_timeout_layout.setSpacing(2)
        # 添加"超时:"文字标签
        port_timeout_layout.addWidget(QLabel("超时:"))
        # 创建文本输入框
        self.port_timeout_input = QLineEdit("3")
        # 设置验证器，只允许输入1-10的整数
        self.port_timeout_input.setValidator(QIntValidator(1, 10))
        # 设置固定宽度为40像素
        self.port_timeout_input.setFixedWidth(40)
        # 设置固定高度为24像素
        self.port_timeout_input.setFixedHeight(24)
        # 将输入框添加到布局
        port_timeout_layout.addWidget(self.port_timeout_input)
        # 设置容器大小策略为固定大小
        port_timeout_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        # 将第三块添加到端口扫描布局
        port_params_layout.addWidget(port_timeout_widget)

        # 添加弹性空间，把控件推到左边
        port_params_layout.addStretch()

        # 将端口扫描区域添加到顶部行，stretch=2表示占据2份空间（比参数区域宽一倍）
        top_row.addWidget(self.port_params_group, 2)

        # 将顶部行添加到主布局
        layout.addLayout(top_row)

        self.passive_group = QGroupBox("被动收集源配置")
        passive_layout = QVBoxLayout(self.passive_group)

        sources_grid = QGridLayout()
        for i, name in enumerate(PASSIVE_SOURCES):
            cb = QCheckBox(name)
            cb.setChecked(True)
            self.source_checks[name] = cb
            sources_grid.addWidget(cb, i // 4, i % 4)
        passive_layout.addLayout(sources_grid)

        api_frame = QFrame()
        api_frame.setFrameShape(QFrame.StyledPanel)
        api_layout = QGridLayout(api_frame)
        api_layout.addWidget(QLabel("<b>API Key 配置 (可选，提高查询限额)</b>"), 0, 0, 1, 2)

        row = 1
        for display_name, key_name in API_KEY_SOURCES.items():
            api_layout.addWidget(QLabel(f"{display_name}:"), row, 0)
            inp = QLineEdit()
            inp.setPlaceholderText(f"输入 {display_name} API Key")
            inp.setEchoMode(QLineEdit.Password)
            self.api_key_inputs[key_name] = inp
            api_layout.addWidget(inp, row, 1)
            row += 1

        passive_layout.addWidget(api_frame)
        layout.addWidget(self.passive_group)

    def _toggle_passive_options(self, state):
        self.passive_group.setEnabled(self.passive_cb.isChecked())

    def _toggle_port_options(self, state):
        enabled = self.port_cb.isChecked()
        self.port_params_group.setEnabled(enabled)
        # 确保自定义输入框在启用时可以输入
        if enabled and self.port_mode_combo.currentText() == "自定义":
            self.port_range_input.setEnabled(True)
            self.port_range_input.setReadOnly(False)

    def _toggle_port_range(self, text):
        print(f"下拉框选择: {text}")  # 调试信息
        visible = "自定义" in text
        print(f"显示输入框: {visible}")  # 调试信息
        self.port_range_input.setVisible(visible)
        if visible:
            self.port_range_input.setEnabled(True)
            self.port_range_input.setReadOnly(False)
            self.port_range_input.setFocus()
            print(f"输入框状态: enabled={self.port_range_input.isEnabled()}, readOnly={self.port_range_input.isReadOnly()}")  # 调试信息

    def browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择字典文件", "",
            "文本文件 (*.txt);;所有文件 (*)"
        )
        if path:
            self.wordlist_path.setText(path)

    def import_domains(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "导入域名列表", "",
            "文本文件 (*.txt);;所有文件 (*)"
        )
        if path:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            self.domain_input.setText(", ".join(domains))
            self.domain_file = path

    def get_domains(self):
        text = self.domain_input.text().strip()
        if not text:
            return []
        items = [d.strip().lower() for d in text.replace("，", ",").replace("\n", ",").split(",")]
        return [d for d in items if d]

    def get_options(self):
        selected_sources = [name for name, cb in self.source_checks.items() if cb.isChecked()]
        api_keys = {}
        for key_name, inp in self.api_key_inputs.items():
            val = inp.text().strip()
            if val:
                api_keys[key_name] = val

        port_mode = self.port_mode_combo.currentText()
        port_range = None
        if port_mode == "自定义范围":
            port_range = self.port_range_input.text().strip()

        # 获取输入框的值，转换为整数，如果为空则使用默认值
        threads = int(self.threads_input.text()) if self.threads_input.text() else 50
        timeout = int(self.timeout_input.text()) if self.timeout_input.text() else 5
        port_threads = int(self.port_threads_input.text()) if self.port_threads_input.text() else 100
        port_timeout = int(self.port_timeout_input.text()) if self.port_timeout_input.text() else 3

        return {
            "passive": self.passive_cb.isChecked(),
            "brute": self.brute_cb.isChecked(),
            "http_probe": self.http_cb.isChecked(),
            "port_scan": self.port_cb.isChecked(),
            "threads": threads,
            "timeout": timeout,
            "passive_sources": selected_sources if selected_sources else None,
            "api_keys": api_keys,
            "port_threads": port_threads,
            "port_timeout": port_timeout,
            "port_mode": port_mode,
            "port_range": port_range,
        }

    def set_scanning(self, scanning):
        self.scan_btn.setEnabled(not scanning)
        self.stop_btn.setEnabled(scanning)
        self.domain_input.setEnabled(not scanning)
        self.import_domain_btn.setEnabled(not scanning)
        self.browse_btn.setEnabled(not scanning)
        self.passive_cb.setEnabled(not scanning)
        self.brute_cb.setEnabled(not scanning)
        self.http_cb.setEnabled(not scanning)
        self.port_cb.setEnabled(not scanning)
        self.threads_input.setEnabled(not scanning)
        self.timeout_input.setEnabled(not scanning)
        self.port_params_group.setEnabled(not scanning and self.port_cb.isChecked())
        self.passive_group.setEnabled(not scanning and self.passive_cb.isChecked())
