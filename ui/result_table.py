from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                               QTableWidget, QTableWidgetItem, QHeaderView,
                               QLabel, QPushButton, QAbstractItemView)
from PySide6.QtCore import Signal, Qt
from ui.export_dialog import ExportDialog


class ResultTable(QWidget):
    selection_changed = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.results = []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        header = QHBoxLayout()
        header.addWidget(QLabel("<b>子域名列表</b>"))
        header.addStretch()
        self.count_label = QLabel("共 0 条")
        self.count_label.setStyleSheet("color: #64748b; font-size: 12px;")
        header.addWidget(self.count_label)
        header.addSpacing(16)
        self.export_btn = QPushButton("导出结果")
        self.export_btn.setObjectName("exportBtn")
        self.export_btn.clicked.connect(self.export_results)
        self.export_btn.setEnabled(False)
        header.addWidget(self.export_btn)
        layout.addLayout(header)

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "子域名", "所属域名", "IP地址", "来源", "状态码", "标题", "服务器", "开放端口"
        ])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.setColumnWidth(0, 220)
        self.table.setColumnWidth(1, 120)
        self.table.setColumnWidth(2, 140)
        self.table.setColumnWidth(3, 60)
        self.table.setColumnWidth(4, 70)
        self.table.setColumnWidth(5, 160)
        self.table.setColumnWidth(6, 90)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_selection)
        layout.addWidget(self.table)

    def add_result(self, result):
        idx = None
        for i, r in enumerate(self.results):
            if r.get("subdomain") == result.get("subdomain"):
                self.results[i] = result
                idx = i
                break
        if idx is None:
            self.results.append(result)
            idx = len(self.results) - 1

        self._update_row(idx, result)
        self.count_label.setText(f"共 {len(self.results)} 条")
        self.export_btn.setEnabled(True)

    def _update_row(self, row, result):
        sub = result.get("subdomain", "")
        domain = result.get("domain", "")
        ip = result.get("ip", "")
        source = result.get("source", "")
        http = result.get("http", {})
        https_info = http.get("https", http.get("http", {}))
        status = str(https_info.get("status", "")) if https_info else ""
        title = https_info.get("title", "") if https_info else ""
        server = https_info.get("server", "") if https_info else ""
        ports = ",".join(str(p["port"]) for p in result.get("ports", [])) if isinstance(result.get("ports"), list) else ""

        self.table.setRowCount(max(self.table.rowCount(), row + 1))
        items = [
            QTableWidgetItem(sub),
            QTableWidgetItem(domain),
            QTableWidgetItem(ip or ""),
            QTableWidgetItem(source),
            QTableWidgetItem(status),
            QTableWidgetItem(title[:80] if title else ""),
            QTableWidgetItem(server),
            QTableWidgetItem(ports),
        ]
        for col, item in enumerate(items):
            self.table.setItem(row, col, item)
        if ip:
            items[0].setData(Qt.UserRole, result)
        self.table.resizeRowToContents(row)

    def _on_selection(self):
        rows = self.table.selectedItems()
        if rows:
            row = rows[0].row()
            item = self.table.item(row, 0)
            if item:
                result = item.data(Qt.UserRole)
                if result:
                    self.selection_changed.emit(result)

    def export_results(self):
        if self.results:
            dlg = ExportDialog(self.results, self)
            dlg.exec()

    def clear_results(self):
        self.results.clear()
        self.table.setRowCount(0)
        self.count_label.setText("共 0 条")
        self.export_btn.setEnabled(False)
