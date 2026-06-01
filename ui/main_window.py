import os
import sys
import json
from datetime import datetime
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QSplitter, QLabel,
                               QMessageBox, QScrollArea)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont
from ui.scan_panel import ScanPanel
from ui.result_table import ResultTable
from ui.detail_panel import DetailPanel
from ui.resources import STYLESHEET
from scanner.engine import ScanEngine


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_FILE = os.path.join(BASE_DIR, ".subdomain_cache.ndjson")


class ScanWorker(QThread):
    subdomain_found = Signal(object)
    progress_updated = Signal(str, int, int)
    status_updated = Signal(str)
    scan_finished = Signal()
    scan_error = Signal(str)

    def __init__(self, domains, wordlist_path, options):
        super().__init__()
        self.domains = domains
        self.wordlist_path = wordlist_path
        self.options = options
        self.engine = ScanEngine()

    def run(self):
        callbacks = {
            "on_status": lambda s: self.status_updated.emit(s),
            "on_subdomain": lambda r: self.subdomain_found.emit(r),
            "on_progress": lambda phase, cur, total: self.progress_updated.emit(phase, cur, total),
            "on_done": lambda: self.scan_finished.emit(),
            "on_error": lambda e: self.scan_error.emit(e),
        }
        self.engine.run(self.domains, self.wordlist_path, self.options, callbacks)

    def stop(self):
        self.engine.stop()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("子域名信息收集工具")
        self.setMinimumSize(1300, 900)
        self.resize(1400, 950)
        self.setStyleSheet(STYLESHEET)

        self.worker = None
        self.is_scanning = False

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 12, 16, 12)

        # Title
        title = QLabel("🔍  子域名信息收集工具")
        title.setObjectName("titleLabel")
        main_layout.addWidget(title)

        # Scan panel with scroll area
        self.scan_panel = ScanPanel()
        self.scan_panel.scan_btn.clicked.connect(self.start_scan)
        self.scan_panel.stop_btn.clicked.connect(self.stop_scan)

        scroll_area = QScrollArea()
        scroll_area.setWidget(self.scan_panel)
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setMaximumHeight(450)
        main_layout.addWidget(scroll_area)

        # Status label (separate row)
        self.status_label = QLabel("就绪")
        self.status_label.setObjectName("statusLabel")
        main_layout.addWidget(self.status_label)

        # Splitter: table (left) + detail (right)
        splitter = QSplitter(Qt.Horizontal)

        self.result_table = ResultTable()
        splitter.addWidget(self.result_table)

        self.detail_panel = DetailPanel()
        splitter.addWidget(self.detail_panel)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        main_layout.addWidget(splitter, 1)

        # Status bar stats
        self.stats_label = QLabel("就绪 - 输入域名开始扫描")
        self.stats_label.setStyleSheet("color: #64748b; font-size: 12px; padding: 4px 0;")
        main_layout.addWidget(self.stats_label)

        self.result_table.selection_changed.connect(self.detail_panel.show_result)

        self._find_default_wordlist()
        self._check_cache_on_startup()

    # ── 缓存文件 (实时增量保存) ──────────────────────

    def _cache_path(self):
        return CACHE_FILE

    def _clear_cache(self):
        try:
            if os.path.isfile(self._cache_path()):
                os.remove(self._cache_path())
        except Exception:
            pass

    def _append_cache(self, result):
        try:
            with open(self._cache_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _load_cache(self):
        results = []
        path = self._cache_path()
        if not os.path.isfile(path):
            return results
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        results.append(json.loads(line))
        except Exception:
            pass
        return results

    def _check_cache_on_startup(self):
        results = self._load_cache()
        if results:
            reply = QMessageBox.question(
                self, "发现上次扫描缓存",
                f"检测到上次未完成的扫描缓存（{len(results)} 条子域名记录）\n"
                "是否恢复数据？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if reply == QMessageBox.Yes:
                for r in results:
                    self.result_table.add_result(r)
                self.status_label.setText(f"已从缓存恢复 {len(results)} 条记录")
                self.stats_label.setText(
                    f"总计 {len(results)}  |  "
                    f"来源: {', '.join(set(r.get('source','') for r in results if r.get('source')))}"
                )

    # ── 扫描控制 ──────────────────────────────────

    def _find_default_wordlist(self):
        candidates = [
            os.path.join(BASE_DIR, "data", "subdomains.txt"),
        ]
        for p in candidates:
            p = os.path.abspath(p)
            if os.path.isfile(p):
                self.wordlist_path = p
                self.scan_panel.wordlist_path.setText(p)
                return
        self.wordlist_path = ""

    def start_scan(self):
        domains = self.scan_panel.get_domains()
        if not domains:
            QMessageBox.warning(self, "提示", "请输入目标域名（多个域名用逗号分隔，或点击「导入列表」）")
            return

        wordlist = self.scan_panel.wordlist_path.text().strip()
        if not wordlist or not os.path.isfile(wordlist):
            wordlist = self.wordlist_path or ""
        if not wordlist or not os.path.isfile(wordlist):
            QMessageBox.warning(self, "提示", "未找到字典文件，请先选择或下载字典")
            return

        options = self.scan_panel.get_options()

        self.is_scanning = True
        self.scan_panel.set_scanning(True)
        self.result_table.clear_results()
        self.detail_panel.clear()
        self.status_label.setText("正在启动...")
        self._clear_cache()

        self.worker = ScanWorker(domains, wordlist, options)
        self.worker.subdomain_found.connect(self.on_subdomain_found)
        self.worker.progress_updated.connect(self.on_progress)
        self.worker.status_updated.connect(self.on_status)
        self.worker.scan_finished.connect(self.on_scan_finished)
        self.worker.scan_error.connect(self.on_scan_error)
        self.worker.start()

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.status_label.setText("正在停止...")

    # ── 信号处理 ──────────────────────────────────

    def on_subdomain_found(self, result):
        self.result_table.add_result(result)
        self._append_cache(result)

    def on_progress(self, phase, current, total):
        pass

    def on_status(self, msg):
        self.status_label.setText(msg)
        if "完成" in msg or "已停止" in msg:
            alive = sum(1 for r in self.result_table.results if r.get("ip"))
            http_ok = sum(
                1 for r in self.result_table.results
                if (r.get("http", {}).get("https", {}) or r.get("http", {}).get("http", {}) or {}).get("status") == 200
            )
            sources = list(set(r.get("source","") for r in self.result_table.results if r.get("source")))
            self.stats_label.setText(
                f"总计 {len(self.result_table.results)}  |  "
                f"DNS解析成功 {alive}  |  "
                f"HTTP 200 {http_ok}  |  "
                f"来源: {', '.join(sources)}"
            )

    def on_scan_finished(self):
        self.is_scanning = False
        self.scan_panel.set_scanning(False)

    def on_scan_error(self, msg):
        self.status_label.setText(f"错误: {msg}")
