import os
import json
import csv
from datetime import datetime
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout,
                               QPushButton, QLabel, QFileDialog, QMessageBox)


class ExportDialog(QDialog):
    def __init__(self, results, parent=None):
        super().__init__(parent)
        self.results = results
        self.setWindowTitle("导出结果")
        self.setMinimumWidth(400)
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(f"共 {len(results)} 条子域名记录，选择导出格式："))

        btn_layout = QHBoxLayout()
        json_btn = QPushButton("导出 JSON")
        json_btn.clicked.connect(self.export_json)
        csv_btn = QPushButton("导出 CSV")
        csv_btn.clicked.connect(self.export_csv)
        btn_layout.addWidget(json_btn)
        btn_layout.addWidget(csv_btn)
        layout.addLayout(btn_layout)

    def _default_path(self, ext):
        return os.path.join(
            os.path.expanduser("~"),
            "Desktop",
            f"subdomain_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}",
        )

    def export_json(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "保存JSON", self._default_path("json"), "JSON (*.json)"
        )
        if path:
            data = []
            for r in self.results:
                data.append({
                    "domain": r.get("domain", ""),
                    "subdomain": r.get("subdomain", ""),
                    "ip": r.get("ip", ""),
                    "source": r.get("source", ""),
                    "dns": r.get("dns", {}),
                    "http": r.get("http", {}),
                    "ssl": r.get("ssl"),
                    "ports": r.get("ports", []),
                })
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            QMessageBox.information(self, "完成", f"已导出 {len(data)} 条记录到:\n{path}")

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "保存CSV", self._default_path("csv"), "CSV (*.csv)"
        )
        if path:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                # 写入标题行
                headers = [
                    "所属域名", "子域名", "IP地址", "来源", "DNS-A", "DNS-AAAA",
                    "CNAME", "HTTP状态码", "标题", "服务器",
                    "SSL颁发者", "SSL过期", "开放端口"
                ]
                writer.writerow(headers)
                # 写入数据行
                for r in self.results:
                    http = r.get("http", {})
                    https_info = http.get("https", http.get("http", {}))
                    dns = r.get("dns", {})
                    ssl_info = r.get("ssl") or {}
                    ports = ",".join(str(p["port"]) for p in r.get("ports", [])) if isinstance(r.get("ports"), list) else ""
                    row_data = [
                        r.get("domain", ""),
                        r.get("subdomain", ""),
                        r.get("ip", ""),
                        r.get("source", ""),
                        ";".join(dns.get("a", [])),
                        ";".join(dns.get("aaaa", [])),
                        dns.get("cname", "") or "",
                        https_info.get("status", ""),
                        https_info.get("title", ""),
                        https_info.get("server", ""),
                        ssl_info.get("issuer", ""),
                        ssl_info.get("not_after", ""),
                        ports,
                    ]
                    writer.writerow(row_data)
            QMessageBox.information(self, "完成", f"已导出 {len(self.results)} 条记录到:\n{path}")
