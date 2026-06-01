from PySide6.QtWidgets import (QWidget, QVBoxLayout, QLabel,
                               QTextEdit, QGroupBox)
from PySide6.QtCore import Qt


class DetailPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.clear()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.header = QLabel("<b>详细信息</b>")
        layout.addWidget(self.header)

        self.text = QTextEdit()
        self.text.setReadOnly(True)
        layout.addWidget(self.text, 1)

    def show_result(self, result):
        if not result:
            return
        sub = result.get("subdomain", "")
        ip = result.get("ip", "无")
        source = result.get("source", "未知")
        dns = result.get("dns", {})
        http = result.get("http", {})
        ssl = result.get("ssl")
        ports = result.get("ports", [])

        lines = []
        lines.append(f"【子域名】{sub}")
        lines.append(f"【IP 地址】{ip}")
        lines.append(f"【发现来源】{source}")
        lines.append("")

        lines.append("━" * 40)
        lines.append("【DNS 记录】")
        if dns.get("a"):
            lines.append(f"  A: {', '.join(dns['a'])}")
        if dns.get("aaaa"):
            lines.append(f"  AAAA: {', '.join(dns['aaaa'])}")
        if dns.get("cname"):
            lines.append(f"  CNAME: {dns['cname']}")
        if dns.get("mx"):
            lines.append(f"  MX: {', '.join(dns['mx'])}")
        if dns.get("ns"):
            lines.append(f"  NS: {', '.join(dns['ns'])}")
        if dns.get("txt"):
            for t in dns["txt"][:3]:
                lines.append(f"  TXT: {t[:120]}")
        if dns.get("soa"):
            lines.append(f"  SOA: {dns['soa']}")
        if not any(dns.values()):
            lines.append("  (无记录)")
        lines.append("")

        for proto in ("https", "http"):
            info = http.get(proto)
            if info:
                lines.append(f"━" * 40)
                lines.append(f"【{proto.upper()} 探测】")
                lines.append(f"  状态码: {info.get('status', '')}")
                lines.append(f"  标题: {info.get('title', '')[:120]}")
                lines.append(f"  服务器: {info.get('server', '')}")
                lines.append(f"  类型: {info.get('content_type', '')}")
                if info.get("location"):
                    lines.append(f"  跳转: {info['location']}")
                lines.append(f"  大小: {info.get('content_length', 0)} bytes")
                break
        lines.append("")

        if ssl:
            lines.append("━" * 40)
            lines.append("【SSL 证书】")
            lines.append(f"  颁发者: {ssl.get('issuer', '')}")
            lines.append(f"  主题: {ssl.get('subject', '')}")
            lines.append(f"  过期: {ssl.get('not_after', '')}")
            if ssl.get("san"):
                sans = ssl["san"][:5]
                lines.append(f"  SAN: {', '.join(sans)}{' ...' if len(ssl['san']) > 5 else ''}")
            if ssl.get("expired") is True:
                lines.append("  ⚠ 证书已过期")
            elif ssl.get("expired") is False:
                lines.append("  ✓ 证书有效")
        lines.append("")

        if ports:
            lines.append("━" * 40)
            lines.append("【开放端口】")
            for p in ports[:20]:
                service = p.get("service", "")
                label = f"  {p['port']}"
                if service:
                    label += f" ({service})"
                lines.append(label)
            if len(ports) > 20:
                lines.append(f"  ... 还有 {len(ports) - 20} 个")
        else:
            lines.append("━" * 40)
            lines.append("【端口扫描】未扫描或无开放端口")

        self.text.setPlainText("\n".join(lines))

    def clear(self):
        self.text.setPlainText("选择左侧子域名查看详细信息")
