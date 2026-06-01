STYLESHEET = """
QMainWindow {
    background-color: #f0f2f5;
}
QLabel#titleLabel {
    font-size: 20px;
    font-weight: bold;
    color: #1a1a2e;
    padding: 4px 0;
}
QLabel#statusLabel {
    font-size: 13px;
    color: #475569;
}
QLabel {
    margin: 0;
    padding: 0;
}
QPushButton#scanBtn {
    background-color: #2563eb;
    color: white;
    border: none;
    border-radius: 6px;
    padding: 4px 16px;
    font-size: 14px;
    font-weight: bold;
}
QPushButton#scanBtn:hover {
    background-color: #1d4ed8;
}
QPushButton#scanBtn:disabled {
    background-color: #93c5fd;
}
QPushButton#stopBtn {
    background-color: #dc2626;
    color: white;
    border: none;
    border-radius: 6px;
    padding: 4px 16px;
    font-size: 14px;
    font-weight: bold;
}
QPushButton#stopBtn:hover {
    background-color: #b91c1c;
}
QPushButton#stopBtn:disabled {
    background-color: #fca5a5;
}
QPushButton#exportBtn {
    background-color: #059669;
    color: white;
    border: none;
    border-radius: 4px;
    padding: 6px 16px;
    font-size: 13px;
}
QPushButton#exportBtn:hover {
    background-color: #047857;
}
QPushButton {
    background-color: #e2e8f0;
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    padding: 6px 14px;
    font-size: 13px;
}
QPushButton:hover {
    background-color: #cbd5e1;
}
QLineEdit {
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    padding: 2px 4px;
    font-size: 13px;
    background: white;
}
QLineEdit:focus {
    border-color: #2563eb;
}
QComboBox {
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    padding: 4px 4px 4px 0px;
    font-size: 13px;
    background: white;
}
QComboBox:focus {
    border-color: #2563eb;
}
QSpinBox {
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    padding: 4px 4px 4px 0px;
    font-size: 13px;
    background: white;
}
QCheckBox {
    font-size: 13px;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
}
QGroupBox {
    font-weight: bold;
    font-size: 13px;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 20px;
    background: white;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}
QTableWidget {
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    background: white;
    gridline-color: #f1f5f9;
    font-size: 13px;
    selection-background-color: #dbeafe;
    selection-color: #1e40af;
}
QTableWidget::item {
    padding: 6px 10px;
}
QHeaderView::section {
    background-color: #f8fafc;
    border: none;
    border-bottom: 2px solid #e2e8f0;
    padding: 8px 10px;
    font-weight: bold;
    font-size: 12px;
    color: #475569;
}
QTextEdit {
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    background: white;
    font-size: 13px;
}
QProgressBar {
    border: none;
    border-radius: 6px;
    background: #e2e8f0;
    height: 22px;
    text-align: center;
    font-size: 12px;
    font-weight: bold;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #2563eb);
    border-radius: 6px;
}
QSplitter::handle {
    background: #e2e8f0;
    width: 2px;
}
"""
