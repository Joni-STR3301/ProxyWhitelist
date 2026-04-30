# -*- coding: utf-8 -*-
import sys
import os
import subprocess
import time
import tempfile
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QTextEdit, QLineEdit,
                             QListWidget, QPushButton, QSplitter, QMessageBox,
                             QListWidgetItem, QAbstractItemView)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal, QObject

WHITELIST_FILE = Path("whitelist.txt")
LOG_FILE = Path("access.log")

class InternetControlGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.proxy_process = None
        self.temp_script_path = None
        self.init_ui()
        self.start_proxy()
        self.start_log_monitoring()

    def init_ui(self):
        self.setWindowTitle("Proxy whitelist")
        self.setGeometry(150, 150, 1200, 700)
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #2b2b2b; color: #ffffff; font-size: 12pt; }
            QTextEdit, QListWidget, QLineEdit { background-color: #3c3c3c; color: #ffffff; border: 1px solid #555; border-radius: 5px; }
            QPushButton { background-color: #4a4a4a; color: #fff; border: 1px solid #555; border-radius: 5px; padding: 5px; }
            QPushButton:hover { background-color: #5a5a5a; }
            QLabel { font-weight: bold; margin-top: 5px; }
            QSplitter::handle { background-color: #555; }
        """)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("background-color: #1e1e1e; font-family: monospace;")

        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Введите домен, например google.com")

        self.add_btn = QPushButton("Добавить")
        self.remove_btn = QPushButton("Удалить")
        self.refresh_btn = QPushButton("Обновить")

        self.whitelist_list = QListWidget()
        self.whitelist_list.setSelectionMode(QAbstractItemView.ExtendedSelection)

        self.status_label = QLabel("Статус: запуск прокси...")

        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        splitter = QSplitter(Qt.Horizontal)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.addWidget(QLabel("📊 Логи доступа:"))
        left_layout.addWidget(self.log_text)
        left_layout.addWidget(self.status_label)

        right_panel = QWidget()
        right_panel.setMaximumWidth(320)
        right_layout = QVBoxLayout(right_panel)
        right_layout.addWidget(QLabel("✏️ Управление белым списком"))
        right_layout.addWidget(QLabel("Домен:"))
        right_layout.addWidget(self.domain_input)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.remove_btn)
        btn_layout.addWidget(self.refresh_btn)
        right_layout.addLayout(btn_layout)

        right_layout.addWidget(QLabel("📋 Разрешённые сайты:"))
        right_layout.addWidget(self.whitelist_list)
        
        right_layout.addStretch()

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([880, 320])

        main_layout.addWidget(splitter)
        self.setCentralWidget(main_widget)

        self.add_btn.clicked.connect(self.add_domain)
        self.remove_btn.clicked.connect(self.remove_domains)
        self.refresh_btn.clicked.connect(self.load_whitelist_ui)

        self.load_whitelist_ui()
        self.update_status()

    def generate_temp_proxy_script(self):
        script_content = f'''
# -*- coding: utf-8 -*-
import sys
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from mitmproxy import http

WHITELIST_FILE = Path(r"{WHITELIST_FILE.absolute()}")
LOG_FILE = Path(r"{LOG_FILE.absolute()}")

def load_whitelist():
    """Загружает белый список из файла при каждом вызове."""
    if not WHITELIST_FILE.exists():
        return set()
    with open(WHITELIST_FILE, "r") as f:
        return {{line.strip().lower() for line in f if line.strip()}}

def log_access(client_ip, url, allowed):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "ALLOWED" if allowed else "BLOCKED"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{{timestamp}}] [{{status}}] [{{client_ip}}] -> {{url}}\\n")
    except:
        pass

def request(flow: http.HTTPFlow):
    whitelist = load_whitelist()
    
    client_ip = flow.client_conn.address[0]
    url = flow.request.pretty_url
    
    if not whitelist:
        log_access(client_ip, url, True)
        return
    
    try:
        hostname = urlparse(url).hostname or ""
        if not hostname:
            log_access(client_ip, url, True)
            return
        hostname = hostname.lower()
    except:
        log_access(client_ip, url, True)
        return
    
    allowed = False
    for allowed_domain in whitelist:
        if hostname == allowed_domain or hostname.endswith(f".{{allowed_domain}}"):
            allowed = True
            break
    
    log_access(client_ip, url, allowed)
    
    if not allowed:
        flow.response = http.Response.make(
            403,
            b"<h1>403 Forbidden</h1><p>This website is not in the allowlist.</p>",
            {{"Content-Type": "text/html"}}
        )
'''
        fd, path = tempfile.mkstemp(suffix=".py", prefix="mitmproxy_", text=True)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script_content)
        return Path(path)

    def start_proxy(self):
        if self.temp_script_path and self.temp_script_path.exists():
            try:
                self.temp_script_path.unlink()
            except:
                pass

        self.temp_script_path = self.generate_temp_proxy_script()
        try:
            self.proxy_process = subprocess.Popen(
                ["mitmdump", "-s", str(self.temp_script_path), "-q"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            time.sleep(2)
            self.update_status("Прокси запущен и работает. Белый список активен.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось запустить прокси: {e}")
            self.update_status(f"Ошибка: {e}")

    def start_log_monitoring(self):
        self.last_position = 0
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self.check_new_logs)
        self.log_timer.start(500)

    def check_new_logs(self):
        if not LOG_FILE.exists():
            return
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                f.seek(self.last_position)
                for line in f:
                    line = line.strip()
                    if line:
                        self.append_formatted_log(line)
                self.last_position = f.tell()
        except Exception as e:
            pass

    def append_formatted_log(self, line):
        import re

        match = re.match(r'\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] -> (.+)', line)
        
        if match:
            timestamp = match.group(1)
            status = match.group(2)
            client_ip = match.group(3)
            url = match.group(4)

            time_color = "#66b3ff" 
            if status == "ALLOWED":
                status_color = "#6fbf6f" 
            else:
                status_color = "#ff7b72"
            default_color = "#d4d4d4"
            
            html_line = (
                f'<span style="color:{time_color};">[{timestamp}]</span> '
                f'<span style="color:{status_color};">[{status}]</span> '
                f'<span style="color:{default_color};">[{client_ip}] -> {url}</span>'
            )
        else:
            html_line = f'<span style="color:#d4d4d4;">{line}</span>'
        
        self.log_text.append(html_line)
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def load_whitelist_ui(self):
        self.whitelist_list.clear()
        if WHITELIST_FILE.exists():
            with open(WHITELIST_FILE, "r") as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        item = QListWidgetItem(domain)
                        item.setForeground(Qt.GlobalColor.green)
                        self.whitelist_list.addItem(item)
        self.update_status()

    def update_status(self, msg=None):
        if msg:
            self.status_label.setText(msg)
        else:
            cnt = self.whitelist_list.count()
            if cnt == 0:
                self.status_label.setText("⚠️ Белый список ПУСТ. Все сайты разрешены. Добавьте сайты для блокировки остальных.")
            else:
                self.status_label.setText(f"Прокси активен. Белый список содержит {cnt} сайтов.")

    def add_domain(self):
        domain = self.domain_input.text().strip().lower()
        if not domain:
            QMessageBox.warning(self, "Ошибка", "Введите домен")
            return
        
        domains = set()
        if WHITELIST_FILE.exists():
            with open(WHITELIST_FILE, "r") as f:
                domains = {line.strip().lower() for line in f if line.strip()}
        
        if domain in domains:
            QMessageBox.information(self, "Информация", f"Домен '{domain}' уже в белом списке")
            return
        
        with open(WHITELIST_FILE, "a") as f:
            f.write(f"{domain}\n")
        
        self.load_whitelist_ui()
        self.domain_input.clear()
        QMessageBox.information(self, "Успех", f"Домен '{domain}' добавлен в белый список")

    def remove_domains(self):
        selected = self.whitelist_list.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Ошибка", "Выберите домены для удаления")
            return
        
        if QMessageBox.question(self, "Подтверждение", f"Удалить {len(selected)} домен(ов)?",
                                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        
        domains = set()
        if WHITELIST_FILE.exists():
            with open(WHITELIST_FILE, "r") as f:
                domains = {line.strip().lower() for line in f if line.strip()}
        
        for item in selected:
            domains.discard(item.text().lower())
        
        with open(WHITELIST_FILE, "w") as f:
            for domain in sorted(domains):
                f.write(f"{domain}\n")
        
        self.load_whitelist_ui()

    def closeEvent(self, event):
        if self.proxy_process:
            self.proxy_process.terminate()
            self.proxy_process.wait()
        if self.temp_script_path and self.temp_script_path.exists():
            try:
                self.temp_script_path.unlink()
            except:
                pass
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = InternetControlGUI()
    window.show()
    sys.exit(app.exec_())