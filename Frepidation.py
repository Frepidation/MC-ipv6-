"""
Minecraft IPv6联机助手 v1.3.6
License: LGPL 3.0
Main Author: 治家长的轶风杏 (Frepidation)(虾脊拔乱写的)
Created: 2025-04-20 Beta
QQ Group Chat:865790973(main);730011260
"""

import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk
import psutil
import socket
import ipaddress
import base64
import threading
import time
import sys
import os
import subprocess
import pycurl
import webbrowser
from io import BytesIO
from functools import wraps
from threading import Thread

class MinecraftHelper:
    def __init__(self, root):
            self.root = root
            self.root.title("Minecraft IPv6联机助手 v1.3.9 By Frepidation")
            self.set_window_icon()

            self.port_scan_lock = threading.Lock()  # 线程锁
            self.cached_ports = []  # 端口缓存
            
            self.ipv6 = None
            self.port = None
            self.port_options = []
            self.running = True
            self.ipv6_fail_count = 0
            self.selected_port = tk.StringVar()
            self.manual_port = None

            self.create_widgets()
            self.add_author_button()

            self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            self.monitor_thread.start()

    def add_author_button(self):
        author_btn = tk.Button(self.root, text="作者主页", command=lambda:
            webbrowser.open("https://space.bilibili.com/3461583151827714?spm_id_from=333.1007.0.0"))
        author_btn.pack(side=tk.BOTTOM, pady=5)

    def set_window_icon(self):
        try:
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                # 修复路径获取方式
                base_path = os.path.dirname(os.path.abspath(__file__))

            icon_path = os.path.join(base_path, "icon.png")
            print(f"尝试加载图标路径: {icon_path}")  # 调试语句

            icon_image = Image.open(icon_path)
            self.tk_icon = ImageTk.PhotoImage(icon_image)
            self.root.iconphoto(False, self.tk_icon)
        except Exception as e:
            print(f"设置窗口图标失败: {e}")

    def create_widgets(self):
        # 状态框架
        self.status_frame = tk.LabelFrame(self.root, text="实时状态", padx=10, pady=5)
        self.status_frame.pack(padx=10, pady=5, fill=tk.X)

        # IP显示
        self.ip_label = tk.Label(self.status_frame, text="IPv6地址: 检测中...", anchor='w')
        self.ip_label.pack(fill=tk.X)

        # 端口选择框架
        self.port_frame = tk.Frame(self.status_frame)
        self.port_frame.pack(fill=tk.X, pady=3)

        # 端口标签
        self.port_label = tk.Label(self.port_frame, text="端口号: ", anchor='w')
        self.port_label.pack(side=tk.LEFT)

        # 端口下拉框
        self.port_combobox = ttk.Combobox(
            self.port_frame,
            textvariable=self.selected_port,
            state="readonly",
            width=15
        )
        self.port_combobox.pack(side=tk.LEFT, padx=5)
        self.port_combobox.bind("<Button-1>", self.async_update_ports)
        self.port_combobox.bind("<<ComboboxSelected>>", self.update_selected_port)

        # 手动输入按钮
        self.manual_btn = tk.Button(
            self.port_frame,
            text="选择Java进程",
            command=self.show_process_dialog
        )
        self.manual_btn.pack(side=tk.LEFT, padx=5)

        # 端口输入框
        self.port_entry = tk.Entry(
            self.port_frame,
            textvariable=self.selected_port,
            width=17,
            validate="key",
            validatecommand=(self.root.register(self.validate_port), '%P')
        )
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.bind("<FocusOut>", self.update_selected_port)
        self.port_entry.edited = False  # 添加编辑状态标记

        # 操作按钮框架
        self.control_frame = tk.LabelFrame(self.root, text="链接操作", padx=10, pady=5)
        self.control_frame.pack(padx=10, pady=5, fill=tk.X)

        self.btn_frame = tk.Frame(self.control_frame)
        self.btn_frame.pack(side=tk.RIGHT)

        # 操作按钮
        self.copy_btn = tk.Button(self.btn_frame, text="复制加密链接",
                                  command=self.copy_encrypted, state=tk.DISABLED)
        self.copy_btn.pack(side=tk.LEFT, padx=2)

        self.decrypt_btn = tk.Button(self.btn_frame, text="解密链接",
                                     command=self.paste_decrypted)
        self.decrypt_btn.pack(side=tk.LEFT, padx=2)

        # 解密输入框
        self.decrypt_frame = tk.Frame(self.control_frame)
        self.decrypt_frame.pack(fill=tk.X, pady=5)

        self.decrypt_label = tk.Label(self.decrypt_frame, text="解密链接:")
        self.decrypt_label.pack(side=tk.LEFT)

        self.decrypt_entry = tk.Entry(self.decrypt_frame, width=40)
        self.decrypt_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        # 状态栏
        self.status_bar = tk.Label(self.root, text="就绪", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def monitor_loop(self):
        while self.running:
            try:
                new_ip = self.get_public_ipv6()
                new_ports = self.get_java_ports()

                timeout_flag = self.ipv6_fail_count >= 3
                self.root.after(0, self.update_display, new_ip, new_ports, timeout_flag)
                self.root.after(0, self.update_port_combobox, new_ports)

                best_port = self.select_best_port(new_ports)
                if best_port:
                    self.port = best_port
                    self.selected_port.set(best_port)

                btn_state = tk.NORMAL if new_ip and self.port else tk.DISABLED
                self.root.after(0, self.copy_btn.config, {'state': btn_state})

                if new_ip is None:
                    self.ipv6_fail_count += 1
                else:
                    self.ipv6_fail_count = 0
            except Exception as e:
                print(f"端口扫描异常: {e}")
                return []
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("监控错误", str(e)))
                self.root.after(0, self.status_bar.config, {'text': f"监控错误: {str(e)}"})
            time.sleep(3)

    def get_public_ipv6(self):
        buffer = BytesIO()
        c = pycurl.Curl()

        c.setopt(c.URL, 'https://6.ipw.cn/')
        c.setopt(c.WRITEDATA, buffer)
        c.setopt(c.IPRESOLVE, c.IPRESOLVE_V6)
        c.setopt(c.FOLLOWLOCATION, True)
        c.setopt(c.TIMEOUT, 10)
        c.setopt(c.SSL_VERIFYPEER, 0)
        c.setopt(c.SSL_VERIFYHOST, 0)

        try:
            c.perform()
        except pycurl.error as e:
            print(f"请求失败: {e}")
            return None

        http_code = c.getinfo(c.HTTP_CODE)
        if http_code != 200:
            print(f"HTTP 错误码: {http_code}")
            return None

        ip_address = buffer.getvalue().decode('utf-8').strip()
        c.close()

        return ip_address

    def update_display(self, ip, ports, timeout_flag):
        # 更新IP地址显示
        if timeout_flag:
            self.ip_label.config(text="IPv6地址: 检测超时，请检查网络或联系光猫管理员", fg="#FF5722")
        elif ip:
            self.ip_label.config(text=f"IPv6地址: {ip}", fg="#4CAF50")
        else:
            self.ip_label.config(text="IPv6地址: 未检测到有效地址", fg="#FF9800")

        # 更新状态栏
        self.ipv6 = ip
        status_text = "就绪" if ip and ports else "正在检测网络..."
        status_color = "#4CAF50" if ip and ports else "#FF9800"
        port_status = f"可用端口: {len(ports)}" if ports else "未检测到端口"
        combined_status = f"{status_text} | {port_status}"
        self.status_bar.config(text=combined_status, fg=status_color)

    def run_async(func):
        @wraps(func)
        def async_func(*args, **kwargs):
            thread = Thread(target=func, args=args, kwargs=kwargs)
            thread.daemon = True
            thread.start()
        return async_func

    def async_update_ports(self, event=None):
        """异步触发端口更新（接受事件参数）"""
        if not self.port_scan_lock.locked():
            threading.Thread(target=self.safe_get_ports, daemon=True).start()

    def safe_get_ports(self):
        """线程安全的端口获取"""
        with self.port_scan_lock:
            new_ports = self.get_java_ports()
            if new_ports != self.cached_ports:
                self.cached_ports = new_ports
                self.root.after(0, self.update_port_display)

    def get_java_ports(self):
        ports = []
        has_priority_process = False
        manual_updated = False

        # 如果手动端口仍然有效则优先返回
        if hasattr(self, 'manual_port'):
            if self.manual_port in ports:
                return [self.manual_port]
            else:
                # 如果进程端口变化则清除手动端口
                del self.manual_port
                manual_updated = True

        # 第一阶段：优先搜索主类进程
        priority_classes = [
            'net.minecraft.client.main.Main',
            'net.minecraft.launchwrapper.Launch'
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # 过滤Java进程
                if proc.info['name'].lower() not in ['javaw.exe', 'java.exe']:
                    continue
                    
                cmdline = ' '.join(proc.info['cmdline'])
                # 检查是否是优先类
                is_priority = any(cls in cmdline for cls in priority_classes)
                
                if not is_priority:
                    continue
                    
                has_priority_process = True
                # 收集端口
                for conn in proc.net_connections(kind='inet'):
                    if conn.status == psutil.CONN_LISTEN and conn.laddr.port:
                        ports.append(conn.laddr.port)
                        
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        # 如果有优先进程但没找到端口，直接返回
        if has_priority_process and not ports:
            return []

        # 第二阶段：普通Java进程搜索
        if not has_priority_process:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['name'].lower() not in ['javaw.exe', 'java.exe']:
                        continue
                        
                    for conn in proc.net_connections(kind='inet'):
                        if conn.status == psutil.CONN_LISTEN and conn.laddr.port:
                            ports.append(conn.laddr.port)
                            
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
        # 自动清理逻辑
        if hasattr(self, 'manual_port'):
            if self.manual_port in ports:
                # 当手动端口被自动检测到时，转为自动模式
                self.status_bar.config(text=f"端口{self.manual_port}已被自动检测", fg="#4CAF50")
                del self.manual_port
            else:
        # 保留未检测到的手动端口
                ports.append(self.manual_port)
        # 合并手动端口（如果未被更新）
        if hasattr(self, 'manual_port') and not manual_updated:
            ports.append(self.manual_port)
            
        return sorted(set(ports))

    def select_best_port(self, ports):
        # 优先使用手动输入的端口
        if hasattr(self, 'manual_port'):
            return self.manual_port
        if not ports:
            return None  # 不自动弹出对话框
        for preferred in [25565, 31074]:
            if preferred in ports:
                return preferred
        return min(ports)

    def scan_ports(self):
        """扫描端口时重置编辑状态"""
        self.port_entry.edited = False
        # 每次扫描时检查手动端口有效性
        current_ports = self.get_java_ports()
        
        # 如果当前端口包含手动端口，保持手动设置
        if hasattr(self, 'manual_port'):
            if self.manual_port in current_ports:
                return self.manual_port
                
        # 选择最佳端口（可能触发手动输入）
        best_port = self.select_best_port(current_ports)
        
        # 自动更新手动端口
        if hasattr(self, 'manual_port') and best_port != self.manual_port:
            print(f"端口已更新: {self.manual_port} -> {best_port}")
            self.manual_port = best_port
            
        return best_port

    def validate_port(self, new_value):
         """验证端口输入是否合法"""
         if new_value == "":
             return True
         if not new_value.isdigit():
             return False
         return 0 <= int(new_value) <= 65535

    def update_port_combobox(self, new_ports):
        """更新端口显示"""
        current = self.selected_port.get()

        if not self.port_entry.edited:
            best_port = self.select_best_port(new_ports)
            if best_port:
                self.selected_port.set(str(best_port))
                self.port = best_port

        if new_ports:
            status = f"检测到{len(new_ports)}个可用端口" if len(new_ports) > 1 else "已锁定端口"
            self.status_bar.config(text=status, fg="#4CAF50")
        else:
            self.status_bar.config(text="未检测到Java进程端口", fg="#FF9800")

    def update_selected_port(self, event=None):
        """端口更新处理（修改后）"""
        port_str = self.selected_port.get()
        if port_str:
            try:
                self.port = int(port_str)
                self.manual_port = self.port  # 存储为手动端口
                self.port_entry.edited = True  # 标记已手动编辑
                self.status_bar.config(text=f"手动指定端口: {self.port}", fg="#2196F3")
            except ValueError:
                messagebox.showerror("错误", "无效的端口号")
    def show_process_dialog(self):
        """显示Java进程选择对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("选择Java进程")

        processes = self.get_java_processes()
        if not processes:
            messagebox.showinfo("提示", "未找到正在运行的Java进程", parent=dialog)
            dialog.destroy()
            return

        listbox = tk.Listbox(dialog, width=60, height=15)
        scrollbar = tk.Scrollbar(dialog)

        for pid, cmd in processes:
            listbox.insert(tk.END, f"PID: {pid} | {self.truncate_cmd(cmd)}")
        def on_select():
            selection = listbox.curselection()
            if selection:
                pid = processes[selection[0]][0]
                self.scan_process_ports(pid)
                dialog.destroy()

        tk.Button(dialog, text="选择", command=on_select).pack(side=tk.BOTTOM)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=listbox.yview)

    def truncate_cmd(self, cmd):
        """缩短命令行显示"""
        MAX_LENGTH = 50
        return cmd[:MAX_LENGTH] + "..." if len(cmd) > MAX_LENGTH else cmd

    def get_java_processes(self):
        """获取所有Java进程列表"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['name'].lower() in ['javaw.exe', 'java.exe']:
                    cmd = ' '.join(proc.info['cmdline'])
                    processes.append((proc.info['pid'], cmd))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        return processes

    def scan_process_ports(self, pid):
        """扫描指定进程的监听端口"""
        try:
            proc = psutil.Process(pid)
            ports = []
            for conn in proc.net_connections(kind='inet'):
                if conn.status == psutil.CONN_LISTEN and conn.laddr.port:
                    ports.append(conn.laddr.port)

            if ports:
                self.manual_port = ports[0]
                self.selected_port.set(str(ports[0]))
                self.status_bar.config(text=f"已选择进程端口: {ports[0]}", fg="#2196F3")
            else:
                messagebox.showinfo("提示", "该进程没有监听任何端口")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def update_port_display(self):
        """主线程UI更新"""
        # 更新下拉框选项
        self.port_combobox['values'] = self.cached_ports

        # 自动选择最佳端口
        if not self.port_entry.edited:
            best_port = self.select_best_port(self.cached_ports)
            if best_port:
                self.selected_port.set(str(best_port))
                self.port = best_port

    def center_window(self, window):
        """居中窗口"""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f'+{x}+{y}')

    def update_display(self, ip, ports, timeout_flag):
         if timeout_flag:
             self.ip_label.config(text="IPv6地址: 检测超时，请检查网络或联系光猫管理员", fg="#FF5722")
         elif ip:
             self.ip_label.config(text=f"IPv6地址: {ip}", fg="#4CAF50")
         else:
             self.ip_label.config(text="IPv6地址: 未检测到有效地址", fg="#FF9800")

         self.ipv6 = ip
         status_text = "就绪" if ip and ports else "正在检测网络..."
         status_color = "#4CAF50" if ip and ports else "#FF9800"
         port_status = f"可用端口: {len(ports)}" if ports else "未检测到端口"
         combined_status = f"{status_text} | {port_status}"
         self.status_bar.config(text=combined_status, fg=status_color)

    def handle_manual_port(self):
        # 使用Tkinter对话框在主线程获取输入
        self.root.after(0, self.show_port_dialog)
        return None  # 暂时返回None，通过对话框异步处理

    def show_port_dialog(self):
        """手动输入端口对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("手动输入端口")

        # 设置对话框属性
        dialog.transient(self.root)  # 设置为顶级窗口的子窗口
        dialog.grab_set()  # 独占焦点
        dialog.resizable(False, False)

        # 设置对话框图标
        try:
            dialog.iconphoto(False, self.tk_icon)
        except Exception as e:
            print(f"设置对话框图标失败: {e}")

        # 输入验证函数
        def validate(new_val):
            if not new_val: return True
            if not new_val.isdigit(): return False
            return 1 <= int(new_val) <= 65535

        # 界面布局
        tk.Label(dialog, text="输入端口 (1-65535):").grid(row=0, column=0, padx=5, pady=5)
        entry = ttk.Entry(dialog, validate="key",
                          validatecommand=(dialog.register(validate), '%P'))
        entry.grid(row=0, column=1, padx=5, pady=5)

        # 显示当前检测到的端口
        current_ports = self.get_java_ports()
        tip_text = f"检测到可用端口: {', '.join(map(str, current_ports))}" if current_ports else "当前无自动检测端口"
        ttk.Label(dialog, text=tip_text, foreground="#666").grid(row=1, column=0, columnspan=2)

        # 确认回调
        def on_confirm():
            port_str = entry.get()
            if not port_str:
                messagebox.showerror("错误", "端口不能为空", parent=dialog)
                return

            port = int(port_str)
            self.manual_port = port
            self.selected_port.set(port)
            self.port_entry.edited = True
            self.status_bar.config(text=f"手动指定端口: {port}", fg="#2196F3")
            dialog.destroy()

        # 按钮布局
        btn_frame = tk.Frame(dialog)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=5)

        ttk.Button(btn_frame, text="确定", command=on_confirm).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)

        # 焦点和回车绑定
        entry.focus_set()
        dialog.bind('<Return>', lambda e: on_confirm())

        # 居中显示
        self.center_window(dialog)

    def encrypt_data(self):
        if not self.ipv6 or not self.port:
            return None
        raw_str = f"[{self.ipv6}]:{self.port}"
        return base64.b64encode(raw_str.encode()).decode()

    def decrypt_data(self, encrypted):
        try:
            decoded = base64.b64decode(encrypted).decode()
            if not decoded.startswith('[') or ']' not in decoded:
                return None
            ip_part, port_part = decoded.split(']:')
            ip = ip_part[1:]
            port = port_part.strip()
            ipaddress.IPv6Address(ip)
            if not port.isdigit():
                return None
            return f"[{ip}]:{port}"
        except Exception as e:
            print(f"解密失败: {e}")
            return None

    def copy_encrypted(self):
        self.copy_btn.config(state=tk.DISABLED)
        encrypted = self.encrypt_data()
        if encrypted:
            self.root.clipboard_clear()
            self.root.clipboard_append(encrypted)
            messagebox.showinfo("成功", "加密链接已复制到剪贴板")

            # 重置手动选择
            if hasattr(self, 'manual_port'):
                del self.manual_port
            self.port_entry.edited = False
            self.async_update_ports()
        else:
            messagebox.showwarning("警告", "无法生成有效链接")
        self.copy_btn.config(state=tk.NORMAL)

    def paste_decrypted(self):
        encrypted = self.decrypt_entry.get()
        decrypted = self.decrypt_data(encrypted)
        if decrypted:
            self.root.clipboard_clear()
            self.root.clipboard_append(decrypted)
            messagebox.showinfo("成功", "解密后的链接已复制到剪贴板")
        else:
            messagebox.showerror("错误", "无效的加密链接")

    def on_close(self):
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("650x300")  # 增加高度以适应新按钮
    app = MinecraftHelper(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

"""
Minecraft IPv6联机助手 v1.3.6
License: LGPL 3.0
Author: 治家长的轶风杏 (Frepidation)
Created: 2025-04-20 Beta
"""