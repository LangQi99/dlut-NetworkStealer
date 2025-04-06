import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QLineEdit,
                             QTableWidget, QTableWidgetItem, QTabWidget,
                             QMessageBox, QProgressBar, QComboBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtCore import QUrl
import utils
from data_storage import DataStorage
from scapy.all import sniff, ARP

lambda: "从左往右的第二位mac地址必须为2,6,A,E。只有第二位为这些数字时候才会生效。"


class ScanNetworkThread(QThread):
    progress_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(list)

    def __init__(self, network_address):
        super().__init__()
        self.network_address = network_address

    def run(self):
        try:
            active_ips = utils.scan_network(self.network_address)
            self.finished_signal.emit(active_ips)
        except Exception as e:
            self.progress_signal.emit(f"扫描出错: {str(e)}")


class ArpHeartbeatThread(QThread):
    heartbeat_signal = pyqtSignal(str, str, str)  # MAC地址, IP地址, 时间戳

    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.running = True

    def run(self):
        def arp_callback(packet):
            if packet.haslayer(ARP) and self.running:
                arp = packet[ARP]
                if arp.op == 1:  # who-has 请求
                    self.heartbeat_signal.emit(
                        arp.hwsrc.replace(":", "-").upper(),
                        arp.psrc,
                        utils.get_current_time())
            return self.running

        sniff(filter="arp", prn=arp_callback, store=0, iface=self.iface,
              promisc=True, stop_filter=lambda _: not self.running)

    def stop(self):
        self.running = False


class NetworkStealerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Stealer")
        self.setMinimumSize(800, 600)
        self.mac_data = DataStorage("mac_data.json")

        # 创建主窗口部件和布局
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # 创建选项卡
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # 添加 GitHub 链接
        github_link = QPushButton("LangQi99")
        github_link.setStyleSheet(
            "QPushButton { border: none; color: blue; text-decoration: underline; }")
        github_link.setCursor(Qt.CursorShape.PointingHandCursor)

        def open_link():
            url = "langqi99.com"
            try:
                if utils.ping(url):
                    QDesktopServices.openUrl(QUrl("https://langqi99.com"))
                else:
                    QDesktopServices.openUrl(
                        QUrl("https://github.com/LangQi99"))
            except:
                QDesktopServices.openUrl(QUrl("https://github.com/LangQi99"))
        github_link.clicked.connect(lambda: open_link())

        # 将链接添加到选项卡栏的最右侧
        tabs.setCornerWidget(github_link, Qt.Corner.TopRightCorner)

        # 网络状态选项卡
        status_tab = QWidget()
        status_layout = QVBoxLayout(status_tab)

        # 添加状态表格
        self.status_table = QTableWidget()
        self.status_table.setColumnCount(2)
        self.status_table.setHorizontalHeaderLabels(["项目", "状态"])
        self.status_table.setColumnWidth(1, 150)  # 设置第二列宽度
        status_layout.addWidget(self.status_table)

        # 创建水平布局来容纳按钮
        button_layout = QHBoxLayout()

        # 添加保存到数据存储的按钮
        save_button = QPushButton("保存数据")
        save_button.setFixedSize(120, 35)
        save_button.clicked.connect(lambda: self.save_to_storage())
        button_layout.addWidget(save_button)

        # 添加刷新按钮
        refresh_button = QPushButton("刷新数据")
        refresh_button.setFixedSize(120, 35)
        refresh_button.clicked.connect(lambda: self.refresh_network_status())
        button_layout.addWidget(refresh_button)

        # 添加跳转登录按钮
        login_button = QPushButton("跳转登录")
        login_button.setFixedSize(120, 35)
        login_button.clicked.connect(lambda: self.open_login_page())
        button_layout.addWidget(login_button)

        # 添加按钮布局到主布局
        button_layout.addStretch()  # 添加弹性空间，使按钮靠左对齐
        status_layout.addLayout(button_layout)

        # 网络扫描选项卡
        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)

        network_layout = QHBoxLayout()
        network_label = QLabel("网络地址:")
        self.network_input = QLineEdit(utils.get_local_ip()+"/24")
        scan_button = QPushButton("开始扫描")
        scan_button.clicked.connect(lambda: self.start_network_scan())
        network_layout.addWidget(network_label)
        network_layout.addWidget(self.network_input)
        network_layout.addWidget(scan_button)
        scan_layout.addLayout(network_layout)

        self.scan_progress = QProgressBar()
        scan_layout.addWidget(self.scan_progress)

        self.scan_result_table = QTableWidget()
        self.scan_result_table.setColumnCount(1)
        self.scan_result_table.setHorizontalHeaderLabels(["活跃IP"])
        scan_layout.addWidget(self.scan_result_table)

        # MAC扫描选项卡
        mac_scan_tab = QWidget()
        mac_scan_layout = QVBoxLayout(mac_scan_tab)

        # 添加网卡选择下拉框
        adapter_select_layout = QHBoxLayout()
        adapter_label = QLabel("选择网卡:")
        self.adapter_combo = QComboBox()
        # 在创建时就连接信号
        self.adapter_combo.currentIndexChanged.connect(
            self.on_adapter_changed)
        self.refresh_adapter_combo_button = QPushButton("刷新")
        self.refresh_adapter_combo_button.clicked.connect(
            lambda: self.refresh_adapter_combo())
        adapter_select_layout.addWidget(adapter_label)
        adapter_select_layout.addWidget(self.adapter_combo)
        adapter_select_layout.addWidget(self.refresh_adapter_combo_button)
        mac_scan_layout.addLayout(adapter_select_layout)

        mac_scan_network_layout = QHBoxLayout()
        mac_scan_network_label = QLabel("网络地址:")
        self.mac_scan_network_input = QLineEdit(utils.get_local_ip()+"/24")
        mac_scan_button = QPushButton("开始扫描")
        mac_scan_button.clicked.connect(lambda: self.start_mac_scan())
        mac_scan_network_layout.addWidget(mac_scan_network_label)
        mac_scan_network_layout.addWidget(self.mac_scan_network_input)
        mac_scan_network_layout.addWidget(mac_scan_button)
        mac_scan_layout.addLayout(mac_scan_network_layout)

        self.mac_scan_progress = QProgressBar()
        mac_scan_layout.addWidget(self.mac_scan_progress)

        self.mac_scan_result_table = QTableWidget()
        self.mac_scan_result_table.setColumnCount(4)
        self.mac_scan_result_table.setHorizontalHeaderLabels(
            ["MAC地址", "IP数量", "IP地址列表", "备注"])
        self.mac_scan_result_table.setColumnWidth(0, 150)  # MAC地址列
        self.mac_scan_result_table.setColumnWidth(1, 80)   # IP数量列
        self.mac_scan_result_table.setColumnWidth(2, 300)  # IP地址列表列
        self.mac_scan_result_table.setColumnWidth(3, 80)  # 备注列
        mac_scan_layout.addWidget(self.mac_scan_result_table)

        # ARP心跳选项卡
        heartbeat_tab = QWidget()
        heartbeat_layout = QVBoxLayout(heartbeat_tab)

        # ARP缓存选项卡
        arp_tab = QWidget()
        arp_layout = QVBoxLayout(arp_tab)

        arp_button = QPushButton("获取ARP缓存")
        arp_button.clicked.connect(lambda: self.get_arp_info())
        arp_layout.addWidget(arp_button)

        self.arp_table = QTableWidget()
        self.arp_table.setColumnCount(4)
        self.arp_table.setHorizontalHeaderLabels(
            ["MAC地址", "出现次数", "状态", "活跃IP"])
        # 设置MAC地址列的宽度
        self.arp_table.setColumnWidth(0, 150)  # MAC地址列
        arp_layout.addWidget(self.arp_table)

        # 网卡管理选项卡
        adapter_tab = QWidget()
        adapter_layout = QVBoxLayout(adapter_tab)

        refresh_button = QPushButton("刷新网卡列表")
        refresh_button.clicked.connect(lambda: self.refresh_adapters())
        adapter_layout.addWidget(refresh_button)

        self.adapter_table = QTableWidget()
        self.adapter_table.setColumnCount(3)
        self.adapter_table.setHorizontalHeaderLabels(["适配器编号", "适配器ID", "描述"])
        self.adapter_table.setColumnWidth(2, 250)  # 描述
        adapter_layout.addWidget(self.adapter_table)

        mac_layout = QHBoxLayout()
        self.mac_input = QLineEdit()
        self.mac_input.setPlaceholderText("输入新的MAC地址 (格式: xx-xx-xx-xx-xx-xx)")
        change_mac_button = QPushButton("修改MAC地址")
        change_mac_button.clicked.connect(lambda: self.change_mac_address())
        mac_layout.addWidget(self.mac_input)
        mac_layout.addWidget(change_mac_button)
        adapter_layout.addLayout(mac_layout)

        reboot_button = QPushButton("重启选中网卡")
        reboot_button.clicked.connect(lambda: self.reboot_adapter())
        adapter_layout.addWidget(reboot_button)

        # 数据存储选项卡
        storage_tab = QWidget()
        storage_layout = QVBoxLayout(storage_tab)

        # 添加按钮
        add_button = QPushButton("+")
        add_button.setFixedSize(30, 30)  # 设置按钮为正方形
        add_button.clicked.connect(lambda: self.add_new_entry())
        add_button_layout = QHBoxLayout()
        add_button_layout.addWidget(add_button)
        add_button_layout.addStretch()  # 将按钮推到左侧
        storage_layout.addLayout(add_button_layout)

        # 数据表格
        self.storage_table = QTableWidget()
        self.storage_table.setColumnCount(3)
        self.storage_table.setHorizontalHeaderLabels(["MAC地址", "备注", "操作"])
        self.storage_table.setColumnWidth(0, 150)
        self.storage_table.itemDoubleClicked.connect(
            lambda: self.handle_item_double_clicked())
        self.storage_table.itemChanged.connect(
            self.handle_item_changed)
        storage_layout.addWidget(self.storage_table)

        # 添加免责声明标签
        disclaimer_label = QLabel("仅供学习交流，用户自行承担使用风险")
        disclaimer_label.setStyleSheet("color: gray;")
        disclaimer_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        storage_layout.addWidget(disclaimer_label)

        # 添加选项卡到窗口
        # 第一组：主要功能
        tabs.addTab(mac_scan_tab, "地址扫描")
        tabs.addTab(heartbeat_tab, "ARP心跳")
        tabs.addTab(adapter_tab, "网卡管理")
        tabs.addTab(storage_tab, "数据存储")
        tabs.addTab(status_tab, "网络状态")

        # 第二组：网络工具
        scan_arp_group = QTabWidget()
        scan_arp_group.addTab(scan_tab, "网络扫描")
        scan_arp_group.addTab(arp_tab, "ARP缓存")
        tabs.addTab(scan_arp_group, "其他工具")

        # 添加网卡选择
        heartbeat_adapter_layout = QHBoxLayout()
        heartbeat_adapter_label = QLabel("选择网卡:")
        self.heartbeat_adapter_combo = QComboBox()
        self.heartbeat_adapter_combo.currentIndexChanged.connect(
            lambda: self.on_heartbeat_adapter_changed())
        self.refresh_heartbeat_adapter_button = QPushButton("刷新")
        self.refresh_heartbeat_adapter_button.clicked.connect(
            lambda: self.refresh_heartbeat_adapter_combo())
        heartbeat_adapter_layout.addWidget(heartbeat_adapter_label)
        heartbeat_adapter_layout.addWidget(self.heartbeat_adapter_combo)
        heartbeat_adapter_layout.addWidget(
            self.refresh_heartbeat_adapter_button)
        heartbeat_layout.addLayout(heartbeat_adapter_layout)

        # 控制按钮
        control_layout = QHBoxLayout()
        self.start_heartbeat_button = QPushButton("开始监听")
        self.start_heartbeat_button.clicked.connect(
            lambda: self.toggle_heartbeat_monitoring())
        self.clear_heartbeat_button = QPushButton("清空记录")
        self.clear_heartbeat_button.clicked.connect(
            lambda: self.clear_heartbeat_records())
        control_layout.addWidget(self.start_heartbeat_button)
        control_layout.addWidget(self.clear_heartbeat_button)
        control_layout.addStretch()
        heartbeat_layout.addLayout(control_layout)

        # ARP心跳记录表格
        self.heartbeat_table = QTableWidget()
        self.heartbeat_table.setColumnCount(6)
        self.heartbeat_table.setHorizontalHeaderLabels(
            ["MAC地址", "计数", "活跃", "IP", "时间", "备注"])
        # 设置MAC地址列的宽度
        self.heartbeat_table.setColumnWidth(0, 150)  # MAC地址列
        self.heartbeat_table.setColumnWidth(1, 50)  # 出现次数列
        self.heartbeat_table.setColumnWidth(2, 150)  # 活跃列
        self.heartbeat_table.setColumnWidth(3, 120)  # IP列
        self.heartbeat_table.setColumnWidth(4, 80)  # 时间列
        self.heartbeat_table.setColumnWidth(5, 80)  # 备注列
        heartbeat_layout.addWidget(self.heartbeat_table)

        # 创建定时器，每分钟更新一次相对时间
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_relative_times)
        self.update_timer.start(60000)  # 60000毫秒 = 1分钟

        # 初始化心跳监听相关变量
        self.heartbeat_thread = None
        self.heartbeat_records = {}  # 存储心跳记录
        self.is_monitoring = False

        # 初始化心跳监听的网卡下拉框
        self.refresh_heartbeat_adapter_combo()

        self.refresh_adapters()
        self.refresh_storage_table()
        self.refresh_network_status()  # 初始化时刷新网络状态

        # 初始化网卡下拉框
        self.refresh_adapter_combo()

    def start_network_scan(self):
        network_address = self.network_input.text()
        self.scan_thread = ScanNetworkThread(network_address)
        self.scan_thread.finished_signal.connect(self.update_scan_results)
        self.scan_thread.start()
        self.scan_progress.setRange(0, 0)  # 显示忙碌状态

    def update_scan_results(self, active_ips):
        self.scan_result_table.setRowCount(len(active_ips))
        for i, ip in enumerate(active_ips):
            self.scan_result_table.setItem(i, 0, QTableWidgetItem(ip))
        self.scan_progress.setRange(0, 100)
        self.scan_progress.setValue(100)

    def get_arp_info(self):
        active_ips = []
        for row in range(self.scan_result_table.rowCount()):
            ip = self.scan_result_table.item(row, 0).text()
            active_ips.append(ip)

        arp_table = utils._get_arp_table()
        arp_info = utils.get_arp_info(active_ips, arp_table)

        self.arp_table.setRowCount(len(arp_info))
        for i, (mac, info) in enumerate(arp_info.items()):
            self.arp_table.setItem(i, 0, QTableWidgetItem(mac))
            self.arp_table.setItem(i, 1, QTableWidgetItem(str(info["count"])))
            self.arp_table.setItem(i, 2, QTableWidgetItem(info["status"]))
            self.arp_table.setItem(i, 3, QTableWidgetItem(
                ", ".join(info["active_ips"])))

    def refresh_adapters(self):
        adapters = utils.get_active_adapters()
        self.adapter_table.setRowCount(len(adapters))
        for i, adapter in enumerate(adapters):
            self.adapter_table.setItem(
                i, 0, QTableWidgetItem(adapter["adapter_index"]))
            self.adapter_table.setItem(
                i, 1, QTableWidgetItem(adapter["adapter_id"]))
            self.adapter_table.setItem(
                i, 2, QTableWidgetItem(adapter["description"]))

    def change_mac_address(self):
        selected_rows = self.adapter_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "警告", "请先选择一个网卡")
            return

        adapter_index = self.adapter_table.item(
            selected_rows[0].row(), 0).text()
        new_mac = self.mac_input.text()

        if utils.modify_mac_address(adapter_index, new_mac):
            QMessageBox.information(self, "成功", "MAC地址修改成功，请重启网卡使更改生效")
        else:
            QMessageBox.warning(self, "失败", "MAC地址修改失败\n尝试使用管理员权限打开")

    def reboot_adapter(self):
        selected_rows = self.adapter_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "警告", "请先选择一个网卡")
            return

        adapter_id = self.adapter_table.item(selected_rows[0].row(), 1).text()

        if utils.reboot_adapter(adapter_id):
            QMessageBox.information(self, "成功", "网卡重启指令已发送")
        else:
            QMessageBox.warning(self, "失败", "网卡重启失败\n尝试使用管理员权限打开")

    def refresh_storage_table(self):
        entries = self.mac_data.get_all_entries()
        self.storage_table.setRowCount(len(entries))

        # 显示现有条目
        for i, entry in enumerate(entries):
            mac_item = QTableWidgetItem(entry["mac_address"])
            note_item = QTableWidgetItem(entry["note"])
            self.storage_table.setItem(i, 0, mac_item)
            self.storage_table.setItem(i, 1, note_item)

            delete_button = QPushButton("删除")
            delete_button.clicked.connect(
                lambda checked, row=i: self.remove_storage_entry(row))
            self.storage_table.setCellWidget(i, 2, delete_button)

    def add_new_entry(self):
        self.mac_data.add_entry("", "")
        self.refresh_storage_table()
        # 自动开始编辑新添加的MAC地址单元格
        new_row = len(self.mac_data.get_all_entries()) - 1
        self.storage_table.editItem(self.storage_table.item(new_row, 0))

    def handle_item_double_clicked(self, item):
        row = item.row()
        col = item.column()

        # 如果是现有条目
        if col < 2:  # 只允许编辑MAC地址和备注列
            self.storage_table.editItem(item)

    def remove_storage_entry(self, row):
        self.mac_data.remove_entry(row)
        self.refresh_storage_table()

    def handle_item_changed(self, item):
        row = item.row()
        col = item.column()

        # 确保是在编辑现有条目
        entries = self.mac_data.get_all_entries()
        if row >= len(entries):
            return

        # 获取当前行的数据
        mac = self.storage_table.item(row, 0).text().strip(
        ) if self.storage_table.item(row, 0) else ""
        note = self.storage_table.item(row, 1).text(
        ).strip() if self.storage_table.item(row, 1) else ""

        # 更新数据
        if mac or note:  # 只要有一个字段不为空就保存
            self.mac_data.update_entry(row, mac, note)

    def refresh_network_status(self):
        """刷新网络状态信息"""
        network_info = utils.get_dlut_network_info()

        # 清空并设置表格行数
        self.status_table.setRowCount(len(network_info))

        # 填充数据
        for i, (key, value) in enumerate(network_info.items()):
            self.status_table.setItem(i, 0, QTableWidgetItem(key))
            self.status_table.setItem(i, 1, QTableWidgetItem(str(value)))

    def save_to_storage(self):
        """将网络状态中的MAC地址和姓名保存到数据存储"""
        mac_address = None
        name = None

        # 从状态表格中获取MAC地址和姓名
        for row in range(self.status_table.rowCount()):
            key = self.status_table.item(row, 0).text()
            value = self.status_table.item(row, 1).text()

            if key == "MAC 地址":
                mac_address = value
            elif key == "姓名":
                name = value

        if mac_address and name:
            # 添加新条目到数据存储
            self.mac_data.add_entry(mac_address, name)
            self.refresh_storage_table()
            QMessageBox.information(self, "成功", "已成功保存到数据存储")
        else:
            QMessageBox.warning(self, "错误", "未找到MAC地址或姓名信息")

    def keyPressEvent(self, event):
        super().keyPressEvent(event)

    def open_login_page(self):
        """打开登录页面"""
        try:
            # 获取状态检查数据
            import requests
            import json

            response = requests.get(
                'http://172.20.30.1/drcom/chkstatus?callback=', timeout=5)
            data_text = response.text

            # 提取JSON部分
            json_str = "{" + data_text.split("({")[1].split("})")[0] + "}"
            data = json.loads(json_str)

            # 获取IP地址
            v4ip = data.get('v4ip')
            if not v4ip:
                v4ip = data.get('v46ip')

            if v4ip:
                # 构建登录URL
                login_url = f"https://sso.dlut.edu.cn/cas/login?service=http%3A%2F%2F172.20.30.2%3A8080%2FSelf%2Fsso_login%3Fwlan_user_ip%3D{v4ip}%26authex_enable%3D%26type%3D1"
                # 打开浏览器
                QDesktopServices.openUrl(QUrl(login_url))
            else:
                QMessageBox.warning(self, "错误", "无法获取IP地址")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"打开登录页面失败: {str(e)}")

    def refresh_adapter_combo(self):
        """刷新网卡下拉框"""
        # 暂时断开信号连接，避免刷新时触发不必要的更新
        self.adapter_combo.currentIndexChanged.disconnect(
            self.on_adapter_changed)

        # 保存当前选中的适配器ID
        current_adapter_id = None
        if self.adapter_combo.currentData():
            current_adapter_id = self.adapter_combo.currentData()['adapter_id']

        self.adapter_combo.clear()
        adapters = utils.get_active_adapters()

        selected_index = 0
        for i, adapter in enumerate(adapters):
            self.adapter_combo.addItem(adapter['adapter_id'], adapter)
            # 如果找到之前选中的适配器，记录其索引
            if current_adapter_id and adapter['adapter_id'] == current_adapter_id:
                selected_index = i

        # 重新连接信号
        self.adapter_combo.currentIndexChanged.connect(
            self.on_adapter_changed)

        # 设置选中项
        if self.adapter_combo.count() > 0:
            self.adapter_combo.setCurrentIndex(selected_index)
            # 手动触发一次更新
            self.on_adapter_changed()

    def on_adapter_changed(self, check=False):
        """处理网卡选择变化"""
        selected_adapter = self.adapter_combo.currentData()
        if selected_adapter:
            try:
                # 获取选中网卡的IP地址
                local_ip = utils.get_local_ip_by_interface(
                    selected_adapter['adapter_id'])
                if local_ip:
                    self.mac_scan_network_input.setText(f"{local_ip}/24")
            except Exception as e:
                print(f"获取IP地址失败: {str(e)}")
                # 发生错误时清空输入框
                self.mac_scan_network_input.clear()

    def start_mac_scan(self):
        """开始MAC地址扫描"""
        network_address = self.mac_scan_network_input.text()

        # 获取选中的网卡
        selected_adapter = self.adapter_combo.currentData()
        selected_iface = selected_adapter['adapter_id'] if selected_adapter else None

        # 创建扫描线程
        class MacScanThread(QThread):
            progress_signal = pyqtSignal(str)
            finished_signal = pyqtSignal(dict)

            def __init__(self, network_address, iface):
                super().__init__()
                self.network_address = network_address
                self.iface = iface

            def run(self):
                try:
                    results = utils.send_arp_scan(
                        self.network_address, self.iface)
                    self.finished_signal.emit(results)
                except Exception as e:
                    self.progress_signal.emit(f"扫描出错: {str(e)}")

        # 创建并启动线程
        self.mac_scan_thread = MacScanThread(network_address, selected_iface)
        self.mac_scan_thread.finished_signal.connect(
            self.update_mac_scan_results)
        self.mac_scan_thread.start()
        self.mac_scan_progress.setRange(0, 0)  # 显示忙碌状态

    def get_mac_note(self, mac_address):
        """从数据存储中获取MAC地址对应的备注"""
        entries = self.mac_data.get_all_entries()
        for entry in entries:
            if entry["mac_address"].upper() == mac_address.upper():
                return entry["note"]
        return ""

    def update_mac_scan_results(self, results):
        """更新MAC扫描结果"""
        # 重新组织数据，将相同MAC地址的IP合并
        mac_to_ips = {}
        for ip, mac in results.items():
            if mac in mac_to_ips:
                mac_to_ips[mac].append(ip)
            else:
                mac_to_ips[mac] = [ip]

        # 更新表格列标题
        self.mac_scan_result_table.setColumnCount(4)
        self.mac_scan_result_table.setHorizontalHeaderLabels(
            ["MAC地址", "IP数量", "IP地址列表", "备注"])

        # 设置列宽
        self.mac_scan_result_table.setColumnWidth(0, 150)  # MAC地址列
        self.mac_scan_result_table.setColumnWidth(1, 80)   # IP数量列
        self.mac_scan_result_table.setColumnWidth(2, 300)  # IP地址列表列
        self.mac_scan_result_table.setColumnWidth(3, 80)  # 备注列

        # 填充表格
        self.mac_scan_result_table.setRowCount(len(mac_to_ips))
        for i, (mac, ips) in enumerate(mac_to_ips.items()):
            self.mac_scan_result_table.setItem(i, 0, QTableWidgetItem(mac))
            self.mac_scan_result_table.setItem(
                i, 1, QTableWidgetItem(str(len(ips))))
            self.mac_scan_result_table.setItem(
                i, 2, QTableWidgetItem(", ".join(ips)))
            # 添加备注
            note = self.get_mac_note(mac)
            self.mac_scan_result_table.setItem(i, 3, QTableWidgetItem(note))

        self.mac_scan_progress.setRange(0, 100)
        self.mac_scan_progress.setValue(100)

    def refresh_heartbeat_adapter_combo(self):
        """刷新心跳监听的网卡下拉框"""
        self.heartbeat_adapter_combo.clear()
        adapters = utils.get_active_adapters()
        for adapter in adapters:
            self.heartbeat_adapter_combo.addItem(
                adapter['adapter_id'], adapter)

    def on_heartbeat_adapter_changed(self):
        """处理心跳监听网卡选择变化"""
        if self.is_monitoring:
            self.toggle_heartbeat_monitoring()  # 停止当前监听

    def toggle_heartbeat_monitoring(self):
        """切换心跳监听状态"""
        if not self.is_monitoring:
            selected_adapter = self.heartbeat_adapter_combo.currentData()
            if not selected_adapter:
                QMessageBox.warning(self, "警告", "请先选择网卡")
                return

            self.heartbeat_thread = ArpHeartbeatThread(
                selected_adapter['adapter_id'])
            self.heartbeat_thread.heartbeat_signal.connect(
                self.handle_heartbeat)
            self.heartbeat_thread.finished.connect(
                self.on_heartbeat_thread_finished)
            self.heartbeat_thread.start()
            self.is_monitoring = True
            self.start_heartbeat_button.setText("停止监听")
            self.heartbeat_adapter_combo.setEnabled(False)
            # 启动定时器
            self.update_timer.start(60000)
        else:
            if self.heartbeat_thread:
                self.heartbeat_thread.stop()
            self.is_monitoring = False
            self.start_heartbeat_button.setText("开始监听")
            self.heartbeat_adapter_combo.setEnabled(True)
            # 停止定时器
            self.update_timer.stop()

    def handle_heartbeat(self, mac_address, ip_address, timestamp):
        """处理收到的心跳信号"""
        if mac_address not in self.heartbeat_records:
            self.heartbeat_records[mac_address] = {
                'count': 0,
                'last_time': timestamp,
                'ip_address': ip_address
            }
            # 添加新行
            row = self.heartbeat_table.rowCount()
            self.heartbeat_table.insertRow(0)
        else:
            # 更新IP地址
            self.heartbeat_records[mac_address]['ip_address'] = ip_address
            # 查找现有行
            for row in range(self.heartbeat_table.rowCount()):
                if self.heartbeat_table.item(row, 0).text() == mac_address:
                    self.heartbeat_table.removeRow(row)
                    self.heartbeat_table.insertRow(0)
                    break

        # 更新记录
        self.heartbeat_records[mac_address]['count'] += 1
        self.heartbeat_records[mac_address]['last_time'] = timestamp

        # 更新表格
        self.heartbeat_table.setItem(0, 0, QTableWidgetItem(mac_address))
        self.heartbeat_table.setItem(0, 1, QTableWidgetItem(
            str(self.heartbeat_records[mac_address]['count'])))
        self.heartbeat_table.setItem(0, 2, QTableWidgetItem(
            self.heartbeat_records[mac_address]['last_time']))
        self.heartbeat_table.setItem(0, 3, QTableWidgetItem(
            self.heartbeat_records[mac_address]['ip_address']))
        relative_time = utils.get_relative_time(
            self.heartbeat_records[mac_address]['last_time'])
        self.heartbeat_table.setItem(0, 4, QTableWidgetItem(relative_time))
        # 添加备注
        note = self.get_mac_note(mac_address)
        self.heartbeat_table.setItem(0, 5, QTableWidgetItem(note))

    def update_relative_times(self):
        """更新所有条目的相对时间显示"""
        for row in range(self.heartbeat_table.rowCount()):
            mac = self.heartbeat_table.item(row, 0).text()
            if mac in self.heartbeat_records:
                relative_time = utils.get_relative_time(
                    self.heartbeat_records[mac]['last_time'])
                self.heartbeat_table.setItem(
                    row, 4, QTableWidgetItem(relative_time))

    def clear_heartbeat_records(self):
        """清空心跳记录"""
        self.heartbeat_records.clear()
        self.heartbeat_table.setRowCount(0)

    def on_heartbeat_thread_finished(self):
        """处理心跳线程结束"""
        self.heartbeat_thread = None


def main():
    app = QApplication(sys.argv)
    window = NetworkStealerGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
