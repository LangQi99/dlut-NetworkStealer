import os
import ipaddress
import threading
import subprocess
import time
import winreg
import wmi
import ctypes
from collections import defaultdict
import socket
from pythonping import ping
import scapy
import scapy.all as scapy
from scapy.all import conf, get_if_addr
from datetime import datetime


def get_dlut_network_info():
    """
    获取dlut校园网认证信息
    请求url: http://172.20.30.1/drcom/chkstatus?callback=
    响应格式: hide
    """
    import requests
    import json
    import re

    try:
        url = "http://172.20.30.1/drcom/chkstatus?callback="
        response = requests.get(url, timeout=5)

        # 提取JSON部分
        json_str = re.search(r'\((.*)\)', response.text).group(1)
        data = json.loads(json_str)

        # 根据图片提取需要的信息
        result = {
            "登录状态": "在线" if data.get("result") == 1 else "离线",
            "账号": data.get("uid", ""),
            "姓名": data.get("NID", ""),
            "剩余流量": f"{data.get('olflow', 0) / (1024 * 1024):.2f} GB",
            "账户余额": f"{data.get('fee', 0) / 10000:.2f} 元",
            "终端类型": "PC",  # 根据图片显示
            "IP 地址": data.get("v4ip", ""),
            "MAC 地址": ":".join([data.get("olmac", "")[i:i+2].upper() for i in range(0, 12, 2)]).replace(":", "-")
        }

        return result
    except Exception as e:
        return {
            "登录状态": "无法获取",
            "账号": "若连接凌水校区校园网",
            "姓名": "属于正常现象",
            "剩余流量": "",
            "账户余额": "",
            "终端类型": "PC",
            "IP 地址": "",
            "MAC 地址": ""
        }


def get_local_ip_by_interface(interface: str) -> str:
    """
    获取指定接口的本地IP地址
    """
    return get_if_addr(interface)


def get_local_ip():
    try:
        # 连接到外部地址，不实际发送数据，只是为了确定本地IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google DNS
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        return f"Error: {e}"


def scan_network(network_address) -> list[str]:
    """
    扫描指定网络地址的活跃主机
    返回活跃主机的ip列表
    """
    network = ipaddress.ip_network(network_address, strict=False)
    active_ips = []
    lock = threading.Lock()

    def ping_ip(ip):
        try:
            response = ping(str(ip), count=1, timeout=0.2)
            if response.success():
                with lock:
                    active_ips.append(str(ip))
        except Exception as e:
            print(f"ping {ip} 时出错: {e}")

    total_hosts = sum(1 for _ in network.hosts())
    print(f"开始扫描网络 {network}，共 {total_hosts} 个主机...")

    threads = []
    for ip in network.hosts():
        t = threading.Thread(target=ping_ip, args=(ip,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"扫描完成，发现 {len(active_ips)} 个活动主机")
    return active_ips


def _check_mac_address(mac_address: str) -> bool:
    """
    检查MAC地址是否符合要求
    返回是否符合要求
    """
    return mac_address[1].upper() in ['2', '6', 'A', 'E']


def check_valid_mac_address(mac_address: str) -> bool:
    """
    检查是否是MAC地址
    返回是否是MAC地址
    """
    return len(mac_address) == 17


def _get_arp_table() -> list[str]:
    """
    获取ARP表
    返回ARP表的列表
    """
    arp_output = subprocess.check_output(
        'arp -a', shell=True).decode(encoding='gbk', errors='ignore')
    devices = []
    for line in arp_output.splitlines():
        if '-' in line:
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1].replace(":", "-").upper()
                if not check_valid_mac_address(mac):
                    continue
                devices.append((ip, mac))
    return devices


def get_arp_info(active_ips: list[str], arp_table: list[str]) -> dict:
    """
    生成一段信息
    输出全部mac地址 以及出现的次数 和 是否活跃 如果活跃 则附上活跃ip
    如果active_ips为空 则活跃状态是未知
    """
    mac_info = defaultdict(
        lambda: {"count": 0, "active_ips": [], "status": "未知"})

    # 统计MAC地址出现次数和关联IP
    for ip, mac in arp_table:
        mac_info[mac]["count"] += 1
        if active_ips:
            if ip in active_ips:
                mac_info[mac]["active_ips"].append(ip)
                mac_info[mac]["status"] = "活跃"
            else:
                if mac_info[mac]["status"] != "活跃":
                    mac_info[mac]["status"] = "离线"

    # 返回字典格式，key是mac
    result = {}
    for mac, info in mac_info.items():
        result[mac] = {
            "count": info["count"],
            "status": info["status"],
            "active_ips": info["active_ips"]
        }

    return result


def get_active_adapters() -> list[dict]:
    """
    获取活跃的网卡
    包含 适配器编号 适配器连接ID 适配器描述 
    返回网卡的列表
    """
    results = []
    path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"

    try:
        # 获取WMI连接信息
        c = wmi.WMI()
        wmi_adapters = []
        for interface in c.Win32_NetworkAdapter(PhysicalAdapter=True):
            if interface.NetEnabled:
                wmi_adapters.append({
                    'name': interface.Name,
                    'description': interface.Description,
                    'NetConnectionID': interface.NetConnectionID
                })

        # 获取注册表信息
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             path, 0, winreg.KEY_READ)
        index = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, index)
                if subkey_name.isdigit():
                    subkey_path = f"{path}\\{subkey_name}"
                    subkey = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_READ)

                    try:
                        driver_desc = winreg.QueryValueEx(
                            subkey, "DriverDesc")[0]
                        # 匹配WMI和注册表信息
                        for wmi_adapter in wmi_adapters:
                            if (driver_desc.lower() in wmi_adapter['description'].lower() or
                                    wmi_adapter['description'].lower() in driver_desc.lower()):
                                results.append({
                                    'adapter_index': subkey_name,
                                    'adapter_id': wmi_adapter['NetConnectionID'],
                                    'description': driver_desc
                                })
                    except WindowsError:
                        pass
                    finally:
                        winreg.CloseKey(subkey)
                index += 1
            except WindowsError:
                break
        winreg.CloseKey(key)
    except Exception as e:
        print(f"获取网卡信息时出错: {e}")

    return results


def modify_mac_address(adapter_index: str, new_mac: str) -> bool:
    """
    修改网卡的MAC地址
    返回是否修改成功
    """
    # 检查管理员权限
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("需要管理员权限来修改MAC地址")
        return False

    # 格式化MAC地址
    new_mac = new_mac.replace('-', '').replace(':', '')
    if len(new_mac) != 12:
        print("错误：MAC地址格式不正确")
        return False

    try:
        # 打开对应适配器的注册表项
        key_path = rf"SYSTEM\CurrentControlSet\Control\Class\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{adapter_index}"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             key_path, 0, winreg.KEY_ALL_ACCESS)

        # 设置新的MAC地址
        winreg.SetValueEx(key, "NetworkAddress", 0, winreg.REG_SZ, new_mac)
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"修改MAC地址时出错: {e}")
        return False


def reboot_adapter(adapter_id: str) -> bool:
    """
    重启网卡
    返回是否重启成功
    """
    print(f"准备重启网卡: {adapter_id}")
    # 检查管理员权限
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("需要管理员权限来重启网卡")
        return False

    try:
        # 创建一个线程来执行网卡重启操作
        def restart_thread():
            try:
                print(f"开始重启网卡 {adapter_id} 的线程")
                # 禁用网络适配器
                print(f"正在禁用网络适配器: {adapter_id}")
                disable_cmd = f'netsh interface set interface "{adapter_id}" admin=disable'
                subprocess.run(disable_cmd, shell=True, check=True)
                print(f"网络适配器 {adapter_id} 已禁用")

                # 等待3秒
                print(f"等待3秒后重新启用网卡...")
                time.sleep(3)

                # 启用网络适配器
                print(f"正在启用网络适配器: {adapter_id}")
                enable_cmd = f'netsh interface set interface "{adapter_id}" admin=enable'
                subprocess.run(enable_cmd, shell=True, check=True)
                print(f"网络适配器 {adapter_id} 已重新启用")
                print(f"网卡 {adapter_id} 重启完成")
            except Exception as e:
                print(f"重启网卡线程中出错: {e}")
                print(f"网卡 {adapter_id} 重启失败")

        # 启动后台线程执行重启操作
        print(f"创建重启网卡 {adapter_id} 的后台线程")
        thread = threading.Thread(target=restart_thread)
        thread.daemon = True  # 设置为守护线程，主程序退出时自动结束
        thread.start()
        print(f"重启网卡 {adapter_id} 的线程已启动")

        return True
    except Exception as e:
        print(f"创建重启网卡 {adapter_id} 线程时出错: {e}")
        return False


def send_arp_scan(network_address: str, iface: str = None) -> dict:
    """
    发送ARP请求包扫描网络中的设备
    Args:
        network_address: 要扫描的网络地址
        iface: 用于发送ARP包的网卡接口名称
    返回一个字典，包含IP地址和对应的MAC地址
    """
    try:
        results = {}

        # 创建ARP请求包
        arp_request = scapy.ARP(pdst=network_address)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request

        # 发送ARP请求并等待响应
        conf.iface = iface
        answered_list = scapy.srp(
            arp_request_broadcast, timeout=2, verbose=False)[0]
        print(answered_list)
        # 处理响应
        for sent, received in answered_list:
            results[received.psrc] = received.hwsrc.upper().replace(":", "-")

        return results
    except Exception as e:
        print(f"ARP扫描出错: {str(e)}")
        return {}


def get_current_time():
    """获取当前时间的格式化字符串"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_relative_time(timestamp_str: str) -> str:
    """计算相对于当前时间的时间差，返回格式化的字符串"""
    try:
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        diff = now - timestamp

        total_seconds = int(diff.total_seconds())

        if total_seconds < 60:
            return "1分钟内"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            return minutes + "分钟"
        elif total_seconds < 86400:
            hours = total_seconds // 3600
            return hours + "小时"
        else:
            days = total_seconds // 86400
            return days + "天"
    except:
        return "未知"
