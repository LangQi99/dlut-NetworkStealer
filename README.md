# NetworkStealer

**本软件仅供学习交流，请勿用于非法用途，用户承担使用本软件可能带来的任何后果，作者不承担任何责任。**

一个基于Python的网络工具。

适用于欺骗仅认证MAC地址的校园网，可以主动、被动获取离线、在线的MAC地址，允许Windows设备修改网卡MAC地址。



## 环境要求
- Python 3.13 (其余版本未测试)
- Windows 操作系统

## 安装步骤

1. 创建并激活虚拟环境（推荐）
```bash
python -m venv venv
.\venv\Scripts\activate
```

2. 安装项目依赖
```bash
pip install -r requirements.txt
```

3. 安装 pyinstaller（可选、用于编译）
```bash
pip install pyinstaller
```

## 运行方式

### 直接运行
```bash
python entry.py
```

### 编译为可执行文件

1. 编译 Python 文件为 pyd
```bash
python setup.py build_ext --inplace
```

2. 编译为可执行文件（两种方式）
```bash
# 普通版本
pyinstaller -F -w entry.py

# 管理员权限版本
pyinstaller -F -w entry.py --uac-admin
```

或者直接运行 `build.bat` 脚本：
```bash
.\build.bat
```

编译后的可执行文件将在 `dist` 目录中生成。

## 注意事项
- 确保以管理员权限运行程序以获得完整功能
- 编译过程可能需要几分钟时间
- 运行前请确保所有依赖都已正确安装
