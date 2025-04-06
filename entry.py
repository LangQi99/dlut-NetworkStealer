import requests
import scapy.all
import GUI
import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QLineEdit,
                             QTableWidget, QTableWidgetItem, QTabWidget,
                             QMessageBox, QProgressBar)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from pythonping import ping
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
import utils
import data_storage
if __name__ == '__main__':
    GUI.main()
