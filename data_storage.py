import json
import os


class DataStorage:
    def __init__(self, file_name="default.json"):
        # 使用AppData目录存储数据
        appdata_dir = os.environ.get("APPDATA")
        my_app_dir = os.path.join(appdata_dir, "NetStealer")
        os.makedirs(my_app_dir, exist_ok=True)
        self.file_path = os.path.join(my_app_dir, file_name)
        self.data = self._load_data()

    def _load_data(self):
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return []
        return []

    def _save_data(self):
        with open(self.file_path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)

    def add_entry(self, mac_address, note=""):
        entry = {
            "mac_address": mac_address,
            "note": note
        }
        self.data.append(entry)
        self._save_data()

    def remove_entry(self, index):
        if 0 <= index < len(self.data):
            self.data.pop(index)
            self._save_data()

    def update_entry(self, index, mac_address=None, note=None):
        if 0 <= index < len(self.data):
            if mac_address is not None:
                self.data[index]["mac_address"] = mac_address
            if note is not None:
                self.data[index]["note"] = note
            self._save_data()

    def get_all_entries(self):
        return self.data
