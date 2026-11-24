import os
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    def __init__(self, config_file: str = "config.json"):
        self.config_path = BASE_DIR / config_file
        self.settings = self._load_defaults()
        if self.config_path.exists():
            self._load_from_file()
        self._load_from_env()

    def _load_defaults(self) -> dict:
        # Default inventory looks for parent Unique Application Names.xlsx first, then local inventory.xlsx
        parent_inventory = BASE_DIR.parent / "Unique Application Names.xlsx"
        inv_path = str(parent_inventory) if parent_inventory.exists() else str(BASE_DIR / "inventory.xlsx")

        return {
            "inoreader": {
                "email": "",
                "password": "",
                "app_id": "",
                "app_key": "",
                "token": "",
                "stream_id": "user/-/state/com.google/reading-list",
                "verify_ssl": False,
                "use_mock_if_missing": False
            },
            "gemini": {
                "api_key": "",
                "model": "gemini-3.5-flash-lite",
                "requests_per_minute": 12,
                "verify_ssl": False,
                "use_fallback_if_missing": True
            },
            "openai": {
                "api_key": "",
                "model": "gpt-4o-mini",
                "enabled": False
            },
            "nvd": {
                "api_key": ""
            },
            "tenable": {
                "access_key": "",
                "secret_key": "",
                "base_url": "https://cloud.tenable.com"
            },
            "paths": {
                "inventory_excel": inv_path,
                "master_excel": str(BASE_DIR / "reports" / "Master_Advisories.xlsx"),
                "daily_reports_dir": str(BASE_DIR / "reports" / "daily"),
                "cache_db": str(BASE_DIR / "data" / "advisory_cache.db"),
                "log_dir": str(BASE_DIR / "logs"),
                "telecom_list_excel": str(BASE_DIR / "Global Telecom List.xlsx"),
                "vendor_list_excel": str(BASE_DIR / "Vendor List.xlsx"),
                "master_telecom_excel": str(BASE_DIR / "reports" / "Master_Telecom_Advisories.xlsx"),
                "master_vendor_excel": str(BASE_DIR / "reports" / "Master_Vendor_Advisories.xlsx"),
                "master_miscellaneous_excel": str(BASE_DIR / "reports" / "Master_Miscellaneous_Advisories.xlsx"),
            },
            "matching": {
                "case_sensitive": False,
                "min_word_length": 3
            },
            "deduplication": {
                "pending_days": 7,
                "same_event_confidence_threshold": 0.85,
                "candidate_similarity_threshold": 0.18,
            }
        }

    def _load_from_file(self):
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self._deep_update(self.settings, data)
        except Exception as e:
            print(f"[Warning] Failed to read {self.config_path}: {e}")

    def _load_from_env(self):
        if os.getenv("INOREADER_TOKEN"):
            self.settings["inoreader"]["token"] = os.getenv("INOREADER_TOKEN")
        if os.getenv("INOREADER_APP_ID"):
            self.settings["inoreader"]["app_id"] = os.getenv("INOREADER_APP_ID")
        if os.getenv("INOREADER_APP_KEY"):
            self.settings["inoreader"]["app_key"] = os.getenv("INOREADER_APP_KEY")
        if os.getenv("INOREADER_EMAIL"):
            self.settings["inoreader"]["email"] = os.getenv("INOREADER_EMAIL")
        if os.getenv("INOREADER_PASSWORD"):
            self.settings["inoreader"]["password"] = os.getenv("INOREADER_PASSWORD")
        if os.getenv("GEMINI_API_KEY"):
            self.settings["gemini"]["api_key"] = os.getenv("GEMINI_API_KEY")
        if os.getenv("NVD_API_KEY"):
            self.settings["nvd"]["api_key"] = os.getenv("NVD_API_KEY")
        if os.getenv("TENABLE_ACCESS_KEY"):
            self.settings["tenable"]["access_key"] = os.getenv("TENABLE_ACCESS_KEY")
        if os.getenv("TENABLE_SECRET_KEY"):
            self.settings["tenable"]["secret_key"] = os.getenv("TENABLE_SECRET_KEY")
        if os.getenv("TENABLE_BASE_URL"):
            self.settings["tenable"]["base_url"] = os.getenv("TENABLE_BASE_URL")

    def _deep_update(self, base_dict: dict, update_dict: dict):
        for k, v in update_dict.items():
            if isinstance(v, dict) and k in base_dict and isinstance(base_dict[k], dict):
                self._deep_update(base_dict[k], v)
            else:
                base_dict[k] = v

    def save_template(self):
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.settings, f, indent=4)

    def get(self, *keys, default=None):
        val = self.settings
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val
