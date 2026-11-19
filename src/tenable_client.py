from typing import Any, Dict, List, Optional

import requests


class TenableClient:
    def __init__(
        self,
        access_key: str = "",
        secret_key: str = "",
        base_url: str = "https://cloud.tenable.com",
    ):
        self.access_key = access_key.strip()
        self.secret_key = secret_key.strip()
        self.base_url = base_url.rstrip("/")
        self._plugin_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._plugins_loaded = False
        self._plugin_load_error: Optional[RuntimeError] = None

    def is_configured(self) -> bool:
        return bool(self.access_key and self.secret_key)

    def lookup_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        cve_id = cve_id.strip().upper()
        if not self.is_configured() or not cve_id:
            return []
        if self._plugin_load_error:
            raise self._plugin_load_error
        if cve_id in self._plugin_cache:
            return self._plugin_cache[cve_id]

        self._load_plugins()
        return self._plugin_cache.get(cve_id, [])

    def _load_plugins(self):
        if self._plugins_loaded:
            return
        if self._plugin_load_error:
            raise self._plugin_load_error

        headers = {
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}",
            "Accept": "application/json",
        }
        page = 1
        page_size = 10000
        while True:
            try:
                response = requests.get(
                    f"{self.base_url}/plugins/plugin",
                    headers=headers,
                    params={"size": page_size, "page": page},
                    timeout=30,
                )
                if response.status_code != 200:
                    raise RuntimeError(
                        f"Tenable plugin catalog page {page} returned "
                        f"HTTP {response.status_code}: {response.text[:200]}"
                    )
                data = response.json()
            except (requests.RequestException, ValueError, RuntimeError) as e:
                self._plugin_load_error = RuntimeError(f"Tenable plugin catalog fetch failed: {e}")
                raise self._plugin_load_error from e

            catalog = data.get("data") if isinstance(data, dict) else None
            plugins = catalog.get("plugin_details") if isinstance(catalog, dict) else None
            if not isinstance(plugins, list):
                self._plugin_load_error = RuntimeError(
                    f"Tenable plugin catalog page {page} returned an unexpected response."
                )
                raise self._plugin_load_error

            for plugin in plugins:
                if not isinstance(plugin, dict):
                    continue
                attributes = plugin.get("attributes", {})
                if not isinstance(attributes, dict):
                    continue
                cvss_vector = attributes.get("cvss_vector", {})
                if isinstance(cvss_vector, dict):
                    cvss_vector = cvss_vector.get("raw", "")
                normalized = {
                    "id": plugin.get("id"),
                    "name": plugin.get("name", ""),
                    "solution": attributes.get("solution", ""),
                    "cvss_base_score": attributes.get("cvss4_base_score")
                    or attributes.get("cvss3_base_score")
                    or attributes.get("cvss_base_score"),
                    "cvss_vector": cvss_vector,
                }
                cves = attributes.get("cve", [])
                if isinstance(cves, str):
                    cves = [cves]
                if not isinstance(cves, list):
                    continue
                for cve_id in cves:
                    normalized_cve = str(cve_id).upper()
                    self._plugin_cache.setdefault(normalized_cve, []).append(normalized)

            if len(plugins) < page_size:
                self._plugins_loaded = True
                return
            page += 1
