"""
rule_manager.py - Manages blocking rules
Mirrors: rule_manager.h

Rule types:
  - IP blacklist      → block all traffic from a source IP
  - App blacklist     → block all traffic for an AppType (e.g. YouTube)
  - Domain blacklist  → block any SNI containing this substring
"""

from typing import Set
from types_dpi import AppType


class RuleManager:
    def __init__(self):
        self._blocked_ips: Set[str] = set()
        self._blocked_apps: Set[AppType] = set()
        self._blocked_domains: Set[str] = set()

    def add_blocked_ip(self, ip: str):
        self._blocked_ips.add(ip.strip())

    def add_blocked_app(self, app_name: str):
        """Accept app name as string (case-insensitive) and map to AppType."""
        try:
            app_type = AppType[app_name.upper()]
            self._blocked_apps.add(app_type)
        except KeyError:
            print(f"[Rules] WARNING: Unknown app '{app_name}'. "
                  f"Valid apps: {[e.name for e in AppType]}")

    def add_blocked_domain(self, domain: str):
        self._blocked_domains.add(domain.lower().strip())

    def is_blocked(self, src_ip: str, app_type: AppType, sni: str) -> bool:
        """
        Returns True if this packet should be dropped.

        Check order:
          1. Source IP blacklist
          2. App type blacklist
          3. Domain substring match
        """
        if src_ip in self._blocked_ips:
            return True

        if app_type in self._blocked_apps:
            return True

        sni_lower = sni.lower()
        for domain in self._blocked_domains:
            if domain in sni_lower:
                return True

        return False

    @property
    def blocked_apps(self) -> Set[AppType]:
        return self._blocked_apps
