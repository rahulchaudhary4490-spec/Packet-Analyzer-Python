"""
types_dpi.py - Core data structures
Mirrors: types.h / types.cpp

FiveTuple  → uniquely identifies a network connection
Flow       → tracks state of a single connection
AppType    → classified application type
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional


class AppType(Enum):
    UNKNOWN   = auto()
    HTTP      = auto()
    HTTPS     = auto()
    DNS       = auto()
    GOOGLE    = auto()
    YOUTUBE   = auto()
    FACEBOOK  = auto()
    TWITTER   = auto()
    INSTAGRAM = auto()
    TIKTOK    = auto()
    NETFLIX   = auto()
    AMAZON    = auto()
    GITHUB    = auto()
    REDDIT    = auto()
    LINKEDIN  = auto()
    TWITCH    = auto()
    DISCORD   = auto()
    WHATSAPP  = auto()
    TELEGRAM  = auto()
    ZOOM      = auto()
    MICROSOFT = auto()
    APPLE     = auto()
    CLOUDFLARE = auto()


def sni_to_app_type(sni: str) -> AppType:
    """
    Map a domain name (SNI or HTTP Host) to an AppType.
    Mirrors: sniToAppType() in types.cpp
    """
    sni = sni.lower()
    mappings = [
        ("youtube",    AppType.YOUTUBE),
        ("googlevideo", AppType.YOUTUBE),
        ("facebook",   AppType.FACEBOOK),
        ("instagram",  AppType.INSTAGRAM),
        ("fbcdn",      AppType.FACEBOOK),
        ("twitter",    AppType.TWITTER),
        ("tiktok",     AppType.TIKTOK),
        ("netflix",    AppType.NETFLIX),
        ("nflxso",     AppType.NETFLIX),
        ("amazon",     AppType.AMAZON),
        ("twitch",     AppType.TWITCH),
        ("discord",    AppType.DISCORD),
        ("whatsapp",   AppType.WHATSAPP),
        ("telegram",   AppType.TELEGRAM),
        ("zoom",       AppType.ZOOM),
        ("reddit",     AppType.REDDIT),
        ("linkedin",   AppType.LINKEDIN),
        ("github",     AppType.GITHUB),
        ("microsoft",  AppType.MICROSOFT),
        ("office",     AppType.MICROSOFT),
        ("apple",      AppType.APPLE),
        ("icloud",     AppType.APPLE),
        ("cloudflare", AppType.CLOUDFLARE),
        ("google",     AppType.GOOGLE),
    ]
    for keyword, app_type in mappings:
        if keyword in sni:
            return app_type
    return AppType.HTTPS


@dataclass(frozen=True)
class FiveTuple:
    """
    Uniquely identifies a network connection.
    All packets with the same 5-tuple belong to the same flow.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP


@dataclass
class Flow:
    """
    Tracks state of a single connection / flow.
    """
    sni: str = ""
    app_type: AppType = AppType.UNKNOWN
    blocked: bool = False
    packet_count: int = 0
    byte_count: int = 0
