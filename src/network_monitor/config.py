"""Configuration loader and validator for school-network-monitor."""

from __future__ import annotations
import os
from pathlib import Path
from typing import List, Optional
import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator, field_validator


class AppConfig(BaseModel):
    name: str = "school-network-monitor"
    log_level: str = "INFO"
    timezone: str = "Asia/Taipei"


class CaptureConfig(BaseModel):
    interface: str = ""
    filter: str = "udp and (port 67 or port 68)"
    enabled: bool = False

    @model_validator(mode="after")
    def validate_interface_when_enabled(self) -> "CaptureConfig":
        if self.enabled and not self.interface.strip():
            raise ValueError(
                "Capture is enabled, but 'capture.interface' is empty. "
                "You must specify a valid network interface name (see CLI: netmon list-interfaces)."
            )
        return self


class SNMPGlobalConfig(BaseModel):
    version: str = "3"
    timeout_seconds: float = 3.0
    retries: int = 1
    poll_interval_seconds: int = 60
    v2_community: Optional[str] = None
    v3_user: Optional[str] = None
    v3_auth_key: Optional[str] = None
    v3_auth_proto: Optional[str] = "SHA"
    v3_priv_key: Optional[str] = None
    v3_priv_proto: Optional[str] = "AES"


class DatabaseConfig(BaseModel):
    path: str = "data/network_monitor.db"


class RetentionConfig(BaseModel):
    dhcp_events_days: int = 30


class ScopeRule(BaseModel):
    group_name: str = "Target Group"
    allowed_servers: List[str] = Field(default_factory=list)
    macs: List[str] = Field(default_factory=list)


class DhcpSettings(BaseModel):
    authorized_servers: List[str] = Field(default_factory=list)
    scope_rules: List[ScopeRule] = Field(default_factory=list)


class SwitchItemConfig(BaseModel):
    management_ip: str
    name: str
    vendor: str = "Generic"
    model: str = "Standard-MIB"
    adapter: str = "standard_mib"
    enabled: bool = True
    snmp_version: Optional[str] = None
    community: Optional[str] = None
    v3_user: Optional[str] = None
    v3_auth_key: Optional[str] = None
    v3_priv_key: Optional[str] = None
    uplink_ports: List[str] = Field(default_factory=list)

    @field_validator("uplink_ports", mode="before")
    @classmethod
    def coerce_none_to_list(cls, v):
        if v is None:
            return []
        return v


class SwitchesConfig(BaseModel):
    switches: List[SwitchItemConfig] = Field(default_factory=list)


class Settings(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    snmp: SNMPGlobalConfig = Field(default_factory=SNMPGlobalConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    retention: RetentionConfig = Field(default_factory=RetentionConfig)
    dhcp: DhcpSettings = Field(default_factory=DhcpSettings)
    switches: List[SwitchItemConfig] = Field(default_factory=list)


def load_settings(
    settings_path: str | Path = "config/settings.yaml",
    switches_path: Optional[str | Path] = None,
) -> Settings:
    settings_p = Path(settings_path)
    if not settings_p.exists():
        raise FileNotFoundError(f"Main settings file not found: {settings_p.resolve()}")

    with open(settings_p, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # 優先順序：使用者指定路徑 -> config/switches.yaml -> config/switches.example.yaml
    target_sw_path = None
    if switches_path and Path(switches_path).exists():
        target_sw_path = Path(switches_path)
    elif Path("config/switches.yaml").exists():
        target_sw_path = Path("config/switches.yaml")
    elif Path("config/switches.example.yaml").exists():
        target_sw_path = Path("config/switches.example.yaml")

    if target_sw_path:
        with open(target_sw_path, "r", encoding="utf-8") as f:
            sw_data = yaml.safe_load(f) or {}
            if "switches" in sw_data:
                data["switches"] = sw_data["switches"]

    # 讀取環境變數覆蓋
    env_v2_comm = os.getenv("NETMON_SNMP_COMMUNITY")
    if env_v2_comm:
        data.setdefault("snmp", {})["v2_community"] = env_v2_comm

    env_v3_user = os.getenv("NETMON_SNMP_V3_USER")
    env_v3_auth = os.getenv("NETMON_SNMP_V3_AUTH")
    env_v3_priv = os.getenv("NETMON_SNMP_V3_PRIV")
    if env_v3_user:
        data.setdefault("snmp", {})["v3_user"] = env_v3_user
    if env_v3_auth:
        data.setdefault("snmp", {})["v3_auth_key"] = env_v3_auth
    if env_v3_priv:
        data.setdefault("snmp", {})["v3_priv_key"] = env_v3_priv

    try:
        return Settings(**data)
    except ValidationError as err:
        raise ValueError(f"Configuration validation failed:\n{err}") from err