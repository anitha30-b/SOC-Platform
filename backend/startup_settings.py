"""Explicit, fail-closed startup controls for shared server installations."""
import os
from dataclasses import dataclass


def enabled(name, environ=None):
    source = os.environ if environ is None else environ
    value = str(source.get(name, "false")).strip().lower()
    if value in {"true", "1", "yes", "on"}:
        return True
    if value in {"false", "0", "no", "off", ""}:
        return False
    raise ValueError(f"{name} must be true or false")


@dataclass(frozen=True)
class StartupSettings:
    initialize_database: bool = False
    firewall_operations: bool = False
    siem_ingestion: bool = False
    snort_collector: bool = False
    host_collectors: bool = False
    server_monitor: bool = False
    postgres_listeners: bool = False

    @classmethod
    def from_environment(cls, environ=None):
        return cls(**{
            field: enabled(variable, environ)
            for field, variable in STARTUP_VARIABLES.items()
        })


STARTUP_VARIABLES = {
    "initialize_database": "SOC_INITIALIZE_DATABASE_ON_STARTUP",
    "firewall_operations": "SOC_ENABLE_FIREWALL_OPERATIONS",
    "siem_ingestion": "SOC_ENABLE_SIEM_INGESTION",
    "snort_collector": "SOC_ENABLE_SNORT_COLLECTOR",
    "host_collectors": "SOC_ENABLE_HOST_COLLECTORS",
    "server_monitor": "SOC_ENABLE_SERVER_MONITOR",
    "postgres_listeners": "SOC_ENABLE_POSTGRES_LISTENERS",
}
