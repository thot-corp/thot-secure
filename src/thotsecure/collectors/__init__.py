"""Collecteurs : observation défensive de la surface déclarée par le tenant.

Un collecteur observe et normalise. Il ne décide rien et n'agit pas : toute action passe
ensuite par le moteur de décision, donc par une politique et une trace d'audit.
"""

from __future__ import annotations

from .base import Collector, CollectorContext, CollectorResult
from .config_audit import ConfigAuditCollector, available_checks
from .dependency_scan import DependencyScanCollector, compare_versions, parse_manifest
from .log_tail import LogTailCollector, parse_log_line
from .net import CertInfo, HttpResponse, fetch, inspect_certificate
from .registry import CollectorRegistry, default_registry
from .runner import CollectorRunner
from .syslog import SyslogCollector, parse_syslog_line
from .tls_cert import TlsCertCollector
from .web_probe import WebProbeCollector

__all__ = [
    "CertInfo",
    "Collector",
    "CollectorContext",
    "CollectorRegistry",
    "CollectorResult",
    "CollectorRunner",
    "ConfigAuditCollector",
    "DependencyScanCollector",
    "HttpResponse",
    "LogTailCollector",
    "SyslogCollector",
    "TlsCertCollector",
    "WebProbeCollector",
    "available_checks",
    "compare_versions",
    "default_registry",
    "fetch",
    "inspect_certificate",
    "parse_log_line",
    "parse_manifest",
    "parse_syslog_line",
]
