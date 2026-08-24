from __future__ import annotations

ATTACK_VERSION = "19.2"
D3FEND_VERSION = "1.5.0"
ECS_VERSION = "9.4.0"
OCSF_VERSION = "1.8.0"
OTEL_LOGS_VERSION = "1.0"
SCENARIO_SCHEMA_VERSION = "1.0.0"
ENGINE_VERSION = "1.0.0"

SUPPORTED_FORMATS = {
    "canonical-json",
    "generic-jsonl",
    "ndjson",
    "csv",
    "syslog",
    "cef",
    "leef",
    "ecs",
    "ocsf",
    "otel",
    "splunk-hec",
    "elasticsearch-bulk",
    "parquet",
}

SOURCE_FAMILIES = {
    "windows-security",
    "sysmon",
    "powershell",
    "linux-auth",
    "auditd",
    "syslog",
    "edr",
    "active-directory",
    "entra",
    "m365",
    "idp",
    "oauth",
    "dns",
    "proxy",
    "firewall",
    "vpn",
    "dhcp",
    "netflow",
    "zeek",
    "cloudtrail",
    "azure-activity",
    "gcp-audit",
    "cloud-control",
    "nginx",
    "apache",
    "app-auth",
    "api-gateway",
    "waf",
    "db-audit",
    "object-storage",
    "email-trace",
    "email-filter",
    "email-link",
    "kubernetes-audit",
    "container-runtime",
    "registry",
    "git-audit",
    "cicd",
    "artifact-registry",
    "mdm",
    "dlp",
    "ot-firewall",
    "ot-remote",
    "engineering-workstation",
    "historian",
    "ot-passive",
}
