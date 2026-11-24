// User workspace menu; route identifiers match the existing page handlers.
export const USER_NAV_GROUPS = [
  {
    "id": "01",
    "icon": "🏠",
    "label": "SOC Overview",
    "items": [
      [
        "Security Dashboard",
        "dashboard"
      ],
      [
        "Risk Overview",
        "risk-overview"
      ],
      [
        "Environment Health",
        "environment-health"
      ]
    ]
  },
  {
    "id": "02",
    "icon": "🖥️",
    "label": "Asset Management",
    "items": [
      [
        "Asset Inventory",
        "asset-inventory"
      ],
      [
        "Asset Discovery",
        "asset-discovery"
      ],
      [
        "Servers",
        "servers"
      ],
      [
        "Endpoints",
        "endpoints"
      ],
      [
        "Network Devices",
        "network-devices"
      ],
      [
        "Applications",
        "applications"
      ],
      [
        "Databases",
        "databases"
      ],
      [
        "Domains",
        "domains"
      ],
      [
        "IP Addresses",
        "ip-addresses"
      ],
      [
        "Asset Groups",
        "asset-groups"
      ]
    ]
  },
  {
    "id": "03",
    "icon": "🌐",
    "label": "Attack Surface",
    "items": [
      [
        "External Attack Surface",
        "external-attack-surface"
      ],
      [
        "Internal Attack Surface",
        "internal-attack-surface"
      ],
      [
        "Domain Discovery",
        "domain-discovery"
      ],
      [
        "Subdomain Discovery",
        "subdomain-discovery"
      ],
      [
        "DNS Security",
        "dns-security"
      ],
      [
        "IP Intelligence",
        "ip-intelligence"
      ],
      [
        "Open Ports",
        "open-ports"
      ],
      [
        "Exposed Services",
        "exposed-services"
      ],
      [
        "SSL/TLS",
        "ssl-tls"
      ],
      [
        "Security Headers",
        "security-headers"
      ]
    ]
  },
  {
    "id": "21",
    "icon": "🧪",
    "label": "Security Testing",
    "items": [
      [
        "VAPT Testing",
        "vapt"
      ],
      [
        "Port Scanner",
        "testing-port-scanner"
      ],
      [
        "Service Discovery",
        "testing-service-discovery"
      ],
      [
        "Code Security",
        "code-security"
      ],
      [
        "Scan History",
        "testing-scan-history"
      ]
    ]
  },
  {
    "id": "04",
    "icon": "🔍",
    "label": "Vulnerability Management",
    "items": [
      [
        "Vulnerabilities",
        "findings"
      ],
      [
        "CVE Database",
        "cve-database"
      ],
      [
        "Remediation",
        "remediation"
      ]
    ]
  },
  {
    "id": "06",
    "icon": "🖥️",
    "label": "Server Security",
    "items": [
      [
        "Server Dashboard",
        "server-dashboard"
      ],
      [
        "Linux Security",
        "linux-security"
      ],
      [
        "Windows Security",
        "windows-security"
      ],
      [
        "SSH Security",
        "ssh-security"
      ],
      [
        "User Accounts",
        "user-accounts"
      ],
      [
        "Privileged Accounts",
        "privileged-accounts"
      ],
      [
        "Running Processes",
        "running-processes"
      ],
      [
        "Services",
        "services"
      ],
      [
        "Firewall",
        "firewall"
      ],
      [
        "System Hardening",
        "system-hardening"
      ],
      [
        "Server Configuration",
        "server-config"
      ]
    ]
  },
  {
    "id": "14",
    "icon": "🌐",
    "label": "Network Security",
    "items": [
      [
        "Network Dashboard",
        "network-dashboard"
      ],
      [
        "Network Discovery",
        "network-discovery"
      ],
      [
        "Network Topology",
        "network-topology"
      ],
      [
        "Traffic Analysis",
        "network-traffic"
      ],
      [
        "Connections",
        "network-connections"
      ],
      [
        "Ports",
        "network-ports"
      ],
      [
        "Protocols",
        "network-protocols"
      ],
      [
        "Firewall",
        "network-firewall"
      ],
      [
        "VPN",
        "network-vpn"
      ],
      [
        "DNS Security",
        "network-dns"
      ],
      [
        "IDS/IPS",
        "network-ids"
      ],
      [
        "Network Anomalies",
        "network-anomalies"
      ]
    ]
  },
  {
    "id": "15",
    "icon": "🔐",
    "label": "Identity Security",
    "items": [
      [
        "Identity Dashboard",
        "identity-dashboard"
      ],
      [
        "Users",
        "identity-users"
      ],
      [
        "Groups",
        "identity-groups"
      ],
      [
        "Privileged Users",
        "identity-privileged"
      ],
      [
        "Authentication",
        "identity-authentication"
      ],
      [
        "MFA",
        "identity-mfa"
      ],
      [
        "Login Anomalies",
        "identity-anomalies"
      ],
      [
        "Identity Risk",
        "identity-risk"
      ]
    ]
  },
  {
    "id": "16",
    "icon": "🔑",
    "label": "Secrets Security",
    "items": [
      [
        "Secrets Dashboard",
        "secrets-dashboard"
      ],
      [
        "Exposed Secrets",
        "secrets-exposed"
      ],
      [
        "API Keys",
        "secrets-api-keys"
      ],
      [
        "Tokens",
        "secrets-tokens"
      ],
      [
        "Credentials",
        "secrets-credentials"
      ],
      [
        "Repository Scanning",
        "secrets-scanning"
      ]
    ]
  },
  {
    "id": "07",
    "icon": "📊",
    "label": "SIEM",
    "items": [
      [
        "SIEM Dashboard",
        "logs"
      ],
      [
        "Log Explorer",
        "log-explorer"
      ],
      [
        "Security Events",
        "security-events"
      ],
      [
        "Authentication Logs",
        "authentication-logs"
      ],
      [
        "Network Logs",
        "network-logs"
      ],
      [
        "Firewall Logs",
        "firewall-logs"
      ],
      [
        "DNS Logs",
        "dns-logs"
      ],
      [
        "Application Logs",
        "application-logs"
      ],
      [
        "Windows Events",
        "windows-events"
      ],
      [
        "Linux Logs",
        "linux-logs"
      ],
      [
        "Log Sources",
        "log-sources"
      ],
      [
        "Saved Searches",
        "saved-searches"
      ]
    ]
  },
  {
    "id": "08",
    "icon": "🚨",
    "label": "Detection",
    "items": [
      [
        "Detection Dashboard",
        "detection-dashboard"
      ],
      [
        "Detection Rules",
        "detection-rules"
      ],
      [
        "Sigma Rules",
        "sigma-rules"
      ],
      [
        "Correlation Rules",
        "correlation-rules"
      ],
      [
        "Behavioral Detection",
        "behavioral-detection"
      ],
      [
        "Anomaly Detection",
        "anomaly-detection"
      ],
      [
        "IOC Detection",
        "ioc-detection"
      ],
      [
        "Detection Coverage",
        "detection-coverage"
      ]
    ]
  },
  {
    "id": "09",
    "icon": "🚨",
    "label": "Alerts",
    "items": [
      [
        "Alert Dashboard",
        "alerts"
      ],
      [
        "All Alerts",
        "alerts-all"
      ],
      [
        "Critical Alerts",
        "alerts-critical"
      ],
      [
        "Open Alerts",
        "alerts-open"
      ],
      [
        "Acknowledged",
        "alerts-acknowledged"
      ],
      [
        "Suppressed",
        "alerts-suppressed"
      ],
      [
        "Alert Correlation",
        "alerts-correlation"
      ],
      [
        "Alert Tuning",
        "alerts-tuning"
      ]
    ]
  },
  {
    "id": "10",
    "icon": "🔥",
    "label": "Incidents",
    "items": [
      [
        "Incident Dashboard",
        "incidents"
      ],
      [
        "Active Incidents",
        "incidents-active"
      ],
      [
        "Critical Incidents",
        "incidents-critical"
      ],
      [
        "Investigation",
        "incidents-investigation"
      ],
      [
        "Evidence",
        "incidents-evidence"
      ],
      [
        "Incident Timeline",
        "incidents-timeline"
      ],
      [
        "Case Management",
        "incidents-cases"
      ],
      [
        "Assignments",
        "incidents-assignments"
      ],
      [
        "SLA Management",
        "incidents-sla"
      ],
      [
        "Incident Playbooks",
        "incidents-playbooks"
      ],
      [
        "Closed Incidents",
        "incidents-closed"
      ]
    ]
  },
  {
    "id": "11",
    "icon": "🧠",
    "label": "Threat Intelligence",
    "items": [
      [
        "Threat Intelligence Dashboard",
        "threat-intelligence"
      ],
      [
        "Indicators",
        "threat-indicators"
      ],
      [
        "Domain Intelligence",
        "threat-domains"
      ],
      [
        "URL Intelligence",
        "threat-urls"
      ],
      [
        "Hash Intelligence",
        "threat-hashes"
      ],
      [
        "Threat Actors",
        "threat-actors"
      ],
      [
        "Campaigns",
        "threat-campaigns"
      ],
      [
        "Malware Intelligence",
        "threat-malware"
      ],
      [
        "CVE Intelligence",
        "threat-cve"
      ],
      [
        "Threat Feeds",
        "threat-feeds"
      ]
    ]
  },
  {
    "id": "12",
    "icon": "🎯",
    "label": "Threat Hunting",
    "items": [
      [
        "Hunting Dashboard",
        "hunt-dashboard"
      ],
      [
        "Query Builder",
        "hunt-builder"
      ],
      [
        "Event Search",
        "hunt-events"
      ],
      [
        "IOC Hunting",
        "hunt-ioc"
      ],
      [
        "User Hunting",
        "hunt-users"
      ],
      [
        "Process Hunting",
        "hunt-processes"
      ],
      [
        "Network Hunting",
        "hunt-network"
      ],
      [
        "Timeline Analysis",
        "hunt-timeline"
      ],
      [
        "Saved Hunts",
        "hunt-saved"
      ]
    ]
  },
  {
    "id": "13",
    "icon": "🧩",
    "label": "MITRE ATT&CK",
    "items": [
      [
        "ATT&CK Dashboard",
        "mitre-attack"
      ],
      [
        "Tactics",
        "mitre-tactics"
      ],
      [
        "Techniques",
        "mitre-techniques"
      ],
      [
        "Sub-Techniques",
        "mitre-subtechniques"
      ],
      [
        "Groups",
        "mitre-groups"
      ],
      [
        "Software",
        "mitre-software"
      ],
      [
        "Detection Coverage",
        "mitre-coverage"
      ]
    ]
  },
  {
    "id": "17",
    "icon": "⚙️",
    "label": "Security Configuration",
    "items": [
      [
        "Security Baselines",
        "config-baselines"
      ],
      [
        "Hardening",
        "config-hardening"
      ],
      [
        "CIS Benchmarks",
        "config-cis"
      ],
      [
        "Linux Configuration",
        "config-linux"
      ],
      [
        "Windows Configuration",
        "config-windows"
      ],
      [
        "Web Server Configuration",
        "config-web"
      ],
      [
        "Configuration Drift",
        "config-drift"
      ]
    ]
  },
  {
    "id": "18",
    "icon": "🤖",
    "label": "SOAR / Automation",
    "items": [
      [
        "Playbooks",
        "soar-playbooks"
      ],
      [
        "Workflows",
        "soar-workflows"
      ],
      [
        "Triggers",
        "soar-triggers"
      ],
      [
        "Actions",
        "soar-actions"
      ],
      [
        "Approvals",
        "soar-approvals"
      ],
      [
        "Response Actions",
        "soar-responses"
      ]
    ]
  },
  {
    "id": "19",
    "icon": "📋",
    "label": "Risk Management",
    "items": [
      [
        "Risk Dashboard",
        "risk-dashboard"
      ],
      [
        "Asset Risk",
        "risk-assets"
      ],
      [
        "Vulnerability Risk",
        "risk-vulnerabilities"
      ],
      [
        "Identity Risk",
        "risk-identity"
      ],
      [
        "Risk Register",
        "risk-register"
      ],
      [
        "Risk Trends",
        "risk-trends"
      ]
    ]
  },
  {
    "id": "20",
    "icon": "🔎",
    "label": "Security Assessment",
    "items": [
      [
        "Network Assessment",
        "assessment-network"
      ],
      [
        "Configuration Assessment",
        "assessment-configuration"
      ],
      [
        "Security Audit",
        "assessment-audit"
      ],
      [
        "Remediation",
        "assessment-remediation"
      ],
      [
        "QA Testing",
        "qa"
      ]
    ]
  },
  {
    "id": "22",
    "icon": "📊",
    "label": "Reports",
    "items": [
      [
        "Security Reports",
        "reports-security"
      ],
      [
        "Vulnerability Reports",
        "reports-vulnerability"
      ],
      [
        "Incident Reports",
        "reports-incidents"
      ],
      [
        "Risk Reports",
        "reports-risk"
      ],
      [
        "Scheduled Reports",
        "reports-scheduled"
      ]
    ]
  },
  {
    "id": "23",
    "icon": "🔔",
    "label": "Notifications",
    "items": [
      [
        "Notification Center",
        "notifications"
      ]
    ]
  },
  {
    "id": "workspace",
    "icon": "⚙",
    "label": "Workspace",
    "items": [
      [
        "Uptime Monitoring",
        "uptime"
      ],
      [
        "Security Copilot",
        "copilot"
      ],
      [
        "Complaints / Support",
        "support"
      ],
      [
        "Profile",
        "profile"
      ]
    ]
  }
];

export function findUserNavigationGroup(route) {
  return USER_NAV_GROUPS.find(group => group.items.some(item => item[1] === route));
}
export function createUserNavigationState(route = 'dashboard') {
  const selected = findUserNavigationGroup(route)?.id || USER_NAV_GROUPS[0]?.id;
  return Object.fromEntries(USER_NAV_GROUPS.map(group => [group.id, group.id === selected]));
}
export function toggleUserNavigation(current, id) {
  return Object.fromEntries(USER_NAV_GROUPS.map(group => [group.id, group.id === id && !current[id]]));
}
