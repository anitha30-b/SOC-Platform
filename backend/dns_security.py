import ipaddress
import json
from typing import Any

import dns.dnssec
import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver


DNS_TIMEOUT = 8.0


def _normalize_domain(domain: str) -> str:
    domain = str(domain or "").strip().lower().rstrip(".")
    if not domain:
        raise ValueError("A DNS domain is required.")

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("DNS Security requires a domain name, not an IP address.")

    return domain


def _query_records(
    resolver: dns.resolver.Resolver,
    name: str,
    rdtype: str,
) -> dict[str, Any]:
    try:
        answers = resolver.resolve(
            name,
            rdtype,
            lifetime=DNS_TIMEOUT,
            raise_on_no_answer=False,
        )

        records = []
        if answers.rrset:
            for record in answers:
                records.append(record.to_text())

        return {
            "status": "FOUND" if records else "NO_RECORD",
            "records": records,
        }

    except dns.resolver.NXDOMAIN:
        return {
            "status": "NXDOMAIN",
            "records": [],
        }

    except dns.resolver.NoNameservers as exc:
        return {
            "status": "ERROR",
            "records": [],
            "error": str(exc),
        }

    except dns.exception.DNSException as exc:
        return {
            "status": "ERROR",
            "records": [],
            "error": str(exc),
        }


def _query_txt(
    resolver: dns.resolver.Resolver,
    name: str,
) -> dict[str, Any]:
    result = _query_records(resolver, name, "TXT")

    normalized = []
    for record in result["records"]:
        value = record.replace('" "', "").strip('"')
        normalized.append(value)

    result["records"] = normalized
    return result


def _find_spf(records: list[str]) -> list[str]:
    return [
        record
        for record in records
        if record.lower().startswith("v=spf1")
    ]


def _parse_spf(records: list[str]) -> dict[str, Any]:
    spf_records = _find_spf(records)

    result = {
        "record_count": len(spf_records),
        "records": spf_records,
        "valid": False,
        "all_policy": None,
        "mechanisms": [],
    }

    if len(spf_records) != 1:
        return result

    record = spf_records[0]
    parts = record.split()

    if not parts or parts[0].lower() != "v=spf1":
        return result

    result["valid"] = True

    for mechanism in parts[1:]:
        if mechanism.startswith(("~all", "-all", "?all", "+all", "all")):
            result["all_policy"] = mechanism
        elif mechanism:
            result["mechanisms"].append(mechanism)

    return result


def _parse_dmarc(records: list[str]) -> dict[str, Any]:
    dmarc_records = [
        record
        for record in records
        if record.lower().startswith("v=dmarc1")
    ]

    result = {
        "record_count": len(dmarc_records),
        "records": dmarc_records,
        "valid": False,
        "policy": None,
        "subdomain_policy": None,
        "percentage": None,
        "rua": [],
        "ruf": [],
    }

    if len(dmarc_records) != 1:
        return result

    record = dmarc_records[0]
    tags = {}

    for item in record.split(";"):
        item = item.strip()
        if "=" not in item:
            continue

        key, value = item.split("=", 1)
        tags[key.strip().lower()] = value.strip()

    if tags.get("v", "").lower() != "dmarc1":
        return result

    result["valid"] = True
    result["policy"] = tags.get("p")
    result["subdomain_policy"] = tags.get("sp")

    if tags.get("pct") is not None:
        try:
            result["percentage"] = int(tags["pct"])
        except ValueError:
            result["percentage"] = None

    for key in ("rua", "ruf"):
        if tags.get(key):
            result[key] = [
                value.strip()
                for value in tags[key].split(",")
                if value.strip()
            ]

    return result


def _check_dnssec(
    resolver: dns.resolver.Resolver,
    domain: str,
) -> dict[str, Any]:
    dnskey = _query_records(resolver, domain, "DNSKEY")
    ds = _query_records(resolver, domain, "DS")

    validation = {
        "status": "UNKNOWN",
        "ad_flag": False,
        "dnskey": dnskey,
        "ds": ds,
    }

    try:
        query = dns.message.make_query(
            domain,
            dns.rdatatype.A,
            want_dnssec=True,
        )

        response = dns.query.udp(
            query,
            resolver.nameservers[0],
            timeout=DNS_TIMEOUT,
        )

        validation["ad_flag"] = bool(response.flags & dns.flags.AD)

        if validation["ad_flag"]:
            validation["status"] = "VALIDATED"
        elif dnskey["records"] and ds["records"]:
            validation["status"] = "SIGNED_UNVALIDATED"
        else:
            validation["status"] = "NOT_VALIDATED"

    except (dns.exception.DNSException, OSError, IndexError) as exc:
        validation["status"] = "ERROR"
        validation["error"] = str(exc)

    return validation


def _finding(
    *,
    finding_id: str,
    title: str,
    vulnerability: str,
    description: str,
    severity: str,
    cvss_score: float,
    risk_level: str,
    evidence: Any,
    impact: str,
    remediation: str,
    references: str,
) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "tool_name": "DNS Security",
        "tool_category": "DNS Security",
        "title": title,
        "vulnerability": vulnerability,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity,
        "risk_level": risk_level,
        "evidence": (
            evidence
            if isinstance(evidence, str)
            else json.dumps(evidence, indent=2, sort_keys=True)
        ),
        "impact": impact,
        "remediation": remediation,
        "references": references,
        "status": "OPEN",
    }


def scan_dns_security(domain: str) -> dict[str, Any]:
    """
    Perform real DNS security checks against a domain.

    This function does not create database records. It returns a structured
    result that the client portal workflow will persist later.
    """
    domain = _normalize_domain(domain)

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    findings: list[dict[str, Any]] = []

    dnssec = _check_dnssec(resolver, domain)

    if dnssec["status"] == "NOT_VALIDATED":
        findings.append(
            _finding(
                finding_id="DNSSEC-001",
                title="DNSSEC validation is not enabled",
                vulnerability="Missing or unvalidated DNSSEC",
                description=(
                    "The domain does not provide evidence of DNSSEC validation "
                    "for the queried record."
                ),
                severity="MEDIUM",
                cvss_score=5.3,
                risk_level="LEVEL_2",
                evidence=dnssec,
                impact=(
                    "DNS responses may be more susceptible to tampering or "
                    "cache-poisoning attacks."
                ),
                remediation=(
                    "Deploy DNSSEC for the domain and publish the appropriate "
                    "DS record at the parent zone."
                ),
                references="DNSSEC / RFC 4033",
            )
        )

    elif dnssec["status"] == "SIGNED_UNVALIDATED":
        findings.append(
            _finding(
                finding_id="DNSSEC-002",
                title="DNSSEC appears signed but validation was not confirmed",
                vulnerability="DNSSEC validation could not be confirmed",
                description=(
                    "DNSKEY and DS records were observed, but the queried "
                    "response did not carry the authenticated-data flag."
                ),
                severity="LOW",
                cvss_score=3.1,
                risk_level="LEVEL_3",
                evidence=dnssec,
                impact=(
                    "DNSSEC may be deployed without providing authenticated "
                    "validation to this resolver path."
                ),
                remediation=(
                    "Verify the DNSSEC chain of trust and resolver validation "
                    "configuration."
                ),
                references="DNSSEC / RFC 4033 / RFC 4034",
            )
        )

    spf_raw = _query_txt(resolver, domain)
    spf = _parse_spf(spf_raw["records"])

    if spf["record_count"] == 0:
        findings.append(
            _finding(
                finding_id="SPF-001",
                title="SPF record is missing",
                vulnerability="Missing SPF policy",
                description="No SPF TXT record was found for the domain.",
                severity="MEDIUM",
                cvss_score=5.3,
                risk_level="LEVEL_2",
                evidence=spf_raw,
                impact=(
                    "Mail receivers have less information available to "
                    "identify authorized senders for the domain."
                ),
                remediation=(
                    "Publish a valid SPF TXT record listing authorized "
                    "mail-sending services."
                ),
                references="SPF / RFC 7208",
            )
        )

    elif spf["record_count"] > 1:
        findings.append(
            _finding(
                finding_id="SPF-002",
                title="Multiple SPF records detected",
                vulnerability="Multiple SPF TXT policies",
                description=(
                    "More than one SPF policy was found. Multiple SPF records "
                    "can cause SPF evaluation to return a permanent error."
                ),
                severity="HIGH",
                cvss_score=7.1,
                risk_level="LEVEL_1",
                evidence=spf,
                impact=(
                    "Legitimate mail may fail SPF evaluation and the intended "
                    "anti-spoofing policy may not be enforced."
                ),
                remediation=(
                    "Combine the authorized mechanisms into a single SPF "
                    "record and remove duplicate SPF policies."
                ),
                references="SPF / RFC 7208",
            )
        )

    elif spf["valid"] and spf["all_policy"] == "+all":
        findings.append(
            _finding(
                finding_id="SPF-003",
                title="SPF explicitly authorizes all senders",
                vulnerability="Overly permissive SPF policy",
                description="The SPF record ends with +all.",
                severity="HIGH",
                cvss_score=7.5,
                risk_level="LEVEL_1",
                evidence=spf,
                impact=(
                    "Any sender can appear authorized by SPF for the domain, "
                    "weakening sender authentication."
                ),
                remediation=(
                    "Replace +all with an appropriate restrictive policy such "
                    "as -all after validating all legitimate senders."
                ),
                references="SPF / RFC 7208",
            )
        )

    elif spf["valid"] and spf["all_policy"] == "?all":
        findings.append(
            _finding(
                finding_id="SPF-004",
                title="SPF policy is neutral",
                vulnerability="Weak SPF terminal policy",
                description="The SPF record ends with ?all.",
                severity="LOW",
                cvss_score=3.1,
                risk_level="LEVEL_3",
                evidence=spf,
                impact=(
                    "Unauthenticated senders are not explicitly rejected by "
                    "the SPF policy."
                ),
                remediation=(
                    "After validating authorized senders, consider a stricter "
                    "terminal SPF policy."
                ),
                references="SPF / RFC 7208",
            )
        )

    dmarc_raw = _query_txt(resolver, f"_dmarc.{domain}")
    dmarc = _parse_dmarc(dmarc_raw["records"])

    if dmarc["record_count"] == 0:
        findings.append(
            _finding(
                finding_id="DMARC-001",
                title="DMARC record is missing",
                vulnerability="Missing DMARC policy",
                description="No DMARC TXT record was found.",
                severity="MEDIUM",
                cvss_score=5.3,
                risk_level="LEVEL_2",
                evidence=dmarc_raw,
                impact=(
                    "The domain does not publish a DMARC policy to instruct "
                    "receivers how to handle authentication failures."
                ),
                remediation=(
                    "Publish a DMARC policy at _dmarc.<domain> and gradually "
                    "move from monitoring to enforcement."
                ),
                references="DMARC / RFC 7489",
            )
        )

    elif dmarc["record_count"] > 1:
        findings.append(
            _finding(
                finding_id="DMARC-002",
                title="Multiple DMARC records detected",
                vulnerability="Multiple DMARC policies",
                description=(
                    "More than one DMARC TXT record was found. This can make "
                    "the DMARC policy invalid."
                ),
                severity="HIGH",
                cvss_score=7.1,
                risk_level="LEVEL_1",
                evidence=dmarc,
                impact=(
                    "Receivers may be unable to apply the intended DMARC policy."
                ),
                remediation=(
                    "Publish exactly one valid DMARC policy for the domain."
                ),
                references="DMARC / RFC 7489",
            )
        )

    elif dmarc["valid"] and dmarc["policy"] == "none":
        findings.append(
            _finding(
                finding_id="DMARC-003",
                title="DMARC is configured only for monitoring",
                vulnerability="Non-enforcing DMARC policy",
                description="The DMARC policy is p=none.",
                severity="LOW",
                cvss_score=3.1,
                risk_level="LEVEL_3",
                evidence=dmarc,
                impact=(
                    "DMARC failures are reported but unauthorized messages "
                    "are not instructed to be rejected or quarantined."
                ),
                remediation=(
                    "Review DMARC reports and move toward p=quarantine or "
                    "p=reject after legitimate mail sources are validated."
                ),
                references="DMARC / RFC 7489",
            )
        )

    elif dmarc["valid"] and dmarc["policy"] not in {
        "quarantine",
        "reject",
    }:
        findings.append(
            _finding(
                finding_id="DMARC-004",
                title="DMARC policy is invalid or incomplete",
                vulnerability="Invalid DMARC policy",
                description="The DMARC record does not contain a recognized enforcement policy.",
                severity="MEDIUM",
                cvss_score=5.3,
                risk_level="LEVEL_2",
                evidence=dmarc,
                impact="Receivers may not apply the intended DMARC protection.",
                remediation="Publish a valid DMARC policy using p=none, p=quarantine, or p=reject.",
                references="DMARC / RFC 7489",
            )
        )

    mx = _query_records(resolver, domain, "MX")
    ns = _query_records(resolver, domain, "NS")
    caa = _query_records(resolver, domain, "CAA")

    if mx["status"] == "ERROR":
        findings.append(
            _finding(
                finding_id="DNS-MX-001",
                title="MX lookup failed",
                vulnerability="DNS mail exchanger lookup failure",
                description="The authoritative DNS response could not be reliably retrieved.",
                severity="INFO",
                cvss_score=0.0,
                risk_level="LEVEL_3",
                evidence=mx,
                impact="Mail-routing posture could not be evaluated.",
                remediation="Verify authoritative DNS availability and delegation.",
                references="DNS / RFC 1035",
            )
        )

    if ns["status"] == "NO_RECORD":
        findings.append(
            _finding(
                finding_id="DNS-NS-001",
                title="No NS records returned",
                vulnerability="Missing authoritative nameserver records",
                description="No NS records were returned for the target domain.",
                severity="HIGH",
                cvss_score=7.5,
                risk_level="LEVEL_1",
                evidence=ns,
                impact="The domain's authoritative DNS delegation may be broken.",
                remediation="Verify the parent-zone delegation and publish valid authoritative NS records.",
                references="DNS / RFC 1034 / RFC 1035",
            )
        )

    if caa["status"] == "NO_RECORD":
        findings.append(
            _finding(
                finding_id="CAA-001",
                title="CAA record is not configured",
                vulnerability="Missing Certificate Authority Authorization",
                description="No CAA record was found at the domain.",
                severity="LOW",
                cvss_score=3.1,
                risk_level="LEVEL_3",
                evidence=caa,
                impact=(
                    "The domain does not explicitly restrict which certificate "
                    "authorities may issue certificates."
                ),
                remediation=(
                    "Consider publishing CAA records that authorize the "
                    "certificate authorities used by the organization."
                ),
                references="CAA / RFC 8659",
            )
        )

    checks = {
        "domain": domain,
        "dnssec": dnssec,
        "spf": spf,
        "dmarc": dmarc,
        "mx": mx,
        "ns": ns,
        "caa": caa,
    }

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for item in findings:
        key = item["severity"].lower()
        if key in counts:
            counts[key] += 1

    if findings:
        score = max(
            0.0,
            round(
                10.0
                - (
                    counts["critical"] * 3.0
                    + counts["high"] * 2.0
                    + counts["medium"] * 1.0
                    + counts["low"] * 0.25
                ),
                2,
            ),
        )
    else:
        score = 10.0

    highest_severity = (
        max(
            (item["severity"] for item in findings),
            key=lambda value: severity_order.get(value, 0),
        )
        if findings
        else "PASS"
    )

    return {
        "status": "COMPLETED",
        "domain": domain,
        "security_score": score,
        "highest_severity": highest_severity,
        "finding_count": len(findings),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "info_count": counts["info"],
        "checks": checks,
        "findings": findings,
    }
