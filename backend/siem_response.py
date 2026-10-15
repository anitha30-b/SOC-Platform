import ipaddress
import subprocess


SIEM_CHAIN = "SIEM-BLOCK"


def validate_source_ip(source_ip):
    try:
        ip = ipaddress.ip_address(str(source_ip).strip())
    except ValueError:
        return False, "Invalid IP address"

    if ip.version != 4:
        return False, "IPv6 blocking is not supported by this IPv4 handler"

    if ip.is_loopback:
        return False, "Loopback addresses cannot be blocked"

    if ip.is_unspecified:
        return False, "Unspecified addresses cannot be blocked"

    if ip.is_multicast:
        return False, "Multicast addresses cannot be blocked"

    return True, str(ip)


def _run_iptables(*args):
    return subprocess.run(
        ["sudo", "-n", "/usr/local/sbin/soc-siem-firewall", *args],
        capture_output=True,
        text=True,
        timeout=10,
    )


def ensure_firewall_chain():
    """Create the SIEM chain and INPUT hook once, preserving other chains."""
    chain_check = _run_iptables("-S", SIEM_CHAIN)

    if chain_check.returncode != 0:
        created = _run_iptables("-N", SIEM_CHAIN)
        if created.returncode != 0:
            # Recheck in case another startup created it concurrently.
            chain_check = _run_iptables("-S", SIEM_CHAIN)
            if chain_check.returncode != 0:
                return {
                    "success": False,
                    "reason": created.stderr.strip()
                    or "Could not create SIEM firewall chain",
                }

    hook_check = _run_iptables("-C", "INPUT", "-j", SIEM_CHAIN)
    if hook_check.returncode != 0:
        inserted = _run_iptables("-I", "INPUT", "1", "-j", SIEM_CHAIN)
        if inserted.returncode != 0:
            hook_check = _run_iptables("-C", "INPUT", "-j", SIEM_CHAIN)
            if hook_check.returncode != 0:
                return {
                    "success": False,
                    "reason": inserted.stderr.strip()
                    or "Could not connect SIEM chain to INPUT",
                }

    if (
        _run_iptables("-S", SIEM_CHAIN).returncode != 0
        or _run_iptables("-C", "INPUT", "-j", SIEM_CHAIN).returncode != 0
    ):
        return {
            "success": False,
            "reason": "SIEM firewall chain verification failed",
        }

    return {"success": True, "chain": SIEM_CHAIN, "hook": "INPUT"}


def block_ip(source_ip):
    valid, value = validate_source_ip(source_ip)

    if not valid:
        return {
            "success": False,
            "action": "block",
            "ip": str(source_ip),
            "reason": value,
        }

    ip = value

    firewall_status = ensure_firewall_chain()
    if not firewall_status["success"]:
        return {
            "success": False,
            "action": "block",
            "ip": ip,
            "reason": firewall_status["reason"],
        }

    check = _run_iptables(
        "-C",
        SIEM_CHAIN,
        "-s",
        ip,
        "-j",
        "DROP",
    )

    if check.returncode == 0:
        return {
            "success": True,
            "action": "already_blocked",
            "ip": ip,
            "chain": SIEM_CHAIN,
        }

    result = _run_iptables(
        "-A",
        SIEM_CHAIN,
        "-s",
        ip,
        "-j",
        "DROP",
    )

    if result.returncode != 0:
        return {
            "success": False,
            "action": "block",
            "ip": ip,
            "reason": result.stderr.strip()
            or "iptables command failed",
        }

    verify = _run_iptables(
        "-C",
        SIEM_CHAIN,
        "-s",
        ip,
        "-j",
        "DROP",
    )

    if verify.returncode != 0:
        return {
            "success": False,
            "action": "block",
            "ip": ip,
            "reason": "Firewall rule could not be verified",
        }

    return {
        "success": True,
        "action": "blocked",
        "ip": ip,
        "chain": SIEM_CHAIN,
    }
