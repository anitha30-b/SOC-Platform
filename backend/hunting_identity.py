"""Conservative, read-only identity extraction for hunting views."""
import re

_ACCOUNT = r"[A-Za-z0-9_.@\\$-]{1,255}"
_END = r"(?=\s|$|\()"


def extract_message_identity(event_type, message):
    kind = str(event_type or "").lower()
    text = str(message or "")
    patterns = []

    if kind in {"authentication", "authentication_failure", "invalid_user",
                "authentication_success"}:
        patterns.extend([
            (
                rf"\bFailed password for (?:invalid user )?(?P<name>{_ACCOUNT}) from ",
                "SSH attempted account",
            ),
            (
                rf"\bInvalid user (?P<name>{_ACCOUNT}) from ",
                "SSH attempted account",
            ),
            (
                rf"\bAccepted (?:password|publickey|keyboard-interactive(?:/pam)?) "
                rf"for (?P<name>{_ACCOUNT}) from ",
                "SSH authenticated account reported by message",
            ),
        ])

    if kind in {"privileged_session_opened", "privileged_session_closed"}:
        patterns.append((
            rf"pam_unix\(sudo:session\): session (?:opened|closed) "
            rf"for user (?P<name>{_ACCOUNT}){_END}",
            "sudo session target account",
        ))

    if kind == "privileged_command":
        patterns.append((
            rf"(?:^|\s)(?P<name>{_ACCOUNT})\s*:\s*TTY=[^;\r\n]*;"
            rf"\s*PWD=[^;\r\n]*;\s*USER=",
            "sudo invoking account",
        ))

    for pattern, role in patterns:
        match = re.search(pattern, text)
        if match:
            return {
                "username": match.group("name"),
                "identity_basis": "Parsed from recorded message",
                "identity_role": role,
            }
    return None
