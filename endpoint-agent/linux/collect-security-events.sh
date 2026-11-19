#!/usr/bin/env bash
set -euo pipefail

: "${SOC_API_URL:?SOC_API_URL is required}"
: "${SOC_API_KEY:?SOC_API_KEY is required}"
: "${SOC_ENDPOINT_ID:?SOC_ENDPOINT_ID is required}"

HOSTNAME_VALUE="$(hostname)"
IP_ADDRESS="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')"

OS_NAME="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-${NAME:-Linux}}")"
OS_VERSION="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
ARCHITECTURE="$(uname -m)"

echo "Linux security telemetry collector"
echo "Endpoint: ${SOC_ENDPOINT_ID}"
echo "Hostname: ${HOSTNAME_VALUE}"
echo "IP: ${IP_ADDRESS}"
echo "OS: ${OS_NAME}"
echo "Version: ${OS_VERSION}"
echo "Architecture: ${ARCHITECTURE}"

EVENT_LINES="$(
    journalctl \
        --no-pager \
        --since "24 hours ago" \
        -o short-iso |
    grep -Ei \
        'authentication failure|failed password|invalid user|sudo:session.*session opened|sudo:session.*session closed|useradd|userdel|passwd|password changed|privileged command|COMMAND=|login:session|systemd-user:session' \
    || true
)"

if [[ -z "${EVENT_LINES}" ]]; then
    echo "No Linux security events found."
    exit 0
fi

TMP_EVENTS="$(mktemp)"
trap 'rm -f "$TMP_EVENTS"' EXIT

: > "${TMP_EVENTS}"

accepted_local=0

while IFS= read -r line; do
    [[ -z "${line}" ]] && continue

    timestamp="$(printf '%s\n' "${line}" | awk '{print $1}')"
    message="$(printf '%s\n' "${line}" | sed -E 's/^[^ ]+ [^ ]+ [^ ]+ //')"

    event_type="linux_security_event"
    severity="INFO"

    if printf '%s\n' "${line}" | grep -Eqi 'authentication failure|failed password'; then
        event_type="authentication_failure"
        severity="HIGH"
    elif printf '%s\n' "${line}" | grep -Eqi 'invalid user'; then
        event_type="invalid_user"
        severity="HIGH"
    elif printf '%s\n' "${line}" | grep -Eqi 'useradd'; then
        event_type="account_creation"
        severity="MEDIUM"
    elif printf '%s\n' "${line}" | grep -Eqi 'COMMAND=.*(usermod.*(-aG|-G|--groups)(=|[[:space:]]+)(sudo|wheel|admin|admins|docker|lxd|disk|shadow)|gpasswd.*(-a|-d|--add|--delete).* (sudo|wheel|admin|admins|docker|lxd|disk|shadow)|adduser.* (sudo|wheel|admin|admins|docker|lxd|disk|shadow))'; then
        event_type="privileged_group_change_attempt"
        severity="MEDIUM"
    elif printf '%s\n' "${line}" | grep -Eqi 'usermod'; then
        event_type="account_modification"
        severity="MEDIUM"
    elif printf '%s\n' "${line}" | grep -Eqi 'passwd|password changed'; then
        event_type="password_change"
        severity="MEDIUM"
    elif printf '%s\n' "${line}" | grep -Eqi 'sudo:session.*session opened'; then
        event_type="privileged_session_opened"
        severity="INFO"
    elif printf '%s\n' "${line}" | grep -Eqi 'sudo:session.*session closed'; then
        event_type="privileged_session_closed"
        severity="INFO"
    elif printf '%s\n' "${line}" | grep -Eqi 'privileged command|COMMAND='; then
        event_type="privileged_command"
        severity="MEDIUM"
    elif printf '%s\n' "${line}" | grep -Eqi 'login:session|systemd-user:session'; then
        event_type="authentication_session"
        severity="INFO"
    fi

    event_id="$(
        printf '%s|%s|%s' "${SOC_ENDPOINT_ID}" "${timestamp}" "${line}" |
        sha256sum |
        awk '{print $1}'
    )"

    raw_event="$(
        python - "${line}" "${HOSTNAME_VALUE}" "${IP_ADDRESS}" "${OS_NAME}" "${OS_VERSION}" "${ARCHITECTURE}" <<'PY'
import json
import sys

line, hostname, ip_address, os_name, os_version, architecture = sys.argv[1:]

print(json.dumps({
    "collector": "endpoint-agent/linux/collect-security-events.sh",
    "hostname": hostname,
    "ip_address": ip_address,
    "os_name": os_name,
    "os_version": os_version,
    "architecture": architecture,
    "journal_line": line,
}))
PY
    )"

    event_json="$(
        python - \
            "${event_id}" \
            "${timestamp}" \
            "${event_type}" \
            "${severity}" \
            "${message}" \
            "${SOC_ENDPOINT_ID}" \
            "${raw_event}" <<'PY'
import json
import sys

event_id, timestamp, event_type, severity, message, endpoint_id, raw_event = sys.argv[1:]

event = {
    "event_id": event_id,
    "timestamp": timestamp,
    "event_type": event_type,
    "severity": severity,
    "message": message,
    "target": endpoint_id,
    "endpoint_id": endpoint_id,
    "raw_event": json.loads(raw_event),
}

print(json.dumps(event, separators=(",", ":")))
PY
    )"

    printf '%s\n' "${event_json}" >> "${TMP_EVENTS}"
    accepted_local=$((accepted_local + 1))
done <<< "${EVENT_LINES}"

if [[ "${accepted_local}" -eq 0 ]]; then
    echo "No Linux security events to send."
    exit 0
fi

echo "Collected ${accepted_local} Linux security events."
echo "Sending telemetry in batches of up to 100..."

batch_number=0
batch_events=()

send_batch() {
    local batch_payload
    batch_payload="$(
        printf '%s\n' "${batch_events[@]}" |
        python -c '
import json
import sys

events = [json.loads(line) for line in sys.stdin if line.strip()]
print(json.dumps({"events": events}, separators=(",", ":")))
'
    )"

    batch_number=$((batch_number + 1))
    echo "Sending batch ${batch_number} with ${#batch_events[@]} events..."

    curl \
        --fail-with-body \
        --silent \
        --show-error \
        --request POST \
        --header "X-API-Key: ${SOC_API_KEY}" \
        --header "Content-Type: application/json" \
        --data "${batch_payload}" \
        "${SOC_API_URL%/}/telemetry/ingest"

    echo
    batch_events=()
}

while IFS= read -r event_json; do
    [[ -z "${event_json}" ]] && continue
    batch_events+=("${event_json}")

    if [[ "${#batch_events[@]}" -ge 100 ]]; then
        send_batch
    fi
done < "${TMP_EVENTS}"

if [[ "${#batch_events[@]}" -gt 0 ]]; then
    send_batch
fi

echo "Linux security telemetry ingestion completed."
