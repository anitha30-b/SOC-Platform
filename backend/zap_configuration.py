"""ZAP configuration without credentials in tracked source files.

Company deployments set ZAP_URL and ZAP_API_KEY in the service environment.
The private local fallback is deliberately excluded from handoff packages.
"""
import json
import os
from pathlib import Path
from urllib.parse import urlsplit


def load_zap_configuration(environ=None, private_path=None):
    env = os.environ if environ is None else environ
    path = Path(private_path) if private_path is not None else Path(__file__).with_name('.zap-runtime.local.json')
    local = {}
    if path.is_file():
        try:
            local = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise ValueError('Private local ZAP configuration cannot be read.') from exc
        if not isinstance(local, dict):
            raise ValueError('Private local ZAP configuration must be an object.')
    base = env.get('ZAP_URL') or local.get('ZAP_URL') or 'http://127.0.0.1:8080'
    key = env.get('ZAP_API_KEY') or local.get('ZAP_API_KEY') or ''
    if not isinstance(base, str) or not isinstance(key, str):
        raise ValueError('ZAP configuration values must be strings.')
    parsed = urlsplit(base)
    if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {'', '/'}):
        raise ValueError('ZAP_URL must be an HTTP(S) service origin without credentials, query or path.')
    if len(key) > 512 or any(ord(ch) < 32 or ord(ch) > 126 for ch in key):
        raise ValueError('ZAP_API_KEY has unsupported characters or length.')
    return base.rstrip('/'), key
