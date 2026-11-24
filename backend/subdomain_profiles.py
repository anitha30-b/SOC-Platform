"""Server-controlled DNSRecon wordlists and execution budgets."""
from pathlib import Path

FULL_WORDLIST = Path('/usr/share/dnsrecon/dnsrecon/data/subdomains-top1mil-5000.txt')
QUICK_WORDLIST = Path(__file__).with_name('data') / 'subdomain' / 'quick-250.txt'


def profile_settings(profile='full'):
    if profile not in {'full', 'quick'}:
        raise ValueError('Subdomain discovery profile must be full or quick.')
    path = QUICK_WORDLIST if profile == 'quick' else FULL_WORDLIST
    count = None
    if path.is_file():
        count = sum(bool(line.strip()) and not line.lstrip().startswith('#')
                    for line in path.read_text(encoding='utf-8').splitlines())
    if profile == 'quick' and (count is None or count < 1 or count > 250):
        raise ValueError('The server quick wordlist is missing or invalid.')
    return {'profile': profile, 'wordlist': str(path), 'candidate_count': count,
            'timeout_seconds': 60 if profile == 'quick' else 300,
            'coverage': 'Limited: first 250 valid unique labels from the installed wordlist.'
                        if profile == 'quick' else 'Full installed wordlist; not exhaustive DNS coverage.'}
