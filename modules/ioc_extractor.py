import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse

COMMON_DOMAINS_ALLOWLIST = {
    'google.com', 'www.google.com', 'github.com', 'microsoft.com',
    'twitter.com', 'facebook.com', 'linkedin.com', 'apple.com',
    'schemas.android.com', 'www.w3.org', 'purl.org', 'xmlns.com',
    'example.com', 'tools.ietf.org', 'www.recordedfuture.com',
    'bleepingcomputer.com', 'krebsonsecurity.com', 'thehackernews.com'
}

def _defang_text(text):
    text = text.replace('[.]', '.').replace('(.)', '.').replace('[dot]', '.')
    text = text.replace('hxxp://', 'http://').replace('hxxps://', 'https://')
    text = text.replace('fxp://', 'ftp://').replace('fxps://', 'ftps://')
    text = re.sub(r'\[(at|@)\]', '@', text, flags=re.IGNORECASE)
    text = re.sub(r'\[(colon|:)\]', ':', text, flags=re.IGNORECASE)
    return text

def _clean_html(raw_html):
    return BeautifulSoup(raw_html, "lxml").get_text(separator=' ', strip=True)

def extract_iocs(raw_content):
    text = _clean_html(raw_content)
    defanged_text = _defang_text(text)

    ioc_patterns = {
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
                r'\b(?:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?)::(?:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?)\b',
        'url': r'https?://[^\s/$.?#].[^\s"]*',
        'domain': r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        'email': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'sha512': r'\b[a-fA-F0-9]{128}\b',
        'cve': r'\bCVE-\d{4}-\d{4,7}\b',
        'attack_technique': r'\bT\d{4}(?:\.\d{3})?\b',
        'btc_address': r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b'
    }

    raw_iocs = {}
    for ioc_type, pattern in ioc_patterns.items():
        raw_iocs[ioc_type] = list(set(re.findall(pattern, defanged_text, re.IGNORECASE)))

    final_iocs = {
        'ipv4': raw_iocs.get('ipv4', []),
        'ipv6': raw_iocs.get('ipv6', []),
        'urls': raw_iocs.get('url', []),
        'emails': raw_iocs.get('email', []),
        'cve': raw_iocs.get('cve', []),
        'attack_techniques': raw_iocs.get('attack_technique', []),
        'btc_addresses': raw_iocs.get('btc_address', []),
        'hashes': {
            'md5': raw_iocs.get('md5', []),
            'sha1': raw_iocs.get('sha1', []),
            'sha256': raw_iocs.get('sha256', []),
            'sha512': raw_iocs.get('sha512', [])
        }
    }

    all_hashes = set(
        final_iocs['hashes']['md5'] +
        final_iocs['hashes']['sha1'] +
        final_iocs['hashes']['sha256']
    )
    final_iocs['hashes']['sha1'] = [h for h in final_iocs['hashes']['sha1'] if h not in final_iocs['hashes']['md5']]
    final_iocs['hashes']['sha256'] = [h for h in final_iocs['hashes']['sha256'] if h not in all_hashes]

    url_domains = set()
    for url in final_iocs['urls']:
        try:
            parsed_url = urlparse(url)
            if parsed_url.netloc:
                url_domains.add(parsed_url.netloc.replace('www.', ''))
        except ValueError:
            continue

    all_domains = raw_iocs.get('domain', [])
    filtered_domains = {
        d for d in all_domains
        if d.lower() not in url_domains and
           d.lower() not in COMMON_DOMAINS_ALLOWLIST and
           not any(ip in d for ip in final_iocs['ipv4'])
    }
    final_iocs['domains'] = sorted(list(filtered_domains))

    return {k: v for k, v in final_iocs.items() if v}