import json
import ssl
import urllib.request
import urllib.error
import time


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def _make_request(url, headers=None, timeout=30):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=headers or {"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def _filter_subdomains(subdomains, domain):
    result = set()
    for sub in subdomains:
        sub = sub.strip().lower().rstrip(".")
        if sub.startswith("*."):
            sub = sub[2:]
        if sub and (sub.endswith("." + domain) or sub == domain):
            result.add(sub)
    return result


def crtsh_scan(domain):
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        with _make_request(url) as resp:
            data = json.loads(resp.read().decode())
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                subdomains.add(sub.strip())
    except Exception:
        pass
    return _filter_subdomains(subdomains, domain)


def alienvault_otx_scan(domain):
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        with _make_request(url) as resp:
            data = json.loads(resp.read().decode())
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname", "")
            if hostname:
                subdomains.add(hostname)
    except Exception:
        pass
    return _filter_subdomains(subdomains, domain)


def hackertarget_scan(domain):
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        with _make_request(url) as resp:
            text = resp.read().decode()
        for line in text.strip().split("\n"):
            if "," in line:
                hostname = line.split(",")[0].strip()
                if hostname:
                    subdomains.add(hostname)
    except Exception:
        pass
    return _filter_subdomains(subdomains, domain)


def rapiddns_scan(domain):
    subdomains = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        with _make_request(url) as resp:
            html = resp.read().decode()
        import re
        pattern = r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>'
        matches = re.findall(pattern, html)
        for m in matches:
            subdomains.add(m.strip())
    except Exception:
        pass
    return _filter_subdomains(subdomains, domain)


def anubis_scan(domain):
    subdomains = set()
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    try:
        with _make_request(url) as resp:
            data = json.loads(resp.read().decode())
        for item in data:
            if isinstance(item, str):
                subdomains.add(item)
    except Exception:
        pass
    return _filter_subdomains(subdomains, domain)


def wayback_scan(domain):
    subdomains = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=10000"
    try:
        with _make_request(url, timeout=60) as resp:
            data = json.loads(resp.read().decode())
        for entry in data[1:]:
            original = entry[0] if entry else ""
            if original:
                from urllib.parse import urlparse
                try:
                    hostname = urlparse(original if "://" in original else f"http://{original}").hostname
                    if hostname:
                        subdomains.add(hostname)
                except Exception:
                    pass
    except Exception:
        pass
    return _filter_subdomains(subdomains, domain)


def urlscan_scan(domain, api_key=""):
    subdomains = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["API-Key"] = api_key
    try:
        with _make_request(url, headers=headers) as resp:
            data = json.loads(resp.read().decode())
        for entry in data.get("results", []):
            page = entry.get("page", {})
            hostname = page.get("domain", "")
            if hostname:
                subdomains.add(hostname)
    except Exception:
        pass
    return _filter_subdomains(subdomains, domain)


def virustotal_scan(domain, api_key=""):
    if not api_key:
        return set()
    subdomains = set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=1000"
    headers = {"x-apikey": api_key, "User-Agent": USER_AGENT}
    try:
        while url:
            with _make_request(url, headers=headers) as resp:
                data = json.loads(resp.read().decode())
            for entry in data.get("data", []):
                hostname = entry.get("id", "")
                if hostname:
                    subdomains.add(hostname)
            url = data.get("links", {}).get("next", "")
    except Exception:
        pass
    return _filter_subdomains(subdomains, domain)


def securitytrails_scan(domain, api_key=""):
    if not api_key:
        return set()
    subdomains = set()
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false&include_inactive=true"
    headers = {"apikey": api_key, "User-Agent": USER_AGENT}
    try:
        with _make_request(url, headers=headers) as resp:
            data = json.loads(resp.read().decode())
        for sub in data.get("subdomains", []):
            subdomains.add(f"{sub}.{domain}")
    except Exception:
        pass
    return _filter_subdomains(subdomains, domain)


def certspotter_scan(domain):
    subdomains = set()
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        with _make_request(url) as resp:
            data = json.loads(resp.read().decode())
        for entry in data:
            for name in entry.get("dns_names", []):
                subdomains.add(name)
    except Exception:
        pass
    return _filter_subdomains(subdomains, domain)


def passive_collect(domain, api_keys=None, sources=None, status_callback=None):
    api_keys = api_keys or {}
    all_sources = {
        "crt.sh": lambda d, k: crtsh_scan(d),
        "AlienVault OTX": lambda d, k: alienvault_otx_scan(d),
        "HackerTarget": lambda d, k: hackertarget_scan(d),
        "RapidDNS": lambda d, k: rapiddns_scan(d),
        "Anubis": lambda d, k: anubis_scan(d),
        "Wayback Machine": lambda d, k: wayback_scan(d),
        "CertSpotter": lambda d, k: certspotter_scan(d),
        "URLScan.io": lambda d, k: urlscan_scan(d, k.get("urlscan", "")),
        "VirusTotal": lambda d, k: virustotal_scan(d, k.get("virustotal", "")),
        "SecurityTrails": lambda d, k: securitytrails_scan(d, k.get("securitytrails", "")),
    }

    if sources:
        active_sources = {k: v for k, v in all_sources.items() if k in sources}
    else:
        active_sources = all_sources

    result = set()
    for name, func in active_sources.items():
        if status_callback:
            status_callback(f"  查询 {name}...")
        try:
            found = func(domain, api_keys)
            if found:
                result.update(found)
                if status_callback:
                    status_callback(f"  {name}: 发现 {len(found)} 个")
            else:
                if status_callback:
                    status_callback(f"  {name}: 无结果")
        except Exception as e:
            if status_callback:
                status_callback(f"  {name}: 失败 - {e}")

    return list(result)


def get_all_source_names():
    return [
        "crt.sh",
        "AlienVault OTX",
        "HackerTarget",
        "RapidDNS",
        "Anubis",
        "Wayback Machine",
        "CertSpotter",
        "URLScan.io",
        "VirusTotal",
        "SecurityTrails",
    ]


def get_api_key_sources():
    return {
        "URLScan.io": "urlscan",
        "VirusTotal": "virustotal",
        "SecurityTrails": "securitytrails",
    }
