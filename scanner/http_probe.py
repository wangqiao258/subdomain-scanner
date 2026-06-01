import ssl
import socket
import datetime


def probe_http(subdomain, timeout=5):
    result = {}

    for proto in ("https", "http"):
        host = f"{proto}://{subdomain}"
        try:
            import httpx
            with httpx.Client(verify=False, timeout=timeout, follow_redirects=False) as client:
                resp = client.get(host, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
                result[proto] = {
                    "status": resp.status_code,
                    "title": extract_title(resp.text),
                    "server": resp.headers.get("Server", ""),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "location": resp.headers.get("Location", ""),
                    "content_length": len(resp.content),
                }
                break
        except Exception:
            continue

    return result


def probe_ssl(subdomain, timeout=5):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((subdomain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=subdomain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    not_after = cert.get("notAfter", "")
                    san = cert.get("subjectAltName", [])
                    return {
                        "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
                        "subject": subject.get("commonName", ""),
                        "not_after": not_after,
                        "san": [s[1] for s in san],
                        "expired": is_expired(not_after),
                        "valid": True,
                    }
    except Exception:
        pass
    return None


def extract_title(html):
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:200] if m else ""


def is_expired(date_str):
    try:
        dt = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt < datetime.datetime.now()
    except Exception:
        return None
