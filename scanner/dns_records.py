import dns.resolver
import dns.exception
import socket


RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


def query_dns(subdomain, timeout=5):
    info = {"a": [], "aaaa": [], "cname": None, "mx": [], "ns": [], "txt": [], "soa": None}
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "223.5.5.5"]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(subdomain, rtype, raise_on_no_answer=False)
            if rtype == "A":
                info["a"] = [str(r.address) for r in answers]
            elif rtype == "AAAA":
                info["aaaa"] = [str(r.address) for r in answers]
            elif rtype == "CNAME":
                info["cname"] = str(answers[0].target) if answers else None
            elif rtype == "MX":
                info["mx"] = [str(r.exchange) for r in answers]
            elif rtype == "NS":
                info["ns"] = [str(r.target) for r in answers]
            elif rtype == "TXT":
                info["txt"] = ["".join(r.strings) for r in answers]
            elif rtype == "SOA":
                if answers:
                    info["soa"] = str(answers[0].mname)
        except (dns.exception.DNSException, Exception):
            pass

    if not info["a"] and not info["aaaa"]:
        try:
            ip = socket.gethostbyname(subdomain)
            info["a"] = [ip]
        except Exception:
            pass

    return info
