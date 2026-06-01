import os
import time
import threading
from scanner.dns_brute import dns_brute_scan
from scanner.passive_sources import passive_collect, get_all_source_names
from scanner.dns_records import query_dns
from scanner.http_probe import probe_http, probe_ssl
from scanner.port_scan import scan_ports, parse_port_range, COMMON_PORTS, TOP_1000_PORTS


class ScanEngine:
    def __init__(self):
        self._stop = False

    def stop(self):
        self._stop = True

    def _clean_domain(self, domain):
        domain = domain.strip().lower()
        if domain.startswith("http://") or domain.startswith("https://"):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc or urlparse(domain).hostname
        return domain.rstrip(".")

    def run(self, domains, wordlist_path, options, callbacks):
        self._stop = False

        if isinstance(domains, str):
            domains = [domains]
        domains = [self._clean_domain(d) for d in domains if d.strip()]
        if not domains:
            callbacks.get("on_error", lambda x: None)("未输入有效域名")
            callbacks.get("on_done", lambda: None)()
            return

        results = {}
        found_subdomains = set()

        on_status = callbacks.get("on_status", lambda x: None)
        on_subdomain = callbacks.get("on_subdomain", lambda x: None)
        on_progress = callbacks.get("on_progress", lambda c, t, l: None)
        on_done = callbacks.get("on_done", lambda: None)
        on_error = callbacks.get("on_error", lambda x: None)

        wordlist = self._load_wordlist(wordlist_path)
        if not wordlist:
            on_error("字典文件为空或无法读取")
            on_done()
            return

        for idx, domain in enumerate(domains):
            if self._stop:
                break
            on_status(f"[{idx+1}/{len(domains)}] 开始扫描: {domain}")

            # Phase 1: Passive collection
            if options.get("passive", True) and not self._stop:
                on_status(f"[{idx+1}/{len(domains)}] 被动收集: {domain}")
                api_keys = options.get("api_keys", {})
                sources = options.get("passive_sources", None)
                def passive_status(msg):
                    on_status(f"[{idx+1}/{len(domains)}] {msg}")
                try:
                    subs = passive_collect(domain, api_keys=api_keys, sources=sources, status_callback=passive_status)
                    for s in subs:
                        if s not in found_subdomains:
                            found_subdomains.add(s)
                            result = self._new_result(s, domain)
                            result["source"] = "passive"
                            results[s] = result
                            on_subdomain(result)
                except Exception as e:
                    on_error(f"被动收集 {domain}: {e}")

            # Phase 2: DNS brute force (results appear in real-time via found_callback)
            if options.get("brute", True) and not self._stop:
                on_status(f"[{idx+1}/{len(domains)}] DNS 字典枚举: {domain}")
                def brute_progress(current, total):
                    if self._stop:
                        return
                    on_progress("brute", current, total)
                def brute_target(target):
                    if not self._stop:
                        on_status(f"> 正在探测: {target}")
                def brute_found(sub, ip):
                    if sub not in found_subdomains:
                        found_subdomains.add(sub)
                        result = self._new_result(sub, domain)
                        result["source"] = "brute"
                        result["ip"] = ip
                        results[sub] = result
                        on_subdomain(result)
                try:
                    dns_brute_scan(
                        domain, wordlist,
                        threads=options.get("threads", 50),
                        timeout=options.get("timeout", 5),
                        progress_callback=brute_progress,
                        target_callback=brute_target,
                        found_callback=brute_found,
                    )
                except Exception as e:
                    on_error(f"DNS枚举 {domain}: {e}")

        # Phase 3: DNS records + HTTP probe + SSL
        if results and not self._stop:
            total_sub = len(results)
            done_sub = [0]
            on_status(f"[3/4] 信息收集 ({total_sub} 个)...")

            def process_subdomain(sub, res):
                if self._stop:
                    return
                on_status(f"> 正在探测: {sub}")
                dns_info = query_dns(sub, timeout=options.get("timeout", 5))
                res["dns"] = dns_info

                ip = None
                if dns_info.get("a"):
                    ip = dns_info["a"][0]
                elif dns_info.get("aaaa"):
                    ip = dns_info["aaaa"][0]
                res["ip"] = ip

                if options.get("http_probe", True) and not self._stop:
                    http_info = probe_http(sub, timeout=options.get("timeout", 5))
                    res["http"] = http_info
                    if http_info.get("https"):
                        ssl_info = probe_ssl(sub, timeout=options.get("timeout", 5))
                        res["ssl"] = ssl_info

                with threading.Lock():
                    done_sub[0] += 1
                    on_progress("info", done_sub[0], total_sub)
                on_subdomain(res)

            threads = []
            for sub, res in list(results.items()):
                if self._stop:
                    break
                t = threading.Thread(target=process_subdomain, args=(sub, res))
                t.start()
                threads.append(t)
                if len(threads) >= options.get("threads", 50):
                    for t in threads:
                        t.join()
                    threads = []
            for t in threads:
                t.join()

        # Phase 4: Port scan
        if options.get("port_scan", False) and not self._stop:
            unique_ips = set()
            for res in results.values():
                if res.get("ip"):
                    unique_ips.add(res["ip"])
            if unique_ips:
                total_ips = len(unique_ips)
                done_ips = [0]
                on_status(f"[4/4] 端口扫描 ({total_ips} 个IP)...")

                port_mode = options.get("port_mode", "常见端口(~300)")
                port_range_str = options.get("port_range", "")
                port_threads = options.get("port_threads", 100)
                port_timeout = options.get("port_timeout", 3)

                if port_mode == "Top 1000":
                    ports_to_scan = TOP_1000_PORTS
                elif port_mode == "自定义范围" and port_range_str:
                    ports_to_scan = parse_port_range(port_range_str)
                else:
                    ports_to_scan = COMMON_PORTS

                if not ports_to_scan:
                    on_error("端口范围无效，跳过端口扫描")
                else:
                    on_status(f"  端口范围: {len(ports_to_scan)} 个端口, 线程: {port_threads}, 超时: {port_timeout}s")
                    for ip in unique_ips:
                        if self._stop:
                            break
                        on_status(f"> 端口扫描: {ip}")
                        ports = scan_ports(ip, ports=ports_to_scan, threads=port_threads, timeout=port_timeout)
                        for res in results.values():
                            if res.get("ip") == ip:
                                res["ports"] = ports
                        done_ips[0] += 1
                        on_progress("port", done_ips[0], total_ips)

        if self._stop:
            on_status("扫描已停止")
        else:
            on_status(f"扫描完成，共 {len(domains)} 个域名，发现 {len(results)} 个子域名")

        on_done()

    def _load_wordlist(self, path):
        if not path or not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception:
            return []

    def _new_result(self, subdomain, parent_domain=""):
        return {
            "subdomain": subdomain,
            "domain": parent_domain,
            "ip": None,
            "source": "",
            "dns": {},
            "http": {},
            "ssl": None,
            "ports": [],
            "alive": False,
        }
