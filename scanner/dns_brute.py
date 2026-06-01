import threading
import dns.resolver
import dns.exception
import dns.name


def dns_brute_scan(domain, wordlist, threads=50, timeout=5, progress_callback=None, target_callback=None, found_callback=None):
    subdomains = set()
    lock = threading.Lock()

    total = len(wordlist)
    done = [0]

    def worker(chunk):
        local_found = []
        r = dns.resolver.Resolver()
        r.nameservers = ["1.1.1.1", "8.8.8.8", "223.5.5.5"]
        r.timeout = timeout
        r.lifetime = timeout
        for sub in chunk:
            target = f"{sub.strip()}.{domain}"
            if target_callback:
                target_callback(target)
            try:
                answers = r.resolve(target, "A")
                ip = str(answers[0].address)
                with lock:
                    if target not in subdomains:
                        subdomains.add(target)
                        local_found.append(target)
                        if found_callback:
                            found_callback(target, ip)
            except dns.resolver.NXDOMAIN:
                pass
            except dns.exception.Timeout:
                pass
            except Exception:
                pass
            with lock:
                done[0] += 1
                if progress_callback and done[0] % 50 == 0:
                    progress_callback(done[0], total)
        return local_found

    chunk_size = max(1, len(wordlist) // threads)
    chunks = [wordlist[i:i + chunk_size] for i in range(0, len(wordlist), chunk_size)]

    all_results = []
    thread_list = []
    for chunk in chunks:
        t = threading.Thread(target=lambda c=chunk: all_results.extend(worker(c)))
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    if progress_callback:
        progress_callback(total, total)

    return list(subdomains)
