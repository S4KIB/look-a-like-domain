import socket
import time
from concurrent.futures import ThreadPoolExecutor

from Practice3 import generate_variants


name = "sjiblbd"
tld = "com"

# The company's own domains. They are not threats, so they are skipped.
OFFICIAL = {"sjiblbd", name + "." + tld}


def lookup(domain):
    try:
        host, aliases, ips = socket.gethostbyname_ex(domain)
    except (socket.gaierror, UnicodeError):
        return None                      # not registered

    ipv6 = []
    try:
        for info in socket.getaddrinfo(domain, None, socket.AF_INET6):
            ipv6.append(info[4][0])
    except (socket.gaierror, UnicodeError):
        pass

    reverse = "-"
    try:
        reverse = socket.gethostbyaddr(ips[0])[0]
    except (socket.herror, socket.gaierror):
        reverse = "-"

    return {"domain": domain, "ips": ips, "ipv6": sorted(set(ipv6)), "reverse": reverse}


def print_report(hits, total, seconds):
    print("=" * 100)
    print(f"REPORT: {name}.{tld}   Checked: {total}   Registered: {len(hits)}   Time: {seconds:.2f} seconds")
    print("=" * 100)

    if not hits:
        print("No registered lookalike domains found.")
        return

    print(f"{'DOMAIN':<30}{'TECHNIQUE':<22}{'IPv4':<20}{'IPv6':<8}REVERSE DNS")
    print("-" * 100)
    for h in hits:
        ipv4 = h["ips"][0] + (f" (+{len(h['ips']) - 1})" if len(h["ips"]) > 1 else "")
        ipv6 = "yes" if h["ipv6"] else "-"
        print(f"{h['domain']:<30}{h['technique']:<22}{ipv4:<20}{ipv6:<8}{h['reverse']}")


if __name__ == "__main__":
    variants = generate_variants(name, tld)
    variants = {d: t for d, t in variants.items() if d not in OFFICIAL}
    domains = list(variants)

    print(f"Checking {len(domains)} variations...\n")

    start = time.time()
    with ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(lookup, domains))

    hits = []
    for domain, res in zip(domains, results):
        if res:
            res["technique"] = variants[domain]
            hits.append(res)

    print_report(hits, len(domains), time.time() - start)