import argparse
import os
import re
import shutil
import sys
import textwrap
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import dns.exception
import dns.resolver

from Practice3 import generate_variants
import feeds
from Practice6 import find_new
from Practice9 import rdap_lookup, ssl_lookup
from Practice10 import judge
from Practice7 import check_web


name = "sjiblbd"
tld = "com"

# The company's own domains. They are not threats, so they are skipped.
OFFICIAL = {"sjiblbd.com", "sjibl-bd.com", name + "." + tld}

# How many variations to check. None = all of them. For a quick test use:  python Practice5.py domain.com --limit 30
LIMIT = None

# DNS servers to ask. [] = use the computer's default.
DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]

# ---- Extra checks that give the verdict its clues ----
# These two CONTACT the remote domain's server (they can see your IP address).
# Use them only on your personal laptop with public practice domains.
# NEVER enable them on a bank network without written approval.
ENABLE_WEB_CHECK = True    # is a website live? (HTTP headers only, see webcheck.py)
ENABLE_SSL_CHECK = True    # SSL certificate (TLS handshake only, see rdap.py)

# This one asks a public registry service, not the domain itself.
ENABLE_RDAP = True         # registration date and registrar (see rdap.py)
RDAP_MAX = 40              # look up at most this many domains per run (the public service rate-limits)
RDAP_DELAY = 0.5           # seconds between real lookups (cached ones need no wait)

# Known-bad lists (see feeds.py). The lists are downloaded and matched on your computer.
ENABLE_FEEDS = True

# Your own decisions. One domain per line, lines starting with # are ignored.
HERE = os.path.dirname(os.path.abspath(__file__))
OFFICIAL_FILE = os.path.join(HERE, "data", "official_domains.txt")   # the company's other real domains
UNSAFE_FILE = os.path.join(HERE, "data", "unsafe_domains.txt")   # always shown as UNSAFE
SAFE_FILE = os.path.join(HERE, "data", "safe_domains.txt")       # always shown as SAFE

# Print every IP, mail server, name server and the full redirect target for each domain, nothing cut off.
SHOW_FULL_DETAILS = True

# Collects DNS errors (timeouts etc.) so they are not hidden
errors = []

_local = threading.local()


def get_resolver():
    # One resolver per thread, so threads do not interfere with each other
    if not hasattr(_local, "resolver"):
        r = dns.resolver.Resolver()
        r.timeout = 3
        r.lifetime = 3
        if DNS_SERVERS:
            r.nameservers = DNS_SERVERS
        _local.resolver = r
    return _local.resolver


def get_records(domain, rtype):
    """Return a list of records. None = domain does not exist. [] = no record of this type."""
    try:
        answers = get_resolver().resolve(domain, rtype)
        return [r.to_text() for r in answers]
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return []                        # normal: this domain has no record of this type
    except dns.exception.DNSException as e:
        errors.append(type(e).__name__)  # real problem: timeout, no nameservers, etc.
        return []


def txt_text(record):
    """A TXT record comes as '"part one" "part two"'. Join the parts into one string."""
    parts = re.findall(r'"([^"]*)"', record)
    return "".join(parts) if parts else record.strip('"')


def get_mail_policy(domain):
    """
    Email set-up of a domain (only DNS questions, no connection to the domain):
      SPF   = TXT record that lists the servers allowed to send email for the domain
      DMARC = TXT record at _dmarc.domain that says what to do with email that fails the checks
    Returns (spf_text, dmarc_text), an empty string when there is none.
    """
    spf = ""
    for t in get_records(domain, "TXT") or []:
        value = txt_text(t)
        if value.lower().startswith("v=spf1"):
            spf = value
            break
    dmarc = ""
    for t in get_records("_dmarc." + domain, "TXT") or []:
        value = txt_text(t)
        if value.lower().startswith("v=dmarc1"):
            dmarc = value
            break
    return spf, dmarc


def check(domain):
    a = get_records(domain, "A")
    if a is None:
        return None                      # not registered
    mx = get_records(domain, "MX") or []
    mx = [m for m in mx if m.split()[-1] != "."]   # null MX ("0 .") means "this domain accepts no email"
    ns = get_records(domain, "NS") or []
    if not (a or mx or ns):
        return None
    spf, dmarc = get_mail_policy(domain)
    return {"domain": domain, "a": a, "mx": mx, "ns": ns, "spf": spf, "dmarc": dmarc, "risk": ""}


# =====================================================================
# Terminal report
# =====================================================================
RESET = "\033[0m"
COLORS = {"UNSAFE": "\033[91m", "SAFE": "\033[92m", "NEW": "\033[1;96m", "DIM": "\033[90m",
          "BOLD": "\033[1m", "WARN": "\033[93m", "BAD": "\033[91m"}


def paint(text, key, on):
    return f"{COLORS[key]}{text}{RESET}" if on else text


def short(text, width):
    return text if len(text) <= width else text[:width - 2] + ".."


def base(host):
    """ns3.afternic.com. -> afternic.com"""
    parts = host.strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def first_mx(mx_list):
    """'10 alt4.aspmx.l.google.com.' list -> host with the lowest priority number"""
    best = None
    for m in mx_list:
        bits = m.split()
        if len(bits) == 2 and bits[0].isdigit():
            if best is None or int(bits[0]) < best[0]:
                best = (int(bits[0]), bits[1].strip("."))
    return best[1] if best else "-"


def with_more(first, total, maxw):
    suffix = f" (+{total - 1})" if total > 1 else ""
    return short(first, maxw - len(suffix)) + suffix


def top_providers(items, n=4):
    count = {}
    for i in items:
        count[i] = count.get(i, 0) + 1
    ranked = sorted(count.items(), key=lambda x: (-x[1], x[0]))[:n]
    return ", ".join(f"{k} ({v})" for k, v in ranked) or "-"


def age_short(age):
    """Registration age in a few characters: 10d, 8m, 23y, n/a"""
    if age is None:
        return "n/a"
    if age < 60:
        return f"{age}d"
    if age < 730:
        return f"{age // 30}m"
    return f"{age // 365}y"


def ssl_short(h):
    s = h.get("ssl")
    return s if s else "-"


# Well-known parking / domain-for-sale services (my own short list, it is not complete)
PARKING = {"sedo.com", "afternic.com", "godaddy.com", "dan.com", "hugedomains.com",
           "bodis.com", "parkingcrew.net", "above.com", "undeveloped.com"}


def redirect_kind(domain, target):
    """Say what kind of place a redirect leads to."""
    t, d = base(target), base(domain)
    if t == d:
        return "same site (http to https, or www)"
    if t in {base(o) for o in OFFICIAL}:
        return "OFFICIAL site (the company may own this domain)"
    if t in PARKING:
        return "parking / domain-for-sale service"
    return "a DIFFERENT site, check it"


def web_cell(h):
    """Website column. A long redirect target is not cut: the full target is printed below the table."""
    web = h.get("web", "-")
    if len(web) > 40 and " > " in web:
        web = web.split(" > ")[0] + " > see below"
    return web


def spf_allows_sending(spf):
    """False for an empty SPF and for 'v=spf1 -all' (a record that says: nobody may send email)."""
    for token in spf.lower().split()[1:]:
        t = token.lstrip("+-~?")
        if t.startswith(("include:", "ip4:", "ip6:", "exists:", "redirect=")) or t in ("a", "mx", "ptr") \
                or t.startswith(("a:", "a/", "mx:", "mx/")):
            return True
    return False


def mail_setup(h):
    """MX + SPF + DMARC in a few characters. The more of them, the better prepared the domain is to send email."""
    parts = []
    if h.get("mx"):
        parts.append("MX")
    if h.get("spf"):
        parts.append("SPF" if spf_allows_sending(h["spf"]) else "SPF(deny)")
    if h.get("dmarc"):
        parts.append("DMARC")
    return "+".join(parts) if parts else "-"


def dmarc_policy(dmarc):
    m = re.search(r"\bp=(\w+)", dmarc or "", re.I)
    return m.group(1).lower() if m else "-"


def spf_ending(spf):
    """-all = reject others, ~all = soft fail, ?all = neutral, +all = allow everyone"""
    m = re.search(r"([-~?+]?all)\b", spf or "")
    return m.group(1) if m else "-"


def print_report(hits, target, total, seconds, first_run, new_count, errors):
    color = sys.stdout.isatty()
    width = shutil.get_terminal_size((120, 20)).columns - 4     # small safety margin so lines never wrap

    # ---------- Cell values: full text, nothing is cut here ----------
    def cell_values(h):
        return {
            "STATUS": h["status"],
            "RISK": h["risk"],
            "DOMAIN": h["domain"],
            "AGE": age_short(h.get("age_days")),
            "SSL": ssl_short(h),
            "WEB": web_cell(h),
            "MAIL SETUP": mail_setup(h),
            "IP": with_more(h["a"][0], len(h["a"]), 999) if h["a"] else "-",
            "NAME SERVER": with_more(h["ns"][0].strip("."), len(h["ns"]), 999) if h["ns"] else "-",
            "MAIL SERVER": with_more(first_mx(h["mx"]), len(h["mx"]), 999) if h["mx"] else "-",
            "TECHNIQUE": h["technique"],
        }

    all_values = [cell_values(h) for h in hits]

    # Columns in priority order. Each column is as wide as its longest value.
    # If the terminal is too narrow, the columns on the right are hidden (their full values are in FULL DETAILS).
    wanted = ["STATUS", "RISK", "DOMAIN"]
    if ENABLE_RDAP:
        wanted.append("AGE")
    if ENABLE_SSL_CHECK:
        wanted.append("SSL")
    if ENABLE_WEB_CHECK:
        wanted.append("WEB")
    wanted += ["MAIL SETUP", "IP", "NAME SERVER", "MAIL SERVER", "TECHNIQUE"]

    MAX_W = 60   # only a really long value is cut at this width
    widths = {t: min(MAX_W, max([len(t)] + [len(v[t]) for v in all_values]) + 2) for t in wanted}
    used, shown, hidden = 0, [], []
    for t in wanted:
        if not hidden and used + widths[t] <= width:
            shown.append((t, widths[t]))
            used += widths[t]
        else:
            hidden.append(t)
    line_w = max(used, 70)
    bar, thin = "=" * line_w, "-" * line_w

    unsafe = [h for h in hits if h["risk"] == "UNSAFE"]
    safe = [h for h in hits if h["risk"] == "SAFE"]

    # ---------- Header ----------
    print()
    print(bar)
    print(paint(" LOOKALIKE DOMAIN SAFETY REPORT", "BOLD", color))
    print(bar)
    print(f" Target      : {target}")
    print(f" Scan time   : {datetime.now():%Y-%m-%d %H:%M}    Duration: {seconds:.1f} s")
    print(f" Checked     : {total}    Registered: {len(hits)}    "
          f"NEW: {paint(str(new_count), 'NEW', color) if new_count else 0}")
    ready = sum(1 for h in hits if h.get("mx") and spf_allows_sending(h.get("spf", "")))
    full = sum(1 for h in hits if h.get("mx") and spf_allows_sending(h.get("spf", "")) and h.get("dmarc"))
    used_checks = ["DNS"] + [n for n, on in (("RDAP", ENABLE_RDAP), ("SSL", ENABLE_SSL_CHECK),
                                             ("Website", ENABLE_WEB_CHECK)) if on]
    print(f" Clues used  : {', '.join(used_checks)}")
    print(f" Email ready : {ready} of {len(hits)} domains have MX + SPF (can receive and send email), "
          f"{full} also have DMARC")
    if first_run:
        print(paint(" First run: all hits saved as the baseline. NEW hits appear from the next run.", "DIM", color))
    print(thin)

    if errors:
        kinds = ", ".join(f"{k} x{v}" for k, v in errors.items())
        print(paint(f" DNS errors  : {kinds}", "WARN", color))
        if not hits:
            print(paint(" WARNING: 0 results and DNS errors. DNS may be failing. Check internet or DNS_SERVERS.", "BAD", color))
        print(thin)

    if not hits:
        print(" No registered lookalike domains found.")
        print(bar)
        return

    # ---------- Summary with bars ----------
    print(" RISK SUMMARY")
    biggest = max(len(unsafe), len(safe)) or 1
    for label, group in (("UNSAFE", unsafe), ("SAFE", safe)):
        n = round(len(group) / biggest * 30)
        print(f"   {paint(f'{label:<7}', label, color)} {paint('#' * n, label, color)}{' ' * (30 - n)} {len(group)}")
    print(thin)

    mail = [base(first_mx(h["mx"])) for h in hits if h["mx"]]
    ns = [base(n) for h in hits for n in h["ns"][:1]]
    print(f" TOP MAIL PROVIDERS : {top_providers(mail)}")
    print(f" TOP NAME SERVERS   : {top_providers(ns)}")
    print(thin)

    # ---------- Table ----------
    print("".join(f"{t:<{w}}" for t, w in shown).rstrip())
    print(thin)
    for h, values in zip(hits, all_values):
        row = ""
        for title, w in shown:
            cell = short(values[title], w - 1).ljust(w)
            if title == "RISK":
                cell = paint(cell, h["risk"], color)
            elif title == "STATUS" and h["status"] == "NEW":
                cell = paint(cell, "NEW", color)
            row += cell
        print(row.rstrip())
    print(thin)
    if hidden:
        print(f" Hidden because the terminal is too narrow: {', '.join(hidden)}. "
              f"Make the terminal wider, or see FULL DETAILS below.")
        print(thin)

    # ---------- Where the redirects go ----------
    redirects = [h for h in hits if h.get("redirect_to")]
    if redirects:
        print(paint(" WHERE THE REDIRECTS GO (the tool does not follow them, it only reads the first answer)", "BOLD", color))
        for h in sorted(redirects, key=lambda h: redirect_kind(h["domain"], h["redirect_to"])):
            print(f"   {h['domain']:<26} -> {h['redirect_to']:<30} {redirect_kind(h['domain'], h['redirect_to'])}")
        print(thin)

    # ---------- Why each UNSAFE domain is UNSAFE ----------
    if unsafe:
        print(paint(" WHY EACH UNSAFE DOMAIN IS UNSAFE", "BOLD", color))
        for h in unsafe:
            extra = []
            if h.get("registrar") and h["registrar"] != "-":
                extra.append(f"registrar: {h['registrar']}")
            if h.get("ssl") == "INVALID":
                extra.append(f"SSL: invalid ({h['ssl_reason']})")
            elif h.get("issuer") and h["issuer"] != "-":
                extra.append(f"SSL issuer: {h['issuer']}")
            print(f"   {paint(h['domain'], 'UNSAFE', color)}  (score {h['score']})"
                  + (f"   [{'; '.join(extra)}]" if extra else ""))
            for r in h["why"]:
                print(f"       {r}")
        print(thin)

    # ---------- Full details: every value, nothing cut off ----------
    if SHOW_FULL_DETAILS:
        def line(label, text):
            print(textwrap.fill(f"{label:<11}: {text}", width=max(width, 60), initial_indent="     ",
                                subsequent_indent=" " * 18, break_long_words=False, break_on_hyphens=False))

        print(paint(" FULL DETAILS (nothing is cut off)", "BOLD", color))
        for h in hits:
            print(f" {paint(h['domain'], h['risk'], color)}   [{h['risk']}, {h['status']}]   technique: {h['technique']}")
            line("IP", ", ".join(h["a"]) or "-")
            line("MAIL", ", ".join(h["mx"]) or "-")
            line("NAME SERVER", ", ".join(n.strip(".") for n in h["ns"]) or "-")
            line("SPF", f"{h['spf']}   (ending: {spf_ending(h['spf'])})" if h.get("spf") else "none")
            line("DMARC", f"{h['dmarc']}   (policy: {dmarc_policy(h['dmarc'])})" if h.get("dmarc") else "none")
            if ENABLE_WEB_CHECK:
                line("WEBSITE", h.get("web", "-"))
            if ENABLE_SSL_CHECK:
                s = h.get("ssl", "-")
                if s == "INVALID":
                    s += f" ({h.get('ssl_reason')})"
                elif s == "VALID":
                    s += f", issuer {h.get('issuer')}, issued {h.get('issued')}, expires in {h.get('days_left')} days"
                line("SSL", s)
            if ENABLE_RDAP:
                age = h.get("age_days")
                line("REGISTERED", f"{h.get('registered')} ({age} days ago), registrar {h.get('registrar')}"
                     if age is not None else "no RDAP data")
        print(thin)

    print(" MAIL SETUP = MX (receives email) + SPF (lists servers allowed to send) + DMARC (policy for failed checks).")
    print("              SPF(deny) = the record allows nobody to send. MX + SPF together suggest the domain is set up to")
    print("              send and receive email, which phishing emails need. It is a clue, not proof.")
    print(" AGE = time since registration (d = days, m = months, y = years, n/a = no RDAP data).")
    print(" SAFE = no strong danger signs found. It does NOT prove a site is safe.")
    print(" UNSAFE = several danger signs together. Analyst review is needed for every hit.")
    print()


# =====================================================================
# Scan
# =====================================================================
def set_target(domain):
    """
    Choose the domain to protect, e.g. 'sjiblbd.com'. Variations are made from it.
    The domain itself and every domain in data/official_domains.txt are treated as official (not threats).
    """
    global name, tld, OFFICIAL
    d = domain.strip().lower()
    d = d.split("://")[-1].split("/")[0]
    if d.startswith("www."):
        d = d[4:]
    if "." not in d:
        sys.exit("Please give a full domain such as sjiblbd.com")
    name, tld = d.split(".", 1)
    OFFICIAL = {d} | read_list(OFFICIAL_FILE)


def get_hits():
    """
    DNS scan. Returns (hits, number_of_domains_checked).
    This function is also used by rdap.py to get the hit list.
    """
    variants = generate_variants(name, tld)
    variants = {d: t for d, t in variants.items() if d not in OFFICIAL}
    domains = list(variants)
    if LIMIT:
        domains = domains[:LIMIT]

    print(f"Checking {len(domains)} variations of {name}.{tld}...\n")

    with ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(check, domains))

    hits = []
    for domain, res in zip(domains, results):
        if res:
            res["technique"] = variants[domain]
            hits.append(res)
    return hits, len(domains)


def read_list(path):
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as f:
        return {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}


def apply_lists(hits):
    """Mark hits that are on a known-bad list, and hits you decided about yourself. Prints what it found."""
    print("Known-bad lists and your own lists...")
    if ENABLE_FEEDS and hits:
        feeds.refresh()
        index = feeds.load_index()
        listed = 0
        for h in hits:
            h["listed"] = feeds.match(h["domain"], index)
            listed += bool(h["listed"])
        print(f"  bad lists   : {len(index)} bad hosts loaded, {listed} of your {len(hits)} domains are on them")
        if listed == 0:
            print("                (the default list only has malware sites. Add a phishing list in feeds.py for more.)")
    else:
        print("  bad lists   : off")

    unsafe, safe = read_list(UNSAFE_FILE), read_list(SAFE_FILE)
    marked_unsafe = marked_safe = 0
    for h in hits:
        if h["domain"] in unsafe:
            h["analyst"] = "unsafe"
            marked_unsafe += 1
        elif h["domain"] in safe:
            h["analyst"] = "safe"
            marked_safe += 1
    for label, path, items, marked in (("unsafe list ", UNSAFE_FILE, unsafe, marked_unsafe),
                                       ("safe list   ", SAFE_FILE, safe, marked_safe)):
        if os.path.exists(path):
            print(f"  {label}: {len(items)} domains in the file, {marked} of them are in this scan")
        else:
            print(f"  {label}: file NOT found ({path})")


def add_clues(hits):
    """Collect the extra clues for every hit: registration date, SSL certificate, website."""
    # 1. Registration date and registrar (public registry, one by one because of rate limits)
    if ENABLE_RDAP:
        todo = hits[:RDAP_MAX]
        print(f"RDAP lookup for {len(todo)} registered domains (cached results are reused)...")
        for h in hits:
            h["age_days"], h["registrar"], h["registered"] = None, "-", None
        for h in todo:
            r = rdap_lookup(h["domain"])
            h["age_days"], h["registrar"], h["registered"] = r["age_days"], r["registrar"], r["registered"]
            if r["status"] == "rate limited":
                print("RDAP rate limit reached. Remaining domains skipped. Try again later.")
                break
            if not r["cached"]:
                time.sleep(RDAP_DELAY)

    # 2. SSL certificate (TLS handshake only)
    if ENABLE_SSL_CHECK:
        print(f"SSL certificate check for {len(hits)} registered domains (handshake only)...")
        with ThreadPoolExecutor(max_workers=10) as ex:
            results = list(ex.map(lambda h: ssl_lookup(h["domain"]), hits))
        for h, s in zip(hits, results):
            h.update(ssl=s["ssl"], ssl_reason=s["reason"], issuer=s["issuer"],
                     issued=s["issued"], cert_age=s["cert_age"], days_left=s["days_left"])

    # 3. Is a website live? (HTTP headers only)
    if ENABLE_WEB_CHECK:
        print(f"Website check for {len(hits)} registered domains (headers only)...")
        with ThreadPoolExecutor(max_workers=10) as ex:
            results = list(ex.map(lambda h: check_web(h["domain"]), hits))
        for h, w in zip(hits, results):
            h["web"] = w["text"] + (f" > {w['redirect_to']}" if w["redirect_to"] else "")
            h["redirect_to"] = w["redirect_to"]


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Lookalike domain scan with a SAFE / UNSAFE verdict")
    ap.add_argument("domain", nargs="?", help="domain to protect, for example sjiblbd.com")
    ap.add_argument("--limit", type=int, help="check only the first N variations (quick test)")
    args = ap.parse_args()
    if args.domain:
        set_target(args.domain)
    if args.limit:
        LIMIT = args.limit

    start = time.time()
    hits, checked = get_hits()

    add_clues(hits)
    apply_lists(hits)

    # Verdict for every hit (rules are in verdict.py)
    for h in hits:
        h["risk"], h["score"], h["why"] = judge(h)

    # Baseline: compare with the previous scan (logic is in baseline.py)
    if hits:
        first_run, new = find_new(f"{name}.{tld}", [h["domain"] for h in hits])
        if first_run:
            new = set()                  # first run: nothing can be "new" yet
    else:
        first_run, new = False, set()    # no hits: do not touch the baseline file
    for h in hits:
        if first_run:
            h["status"] = "BASELINE"
        else:
            h["status"] = "NEW" if h["domain"] in new else "KNOWN"

    # NEW first, then UNSAFE before SAFE, highest score first
    hits.sort(key=lambda h: (h["status"] != "NEW", h["risk"] != "UNSAFE", -h["score"], h["domain"]))

    error_counts = {}
    for e in errors:
        error_counts[e] = error_counts.get(e, 0) + 1

    print_report(hits, f"{name}.{tld}", checked, time.time() - start,
                 first_run, len(new), error_counts)