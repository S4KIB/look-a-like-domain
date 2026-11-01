import json
import os
import shutil
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(HERE, "rdap_cache.json")
RDAP_URL = "https://rdap.org/domain/"        # redirects to the right registry for each TLD

RDAP_MAX = 40        # look up at most this many domains per run (the public service rate-limits)
RDAP_DELAY = 0.5     # seconds to wait between real lookups (cached ones need no wait)
NEW_DAYS = 30        # registered / issued in the last 30 days  -> NEW
RECENT_DAYS = 365    # registered in the last year              -> RECENT

ENABLE_SSL = True    # set False to skip the SSL check (it contacts the remote server)
SSL_TIMEOUT = 4      # seconds to wait for each server

RESET = "\033[0m"
COLORS = {"NEW": "\033[91m", "RECENT": "\033[93m", "BOLD": "\033[1m", "BAD": "\033[91m", "WARN": "\033[93m"}


# ---------------------------------------------------------------- RDAP lookup
def _load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}
    return {}


def _save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, sort_keys=True)


def _age_days(registered):
    d = datetime.strptime(registered, "%Y-%m-%d").date()
    return (datetime.now(timezone.utc).date() - d).days


def _parse_date(text):
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def rdap_lookup(domain):
    """
    Returns a dict:
      status     : 'ok', 'not found', 'rate limited' or 'error: ...'
      registered : 'YYYY-MM-DD' or None
      age_days   : int or None
      registrar  : str
      cached     : True if no network request was needed
    """
    cache = _load_cache()
    if domain in cache:
        c = cache[domain]
        return {"status": "ok", "registered": c["registered"], "age_days": _age_days(c["registered"]),
                "registrar": c["registrar"], "cached": True}

    def fail(status):
        return {"status": status, "registered": None, "age_days": None, "registrar": "-", "cached": False}

    req = urllib.request.Request(RDAP_URL + domain,
                                 headers={"User-Agent": "DomainMonitor/1.0", "Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return fail("not found")
        if e.code == 429:
            return fail("rate limited")
        return fail(f"error: HTTP {e.code}")
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
        return fail(f"error: {e}")

    registered = None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            dt = _parse_date(event.get("eventDate", ""))
            if dt:
                registered = dt.date().isoformat()

    registrar = "-"
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            for item in entity.get("vcardArray", [None, []])[1]:
                if item[0] == "fn":
                    registrar = item[3]

    if registered:
        cache[domain] = {"registered": registered, "registrar": registrar}
        _save_cache(cache)

    return {"status": "ok", "registered": registered,
            "age_days": _age_days(registered) if registered else None,
            "registrar": registrar, "cached": False}


# ---------------------------------------------------------------- SSL certificate lookup
def _ssl_reason(err):
    msg = (getattr(err, "verify_message", "") or str(err)).lower()
    if "hostname" in msg or "doesn't match" in msg or "does not match" in msg:
        return "hostname mismatch"
    if "self-signed" in msg or "self signed" in msg:
        return "self-signed"
    if "expired" in msg:
        return "expired"
    return "untrusted"


def _issuer_name(cert):
    fields = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
    return fields.get("organizationName") or fields.get("commonName") or "-"


def ssl_lookup(domain, port=443, timeout=None):
    """
    TLS handshake only (no web page requested). Returns a dict:
      ssl      : 'VALID', 'INVALID' (certificate has a problem) or 'NO SSL' (nothing answers on 443)
      reason   : why it is INVALID (hostname mismatch, self-signed, expired, untrusted)
      issuer   : certificate authority (e.g. Let's Encrypt)
      issued   : 'YYYY-MM-DD'
      expires  : 'YYYY-MM-DD'
      cert_age : days since the certificate was issued
      days_left: days until it expires
    """
    timeout = timeout or SSL_TIMEOUT
    empty = {"ssl": "NO SSL", "reason": "", "issuer": "-", "issued": None, "expires": None,
             "cert_age": None, "days_left": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return dict(empty, ssl="INVALID", reason=_ssl_reason(e))   # a server answered, but its certificate is bad
    except (OSError, ssl.SSLError, UnicodeError, ValueError):
        return empty                                               # refused, timeout, no TLS, bad name...

    now = time.time()
    issued_ts = ssl.cert_time_to_seconds(cert["notBefore"])
    expires_ts = ssl.cert_time_to_seconds(cert["notAfter"])
    return {"ssl": "VALID", "reason": "", "issuer": _issuer_name(cert),
            "issued": datetime.fromtimestamp(issued_ts, timezone.utc).date().isoformat(),
            "expires": datetime.fromtimestamp(expires_ts, timezone.utc).date().isoformat(),
            "cert_age": int((now - issued_ts) // 86400),
            "days_left": int((expires_ts - now) // 86400)}


# ---------------------------------------------------------------- terminal report
def paint(text, key, on):
    return f"{COLORS[key]}{text}{RESET}" if on else text


def short(text, width):
    return text if len(text) <= width else text[:width - 2] + ".."


def age_text(age):
    if age is None:
        return "n/a"
    return f"{age} d" if age < 365 else f"{age} d ({age / 365:.1f} y)"


def ssl_text(r):
    if r["ssl"] == "INVALID":
        return f"INVALID: {r['reason']}"
    return r["ssl"]


def print_rdap_report(rows, source, seconds, skipped):
    color = sys.stdout.isatty()
    width = shutil.get_terminal_size((120, 20)).columns - 1

    # Columns in priority order. Low-priority columns on the right are dropped on a narrow terminal.
    cols = [("FLAG", 9), ("DOMAIN", 28), ("REGISTERED", 13), ("AGE", 18)]
    if ENABLE_SSL:
        cols += [("SSL", 28), ("CERT ISSUED", 13), ("ISSUER", 22), ("EXPIRES IN", 12)]
    cols += [("REGISTRAR", 30)]
    if any(r.get("risk") for r in rows):
        cols += [("DNS RISK", 9)]

    used, shown = 0, []
    for title, w in cols:
        if used + w <= width:
            shown.append((title, w))
            used += w
    line_w = max(used, 60)
    bar, thin = "=" * line_w, "-" * line_w

    with_date = [r for r in rows if r["age_days"] is not None]
    new_n = sum(1 for r in with_date if r["age_days"] < NEW_DAYS)
    recent_n = sum(1 for r in with_date if r["age_days"] < RECENT_DAYS)
    no_data = len(rows) - len(with_date)

    print()
    print(bar)
    print(paint(" RDAP + SSL REPORT" if ENABLE_SSL else " RDAP REPORT", "BOLD", color))
    print(bar)
    print(f" Source      : {source}")
    print(f" Scan time   : {datetime.now():%Y-%m-%d %H:%M}    Duration: {seconds:.1f} s")
    print(f" Domains     : {len(rows)}    With RDAP data: {len(with_date)}    No data (n/a): {no_data}")
    if with_date:
        newest = min(with_date, key=lambda r: r["age_days"])
        print(f" Newest      : {newest['domain']}  ({age_text(newest['age_days'])}, {newest['registrar']})")
        print(f" Registered  : last {NEW_DAYS} days: {new_n}    last {RECENT_DAYS} days: {recent_n}")
    if ENABLE_SSL:
        valid = sum(1 for r in rows if r.get("ssl") == "VALID")
        invalid = sum(1 for r in rows if r.get("ssl") == "INVALID")
        nossl = sum(1 for r in rows if r.get("ssl") == "NO SSL")
        fresh = sum(1 for r in rows if r.get("cert_age") is not None and r["cert_age"] < NEW_DAYS)
        print(f" SSL         : valid: {valid}    invalid: {invalid}    no SSL: {nossl}    "
              f"certificate issued in last {NEW_DAYS} days: {fresh}")
    if skipped:
        print(paint(f" WARNING: RDAP rate limit reached, {skipped} domains were skipped. Run again later.", "NEW", color))
    print(thin)

    print("".join(f"{t:<{w}}" for t, w in shown))
    print(thin)
    for r in rows:
        age = r["age_days"]
        flag = "NEW" if age is not None and age < NEW_DAYS else "RECENT" if age is not None and age < RECENT_DAYS else ""
        days_left = r.get("days_left")
        values = {
            "FLAG": flag,
            "DOMAIN": r["domain"],
            "REGISTERED": r["registered"] or "n/a",
            "AGE": age_text(age),
            "SSL": ssl_text(r) if r.get("ssl") else "-",
            "CERT ISSUED": r.get("issued") or "n/a",
            "ISSUER": r.get("issuer") or "-",
            "EXPIRES IN": f"{days_left} d" if days_left is not None else "n/a",
            "REGISTRAR": r["registrar"] if r["status"] == "ok" else f"no data ({r['status']})",
            "DNS RISK": r.get("risk", ""),
        }
        out = ""
        for title, w in shown:
            cell = short(values[title], w - 1).ljust(w)
            if title == "FLAG" and flag:
                cell = paint(cell, flag, color)
            elif title == "SSL" and r.get("ssl") == "INVALID":
                cell = paint(cell, "BAD", color)
            elif title == "CERT ISSUED" and r.get("cert_age") is not None and r["cert_age"] < NEW_DAYS:
                cell = paint(cell, "WARN", color)
            out += cell
        print(out)
    print(bar)
    print(" NEW = registered in the last 30 days, RECENT = in the last year. n/a = no data (e.g. .bd domains, or no SSL).")
    if ENABLE_SSL:
        print(" SSL: VALID = trusted certificate, INVALID = server answers but certificate is bad, NO SSL = nothing on port 443.")
        print(" A certificate issued in the last 30 days (yellow) on a new domain is a common phishing sign.")
    print(" These are clues, not proof of phishing. Analyst review is needed.")
    print()


# ---------------------------------------------------------------- main
def main():
    start = time.time()

    args = sys.argv[1:]
    if args and args[0] == "--target":
        # Scan a domain with Practice5.py, then look up every hit:  python rdap.py --target sjiblbd.com
        if len(args) < 2:
            sys.exit("Usage: python rdap.py --target sjiblbd.com")
        import Practice5 as P
        P.set_target(args[1])
        hits, _ = P.get_hits()
        rows = [{"domain": h["domain"]} for h in hits]
        source = f"Practice5.py hit list ({P.name}.{P.tld})"
    elif args:
        # Domains typed by hand: python rdap.py bash.com kash.com
        rows = [{"domain": d.lower().strip()} for d in args]
        source = "command line"
    else:
        # Hit list from the DNS scan in Practice5.py (its default domain)
        import Practice5 as P
        hits, _ = P.get_hits()
        rows = [{"domain": h["domain"]} for h in hits]
        source = f"Practice5.py hit list ({P.name}.{P.tld})"

    if not rows:
        print("No domains to look up.")
        return

    todo = rows[:RDAP_MAX]

    # Step 1: RDAP (registration date, registrar)
    print(f"RDAP lookup for {len(todo)} domains (cached results are reused)...")
    skipped = 0
    for i, row in enumerate(todo):
        r = rdap_lookup(row["domain"])
        row.update(status=r["status"], registered=r["registered"],
                   age_days=r["age_days"], registrar=r["registrar"])
        if r["status"] == "rate limited":
            skipped = len(todo) - i - 1
            for rest in todo[i + 1:]:
                rest.update(status="skipped", registered=None, age_days=None, registrar="-")
            break
        if not r["cached"]:
            time.sleep(RDAP_DELAY)
        if (i + 1) % 5 == 0:
            print(f"  {i + 1}/{len(todo)} done")

    # Step 2: SSL certificate (TLS handshake only), several servers at the same time
    if ENABLE_SSL:
        print(f"SSL certificate check for {len(todo)} domains (handshake only)...")
        with ThreadPoolExecutor(max_workers=10) as ex:
            results = list(ex.map(lambda r: ssl_lookup(r["domain"]), todo))
        for row, s in zip(todo, results):
            row.update(s)

    # Newest first, domains without data last
    todo.sort(key=lambda r: (r["age_days"] is None, r["age_days"] if r["age_days"] is not None else 0, r["domain"]))
    print_rdap_report(todo, source, time.time() - start, skipped)


if __name__ == "__main__":
    main()