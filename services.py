import json
import os
import random
import re
import string
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CT_CACHE_FILE = os.path.join(HERE, "ct_cache.json")
CT_MAX_AGE_HOURS = 12
CT_URL = "https://crt.sh/?q=%25.{domain}&output=json"

# category -> names to try in front of the domain (my own list, it is not complete)
CATEGORIES = {
    "Website": ["www", "web", "m", "mobile", "shop", "store", "blog", "portal"],
    "Email": ["mail", "webmail", "smtp", "imap", "pop", "pop3", "mx", "autodiscover", "owa", "exchange"],
    "Login / Payment": ["login", "signin", "secure", "account", "accounts", "auth", "sso", "pay", "payment",
                        "payments", "ibanking", "banking", "online", "wallet", "verify", "my"],
    "Remote access": ["vpn", "remote", "rdp", "ssh", "gateway"],
    "Admin panel": ["admin", "cpanel", "whm", "webdisk", "panel", "dashboard", "manage"],
    "File transfer": ["ftp", "sftp", "files", "download", "upload"],
    "API / App": ["api", "app", "apps", "service", "services"],
    "Support": ["support", "help", "docs"],
    "Testing": ["dev", "test", "staging", "beta", "demo", "uat"],
    "Static / CDN": ["cdn", "static", "assets", "img", "images", "media"],
    "DNS": ["ns", "ns1", "ns2", "dns"],
}
# Names that are especially interesting on a lookalike domain (people log in, pay or manage things there)
SENSITIVE = ("Login / Payment", "Admin panel", "Remote access")

LABEL_TO_CATEGORY = {sub: cat for cat, subs in CATEGORIES.items() for sub in subs}

# Provider hints from DNS records
MX_PROVIDERS = [("google.com", "Google Workspace / Gmail"), ("googlemail.com", "Google Workspace / Gmail"),
                ("protection.outlook.com", "Microsoft 365"), ("outlook.com", "Microsoft 365"),
                ("zoho", "Zoho Mail"), ("secureserver.net", "GoDaddy email"),
                ("registrar-servers.com", "Namecheap email forwarding"), ("yandex", "Yandex Mail"),
                ("protonmail", "Proton Mail"), ("mimecast", "Mimecast")]
SPF_PROVIDERS = [("sendgrid.net", "SendGrid"), ("mailgun.org", "Mailgun"), ("amazonses.com", "Amazon SES"),
                 ("_spf.google.com", "Google Workspace"), ("spf.protection.outlook.com", "Microsoft 365"),
                 ("zoho", "Zoho"), ("mailchimp", "Mailchimp")]
NS_PROVIDERS = [("cloudflare.com", "Cloudflare"), ("domaincontrol.com", "GoDaddy DNS"),
                ("registrar-servers.com", "Namecheap DNS"), ("awsdns", "Amazon Route 53"),
                ("nsone.net", "NS1"), ("googledomains.com", "Google Domains"), ("azure-dns", "Azure DNS")]
TXT_SIGNS = [("google-site-verification=", "Google (Search Console / Workspace)"), ("ms=ms", "Microsoft 365"),
             ("facebook-domain-verification=", "Facebook / Meta"), ("apple-domain-verification=", "Apple"),
             ("stripe-verification=", "Stripe (payments)"), ("atlassian-domain-verification=", "Atlassian"),
             ("zoho-verification=", "Zoho"), ("docusign=", "DocuSign")]


def categorize(label):
    """
    Category of a name. 'login' is exact. 'secure-pay' or 'my-wallet2' are split into words, and a word that is
    in the list decides (a sensitive word wins over a harmless one).
    """
    if label in LABEL_TO_CATEGORY:
        return LABEL_TO_CATEGORY[label]
    words = [w for w in re.split(r"[-_0-9]+", label) if w]
    cats = [LABEL_TO_CATEGORY[w] for w in words if w in LABEL_TO_CATEGORY]
    for c in cats:
        if c in SENSITIVE:
            return c
    return cats[0] if cats else "Other"


# ------------------------------------------------------------------ 1. DNS names
def probe_names(domain, query):
    """
    query(name, record_type) must return a list of records (empty or None = nothing), like Practice5.get_records.
    Returns (wildcard, found) where found is {category: [full names]}.
    """
    random_name = "zz-" + "".join(random.choices(string.ascii_lowercase, k=10))
    if query(f"{random_name}.{domain}", "A"):
        return True, {}                        # every name resolves: names tell us nothing
    found = {}
    for category, subs in CATEGORIES.items():
        for sub in subs:
            name = f"{sub}.{domain}"
            if query(name, "A"):
                found.setdefault(category, []).append(name)
    return False, found


# ------------------------------------------------------------------ 2. Certificates (crt.sh)
def _load_ct_cache():
    if os.path.exists(CT_CACHE_FILE):
        try:
            with open(CT_CACHE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}
    return {}


def ct_subdomains(domain):
    """
    Names that got an SSL certificate, from the public crt.sh search.
    Returns (set_of_names, status) where status is 'ok', 'cached' or 'error: ...'.
    """
    cache = _load_ct_cache()
    item = cache.get(domain)
    if item and time.time() - item["time"] < CT_MAX_AGE_HOURS * 3600:
        return set(item["names"]), "cached"

    req = urllib.request.Request(CT_URL.format(domain=domain), headers={"User-Agent": "DomainMonitor/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
        return set(), f"error: {type(e).__name__}"

    names = set()
    for entry in data:
        for n in str(entry.get("name_value", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith("." + domain):
                names.add(n)
    cache[domain] = {"time": time.time(), "names": sorted(names)}
    try:
        with open(CT_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except OSError:
        pass
    return names, "ok"


# ------------------------------------------------------------------ 3. Provider hints from DNS records
def _first_match(text, table):
    for key, label in table:
        if key in text:
            return label
    return ""


def provider_hints(h):
    """Which provider runs the email and DNS, and other signs from TXT records."""
    mx = " ".join(h.get("mx", [])).lower()
    spf = h.get("spf", "").lower()
    ns = " ".join(h.get("ns", [])).lower()
    email = _first_match(mx, MX_PROVIDERS)
    email_src = "MX" if email else ""
    if not email:
        email = _first_match(spf, SPF_PROVIDERS)
        email_src = "SPF" if email else ""
    signs = []
    for t in h.get("txt", []):
        low = t.lower()
        for key, label in TXT_SIGNS:
            if low.startswith(key) and label not in signs:
                signs.append(label)
    return {"email_provider": f"{email} (from {email_src})" if email else "",
            "dns_provider": _first_match(ns, NS_PROVIDERS), "signs": signs}


# ------------------------------------------------------------------ put everything together
def summarize(h, wildcard, dns_found, ct_names, ct_status):
    """Return the services summary that is stored in h['services']."""
    domain = h["domain"]
    source = {}                                   # full name -> set of sources
    for names in dns_found.values():
        for n in names:
            source.setdefault(n, set()).add("dns")
    for n in ct_names:
        source.setdefault(n, set()).add("cert")

    by_category = {}
    for n in sorted(source):
        label = n[: -(len(domain) + 1)].split(".")[0]
        by_category.setdefault(categorize(label), []).append((n, "+".join(sorted(source[n]))))
    sensitive = any(c in by_category for c in SENSITIVE)
    return {"wildcard": wildcard, "by_category": by_category, "total": len(source), "sensitive": sensitive,
            "ct_status": ct_status, **provider_hints(h)}