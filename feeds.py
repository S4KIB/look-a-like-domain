# feeds.py: downloads public "known bad" lists and checks if a domain is on them.
#
# Why: a browser shows "Dangerous site" because the site is on a block list (Google Safe Browsing and similar),
# not because of its age or SSL certificate. Our own clues cannot see that. A list match is strong evidence.
#
# The lists are downloaded to the feeds_cache folder (at most every 12 hours) and matched on YOUR computer.
# The domains you check are NOT sent to anyone. Only the list itself is downloaded.
#
# Add more lists in FEED_URLS (one name and one URL each). Check each provider's terms of use first,
# especially before using a list inside a bank. The default is the abuse.ch URLhaus list of online malware URLs
# (malware only, it does not list phishing pages). Add a phishing list (PhishTank, OpenPhish...) for phishing coverage.
import os
import time
import urllib.request
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(HERE, "feeds_cache")
MAX_AGE_HOURS = 12

FEED_URLS = {
    "URLhaus (malware)": "https://urlhaus.abuse.ch/downloads/text_online/",
}


def _cache_path(name):
    safe = "".join(c if c.isalnum() else "_" for c in name)
    return os.path.join(CACHE_DIR, safe + ".txt")


def refresh():
    """Download every list that is missing or older than MAX_AGE_HOURS. Keeps the old copy if a download fails."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    for name, url in FEED_URLS.items():
        path = _cache_path(name)
        fresh = os.path.exists(path) and (time.time() - os.path.getmtime(path)) < MAX_AGE_HOURS * 3600
        if fresh:
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DomainMonitor/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            with open(path, "wb") as f:
                f.write(data)
            print(f"  feed downloaded: {name} ({len(data) // 1024} KB)")
        except Exception as e:                       # network problem: use the old copy if there is one
            have = "using the old copy" if os.path.exists(path) else "no copy available"
            print(f"  WARNING: could not download '{name}' ({type(e).__name__}), {have}.")


def load_index():
    """Return {host: list_name} from all cached lists."""
    index = {}
    for name in FEED_URLS:
        path = _cache_path(name)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                host = urlparse(line).hostname if "://" in line else line.split("/")[0]
                if host:
                    index[host.lower().strip(".")] = name
    return index


def match(domain, index):
    """Name of the list that contains this domain (or one of its subdomains), else ''."""
    domain = domain.lower()
    if domain in index:
        return index[domain]
    suffix = "." + domain
    for host, name in index.items():
        if host.endswith(suffix):
            return name
    return ""