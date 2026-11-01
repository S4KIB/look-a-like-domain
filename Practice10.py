# verdict.py: decides if a lookalike domain is SAFE or UNSAFE, and explains why.
#
# HOW IT WORKS
#   Each hit gets yes/no "clues" (features). Every clue that is "yes" adds its points (can be negative).
#   Total points >= UNSAFE_AT  ->  UNSAFE, otherwise SAFE.
#
# WHERE THE CLUES COME FROM (verified sources, read them yourself):
#   [R1] Palo Alto Networks Unit 42, "Newly Registered Domains: Malicious Abuse by Bad Actors"
#        https://unit42.paloaltonetworks.com/newly-registered-domains-malicious-abuse-by-bad-actors/
#        More than 70% of newly registered domains were malicious, suspicious or not safe for work;
#        they recommend treating domains younger than about 32 days with caution.
#   [R2] Palo Alto Networks via TechRadar, "There are more malicious domains online than ever before"
#        https://www.techradar.com/news/there-are-more-malicious-domains-online-than-ever-before
#        Domains that are registered early and left dormant ("strategically aged") can be even more likely to be
#        malicious than new ones. So a domain being OLD is only weak evidence of safety.
#   [R3] APWG Phishing Activity Trends, Q1 2021 (reported by Security Affairs)
#        https://securityaffairs.com/118908/cyber-crime/apwg-phishing-record-q1-2021.html
#        About 83% of phishing sites used HTTPS, and 94.5% of their certificates were free "domain validated" ones.
#        So a VALID SSL certificate is NOT a sign of safety. It gets 0 points here, never a discount.
#   [R4] APWG Q3 2020 (reported by PhishLabs)
#        https://www.phishlabs.com/node/664
#        65% of malicious domains were used for phishing within five days of registration.
#   [R5] UCI "Phishing Websites" dataset (PhishTank + MillerSmiles, 11,055 sites, 30 features)
#        https://archive.ics.uci.edu/dataset/327/phishing
#        Its features include domain age, SSL state and DNS record, so these are standard phishing clues.
#
# WHAT IS NOT FROM A SOURCE (my own reasoning, not measured):
#   - the exact number of points for each clue, and the UNSAFE_AT threshold
#   - "live website", "email set up (MX)", "keyword in the name", "homograph", "lookalike characters"
#   - "SSL certificate issued recently"
#   To measure and tune them with real data, run calibrate.py. It writes verdict_weights.json,
#   and this file loads that automatically.
#
# IMPORTANT: SAFE means "no strong danger signs found". It does NOT prove a site is safe.
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
WEIGHTS_FILE = os.path.join(HERE, "verdict_weights.json")

NEW_DOMAIN_DAYS = 32      # [R1] about one month
YOUNG_DOMAIN_DAYS = 365   # less than a year old
OLD_DOMAIN_DAYS = 1825    # 5+ years old
NEW_CERT_DAYS = 30        # SSL certificate issued in the last 30 days

# Words attackers put in a fake domain to push people to "log in"
KEYWORDS = ["login", "signin", "secure", "verify", "update", "account", "support",
            "wallet", "pay", "banking", "ibanking", "otp", "confirm", "reset"]

# Starting points (my estimates). calibrate.py can replace them with values fitted on real data.
DEFAULT_POINTS = {
    "new_domain": 3,         # [R1] [R4] registered less than 32 days ago
    "young_domain": 1,       # [R1] extrapolation: registered less than 1 year ago
    "old_domain": -1,        # [R2] weak: only a small discount, old domains can be abused too
    "live_website": 2,       # own reasoning: a fake site must be live to trick people
    "email_setup": 2,        # own reasoning: MX record means phishing emails can be sent
    "new_certificate": 2,    # [R3] [R4] phishers use free certificates, a fresh one fits a freshly built site
    "bad_certificate": 1,    # [R5] SSL state is a standard clue
    "keyword": 2,            # own reasoning: words like "login" in the name
    "homograph": 2,          # own reasoning: looks identical to the real name
    "lookalike_chars": 1,    # own reasoning: l -> 1, o -> 0 and similar
}
DEFAULT_UNSAFE_AT = 5

FEATURES = list(DEFAULT_POINTS)


def load_settings():
    """Use verdict_weights.json (made by calibrate.py) if it exists, otherwise the defaults above."""
    points, unsafe_at, source = dict(DEFAULT_POINTS), DEFAULT_UNSAFE_AT, "defaults in verdict.py"
    if os.path.exists(WEIGHTS_FILE):
        try:
            with open(WEIGHTS_FILE, encoding="utf-8") as f:
                data = json.load(f)
            for k, v in data.get("points", {}).items():
                if k in points and isinstance(v, (int, float)):
                    points[k] = int(v)
            unsafe_at = int(data.get("unsafe_at", unsafe_at))
            source = "verdict_weights.json (calibrated)"
        except (OSError, ValueError):
            pass
    return points, unsafe_at, source


POINTS, UNSAFE_AT, SETTINGS_SOURCE = load_settings()


def find_keyword(domain):
    label = domain.split(".")[0]
    for k in KEYWORDS:
        if k in label:
            return k
    return None


def features(h):
    """Turn one hit (a dict) into yes/no clues (1 or 0). Missing information counts as 0."""
    age = h.get("age_days")
    cert_age = h.get("cert_age")
    ssl_status = h.get("ssl")
    technique = h.get("technique", "")
    return {
        "new_domain": int(age is not None and age < NEW_DOMAIN_DAYS),
        "young_domain": int(age is not None and NEW_DOMAIN_DAYS <= age < YOUNG_DOMAIN_DAYS),
        "old_domain": int(age is not None and age >= OLD_DOMAIN_DAYS),
        "live_website": int(str(h.get("web", "")).startswith("LIVE")),
        "email_setup": int(bool(h.get("mx"))),
        "new_certificate": int(ssl_status == "VALID" and cert_age is not None and cert_age < NEW_CERT_DAYS),
        "bad_certificate": int(ssl_status == "INVALID" and h.get("ssl_reason") in ("self-signed", "expired", "untrusted")),
        "keyword": int(find_keyword(h.get("domain", "")) is not None),
        "homograph": int(technique == "unicode homograph"),
        "lookalike_chars": int(technique == "lookalike character"),
    }


def describe(name, h):
    """Short human text for a clue."""
    age = h.get("age_days")
    texts = {
        "new_domain": f"domain only {age} days old",
        "young_domain": "domain less than 1 year old",
        "old_domain": f"domain {age // 365 if age else 0} years old" if age else "old domain",
        "live_website": "website is live",
        "email_setup": "email is set up (MX)",
        "new_certificate": f"SSL certificate only {h.get('cert_age')} days old",
        "bad_certificate": f"bad SSL certificate ({h.get('ssl_reason')})",
        "keyword": f"word '{find_keyword(h.get('domain', ''))}' in the name",
        "homograph": "looks identical (homograph)",
        "lookalike_chars": "lookalike characters",
    }
    return texts[name]


def judge(h, points=None, unsafe_at=None):
    """
    Returns (verdict, score, reasons). verdict is 'SAFE' or 'UNSAFE'.
    points / unsafe_at can be given to test other settings (calibrate.py does this).
    """
    points = points or POINTS
    unsafe_at = UNSAFE_AT if unsafe_at is None else unsafe_at
    f = features(h)
    pts = [(points[n], describe(n, h)) for n in FEATURES if f[n] and points[n] != 0]
    score = sum(p for p, _ in pts)
    verdict = "UNSAFE" if score >= unsafe_at else "SAFE"
    reasons = [f"{p:+d} {t}" for p, t in sorted(pts, key=lambda x: -abs(x[0]))]
    return verdict, score, reasons