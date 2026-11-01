import argparse
import json
import math
import os
import random
import sys
import time
from urllib.parse import urlparse

import Practice10 
from Practice5 import check
from Practice9 import rdap_lookup, ssl_lookup

HERE = os.path.dirname(os.path.abspath(__file__))
PHISH_FILE = os.path.join(HERE, "data", "phishing_domains.txt")
LEGIT_FILE = os.path.join(HERE, "data", "legit_domains.txt")
RDAP_DELAY = 0.5

SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}


def registrable(host):
    """Rough 'main domain' of a host name: a.b.example.com -> example.com, x.co.uk -> x.co.uk"""
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def load_domains(path, limit):
    if not os.path.exists(path):
        sys.exit(f"File not found: {path}\nPut one domain or URL per line (see the notes at the top of calibrate.py).")
    seen, out = set(), []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            host = urlparse(line).hostname if "://" in line else line.split("/")[0]
            if not host or "." not in host:
                continue
            d = registrable(host.lower().strip("."))
            if d not in seen:
                seen.add(d)
                out.append(d)
    random.Random(42).shuffle(out)
    return out[:limit]


# ------------------------------------------------------------------ collect clues
def collect(domains, label, use_ssl):
    """Return a list of (hit_dict, label). Domains that do not resolve are skipped (often already taken down)."""
    rows, skipped, rate_limited = [], 0, False
    for i, d in enumerate(domains, 1):
        res = check(d)
        if res is None:
            skipped += 1
            continue
        h = {"domain": d, "a": res["a"], "mx": res["mx"], "technique": ""}
        r = rdap_lookup(d)                      # registration date from the public registry
        if r["status"] == "rate limited":
            rate_limited = True
            print("  RDAP rate limit reached. Stopping early; run again later (results are cached).")
            break
        h["age_days"] = r["age_days"]
        if not r["cached"]:
            time.sleep(RDAP_DELAY)
        if use_ssl:
            s = ssl_lookup(d)
            h.update(ssl=s["ssl"], ssl_reason=s["reason"], cert_age=s["cert_age"])
        rows.append((h, label))
        if i % 10 == 0:
            print(f"  {i}/{len(domains)} done")
    print(f"  {label}: {len(rows)} usable, {skipped} did not resolve (skipped)")
    return rows, rate_limited


# ------------------------------------------------------------------ small logistic regression (no extra libraries)
def train_logreg(X, y, epochs=3000, lr=0.2, l2=0.01):
    n, m = len(X[0]), len(X)
    w, b = [0.0] * n, 0.0
    for _ in range(epochs):
        gw, gb = [0.0] * n, 0.0
        for xi, yi in zip(X, y):
            z = b + sum(wj * xj for wj, xj in zip(w, xi))
            p = 1 / (1 + math.exp(-max(min(z, 30), -30)))
            e = p - yi
            for j in range(n):
                gw[j] += e * xi[j]
            gb += e
        for j in range(n):
            w[j] -= lr * (gw[j] / m + l2 * w[j])
        b -= lr * gb / m
    return w


def evaluate(rows, points, unsafe_at):
    tp = fp = tn = fn = 0
    for h, label in rows:
        v, _, _ = Practice10.judge(h, points, unsafe_at)
        if label == "phishing":
            tp, fn = (tp + 1, fn) if v == "UNSAFE" else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if v == "UNSAFE" else (fp, tn + 1)
    return tp, fp, tn, fn


def rates(tp, fp, tn, fn):
    tpr = tp / (tp + fn) if tp + fn else 0.0     # phishing caught
    fpr = fp / (fp + tn) if fp + tn else 0.0     # normal domains wrongly flagged
    return tpr, fpr


def show(title, counts):
    tp, fp, tn, fn = counts
    tpr, fpr = rates(*counts)
    print(f"  {title}")
    print(f"      phishing caught (UNSAFE): {tp}/{tp + fn}  = {tpr:.0%}")
    print(f"      normal domains wrongly UNSAFE: {fp}/{fp + tn}  = {fpr:.0%}")


# ------------------------------------------------------------------ main
def main(argv=None):
    ap = argparse.ArgumentParser(description="Measure and tune the SAFE/UNSAFE rules on real labeled domains")
    ap.add_argument("--save", action="store_true", help="write Practice10_weights.json")
    ap.add_argument("--ssl", action="store_true", help="also use SSL clues (contacts the domains!)")
    ap.add_argument("--max", type=int, default=60, help="max domains per class (default 60)")
    args = ap.parse_args(argv)

    print("Collecting clues (DNS + RDAP)...")
    phish, rl1 = collect(load_domains(PHISH_FILE, args.max), "phishing", args.ssl)
    legit, rl2 = collect(load_domains(LEGIT_FILE, args.max), "legit", args.ssl)
    if len(phish) < 5 or len(legit) < 5:
        sys.exit("Not enough usable domains (need at least 5 in each class). Add more domains and run again.")

    # 70% train / 30% test, same split every time
    rng = random.Random(42)
    rng.shuffle(phish)
    rng.shuffle(legit)
    cut = lambda rows: max(1, int(len(rows) * 0.7))
    train = phish[:cut(phish)] + legit[:cut(legit)]
    test = phish[cut(phish):] + legit[cut(legit):]
    if len(phish) < 10 or len(legit) < 10:
        print("\nNOTE: very few domains. Test and training sets overlap, so the numbers below are too optimistic.")
        test = train

    # Only fit clues that actually vary in the training data. The others keep their default points.
    names = Practice10.FEATURES
    X = [[Practice10.features(h)[n] for n in names] for h, _ in train]
    y = [1 if label == "phishing" else 0 for _, label in train]
    usable = [j for j in range(len(names)) if 0 < sum(x[j] for x in X) < len(X)]
    w = train_logreg([[x[j] for j in usable] for x in X], y)
    biggest = max((abs(v) for v in w), default=0) or 1
    points = dict(Practice10.DEFAULT_POINTS)
    for j, wj in zip(usable, w):
        points[names[j]] = int(round(wj * 4 / biggest))

    # Best threshold on the training data (balanced accuracy, ties go to the higher threshold)
    best_t, best_score = Practice10.DEFAULT_UNSAFE_AT, -1
    for t in range(-6, 16):
        tpr, fpr = rates(*evaluate(train, points, t))
        score = (tpr + (1 - fpr)) / 2
        if score >= best_score:
            best_t, best_score = t, score

    # ---------------- report
    print("\n" + "=" * 78)
    print(" CALIBRATION RESULT")
    print("=" * 78)
    print(f" Domains used : phishing {len(phish)}, legit {len(legit)}   (train {len(train)}, test {len(test)})")
    print("-" * 78)
    print(f" {'CLUE':<18}{'DEFAULT':>8}{'FITTED':>8}   {'in phishing':>12}{'in legit':>10}")
    for n in names:
        a = sum(Practice10.features(h)[n] for h, l in phish + legit if l == "phishing")
        b = sum(Practice10.features(h)[n] for h, l in phish + legit if l == "legit")
        note = "" if names.index(n) in usable else "   (no data, kept default)"
        print(f" {n:<18}{Practice10.DEFAULT_POINTS[n]:>+8d}{points[n]:>+8d}   {a:>12}{b:>10}{note}")
    print(f" {'UNSAFE_AT':<18}{Practice10.DEFAULT_UNSAFE_AT:>8}{best_t:>8}")
    print("-" * 78)
    print(" Results on the TEST domains:")
    show("with the DEFAULT rules in Practice10.py", evaluate(test, Practice10.DEFAULT_POINTS, Practice10.DEFAULT_UNSAFE_AT))
    show("with the FITTED rules", evaluate(test, points, best_t))
    print("-" * 78)
    print(" Read this carefully:")
    print("  - Phishing feeds mostly list hacked or free-hosting sites, not lookalikes of one bank, so these numbers")
    print("    describe phishing in general, not 'fake bKash domains'.")
    print("  - Small samples give shaky numbers. Use more domains (--max) before trusting them.")
    print("  - The best data is hits from THIS tool that your analyst marked safe or unsafe. Collect those over time.")
    print("=" * 78)

    if args.save:
        out = {"points": points, "unsafe_at": best_t,
               "trained_on": {"phishing": len(phish), "legit": len(legit), "ssl_used": args.ssl}}
        with open(Practice10.WEIGHTS_FILE, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print(f"\nSaved {Practice10.WEIGHTS_FILE}. Practice10.py will use it from now on (delete the file to go back to defaults).")
    else:
        print("\nNothing was saved. Add --save to write Practice10_weights.json.")


if __name__ == "__main__":
    main()

