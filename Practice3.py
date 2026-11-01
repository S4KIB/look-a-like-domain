import re


def generate_variants(name, tld):
    """name ar tld niye variation banay. Return: {full_domain: technique}"""
    results = {}

    def add(variant, technique):
        ok = re.match(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", variant)
        full = variant + "." + tld
        if ok and variant != name and full not in results:
            results[full] = technique

    # 1. Missing letter
    for i in range(len(name)):
        add(name[:i] + name[i+1:], "missing letter")

    # 2. Double letter (fix: name[i:] hobe, name[i] na)
    for i in range(len(name)):
        add(name[:i] + name[i] + name[i:], "double letter")

    # 3. Swapped letters
    for i in range(len(name) - 1):
        add(name[:i] + name[i+1] + name[i] + name[i+2:], "swapped letter")

    # 4. Hyphen added
    for i in range(1, len(name)):
        add(name[:i] + "-" + name[i:], "hyphen added")

    # 5. Lookalike character
    lookalike = {"l": ["1", "i"], "i": ["l", "1"], "o": ["0"], "0": ["o"],
                 "a": ["4"], "s": ["5"], "e": ["3"], "m": ["rn"], "w": ["vv"]}
    for i, ch in enumerate(name):
        for r in lookalike.get(ch, []):
            add(name[:i] + r + name[i+1:], "lookalike character")

    # 6. Vowel swap
    for i, ch in enumerate(name):
        if ch in "aeiou":
            for v in "aeiou":
                add(name[:i] + v + name[i+1:], "vowel swap")

    # 7. Keyboard neighbor
    rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
    for i, ch in enumerate(name):
        for row in rows:
            if ch in row:
                p = row.index(ch)
                if p > 0:
                    add(name[:i] + row[p-1] + name[i+1:], "keyboard neighbor")
                if p < len(row) - 1:
                    add(name[:i] + row[p+1] + name[i+1:], "keyboard neighbor")

    # 8. Keyword added
    keywords = ["login", "secure", "verify", "online", "update", "account",
                "support", "app", "official", "bd", "pay", "wallet"]
    for k in keywords:
        add(name + "-" + k, "keyword added")
        add(k + "-" + name, "keyword added")
        add(name + k, "keyword added")
        add(k + name, "keyword added")

    # 9. www / prefix / suffix
    add("www" + name, "www without dot")
    for p in ["my", "the", "new", "mobile"]:
        add(p + name, "prefix added")
        add(name + p, "suffix added")

    # 10. Bitsquatting
    for i, ch in enumerate(name):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped.isascii() and (flipped.islower() or flipped.isdigit()):
                add(name[:i] + flipped + name[i+1:], "bitsquatting")

    # 11. Vowel insertion
    for i in range(len(name) + 1):
        for v in "aeiou":
            add(name[:i] + v + name[i:], "vowel insertion")

    # 12. Number added
    for n in "123456789":
        add(name + n, "number added")

    # 13. Bangladesh word
    for w in ["bangladesh", "bangla", "dhaka", "bdt", "taka"]:
        add(name + "-" + w, "bangladesh word")
        add(w + "-" + name, "bangladesh word")

    # 14. Unicode homograph (Cyrillic)
    cyr = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "c": "\u0441", "p": "\u0440"}
    for i, ch in enumerate(name):
        if ch in cyr:
            u = name[:i] + cyr[ch] + name[i+1:]
            add(u.encode("idna").decode(), "unicode homograph")

    # 15. Different TLD
    tlds = ["net", "org", "info", "biz", "co", "io", "xyz", "top", "online",
            "site", "club", "bd", "com.bd", "app"]
    for t in tlds:
        if t != tld:
            results.setdefault(name + "." + t, "different TLD")

    return results


if __name__ == "__main__":
    name = "bkash"
    tld = "net"

    results = generate_variants(name, tld)

    by_type = {}
    for domain, technique in results.items():
        by_type.setdefault(technique, []).append(domain)

    for technique, items in by_type.items():
        print(f"\n[{technique}] {len(items)}")
        for d in items:
            print("   ", d)

    print("\nMot variation:", len(results))