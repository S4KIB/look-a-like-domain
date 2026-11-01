import re

name = "sjiblbd"
tld = "com"

results = {}

def add(variant, technique):
   ok = re.match(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", variant)
   if ok and variant != name and variant not in results:
      results[variant] = technique



for i in range (len(name)):
   add(name[:i] + name[i+1:], "missing letter")

for i in range(len(name)):
   add(name[:i] + name[i] + name[i], "double letter")

for i in range(len(name)-1):
   add(name[:i] + name[i+1] + name[i] + name[i+2:], "swapped letter")

for i in range(1, len(name)):
   add(name[:i] + "-" + name[i:], "hyphen added")

lookalike =  {"l": ["1", "i"], "i": ["l", "1"], "o": ["0"], "0": ["o"],
             "a": ["4"], "s": ["5"], "e": ["3"], "m": ["rn"], "w": ["vv"]}

for i,ch in enumerate(name):
   for r in lookalike.get(ch,[]):
      add(name[:i]+ r + name[i+1:], "lookalike Charachter")

for i, ch in enumerate(name):
   if ch in "aeiou":
      for v in "aeiou":
         add(name[:i] + v + name[i+1:], "vowel swap")

rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
for i, ch in enumerate(name):
   for row in rows:
      if ch in row:
         p = row.index(ch)
         if p > 0:
            add(name[:i] + row[p-1] + name[i+1:], "Keyboard neighbor")
         if p < len(row) -1:
            add(name[:i] + row[p+1] + name[i+1:], "keyboard neighbor")

keywords =  ["login", "secure", "verify", "online", "update", "account",
            "support", "app", "official", "bd", "pay", "wallet"]

for k in keywords:
   add(name + "-" + k, "keyword added")
   add(k + "-" + name, "keyword added")
   add(name + k, "keyword added")
   add(k + name, "keyword added")
   add(name + "." + k, "keyword added")
   add(k + "." + name, "keyword added")
   add(name + k + "." + tld, "keyword added")


add("www" + name, "www without dot")
for p in ["my", "the", "new", "mobile"]:
    add(p + name, "prefix added")
    add(name + p, "suffix added")

tlds = ["net", "org", "info", "biz", "co", "io", "xyz", "top", "online",
        "site", "club", "bd", "com.bd", "app"]

for i, ch in enumerate(name):
   for bit in range(8):
      flipped = chr(ord(ch) ^ (1 << bit))
      if flipped.isascii() and (flipped.islower() or flipped.isdigit()):
         add(name[:i] + flipped + name[i+1:], "bitsquatting")

for i in range(len(name) + 1):
    for v in "aeiou":
        add(name[:i] + v + name[i:], "vowel insertion")

for n in ["1", "2", "3", "4", "5", "6", "7", "8", "9"]:
    add(name + n, "number added")

for w in ["bangladesh", "bangla", "dhaka", "bdt", "taka"]:
    add(name + "-" + w, "bangladesh word")
    add(w + "-" + name, "bangladesh word")

cyr = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "c": "\u0441", "p": "\u0440"}
for i, ch in enumerate(name):
    if ch in cyr:
        u = name[:i] + cyr[ch] + name[i+1:]
        add(u.encode("idna").decode(), "unicode homograph")


by_type = {}
for v, t in results.items():
    by_type.setdefault(t, []).append(v)
 
for t, items in by_type.items():
    print(f"\n[{t}] {len(items)} ")
    for v in items:
        print("   ", v + "." + tld)
 
tld_variants = [name + "." + t for t in tlds if t != tld]
print(f"\n[different TLD] {len(tld_variants)} ")
for v in tld_variants[:5]:
    print("   ", v)


 
total = len(results) + len(tld_variants)