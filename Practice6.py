import json
import os
 
HERE = os.path.dirname(os.path.abspath(__file__))
 
 
def baseline_path(target):
    # One baseline file per target domain, e.g. baseline_bkash.com.json
    return os.path.join(HERE, f"baseline_{target}.json")
 
 
def find_new(target, hit_domains):
    """
    Compare today's hits with the saved baseline.
    Returns (first_run, new_set).
      first_run = True  -> no baseline existed, everything is saved as the baseline
      new_set           -> domains that were not in the previous scan
    """
    path = baseline_path(target)
    first_run = not os.path.exists(path)
 
    old = set()
    if not first_run:
        with open(path, encoding="utf-8") as f:
            old = set(json.load(f))
 
    new = set(hit_domains) - old
 
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sorted(old | set(hit_domains)), f, indent=2)
 
    return first_run, new
 
 
def reset(target):
    """Delete the baseline for a target (start fresh)."""
    path = baseline_path(target)
    if os.path.exists(path):
        os.remove(path)
 
 
if __name__ == "__main__":
    reset("demo.com")
    print(find_new("demo.com", ["a.com", "b.com"]))          # first run
    print(find_new("demo.com", ["a.com", "b.com"]))          # nothing new
    print(find_new("demo.com", ["a.com", "b.com", "c.com"])) # c.com is new
    reset("demo.com")
 
