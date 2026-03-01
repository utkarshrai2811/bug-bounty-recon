#!/usr/bin/env python3
# ============================================================
#  scope_reduce.py — Fast sieve, removes provably worthless hosts
#
#  New in this version:
#  - Detects generated/customer subdomain patterns (hex IDs, UUIDs,
#    long random strings) and collapses them to one representative
#  - Outputs both sieved_hosts.txt (URLs) AND sieved_hosts_rich.txt
#    (full httpx lines) in one pass — no more broken grep -Ff matching
#  - Reports pattern collapse stats
#
#  Usage:
#    python3 scope_reduce.py <live_hosts_rich.txt> <sieved_hosts.txt> <sieved_hosts_rich.txt>
# ============================================================

import sys
import re
from collections import defaultdict

# ─── Removal rules ───────────────────────────────────────────
CDN_PROVIDERS = [
    "cloudfront", "fastly", "akamai", "incapsula", "sucuri",
    "stackpath", "keycdn", "edgecast", "maxcdn", "cdn77",
    "bunnycdn", "azureedge", "trafficmanager",
    # Cloudflare is tricky — many real apps sit behind CF
    # Only remove if it's PURELY a CF redirect with no title/tech
]

DEAD_STATUSES = {"000", ""}

JUNK_TITLES = [
    "default welcome page", "test page", "it works",
    "apache2 ubuntu default", "nginx welcome", "iis windows server",
    "domain for sale", "website coming soon", "under construction",
    "godaddy", "namecheap parking", "parked domain",
    "404 not found", "403 forbidden",
]

# ─── Generated subdomain detection ───────────────────────────
# Matches prefixes that are clearly auto-generated IDs
# e.g. 02df7a62142e.eu.portal.konghq.tech
#      a3f9b1c2d4e5.gateways.konghq.tech
#      550e8400-e29b-41d4-a716-446655440000.api.example.com
GENERATED_PATTERNS = [
    re.compile(r'^[a-f0-9]{8,}\.'),           # hex ID prefix (8+ chars)
    re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-'), # UUID prefix
    re.compile(r'^[a-z0-9]{20,}\.'),           # long random alphanumeric
    re.compile(r'^\d{10,}\.'),                 # long numeric ID
]

def get_base_pattern(hostname):
    """
    If hostname matches a generated prefix pattern, return the base
    (everything after the first dot) as the pattern key.
    Returns None if not generated.

    e.g. '02df7a62142e.eu.portal.konghq.tech' → 'eu.portal.konghq.tech'
    """
    # Strip port if present
    host = hostname.split(':')[0]
    for pat in GENERATED_PATTERNS:
        if pat.match(host):
            rest = host.split('.', 1)
            if len(rest) == 2:
                return rest[1]
    return None

def parse_line(line):
    """Parse an httpx rich output line into components."""
    parts = line.strip().split()
    if not parts:
        return None

    url = parts[0]
    line_lower = line.lower()

    # Status code — first [NNN] token
    status = ""
    for p in parts[1:]:
        if re.match(r'^\[\d{3}\]$', p):
            status = p.strip("[]")
            break

    # All bracketed fields
    brackets = re.findall(r'\[([^\]]*)\]', line)

    # Title is usually the last non-empty bracket
    title = ""
    for b in reversed(brackets):
        if b and not re.match(r'^\d{3}$', b) and len(b) > 1:
            title = b.lower()
            break

    # Port from URL
    port_match = re.search(r':(\d+)(?:/|$)', url)
    if port_match:
        port = port_match.group(1)
    else:
        port = "443" if url.startswith("https") else "80"

    # Hostname
    host_match = re.match(r'https?://([^/:]+)', url)
    hostname = host_match.group(1) if host_match else url

    return {
        "url":       url,
        "hostname":  hostname,
        "status":    status,
        "port":      port,
        "title":     title,
        "line":      line.strip(),
        "line_lower": line_lower,
        "brackets":  brackets,
    }

def is_junk(p):
    """Returns (bool, reason). True = remove."""
    if not p:
        return True, "parse failed"

    # Dead
    if p["status"] in DEAD_STATUSES:
        return True, f"dead (status: {p['status'] or 'none'})"

    # CDN — only remove if pure CDN with nothing interesting
    for cdn in CDN_PROVIDERS:
        if cdn in p["line_lower"]:
            # Keep if there's tech detected or a meaningful title
            has_tech = any(len(b) > 3 and b.lower() not in [p["status"]] for b in p["brackets"][1:])
            has_title = p["title"] and len(p["title"]) > 3
            if not has_tech and not has_title:
                return True, f"CDN ({cdn}) with no tech/title"

    # Empty 200 — 200 but nothing detected
    if p["status"] == "200" and not p["title"] and p["port"] in ["80", "443"]:
        has_tech = any(len(b) > 3 for b in p["brackets"][1:])
        if not has_tech:
            return True, "200 but no title, no tech, standard port"

    # 308 redirect with tiny content — customer portal redirect pattern
    if p["status"] == "308" and "136" in p["brackets"]:
        return True, "308 redirect (likely customer portal redirect)"

    # Junk titles
    for junk in JUNK_TITLES:
        if junk in p["title"]:
            return True, f"junk title: {junk}"

    return False, ""

def main():
    if len(sys.argv) < 4:
        print("Usage: scope_reduce.py <live_hosts_rich.txt> <sieved_hosts.txt> <sieved_hosts_rich.txt>")
        sys.exit(1)

    input_file    = sys.argv[1]
    output_urls   = sys.argv[2]  # URLs only
    output_rich   = sys.argv[3]  # Full httpx lines
    removed_file  = output_urls.replace(".txt", "_removed.txt")

    with open(input_file) as f:
        raw_lines = [l for l in f if l.strip()]

    total = len(raw_lines)
    kept_urls  = []
    kept_rich  = []
    removed    = []

    # ── Pass 1: parse and apply junk rules ──
    parsed = []
    for line in raw_lines:
        p = parse_line(line)
        junk, reason = is_junk(p)
        if junk:
            url = p["url"] if p else line.strip().split()[0]
            removed.append((url, reason))
        else:
            parsed.append(p)

    # ── Pass 2: collapse generated subdomain patterns ──
    # Group by base pattern, keep only the first representative
    pattern_seen = {}       # base_pattern → first url seen
    pattern_count = defaultdict(int)
    collapsed = 0

    for p in parsed:
        base = get_base_pattern(p["hostname"])
        if base:
            pattern_count[base] += 1
            if base not in pattern_seen:
                # First one — keep it as representative
                pattern_seen[base] = p["url"]
                kept_urls.append(p["url"])
                kept_rich.append(p["line"])
            else:
                # Duplicate pattern — collapse
                removed.append((p["url"], f"generated subdomain (pattern: *.{base})"))
                collapsed += 1
        else:
            kept_urls.append(p["url"])
            kept_rich.append(p["line"])

    # ── Write outputs ──
    with open(output_urls, "w") as f:
        f.write("\n".join(kept_urls) + "\n")

    with open(output_rich, "w") as f:
        f.write("\n".join(kept_rich) + "\n")

    with open(removed_file, "w") as f:
        for url, reason in removed:
            f.write(f"[REMOVED] {url} — {reason}\n")

    # ── Stats ──
    kept = len(kept_urls)
    rm   = len(removed)
    pct  = int(100 * rm / total) if total > 0 else 0

    print(f"[✓] Input    : {total} hosts")
    print(f"[✓] Kept     : {kept} hosts → {output_urls}")
    print(f"[✓] Removed  : {rm} hosts ({pct}%) → {removed_file}")
    print(f"[✓] Collapsed: {collapsed} generated subdomain duplicates")

    if pattern_count:
        print(f"\n[*] Top generated subdomain patterns collapsed:")
        for base, count in sorted(pattern_count.items(), key=lambda x: -x[1])[:10]:
            kept_rep = pattern_seen.get(base, "?")
            print(f"    *.{base} — {count} hosts → kept 1 representative")

if __name__ == "__main__":
    main()
