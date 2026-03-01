#!/usr/bin/env python3
# ============================================================
#  notify.py — Telegram notifier for recon.sh
#
#  Fixes vs previous version:
#  - All output suppressed (no [✓] leaking to terminal)
#  - Details arg no longer breaks on spaces — uses sys.argv properly
#  - Enriched final message: includes nonstandard ports inline,
#    top findings preview, sieve stats, timing
#  - Phase messages show elapsed time since scan start
#  - Vuln previews sent as separate follow-up messages
#  - Telegram message length guard (4096 char limit)
#
#  Usage:
#    python3 notify.py start   <target> <outdir> _ _ _
#    python3 notify.py phase   <target> <outdir> <num> <name> <details>
#    python3 notify.py final   <target> <outdir> _ _ _
# ============================================================

import sys, os, json, urllib.request, urllib.parse
from datetime import datetime

BOT_TOKEN = ""
CHAT_ID   = ""
MAX_LEN   = 4000  # Telegram limit is 4096, leave headroom

PHASE_EMOJI = {
    "0": "🔧", "1": "🌐", "2": "🖥️",  "2.5": "🔽",
    "2.6": "🤖", "3": "🔌", "4": "🔍",  "5": "🕸️",
    "6": "📜",  "7": "📂", "8": "🎯",  "9": "☢️",
    "10": "🔎", "11": "🔗", "12": "🏴", "13": "📁",
    "14": "🧠", "15": "📝",
}

def send(text):
    """Send a Telegram message. Truncates if over limit. Silent on failure."""
    if len(text) > MAX_LEN:
        text = text[:MAX_LEN] + "\n... (truncated)"
    url  = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id":    CHAT_ID,
        "text":       text,
        "parse_mode": "Markdown",
    }).encode()
    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            pass  # silent — no stdout leak
    except:
        pass  # never crash the script

def cnt(path):
    try:
        with open(path) as f:
            return sum(1 for l in f if l.strip())
    except:
        return 0

def preview(path, n=6):
    try:
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        if not lines:
            return None
        out = "\n".join(lines[:n])
        if len(lines) > n:
            out += f"\n  ... +{len(lines)-n} more"
        return out
    except:
        return None

def scan_age(outdir):
    """Estimate scan duration from output dir timestamp."""
    try:
        # outdir format: recon_target_20260228_184832
        parts = outdir.rsplit("_", 2)
        if len(parts) >= 2:
            dt = datetime.strptime(f"{parts[-2]}_{parts[-1]}", "%Y%m%d_%H%M%S")
            delta = datetime.now() - dt
            mins = int(delta.total_seconds() // 60)
            secs = int(delta.total_seconds() % 60)
            return f"{mins}m {secs}s"
    except:
        pass
    return "?"

def now():
    return datetime.now().strftime("%H:%M:%S")

# ─────────────────────────────────────────────
def notify_start(target, outdir):
    send(
        f"🚀 *Recon Started*\n"
        f"🎯 Target: `{target}`\n"
        f"🕐 Time: {now()}\n"
        f"📁 Output: `{outdir}`"
    )

def notify_phase(target, outdir, phase_num, phase_name, details):
    emoji = PHASE_EMOJI.get(str(phase_num), "📌")
    age   = scan_age(outdir)
    detail_str = f"\n{details}" if details and details not in ["-", "_", ""] else ""
    send(
        f"{emoji} *Phase {phase_num}* — {phase_name}\n"
        f"🎯 `{target}` | 🕐 {now()} | ⏱ +{age}"
        f"{detail_str}"
    )

def notify_final(target, outdir):
    age = scan_age(outdir)

    # ── Counts ──
    c = {
        "subs":      cnt(f"{outdir}/subdomains/all_subs.txt"),
        "live":      cnt(f"{outdir}/hosts/live_hosts.txt"),
        "sieved":    cnt(f"{outdir}/hosts/sieved_hosts.txt"),
        "tier_a":    cnt(f"{outdir}/hosts/tier_a_hosts.txt"),
        "tier_ab":   cnt(f"{outdir}/hosts/interesting_hosts.txt"),
        "ports":     cnt(f"{outdir}/hosts/open_ports.txt"),
        "ns_ports":  cnt(f"{outdir}/hosts/nonstandard_ports.txt"),
        "urls":      cnt(f"{outdir}/urls/all_urls.txt"),
        "params":    cnt(f"{outdir}/urls/urls_with_params.txt"),
        "js":        cnt(f"{outdir}/js/js_files.txt"),
        "nuclei":    cnt(f"{outdir}/vulns/nuclei_results.txt"),
        "xss":       cnt(f"{outdir}/vulns/xss_results.txt"),
        "cors":      cnt(f"{outdir}/vulns/cors_results.txt"),
        "takeover":  cnt(f"{outdir}/vulns/takeover_candidates.txt"),
        "sensitive": cnt(f"{outdir}/vulns/sensitive_files.txt"),
        "secrets":   cnt(f"{outdir}/js/potential_secrets.txt"),
        "reports":   cnt(f"{outdir}/reports/findings_summary.txt"),
    }

    vuln_total = sum(c[k] for k in ["nuclei","xss","cors","takeover","sensitive","secrets"])
    status = "🚨 *FINDINGS DETECTED*" if vuln_total > 0 else "✅ *No findings*"

    # ── Summary message ──
    msg = (
        f"🏁 *Recon Complete* — `{target}`\n"
        f"⏱ Runtime: {age} | 🕐 {now()}\n\n"
        f"{status}\n\n"
        f"*🔽 Host Funnel*\n"
        f"  🌐 Subdomains    : `{c['subs']}`\n"
        f"  🖥️  Live hosts    : `{c['live']}`\n"
        f"  🔽 After sieve   : `{c['sieved']}`\n"
        f"  🤖 Tier A+B      : `{c['tier_ab']}`  _(Tier A: {c['tier_a']})_\n\n"
        f"*🔌 Ports*\n"
        f"  Open: `{c['ports']}` | Non-standard: `{c['ns_ports']}`\n\n"
        f"*🕸️  URLs*\n"
        f"  Total: `{c['urls']}` | Params: `{c['params']}` | JS: `{c['js']}`\n\n"
        f"*🔥 Findings*\n"
        f"  ☢️  Nuclei    : `{c['nuclei']}`\n"
        f"  🎯 XSS       : `{c['xss']}`\n"
        f"  🔗 CORS      : `{c['cors']}`\n"
        f"  🏴 Takeovers : `{c['takeover']}`\n"
        f"  📁 Sensitive : `{c['sensitive']}`\n"
        f"  🔑 Secrets   : `{c['secrets']}`"
    )
    send(msg)

    # ── Non-standard ports (inline — always useful) ──
    ns_preview = preview(f"{outdir}/hosts/nonstandard_ports.txt", n=20)
    if ns_preview:
        send(f"🔌 *Non-Standard Ports* (`{target}`)\n```\n{ns_preview}\n```")

    # ── Claude findings summary (if available) ──
    findings_summary = preview(f"{outdir}/reports/findings_summary.txt", n=30)
    if findings_summary:
        send(f"🧠 *Claude Triage Summary* (`{target}`)\n```\n{findings_summary}\n```")

    # ── Per-vuln-type previews for anything with hits ──
    vuln_files = [
        ("☢️",  "Nuclei",    f"{outdir}/vulns/nuclei_results.txt",      8),
        ("🎯", "XSS",       f"{outdir}/vulns/xss_results.txt",          8),
        ("🔗", "CORS",      f"{outdir}/vulns/cors_results.txt",         8),
        ("🏴", "Takeovers", f"{outdir}/vulns/takeover_candidates.txt",  8),
        ("📁", "Sensitive", f"{outdir}/vulns/sensitive_files.txt",      10),
        ("🔑", "Secrets",   f"{outdir}/js/potential_secrets.txt",       6),
    ]
    for emoji, label, path, n in vuln_files:
        p = preview(path, n)
        if p:
            send(f"{emoji} *{label}* (`{target}`)\n```\n{p}\n```")

# ─────────────────────────────────────────────
def main():
    # Args: mode target outdir phase_num phase_name details
    # Always 6 args from recon.sh (unused ones passed as _)
    mode     = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    target   = sys.argv[2] if len(sys.argv) > 2 else "unknown"
    outdir   = sys.argv[3] if len(sys.argv) > 3 else ""
    phase_num  = sys.argv[4] if len(sys.argv) > 4 else ""
    phase_name = sys.argv[5] if len(sys.argv) > 5 else ""
    details    = sys.argv[6] if len(sys.argv) > 6 else ""

    if mode == "start":
        notify_start(target, outdir)
    elif mode == "phase":
        notify_phase(target, outdir, phase_num, phase_name, details)
    elif mode == "final":
        notify_final(target, outdir)

if __name__ == "__main__":
    main()
