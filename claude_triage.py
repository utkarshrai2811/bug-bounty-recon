#!/usr/bin/env python3
# ============================================================
#  claude_triage.py — Claude API layers
#
#  Fixes vs previous version:
#  - Pre-filters hosts before sending to Claude:
#    only sends hosts that have SOMETHING interesting in them
#    (status 401/403, non-standard port, known tech keywords)
#    so we don't waste 360 API calls on customer portal redirects
#  - Retry logic with exponential backoff on rate limit
#  - Falls back gracefully per-batch, never crashes script
#  - Better JSON parsing — handles partial responses
#
#  Modes:
#    hosts    → tier sieved hosts into A/B/C/D
#    findings → triage raw vuln output
#    report   → draft H1 report for high/critical findings
# ============================================================

import sys, os, json, time, re, urllib.request, urllib.parse
from datetime import datetime
from collections import defaultdict

CLAUDE_API_KEY = os.environ.get("CLAUDE_API_KEY", "YOUR_API_KEY_HERE")
CLAUDE_MODEL_FAST  = "claude-haiku-4-5-20251001"  # host triage — cheap
CLAUDE_MODEL_SMART = "claude-sonnet-4-6"           # findings + reports — quality
BATCH_SIZE     = 20    # tier 1: 8K output TPM limit, keep responses small
RPM_LIMIT      = 50
SLEEP_BETWEEN  = 60 / RPM_LIMIT  # 12s between calls

# Pre-filter: only send hosts to Claude that have at least one of these
# signals. Everything else is auto-assigned Tier C/D.
INTERESTING_SIGNALS = [
    # Status codes worth investigating
    r'\[401\]', r'\[403\]', r'\[500\]',
    # Non-standard ports
    r':\d{4,5}(?:/|$)',
    # Tech keywords Claude should see
    r'jenkins', r'jira', r'confluence', r'gitlab', r'grafana',
    r'kibana', r'jupyter', r'swagger', r'wordpress', r'phpmyadmin',
    r'adminer', r'actuator', r'elastic', r'prometheus', r'django',
    r'spring', r'rails', r'laravel', r'strapi', r'hasura',
    # Title signals
    r'login', r'dashboard', r'admin', r'portal', r'console',
    r'manage', r'panel', r'index of', r'api',
]
INTERESTING_RE = re.compile('|'.join(INTERESTING_SIGNALS), re.IGNORECASE)

# ─────────────────────────────────────────────
#  API CALL
# ─────────────────────────────────────────────
def claude_call(system_prompt, user_prompt, max_tokens=2000, retries=3, model=None):
    url  = "https://api.anthropic.com/v1/messages"
    body = json.dumps({
        "model":      model or CLAUDE_MODEL_SMART,
        "max_tokens": max_tokens,
        "system":     system_prompt,
        "messages":   [{"role": "user", "content": user_prompt}]
    }).encode()
    headers = {
        "x-api-key":         CLAUDE_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=45) as r:
                result = json.loads(r.read())
                return result["content"][0]["text"]
        except urllib.error.HTTPError as e:
            err_body = e.read().decode()
            if e.code == 429:
                wait = 60 * (attempt + 1)
                print(f"[!] Rate limited — waiting {wait}s (attempt {attempt+1}/{retries})", file=sys.stderr)
                time.sleep(wait)
            else:
                print(f"[!] API error {e.code}: {err_body[:200]}", file=sys.stderr)
                if attempt < retries - 1:
                    time.sleep(15)
        except Exception as e:
            print(f"[!] Request failed: {e}", file=sys.stderr)
            if attempt < retries - 1:
                time.sleep(10)
    return None

def api_call(system, user, max_tokens=2000, model=None):
    result = claude_call(system, user, max_tokens, model=model)
    time.sleep(SLEEP_BETWEEN)
    return result

def parse_json_response(text):
    """Try multiple strategies to extract JSON from Claude's response."""
    if not text:
        print("[DEBUG] parse_json_response: empty response", file=sys.stderr)
        return None

    # Strategy 1: direct parse
    try:
        return json.loads(text)
    except Exception:
        pass

    # Strategy 2: strip markdown fences
    clean = re.sub(r'```(?:json)?\s*|```', '', text).strip()
    try:
        return json.loads(clean)
    except Exception:
        pass

    # Strategy 3: bracket-match outermost JSON array
    try:
        start = text.index('[')
        depth = 0
        for idx, ch in enumerate(text[start:], start):
            if ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
                if depth == 0:
                    return json.loads(text[start:idx+1])
    except (ValueError, json.JSONDecodeError):
        pass

    # Strategy 4: bracket-match outermost JSON object
    try:
        start = text.index('{')
        depth = 0
        for idx, ch in enumerate(text[start:], start):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return json.loads(text[start:idx+1])
    except (ValueError, json.JSONDecodeError):
        pass

    # Debug: log what Claude actually returned so we can diagnose
    print(f"[DEBUG] parse failed. Response preview: {repr(text[:400])}", file=sys.stderr)
    return None

# ─────────────────────────────────────────────
#  LAYER 1 — HOST TRIAGE
# ─────────────────────────────────────────────
HOST_SYSTEM = """You are an expert bug bounty hunter. Classify hosts STRICTLY. Tier A should be rare (5-10% of hosts max).

Tier A — ONLY these qualify:
- Exposed admin/management panels (Jenkins, Grafana, Kibana, Jupyter, phpMyAdmin, Adminer)
- Dev/staging environments with real functionality (dev., staging., internal., corp.)
- Swagger UI / API docs with live "Try it" endpoints
- Spring Actuator /env /dump /heapdump exposed
- Directory listings with sensitive files
- Non-standard ports (not 80/443) running actual services
- GitLab/Gitea self-hosted instances
- Anything titled "index of" or showing server internals

Tier B — Real apps worth scanning:
- Login portals, dashboards, SaaS apps
- API endpoints returning real data
- Partner/merchant portals
- Anything interactive beyond marketing

Tier C — Skip:
- Marketing sites, blogs, landing pages, docs
- CDN/static asset hosts
- Subdomains that just redirect to main site

Tier D — Skip:
- Parking pages, empty responses, pure 301/302 with no content
- Cloudflare/WAF block pages with no backend

Be STRICT with Tier A. When in doubt, use B or C.
Respond ONLY with a valid JSON array. No markdown, no explanation.
Each element: {"url": "https://...", "tier": "A|B|C|D", "reason": "one line"}"""

def triage_hosts(rich_file, outdir):
    with open(rich_file) as f:
        all_lines = [l.strip() for l in f if l.strip()]

    total = len(all_lines)

    # ── Pre-filter: split into interesting (send to Claude) and boring (auto C) ──
    interesting_lines = []
    boring_lines      = []
    for line in all_lines:
        if INTERESTING_RE.search(line):
            interesting_lines.append(line)
        else:
            boring_lines.append(line)

    print(f"[*] {total} sieved hosts → {len(interesting_lines)} interesting (sending to Claude), {len(boring_lines)} auto-C")

    batches = [interesting_lines[i:i+BATCH_SIZE] for i in range(0, len(interesting_lines), BATCH_SIZE)]
    estimated = len(batches) * SLEEP_BETWEEN / 60
    print(f"[*] {len(batches)} batches → ~{estimated:.1f} min at free tier rate limit")

    tier_a, tier_b, tier_c, tier_d = [], [], [], []
    all_results = []
    errors = 0

    # Boring lines → auto Tier C (no API call needed)
    for line in boring_lines:
        url = line.split()[0]
        tier_c.append(url)
        all_results.append({"url": url, "tier": "C", "reason": "auto: no interesting signals"})

    # Interesting lines → Claude
    for i, batch in enumerate(batches):
        print(f"[*] Batch {i+1}/{len(batches)} ({len(batch)} hosts)...")
        batch_text = "\n".join(batch)
        response = api_call(HOST_SYSTEM, f"Classify:\n\n{batch_text}", model=CLAUDE_MODEL_FAST)

        data = parse_json_response(response)
        if not data or not isinstance(data, list):
            print(f"[!] Batch {i+1} parse failed — fallback to Tier B")
            for line in batch:
                url = line.split()[0]
                tier_b.append(url)
                all_results.append({"url": url, "tier": "B", "reason": "API/parse failure — manual review"})
            errors += 1
            continue

        for item in data:
            url  = item.get("url", "").strip()
            tier = item.get("tier", "C").upper()
            reason = item.get("reason", "")
            all_results.append({"url": url, "tier": tier, "reason": reason})
            if   tier == "A": tier_a.append(url)
            elif tier == "B": tier_b.append(url)
            elif tier == "C": tier_c.append(url)
            else:             tier_d.append(url)

        done = min((i+1) * BATCH_SIZE, len(interesting_lines))
        print(f"    {done}/{len(interesting_lines)} | A:{len(tier_a)} B:{len(tier_b)} C:{len(tier_c)} D:{len(tier_d)}")

    # Write outputs
    def wl(path, items):
        with open(path, "w") as f:
            f.write("\n".join(i for i in items if i) + "\n")

    interesting = tier_a + tier_b
    wl(f"{outdir}/hosts/tier_a_hosts.txt",      tier_a)
    wl(f"{outdir}/hosts/tier_b_hosts.txt",      tier_b)
    wl(f"{outdir}/hosts/interesting_hosts.txt", interesting)
    wl(f"{outdir}/hosts/priority_hosts.txt",    tier_a)

    with open(f"{outdir}/hosts/claude_triage_results.json", "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\n[✓] Triage complete — Tier A:{len(tier_a)} B:{len(tier_b)} C:{len(tier_c)} D:{len(tier_d)}")
    print(f"    Interesting (A+B): {len(interesting)} | API errors: {errors} batches")
    return interesting

# ─────────────────────────────────────────────
#  LAYER 2 — FINDINGS TRIAGE
# ─────────────────────────────────────────────
FINDINGS_SYSTEM = """You are an expert bug bounty hunter triaging automated scan results.

Tasks:
1. Remove false positives (nuclei is noisy)
2. Deduplicate (same bug on N subdomains = 1 finding, note affected count)
3. Assess real exploitability
4. Estimate severity: Critical / High / Medium / Low / Info
5. Flag what needs immediate manual verification

Respond ONLY with valid JSON. No markdown, no preamble.

{
  "summary": "2-3 sentence overall assessment",
  "total_unique_findings": 0,
  "findings": [
    {
      "id": 1,
      "title": "concise title",
      "severity": "Critical|High|Medium|Low|Info",
      "type": "XSS|SSRF|IDOR|Misconfig|InfoDisclosure|etc",
      "affected_count": 3,
      "affected_sample": ["url1", "url2"],
      "exploitable": true,
      "confidence": "High|Medium|Low",
      "false_positive_risk": "High|Medium|Low",
      "manual_verify": true,
      "notes": "key context for manual testing"
    }
  ],
  "immediate_action": ["specific things to manually check RIGHT NOW"]
}"""

def read_safe(path, max_lines=150):
    try:
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        truncated = len(lines) > max_lines
        return lines[:max_lines], len(lines), truncated
    except:
        return [], 0, False

def triage_findings(outdir):
    finding_files = {
        "nuclei":    f"{outdir}/vulns/nuclei_results.txt",
        "xss":       f"{outdir}/vulns/xss_results.txt",
        "cors":      f"{outdir}/vulns/cors_results.txt",
        "takeovers": f"{outdir}/vulns/takeover_candidates.txt",
        "sensitive": f"{outdir}/vulns/sensitive_files.txt",
        "secrets":   f"{outdir}/js/potential_secrets.txt",
        "nikto":     f"{outdir}/vulns/nikto_results.txt",
    }

    sections = []
    total_lines = 0
    for name, path in finding_files.items():
        lines, count, trunc = read_safe(path)
        if count > 0:
            total_lines += count
            note = f" (truncated — {count} total)" if trunc else f" ({count} total)"
            sections.append(f"=== {name.upper()}{note} ===\n" + "\n".join(lines))

    if not sections:
        print("[!] No findings to triage")
        return

    findings_text = "\n\n".join(sections)
    print(f"[*] Triaging {total_lines} findings with Claude...")
    response = api_call(FINDINGS_SYSTEM, f"Triage these findings:\n\n{findings_text}", max_tokens=3000, model=CLAUDE_MODEL_SMART)

    data = parse_json_response(response)
    if not data:
        print("[!] Triage parse failed — saving raw response")
        with open(f"{outdir}/reports/triage_raw.txt", "w") as f:
            f.write(response or "no response")
        return

    # Save JSON
    with open(f"{outdir}/reports/triaged_findings.json", "w") as f:
        json.dump(data, f, indent=2)

    # Human-readable summary
    sev_order = ["Critical", "High", "Medium", "Low", "Info"]
    findings  = sorted(data.get("findings", []),
                       key=lambda x: sev_order.index(x.get("severity", "Info"))
                       if x.get("severity") in sev_order else 99)

    summary_path = f"{outdir}/reports/findings_summary.txt"
    with open(summary_path, "w") as f:
        f.write("═══════════════════════════════════════════\n")
        f.write("  CLAUDE FINDINGS TRIAGE\n")
        f.write(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("═══════════════════════════════════════════\n\n")
        f.write(f"SUMMARY:\n{data.get('summary','N/A')}\n\n")
        f.write(f"UNIQUE FINDINGS: {len(findings)}\n\n")

        for finding in findings:
            sev = finding.get("severity", "?")
            f.write(f"[{sev}] {finding.get('title','?')}\n")
            f.write(f"  Type        : {finding.get('type','?')}\n")
            f.write(f"  Exploitable : {finding.get('exploitable','?')}\n")
            f.write(f"  Confidence  : {finding.get('confidence','?')}\n")
            f.write(f"  FP Risk     : {finding.get('false_positive_risk','?')}\n")
            f.write(f"  Verify NOW  : {'YES' if finding.get('manual_verify') else 'No'}\n")
            f.write(f"  Affected    : {finding.get('affected_count','?')} hosts\n")
            sample = finding.get('affected_sample', [])
            if sample:
                f.write(f"  Sample      : {sample[0]}\n")
            f.write(f"  Notes       : {finding.get('notes','')}\n\n")

        immediate = data.get("immediate_action", [])
        if immediate:
            f.write("IMMEDIATE ACTIONS:\n")
            for item in immediate:
                f.write(f"  → {item}\n")

    print(f"[✓] Triage: {len(findings)} unique findings → {summary_path}")
    immediate = data.get("immediate_action", [])
    if immediate:
        print("\n[!] IMMEDIATE:")
        for item in immediate:
            print(f"    → {item}")

# ─────────────────────────────────────────────
#  LAYER 3 — REPORT DRAFTING
# ─────────────────────────────────────────────
REPORT_SYSTEM = """You are an expert bug bounty hunter writing a HackerOne/Bugcrowd report. Be precise, technical, and maximize impact clarity.

Use this exact format:

TITLE: [VulnType] in [Component/Endpoint] allows [Impact]

SEVERITY: Critical|High|Medium|Low

SUMMARY:
2-3 sentences. Plain English. What can an attacker do? Why does it matter?

VULNERABILITY DETAILS:
Root cause. Be technical.

STEPS TO REPRODUCE:
1. Numbered steps
2. Exact URLs, parameters, payloads
3. What to observe at each step

PROOF OF CONCEPT:
Exact curl command or payload.

IMPACT:
Concrete business impact. Data exposed? Auth bypass? Account takeover?

CVSS: [score] [vector]

REMEDIATION:
Specific fix.

REFERENCES:
CVE/CWE if applicable."""

def draft_all_reports(outdir, target):
    triage_path = f"{outdir}/reports/triaged_findings.json"
    if not os.path.exists(triage_path):
        print("[!] No triaged_findings.json — run findings mode first")
        return

    with open(triage_path) as f:
        data = json.load(f)

    findings = data.get("findings", [])
    priority = [f for f in findings
                if f.get("severity") in ["Critical", "High"]
                and f.get("exploitable") == True
                and f.get("false_positive_risk") != "High"]
    if not priority:
        priority = [f for f in findings if f.get("severity") in ["Critical", "High"]]
    if not priority:
        print("[!] No critical/high findings to draft reports for")
        return

    reports_dir = f"{outdir}/reports/drafts"
    os.makedirs(reports_dir, exist_ok=True)
    print(f"[*] Drafting {len(priority)} reports...")

    for i, finding in enumerate(priority):
        title = finding.get("title", f"finding_{i+1}")
        print(f"[*] {i+1}/{len(priority)}: {title}")
        prompt = f"Target: {target}\n\nFinding:\n{json.dumps(finding, indent=2)}\n\nWrite a complete H1 report."
        response = api_call(REPORT_SYSTEM, prompt, max_tokens=2500, model=CLAUDE_MODEL_SMART)
        if response:
            safe = re.sub(r'[^a-zA-Z0-9_-]', '_', title)[:50]
            path = f"{reports_dir}/{i+1:02d}_{safe}.txt"
            with open(path, "w") as f:
                f.write(response)
            print(f"    [✓] → {path}")

    print(f"\n[✓] Reports in {reports_dir}/")

# ─────────────────────────────────────────────
#  ENTRYPOINT
# ─────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  claude_triage.py hosts    <sieved_rich.txt> <outdir>")
        print("  claude_triage.py findings <outdir>")
        print("  claude_triage.py report   <outdir> <target>")
        sys.exit(1)

    if CLAUDE_API_KEY == "YOUR_API_KEY_HERE":
        print("[!] Set CLAUDE_API_KEY environment variable")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "hosts":
        triage_hosts(sys.argv[2], sys.argv[3])
    elif mode == "findings":
        triage_findings(sys.argv[2])
    elif mode == "report":
        draft_all_reports(sys.argv[2], sys.argv[3])
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)

if __name__ == "__main__":
    main()
