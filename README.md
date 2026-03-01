# bug-bounty-recon

An automated bug bounty recon pipeline with AI-powered host triage, findings analysis, and HackerOne report drafting.

---

## Files

| File | Role |
|------|------|
| `recon.sh` | Main orchestrator — runs all 15 phases end to end |
| `scope_reduce.py` | Prunes junk/duplicate hosts before expensive scanning |
| `claude_triage.py` | AI triage for hosts, findings, and report drafting |
| `notify.py` | Sends Telegram notifications at each phase |

---

## Setup

### Environment Variables

```bash
# Required for Telegram notifications (notify.py)
export TELEGRAM_BOT_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"

# Required for AI triage (claude_triage.py)
export CLAUDE_API_KEY="sk-ant-..."

# Optional — for authenticated scanning
export RECON_COOKIE="session=abc123; csrf=xyz"
export RECON_TOKEN="Bearer eyJhbGci..."
```

Add these to `~/.bashrc` or `~/.zshrc` to persist across sessions.

### Tool Dependencies

The pipeline auto-installs Go tools on first run if `go` is available. Python tools and system tools must be installed manually.

**Go tools (auto-installed):** `subfinder`, `httpx`, `naabu`, `nuclei`, `gau`, `waybackurls`, `assetfinder`, `ffuf`, `dalfox`, `anew`

**System tools:** `sqlmap`, `nikto`, `whatweb`, `amass`, `curl`, `jq`, `python3`, `dig`

**Wordlists:**
```bash
sudo snap install seclists
```

---

## Usage

```bash
# Unauthenticated
./recon.sh example.com

# Authenticated (extract cookies from browser DevTools)
export RECON_COOKIE="session=abc; csrf=xyz"
./recon.sh admin.example.com

# Run multiple targets in parallel (tmux)
tmux new-session -s target1
./recon.sh example.com

tmux new-session -s target2
./recon.sh api.example.com
```

---

## Pipeline Flow

```
recon.sh
  │
  ├─ Phase 0   Tool Check          check + auto-install missing tools
  ├─ Phase 1   Subdomain Enum      subfinder + assetfinder + amass
  ├─ Phase 2   Live Host Probe     httpx (with auth headers if set)
  │
  ├─ Phase 2.5 Scope Sieve ──────► scope_reduce.py
  │                                  removes CDN-only hosts, dead hosts,
  │                                  junk titles, collapses generated
  │                                  subdomain patterns (hex IDs, UUIDs)
  │
  ├─ Phase 2.6 Host Triage ──────► claude_triage.py hosts
  │                                  pre-filters hosts by interesting signals
  │                                  sends batches to Claude Haiku for A/B/C/D
  │                                  Tier A = hack immediately
  │                                  Tier B = worth scanning
  │                                  Tier C/D = skip
  │
  ├─ Phase 3   Port Scan           naabu top-1000 ports on all subdomains
  ├─ Phase 4   Tech Fingerprint    whatweb on Tier A+B hosts
  ├─ Phase 5   URL Collection      gau + waybackurls + auth crawl (if authed)
  ├─ Phase 6   JS Analysis         extract endpoints + secrets from JS files
  ├─ Phase 7   Dir Fuzzing         ffuf on Tier A+B hosts
  │                                  auth mode: API-focused wordlist
  │                                  unauthed: raft-medium-directories
  ├─ Phase 8   XSS                 dalfox on parameterised URLs
  ├─ Phase 9   Nuclei              CVEs + exposures + misconfigs + takeovers
  │                                  auth mode: adds token-spray templates
  ├─ Phase 10  Nikto               deep scan on top 10 Tier A hosts only
  ├─ Phase 11  CORS                checks all live hosts for reflected origins
  ├─ Phase 12  Takeover            CNAME + fingerprint check on all subdomains
  ├─ Phase 13  Sensitive Files     /.env, /.git, /actuator, /swagger, etc.
  │
  ├─ Phase 14  Findings Triage ──► claude_triage.py findings
  │                                  deduplicates nuclei/xss/cors results
  │                                  removes false positives
  │                                  assigns severity + exploitability notes
  │
  └─ Phase 15  Report Drafting ──► claude_triage.py report
                                   drafts HackerOne-ready reports per finding
                                   saved to reports/drafts/*.txt
```

Each phase sends a Telegram notification via `notify.py` as it completes.

---

## Output Directory Structure

```
recon_example.com_20260301_120000/
├── subdomains/
│   └── all_subs.txt                 all discovered subdomains
├── hosts/
│   ├── live_hosts.txt               httpx-confirmed live hosts
│   ├── live_hosts_rich.txt          httpx output with title/tech/status
│   ├── sieved_hosts.txt             after scope_reduce.py
│   ├── sieved_hosts_rich.txt        rich version of above
│   ├── sieved_hosts_removed.txt     what scope_reduce.py pruned and why
│   ├── interesting_hosts.txt        Tier A + B (Claude triage output)
│   ├── priority_hosts.txt           Tier A only
│   ├── tier_a_hosts.txt
│   ├── tier_b_hosts.txt
│   ├── claude_triage_results.json   full triage with reasons
│   ├── open_ports.txt               naabu results
│   ├── nonstandard_ports.txt        non-80/443 open ports
│   └── tech_stack.txt               whatweb fingerprints
├── urls/
│   ├── all_urls.txt                 gau + waybackurls combined
│   ├── urls_with_params.txt         URLs with query parameters
│   ├── interesting_urls.txt         .php/.env/.sql etc.
│   ├── interesting_params.txt       params on interesting hosts only
│   └── ffuf_results/                per-host ffuf JSON output
├── js/
│   ├── js_files.txt                 discovered JS file URLs
│   ├── potential_secrets.txt        API keys, tokens found in JS
│   └── endpoints_from_js.txt        API paths extracted from JS
├── vulns/
│   ├── nuclei_results.txt
│   ├── xss_results.txt
│   ├── cors_results.txt
│   ├── takeover_candidates.txt
│   ├── sensitive_files.txt
│   └── manual_findings.txt          add your manual findings here for Claude to triage
├── auth/
│   ├── auth_state.txt               records whether scan ran authenticated
│   ├── authed_probe.txt             httpx result of base target with auth
│   └── authenticated_urls.txt       URLs discovered via authenticated crawl
└── reports/
    ├── summary.txt                  full scan summary with all counts
    ├── findings_summary.txt         Claude's deduplicated findings analysis
    └── drafts/
        └── finding_*.txt            HackerOne-ready report drafts
```

---

## File Details

### `scope_reduce.py`

Runs between httpx and Claude triage to cut noise before spending tokens.

**What it removes:**
- Dead hosts (status 000 or empty)
- Pure CDN hosts with no detected tech or title (Cloudfront, Fastly, Akamai, etc.)
- Empty 200s — responded but no title and no tech fingerprint
- Junk titles — parking pages, default server pages, "coming soon"
- 308 redirects with tiny bodies (customer portal redirect pattern)

**What it collapses:**
- Generated subdomain patterns — hex IDs, UUIDs, long random strings — keeps one representative, drops the rest. For example, 500 customer-specific subdomains like `a3f9b1c2.gateways.example.com` collapse to 1.

Outputs both a plain URL file and a rich httpx file so downstream tools get the context they need.

---

### `claude_triage.py`

Three independent modes, called from `recon.sh` at phases 2.6, 14, and 15.

**Mode 1: `hosts`** — Claude Haiku (cheap, fast)

Pre-filters the sieved rich host file by regex (login, dashboard, admin, api, jenkins, swagger, non-standard ports, 401/403/500 status codes, etc.) then sends matching hosts to Claude in batches of 20.

Tiers:
- **A** — hack immediately: exposed admin panels, dev/staging envs, Swagger UI, Spring Actuator, Jenkins, Grafana, directory listings, non-standard port services
- **B** — worth scanning: real apps with login flows, APIs, portals
- **C** — skip: marketing sites, blogs, docs
- **D** — skip: parking pages, empty responses

**Mode 2: `findings`** — Claude Sonnet (quality analysis)

Reads all vuln output files and runs a single triage pass. Deduplicates (same nuclei template across 50 subdomains = 1 finding), removes false positives, assesses real exploitability, assigns severity, and flags what needs manual verification. Output saved to `reports/findings_summary.txt`.

**Mode 3: `report`** — Claude Sonnet

For each confirmed finding in the summary, drafts a HackerOne-ready report with title, severity, steps to reproduce, impact statement, and fix recommendation. Saved as individual files in `reports/drafts/`.

You can also add your own manually found bugs to `vulns/manual_findings.txt` before running phase 15, and Claude will draft reports for those too.

---

### `notify.py`

Sends Telegram messages at scan start, after each phase, and at scan completion.

Credentials are read from environment variables `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` — never hardcoded.

The final message includes the full host funnel, all finding counts, non-standard port list, and previews of each finding category (nuclei, XSS, CORS, takeovers, sensitive files, secrets).

---

## Authentication Mode

When `RECON_COOKIE` or `RECON_TOKEN` is set, every tool that supports headers passes them through automatically — httpx, ffuf, nuclei, dalfox, whatweb, nikto, and all curl-based checks. This lets the pipeline see auth-gated pages, internal APIs, and session-scoped vulnerabilities that unauthenticated scans miss.

In auth mode, ffuf switches from the standard directory wordlist to an API-focused wordlist (`/api/v1`, `/users`, `/orgs`, `/tokens`, `/audit`, `/billing`, etc.) and nuclei adds token-spray templates.

---

## AI Cost Reference (Anthropic Tier 1)

| Usage | Model | Approximate cost |
|-------|-------|-----------------|
| Host triage (766 hosts) | Haiku | ~$0.05 |
| Findings triage | Sonnet | ~$0.10 |
| Report drafting (5 findings) | Sonnet | ~$0.15 |
| **Full scan** | Both | **~$0.30** |

---

## Legal

Only run against targets you have explicit written permission to test, or programs where the target is in scope on a bug bounty platform (HackerOne, Bugcrowd, etc.). Never test stores or accounts you don't own.
