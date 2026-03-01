#!/usr/bin/env bash
# ============================================================
#  recon.sh - Bug Bounty Recon Pipeline
#  Usage: ./recon.sh <domain>
#  Requirements: CLAUDE_API_KEY in environment (optional)
# ============================================================
# NO set -e — we handle errors per phase so one tool failure
# never kills the whole run. set -euo pipefail was the reason
# the script crashed at Phase 4 last time.
set -uo pipefail

# ─── Colors & helpers ────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[x]${NC} $*"; }
banner()  {
  echo -e "\n${BOLD}${CYAN}=====================================${NC}"
  echo -e "${BOLD}${CYAN}  $*${NC}"
  echo -e "${BOLD}${CYAN}=====================================${NC}\n"
}

# Safe line count — never fails
cnt() { wc -l < "$1" 2>/dev/null || echo 0; }

# Run command, eat errors, never crash script
safe() { "$@" 2>/dev/null || true; }

# Tool check
has_tool() { command -v "$1" &>/dev/null; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
START_TS=$(date +%s)
elapsed() { echo $(( $(date +%s) - START_TS ))s; }

# ─── Telegram (fully silent, background) ─────────────────────
tg() {
  # Args: mode target outdir phase_num phase_name details
  local mode="$1" target="${2:-}" outdir="${3:-}" \
        pnum="${4:-}" pname="${5:-}" details="${6:-}"
  if command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/notify.py" ]]; then
    python3 "$SCRIPT_DIR/notify.py" \
      "$mode" "$target" "$outdir" "$pnum" "$pname" "$details" \
      >/dev/null 2>&1 &
  fi
}

# ─── Input ───────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
  err "Usage: ./recon.sh <domain>"
  exit 1
fi

TARGET="${1,,}"
TARGET="${TARGET#http://}"; TARGET="${TARGET#https://}"; TARGET="${TARGET%%/*}"

CLAUDE_ENABLED=false
if [[ -n "${CLAUDE_API_KEY:-}" ]] && [[ "$CLAUDE_API_KEY" != "YOUR_API_KEY_HERE" ]]; then
  CLAUDE_ENABLED=true
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="recon_${TARGET}_${TIMESTAMP}"
LOG="$OUTDIR/recon.log"

mkdir -p "$OUTDIR"/{subdomains,hosts,urls,js,vulns,reports/drafts}

# Tee all output to log file
exec > >(tee -a "$LOG") 2>&1

echo -e "\n${BOLD}+=============================================+${NC}"
echo -e "${BOLD}|     Bug Bounty Recon Pipeline               |${NC}"
echo -e "${BOLD}|  Target : ${CYAN}${TARGET}${NC}${BOLD}                          |${NC}"
echo -e "${BOLD}|  Output : ${CYAN}${OUTDIR}${NC}${BOLD}              |${NC}"
echo -e "${BOLD}|  Claude : ${CYAN}$($CLAUDE_ENABLED && echo enabled || echo disabled)${NC}${BOLD}                              |${NC}"
echo -e "${BOLD}+=============================================+${NC}\n"

# ─────────────────────────────────────────────
#  PHASE 0 - TOOL CHECK
# ─────────────────────────────────────────────
banner "PHASE 0 - Tool Check"

MISSING_TOOLS=(); AVAILABLE_TOOLS=()

check_tool() {
  if command -v "$1" &>/dev/null; then AVAILABLE_TOOLS+=("$1"); return 0
  else warn "Missing: $1"; MISSING_TOOLS+=("$1"); return 1; fi
}

install_go_tool() {
  local name="$1" pkg="$2"
  if ! command -v "$name" &>/dev/null && command -v go &>/dev/null; then
    info "Installing $name..."
    go install "$pkg" 2>/dev/null && ok "Installed $name" || warn "Failed: $name"
  fi
}

GO_TOOLS=(
  "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "gau:github.com/lc/gau/v2/cmd/gau@latest"
  "waybackurls:github.com/tomnomnom/waybackurls@latest"
  "assetfinder:github.com/tomnomnom/assetfinder@latest"
  "ffuf:github.com/ffuf/ffuf/v2@latest"
  "dalfox:github.com/hahwul/dalfox/v2@latest"
  "anew:github.com/tomnomnom/anew@latest"
)
for entry in "${GO_TOOLS[@]}"; do
  name="${entry%%:*}"; pkg="${entry#*:}"
  install_go_tool "$name" "$pkg"
  check_tool "$name"
done

for t in sqlmap nikto whatweb amass curl jq python3 dig; do check_tool "$t" || true; done

if has_tool nuclei; then
  info "Updating nuclei templates..."
  safe nuclei -update-templates -silent
fi

info "Available: ${AVAILABLE_TOOLS[*]:-none}"
[[ ${#MISSING_TOOLS[@]} -gt 0 ]] && warn "Missing: ${MISSING_TOOLS[*]}"
$CLAUDE_ENABLED && info "Claude: enabled" || warn "Claude: disabled (set CLAUDE_API_KEY)"

tg phase "$TARGET" "$OUTDIR" "0" "Tool Check" "OK: ${AVAILABLE_TOOLS[*]:-none}"
tg start "$TARGET" "$OUTDIR"

# ─────────────────────────────────────────────
#  PHASE 1 - SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────
banner "PHASE 1 - Subdomain Enumeration"

SUBS_FILE="$OUTDIR/subdomains/all_subs.txt"
touch "$SUBS_FILE"

if has_tool subfinder; then
  info "subfinder..."
  c=$(subfinder -d "$TARGET" -silent -all 2>/dev/null | anew "$SUBS_FILE" | wc -l || echo 0)
  info "subfinder: $c new"
fi

if has_tool assetfinder; then
  info "assetfinder..."
  c=$(assetfinder --subs-only "$TARGET" 2>/dev/null \
    | grep -E "\.${TARGET}$|^${TARGET}$" | anew "$SUBS_FILE" | wc -l || echo 0)
  info "assetfinder: $c new"
fi

if has_tool amass; then
  info "amass passive (slow - grab a coffee)..."
  c=$(amass enum -passive -d "$TARGET" -silent 2>/dev/null | anew "$SUBS_FILE" | wc -l || echo 0)
  info "amass: $c new"
fi

TOTAL_SUBS=$(cnt "$SUBS_FILE")
ok "Total unique subdomains: $TOTAL_SUBS"
tg phase "$TARGET" "$OUTDIR" "1" "Subdomain Enum" "$TOTAL_SUBS unique subdomains"

# ─────────────────────────────────────────────
#  PHASE 2 - PROBE LIVE HOSTS
# ─────────────────────────────────────────────
banner "PHASE 2 - Probing Live Hosts"

LIVE_FILE="$OUTDIR/hosts/live_hosts.txt"
LIVE_RICH="$OUTDIR/hosts/live_hosts_rich.txt"

if has_tool httpx && [[ -s "$SUBS_FILE" ]]; then
  info "httpx probing $(cnt "$SUBS_FILE") subdomains..."
  safe httpx -l "$SUBS_FILE" -silent -o "$LIVE_FILE"
  safe httpx -l "$SUBS_FILE" \
    -title -tech-detect -status-code -content-length -web-server \
    -silent -o "$LIVE_RICH"
  LIVE_COUNT=$(cnt "$LIVE_FILE")
  ok "Live: $LIVE_COUNT hosts"
else
  echo "https://$TARGET" > "$LIVE_FILE"
  echo "http://$TARGET"  >> "$LIVE_FILE"
  echo "https://$TARGET [200] [] [] [title: $TARGET]" > "$LIVE_RICH"
  LIVE_COUNT=2
  warn "httpx missing - using base target only"
fi

tg phase "$TARGET" "$OUTDIR" "2" "Live Host Probe" "$LIVE_COUNT live from $TOTAL_SUBS subdomains"

# ─────────────────────────────────────────────
#  PHASE 2.5 - SCOPE SIEVE
#  Removes dead, CDN, and generated customer subdomains
# ─────────────────────────────────────────────
banner "PHASE 2.5 - Scope Sieve"

SIEVED_FILE="$OUTDIR/hosts/sieved_hosts.txt"
SIEVED_RICH="$OUTDIR/hosts/sieved_hosts_rich.txt"

if command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/scope_reduce.py" ]] && [[ -s "$LIVE_RICH" ]]; then
  info "Running sieve on $LIVE_COUNT hosts..."
  python3 "$SCRIPT_DIR/scope_reduce.py" "$LIVE_RICH" "$SIEVED_FILE" "$SIEVED_RICH"
  SIEVED_COUNT=$(cnt "$SIEVED_FILE")
  REMOVED=$(( LIVE_COUNT - SIEVED_COUNT ))
  ok "Sieve: $SIEVED_COUNT kept, $REMOVED removed"
  tg phase "$TARGET" "$OUTDIR" "2.5" "Scope Sieve" "$SIEVED_COUNT kept / $REMOVED removed from $LIVE_COUNT"
else
  warn "scope_reduce.py missing - using all live hosts"
  cp "$LIVE_FILE" "$SIEVED_FILE"
  cp "$LIVE_RICH" "$SIEVED_RICH"
  SIEVED_COUNT=$LIVE_COUNT
  tg phase "$TARGET" "$OUTDIR" "2.5" "Scope Sieve" "Skipped - using all $LIVE_COUNT"
fi

# ─────────────────────────────────────────────
#  PHASE 2.6 - CLAUDE HOST TRIAGE
# ─────────────────────────────────────────────
banner "PHASE 2.6 - Claude Host Triage"

INTERESTING_FILE="$OUTDIR/hosts/interesting_hosts.txt"
PRIORITY_FILE="$OUTDIR/hosts/priority_hosts.txt"
touch "$INTERESTING_FILE" "$PRIORITY_FILE"

if $CLAUDE_ENABLED && [[ -s "$SIEVED_RICH" ]]; then
  info "Claude triaging $(cnt "$SIEVED_FILE") sieved hosts..."
  python3 "$SCRIPT_DIR/claude_triage.py" hosts "$SIEVED_RICH" "$OUTDIR" || true
  INTERESTING_COUNT=$(cnt "$INTERESTING_FILE")
  PRIORITY_COUNT=$(cnt "$PRIORITY_FILE")
  ok "Tier A: $PRIORITY_COUNT | Tier B: $((INTERESTING_COUNT - PRIORITY_COUNT))"
  tg phase "$TARGET" "$OUTDIR" "2.6" "Claude Triage" "Tier A: $PRIORITY_COUNT | Tier B: $((INTERESTING_COUNT - PRIORITY_COUNT)) | Total: $INTERESTING_COUNT"
else
  warn "Claude disabled - interesting = sieved"
  cp "$SIEVED_FILE" "$INTERESTING_FILE"
  cp "$SIEVED_FILE" "$PRIORITY_FILE"
  INTERESTING_COUNT=$SIEVED_COUNT
  PRIORITY_COUNT=$SIEVED_COUNT
  tg phase "$TARGET" "$OUTDIR" "2.6" "Claude Triage" "Skipped - using $SIEVED_COUNT sieved"
fi

# ─────────────────────────────────────────────
#  PHASE 3 - PORT SCAN (ALL SUBS)
# ─────────────────────────────────────────────
banner "PHASE 3 - Port Scanning"

PORTS_FILE="$OUTDIR/hosts/open_ports.txt"
NS_PORTS_FILE="$OUTDIR/hosts/nonstandard_ports.txt"

if has_tool naabu && [[ -s "$SUBS_FILE" ]]; then
  info "naabu on $(cnt "$SUBS_FILE") subdomains (top-1000 ports, 50 concurrent)..."
  safe naabu -list "$SUBS_FILE" -top-ports 1000 -silent -c 50 -o "$PORTS_FILE"
  PORT_COUNT=$(cnt "$PORTS_FILE")
  grep -vE ':80$|:443$' "$PORTS_FILE" > "$NS_PORTS_FILE" 2>/dev/null || true
  NS_COUNT=$(cnt "$NS_PORTS_FILE")
  ok "Ports: $PORT_COUNT open ($NS_COUNT non-standard)"
  if [[ "$NS_COUNT" -gt 0 ]]; then
    warn "Non-standard ports:"
    cat "$NS_PORTS_FILE"
  fi
  tg phase "$TARGET" "$OUTDIR" "3" "Port Scan" "$PORT_COUNT open | $NS_COUNT non-standard"
else
  touch "$PORTS_FILE" "$NS_PORTS_FILE"
  warn "naabu missing - skipping port scan"
  tg phase "$TARGET" "$OUTDIR" "3" "Port Scan" "Skipped"
fi

# ─────────────────────────────────────────────
#  PHASE 4 - TECH FINGERPRINTING
#  Runs whatweb on INTERESTING hosts only (not all 54k)
# ─────────────────────────────────────────────
banner "PHASE 4 - Tech Fingerprinting"

TECH_FILE="$OUTDIR/hosts/tech_stack.txt"
touch "$TECH_FILE"

if has_tool whatweb && [[ -s "$INTERESTING_FILE" ]]; then
  INT_COUNT=$(cnt "$INTERESTING_FILE")
  info "whatweb on $INT_COUNT interesting hosts (30 workers)..."
  cat "$INTERESTING_FILE" | xargs -P 30 -I XXXHOST \
    bash -c 'timeout 10 whatweb --no-errors -q --open-timeout=5 --read-timeout=5 XXXHOST 2>/dev/null || true' \
    >> "$TECH_FILE" 2>/dev/null || true
  TECH_COUNT=$(cnt "$TECH_FILE")
  ok "Tech stack: $TECH_COUNT fingerprints"
  tg phase "$TARGET" "$OUTDIR" "4" "Tech Fingerprint" "$TECH_COUNT from $INT_COUNT interesting hosts"
elif [[ -s "$INTERESTING_FILE" ]] && [[ -s "$LIVE_RICH" ]]; then
  info "whatweb missing - extracting from httpx data..."
  while IFS= read -r host; do
    bare=$(echo "$host" | sed 's|https*://||' | cut -d/ -f1)
    grep -F "$bare" "$LIVE_RICH" >> "$TECH_FILE" 2>/dev/null || true
  done < "$INTERESTING_FILE"
  tg phase "$TARGET" "$OUTDIR" "4" "Tech Fingerprint" "Used httpx fallback"
else
  tg phase "$TARGET" "$OUTDIR" "4" "Tech Fingerprint" "Skipped"
fi

# ─────────────────────────────────────────────
#  PHASE 5 - URL COLLECTION (SIEVED HOSTS)
# ─────────────────────────────────────────────
banner "PHASE 5 - URL Collection"

URLS_FILE="$OUTDIR/urls/all_urls.txt"
INTERESTING_URLS="$OUTDIR/urls/interesting_urls.txt"
PARAMS_FILE="$OUTDIR/urls/urls_with_params.txt"
touch "$URLS_FILE" "$INTERESTING_URLS" "$PARAMS_FILE"

if has_tool gau && [[ -s "$SIEVED_FILE" ]]; then
  info "gau on $(cnt "$SIEVED_FILE") sieved hosts..."
  while IFS= read -r host; do
    domain=$(echo "$host" | sed 's|https*://||' | cut -d/ -f1)
    timeout 60 gau --threads 3 --timeout 10 "$domain" 2>/dev/null | anew "$URLS_FILE" || true
  done < "$SIEVED_FILE"
fi

if has_tool waybackurls; then
  info "waybackurls..."
  echo "$TARGET" | waybackurls 2>/dev/null | anew "$URLS_FILE" || true
fi

if [[ -s "$URLS_FILE" ]]; then
  grep -iE "\.(php|asp|aspx|jsp|json|xml|yaml|env|bak|sql|log|config|conf)(\?|$)" \
    "$URLS_FILE" > "$INTERESTING_URLS" 2>/dev/null || true
  grep -E "(\?|&)[^=]+=." "$URLS_FILE" | sort -u > "$PARAMS_FILE" 2>/dev/null || true
fi

URL_COUNT=$(cnt "$URLS_FILE")
PARAM_COUNT=$(cnt "$PARAMS_FILE")
ok "URLs: $URL_COUNT | Params: $PARAM_COUNT"
tg phase "$TARGET" "$OUTDIR" "5" "URL Collection" "$URL_COUNT total | $PARAM_COUNT with params"

# ─────────────────────────────────────────────
#  PHASE 6 - JS ANALYSIS (INTERESTING HOSTS)
# ─────────────────────────────────────────────
banner "PHASE 6 - JS Analysis"

JS_FILE="$OUTDIR/js/js_files.txt"
JS_SECRETS="$OUTDIR/js/potential_secrets.txt"
JS_ENDPOINTS="$OUTDIR/js/endpoints_from_js.txt"
touch "$JS_FILE" "$JS_SECRETS" "$JS_ENDPOINTS"

if [[ -s "$URLS_FILE" ]] && [[ -s "$INTERESTING_FILE" ]]; then
  info "Extracting JS from interesting hosts..."
  while IFS= read -r host; do
    bare=$(echo "$host" | sed 's|https*://||' | cut -d/ -f1)
    grep -F "$bare" "$URLS_FILE" | grep -E '\.js(\?|$)' | anew "$JS_FILE" || true
  done < "$INTERESTING_FILE"
fi

JS_COUNT=$(cnt "$JS_FILE")
ok "JS files: $JS_COUNT"

if [[ "$JS_COUNT" -gt 0 ]] && has_tool curl; then
  info "Analysing first 100 JS files..."
  head -100 "$JS_FILE" | while IFS= read -r jsurl; do
    content=$(curl -sk --max-time 10 "$jsurl" 2>/dev/null || true)
    [[ -z "$content" ]] && continue
    # Secrets - use python3 for safe regex
    python3 -c "
import re, sys
content = sys.stdin.read()
url = '$jsurl'
pat = r'(api[_-]?key|secret|password|token|auth|apikey|access_key)\s*[:=]\s*[\"'\''][^\"'\'']{8,}[\"'\'']'
for m in re.findall(pat, content, re.I):
    print(f'[{url}] {m}')
" <<< "$content" >> "$JS_SECRETS" 2>/dev/null || true
    # Endpoints
    python3 -c "
import re, sys
content = sys.stdin.read()
url = '$jsurl'
pat = r'[\"'\''` ](/[a-zA-Z0-9_/?=&%-]{3,60})[\"'\''` ]'
for m in sorted(set(re.findall(pat, content))):
    print(f'[{url}] {m}')
" <<< "$content" >> "$JS_ENDPOINTS" 2>/dev/null || true
  done
fi

SECRET_COUNT=$(cnt "$JS_SECRETS")
ENDPOINT_COUNT=$(cnt "$JS_ENDPOINTS")
ok "Secrets: $SECRET_COUNT | Endpoints: $ENDPOINT_COUNT"

DETAIL="$JS_COUNT JS | $ENDPOINT_COUNT endpoints | $SECRET_COUNT secrets"
[[ "$SECRET_COUNT" -gt 0 ]] && DETAIL="$DETAIL | REVIEW SECRETS"
tg phase "$TARGET" "$OUTDIR" "6" "JS Analysis" "$DETAIL"

# ─────────────────────────────────────────────
#  PHASE 7 - DIRECTORY FUZZING (INTERESTING HOSTS)
# ─────────────────────────────────────────────
banner "PHASE 7 - Directory Fuzzing"

WORDLIST=""
for wl in \
  "/snap/seclists/current/Discovery/Web-Content/raft-medium-directories.txt" \
  "/snap/seclists/1214/Discovery/Web-Content/raft-medium-directories.txt" \
  "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt" \
  "/usr/share/wordlists/dirb/common.txt" \
  "$HOME/SecLists/Discovery/Web-Content/raft-medium-directories.txt"; do
  [[ -f "$wl" ]] && WORDLIST="$wl" && break
done

if [[ -z "$WORDLIST" ]]; then
  warn "No SecLists - using built-in wordlist"
  WORDLIST="$OUTDIR/mini_wordlist.txt"
  printf '%s\n' \
    admin login api dashboard config backup test dev staging \
    uploads .env swagger swagger.json openapi.json docs health \
    status metrics actuator graphql wp-admin phpmyadmin \
    > "$WORDLIST"
fi

FFUF_OUT="$OUTDIR/urls/ffuf_results"
FFUF_FINDINGS=0

if has_tool ffuf && has_tool jq && [[ -s "$INTERESTING_FILE" ]]; then
  mkdir -p "$FFUF_OUT"
  INT_COUNT=$(cnt "$INTERESTING_FILE")
  info "ffuf on $INT_COUNT interesting hosts (10 parallel)..."

  # Use XXXHOST as placeholder to avoid quote issues
  cat "$INTERESTING_FILE" | xargs -P 10 -I XXXHOST \
    bash -c '
      safe=$(echo "XXXHOST" | tr "/:.@" "____")
      ffuf -u "XXXHOST/FUZZ" -w "'"$WORDLIST"'" \
           -mc 200,201,204,301,302,307,401,403 \
           -t 30 -timeout 10 -silent \
           -o "'"$FFUF_OUT"'/${safe}.json" -of json 2>/dev/null || true
    ' 2>/dev/null || true

  for f in "$FFUF_OUT"/*.json; do
    [[ -f "$f" ]] || continue
    hits=$(jq '.results | length' "$f" 2>/dev/null || echo 0)
    FFUF_FINDINGS=$(( FFUF_FINDINGS + hits ))
  done
  ok "ffuf: $FFUF_FINDINGS paths found"
  tg phase "$TARGET" "$OUTDIR" "7" "Dir Fuzzing" "$FFUF_FINDINGS paths across $INT_COUNT hosts"
else
  warn "ffuf/jq missing or no interesting hosts"
  tg phase "$TARGET" "$OUTDIR" "7" "Dir Fuzzing" "Skipped"
fi

# ─────────────────────────────────────────────
#  PHASE 8 - XSS (INTERESTING PARAM URLS)
# ─────────────────────────────────────────────
banner "PHASE 8 - XSS Testing"

XSS_OUT="$OUTDIR/vulns/xss_results.txt"
touch "$XSS_OUT"

if has_tool dalfox && [[ -s "$PARAMS_FILE" ]] && [[ -s "$INTERESTING_FILE" ]]; then
  INT_PARAMS="$OUTDIR/urls/interesting_params.txt"
  touch "$INT_PARAMS"
  while IFS= read -r host; do
    bare=$(echo "$host" | sed 's|https*://||' | cut -d/ -f1)
    grep -F "$bare" "$PARAMS_FILE" | anew "$INT_PARAMS" || true
  done < "$INTERESTING_FILE"

  IPCOUNT=$(cnt "$INT_PARAMS")
  info "dalfox on $IPCOUNT param URLs from interesting hosts..."
  head -200 "$INT_PARAMS" | dalfox pipe --silence --no-color \
    -o "$XSS_OUT" 2>/dev/null || true

  XSS_COUNT=$(cnt "$XSS_OUT")
  if [[ "$XSS_COUNT" -gt 0 ]]; then
    ok "XSS: $XSS_COUNT candidates"
    tg phase "$TARGET" "$OUTDIR" "8" "XSS" "FOUND: $XSS_COUNT candidates"
  else
    info "XSS: clean"
    tg phase "$TARGET" "$OUTDIR" "8" "XSS" "Clean - $IPCOUNT URLs tested"
  fi
else
  warn "dalfox missing or no param URLs"
  tg phase "$TARGET" "$OUTDIR" "8" "XSS" "Skipped"
fi

# ─────────────────────────────────────────────
#  PHASE 9 - NUCLEI (INTERESTING HOSTS)
# ─────────────────────────────────────────────
banner "PHASE 9 - Nuclei"

NUCLEI_OUT="$OUTDIR/vulns/nuclei_results.txt"
touch "$NUCLEI_OUT"

if has_tool nuclei && [[ -s "$INTERESTING_FILE" ]]; then
  INT_COUNT=$(cnt "$INTERESTING_FILE")
  info "nuclei on $INT_COUNT interesting hosts..."
  safe nuclei -l "$INTERESTING_FILE" \
    -t cves/ -t exposures/ -t misconfigurations/ \
    -t takeovers/ -t technologies/ \
    -severity critical,high,medium \
    -silent -no-color -c 50 \
    -o "$NUCLEI_OUT"

  NUCLEI_COUNT=$(cnt "$NUCLEI_OUT")
  CRIT_HIGH=$(grep -cE "\[critical\]|\[high\]" "$NUCLEI_OUT" 2>/dev/null || echo 0)
  if [[ "$NUCLEI_COUNT" -gt 0 ]]; then
    ok "Nuclei: $NUCLEI_COUNT findings ($CRIT_HIGH critical/high)"
    grep -E "\[critical\]|\[high\]" "$NUCLEI_OUT" | head -10 || true
    tg phase "$TARGET" "$OUTDIR" "9" "Nuclei" "FOUND: $NUCLEI_COUNT ($CRIT_HIGH crit/high) on $INT_COUNT hosts"
  else
    info "Nuclei: clean"
    tg phase "$TARGET" "$OUTDIR" "9" "Nuclei" "Clean on $INT_COUNT interesting hosts"
  fi
else
  warn "nuclei missing or no interesting hosts"
  tg phase "$TARGET" "$OUTDIR" "9" "Nuclei" "Skipped"
fi

# ─────────────────────────────────────────────
#  PHASE 10 - NIKTO (TIER A TOP 10 ONLY)
# ─────────────────────────────────────────────
banner "PHASE 10 - Nikto"

NIKTO_OUT="$OUTDIR/vulns/nikto_results.txt"
touch "$NIKTO_OUT"

if has_tool nikto && [[ -s "$PRIORITY_FILE" ]]; then
  NIKTO_HOSTS=$(head -10 "$PRIORITY_FILE" | wc -l)
  info "nikto on top $NIKTO_HOSTS Tier A hosts (5 min max each)..."
  head -10 "$PRIORITY_FILE" | while IFS= read -r host; do
    info "  nikto: $host"
    {
      echo "=== $host ==="
      timeout 300 nikto -h "$host" -maxtime 300 -Format txt -nointeractive 2>/dev/null || true
      echo ""
    } >> "$NIKTO_OUT"
  done
  NIKTO_FINDINGS=$(grep -c "^+" "$NIKTO_OUT" 2>/dev/null || echo 0)
  ok "Nikto: $NIKTO_FINDINGS findings"
  tg phase "$TARGET" "$OUTDIR" "10" "Nikto" "$NIKTO_FINDINGS findings on $NIKTO_HOSTS Tier A hosts"
else
  warn "nikto missing or no priority hosts"
  tg phase "$TARGET" "$OUTDIR" "10" "Nikto" "Skipped"
fi

# ─────────────────────────────────────────────
#  PHASE 11 - CORS (ALL LIVE HOSTS)
# ─────────────────────────────────────────────
banner "PHASE 11 - CORS Check"

CORS_OUT="$OUTDIR/vulns/cors_results.txt"
touch "$CORS_OUT"

if has_tool curl && [[ -s "$LIVE_FILE" ]]; then
  LIVE_NOW=$(cnt "$LIVE_FILE")
  info "CORS check on all $LIVE_NOW live hosts (50 parallel)..."
  cat "$LIVE_FILE" | xargs -P 50 -I XXXHOST \
    bash -c '
      resp=$(curl -sk --max-time 8 -I \
        -H "Origin: https://evil.com" \
        -H "Access-Control-Request-Method: GET" \
        "XXXHOST" 2>/dev/null || true)
      acao=$(echo "$resp" | grep -i "access-control-allow-origin" | tr -d "\r")
      acac=$(echo "$resp" | grep -i "access-control-allow-credentials" | tr -d "\r")
      if echo "$acao" | grep -qiE "evil\.com|\*"; then
        if echo "$acac" | grep -qi "true"; then
          echo "[CRITICAL] XXXHOST | reflected+creds | $acao"
        else
          echo "[MEDIUM]   XXXHOST | reflected | $acao"
        fi
      fi
    ' >> "$CORS_OUT" 2>/dev/null || true

  CORS_COUNT=$(cnt "$CORS_OUT")
  CORS_CRIT=$(grep -c "\[CRITICAL\]" "$CORS_OUT" 2>/dev/null || echo 0)
  if [[ "$CORS_COUNT" -gt 0 ]]; then
    ok "CORS: $CORS_COUNT issues ($CORS_CRIT critical)"
    tg phase "$TARGET" "$OUTDIR" "11" "CORS" "FOUND: $CORS_COUNT issues ($CORS_CRIT critical) on $LIVE_NOW hosts"
  else
    info "CORS: clean"
    tg phase "$TARGET" "$OUTDIR" "11" "CORS" "Clean on all $LIVE_NOW live hosts"
  fi
fi

# ─────────────────────────────────────────────
#  PHASE 12 - TAKEOVER (ALL SUBS)
# ─────────────────────────────────────────────
banner "PHASE 12 - Subdomain Takeover"

TAKEOVER_OUT="$OUTDIR/vulns/takeover_candidates.txt"
touch "$TAKEOVER_OUT"

if has_tool curl && has_tool dig && [[ -s "$SUBS_FILE" ]]; then
  ALL_SUBS=$(cnt "$SUBS_FILE")
  info "Takeover check on $ALL_SUBS subdomains (30 parallel)..."

  SIGS_FILE=$(mktemp /tmp/sigs_XXXXXX.txt)
  printf '%s\n' \
    "github|There isn't a GitHub Pages site here" \
    "heroku|No such app" \
    "shopify|Sorry, this shop is currently unavailable" \
    "fastly|Fastly error: unknown domain" \
    "aws_s3|NoSuchBucket" \
    "azure|404 Web Site not found" \
    "tumblr|Whatever you were looking for doesn't currently exist" \
    "pantheon|The gods are wise" \
    "cargo|Not found" \
    > "$SIGS_FILE"

  cat "$SUBS_FILE" | xargs -P 30 -I XXXSUB \
    bash -c '
      cname=$(dig +short CNAME "XXXSUB" 2>/dev/null | head -1 || true)
      [[ -z "$cname" ]] && exit 0
      body=$(curl -sk --max-time 8 "http://XXXSUB" 2>/dev/null || true)
      while IFS="|" read -r svc sig; do
        if echo "$body" | grep -qF "$sig" 2>/dev/null; then
          echo "[TAKEOVER:$svc] XXXSUB -> $cname"
        fi
      done < "'"$SIGS_FILE"'"
    ' >> "$TAKEOVER_OUT" 2>/dev/null || true

  rm -f "$SIGS_FILE"
  TAKEOVER_COUNT=$(cnt "$TAKEOVER_OUT")
  if [[ "$TAKEOVER_COUNT" -gt 0 ]]; then
    ok "Takeovers: $TAKEOVER_COUNT"
    cat "$TAKEOVER_OUT"
    tg phase "$TARGET" "$OUTDIR" "12" "Takeover" "FOUND: $TAKEOVER_COUNT from $ALL_SUBS subs"
  else
    info "Takeover: clean"
    tg phase "$TARGET" "$OUTDIR" "12" "Takeover" "Clean - $ALL_SUBS subs checked"
  fi
fi

# ─────────────────────────────────────────────
#  PHASE 13 - SENSITIVE FILES (SIEVED HOSTS)
# ─────────────────────────────────────────────
banner "PHASE 13 - Sensitive Files"

SENSITIVE_OUT="$OUTDIR/vulns/sensitive_files.txt"
touch "$SENSITIVE_OUT"

if has_tool curl && [[ -s "$SIEVED_FILE" ]]; then
  SIEVED_NOW=$(cnt "$SIEVED_FILE")
  info "Sensitive file check on $SIEVED_NOW sieved hosts (30 parallel)..."

  PATHS_FILE=$(mktemp /tmp/paths_XXXXXX.txt)
  printf '%s\n' \
    "/.env" "/.git/config" "/.git/HEAD" "/config.php" "/wp-config.php" \
    "/config.yml" "/backup.sql" "/.htpasswd" "/robots.txt" "/server-status" \
    "/.DS_Store" "/phpinfo.php" "/swagger.json" "/openapi.json" "/api-docs" \
    "/.aws/credentials" "/actuator/env" "/actuator/mappings" \
    "/graphql" "/graphiql" "/.npmrc" "/.dockerenv" \
    "/docker-compose.yml" "/.bash_history" \
    > "$PATHS_FILE"

  cat "$SIEVED_FILE" | xargs -P 30 -I XXXHOST \
    bash -c '
      while IFS= read -r path; do
        url="XXXHOSTinserted${path}"
        url=$(echo "$url" | sed "s|XXXHOSTinserted|XXXHOST|")
        code=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)
        if [[ "$code" == "200" ]] || [[ "$code" == "206" ]]; then
          size=$(curl -sk --max-time 8 -o /dev/null -w "%{size_download}" "$url" 2>/dev/null || echo 0)
          echo "[${code}] [${size}b] $url"
        fi
      done < "'"$PATHS_FILE"'"
    ' >> "$SENSITIVE_OUT" 2>/dev/null || true

  rm -f "$PATHS_FILE"
  SENS_COUNT=$(cnt "$SENSITIVE_OUT")
  if [[ "$SENS_COUNT" -gt 0 ]]; then
    ok "Sensitive files: $SENS_COUNT"
    tg phase "$TARGET" "$OUTDIR" "13" "Sensitive Files" "FOUND: $SENS_COUNT on $SIEVED_NOW sieved hosts"
  else
    info "Sensitive files: clean"
    tg phase "$TARGET" "$OUTDIR" "13" "Sensitive Files" "Clean - $SIEVED_NOW sieved hosts"
  fi
fi

# ─────────────────────────────────────────────
#  PHASE 14 - CLAUDE FINDINGS TRIAGE
# ─────────────────────────────────────────────
banner "PHASE 14 - Claude Findings Triage"

if $CLAUDE_ENABLED; then
  info "Triaging findings with Claude..."
  python3 "$SCRIPT_DIR/claude_triage.py" findings "$OUTDIR" || true
  tg phase "$TARGET" "$OUTDIR" "14" "Findings Triage" "Done - see reports/findings_summary.txt"
else
  warn "Claude disabled"
  tg phase "$TARGET" "$OUTDIR" "14" "Findings Triage" "Skipped"
fi

# ─────────────────────────────────────────────
#  PHASE 15 - CLAUDE REPORT DRAFTING
# ─────────────────────────────────────────────
banner "PHASE 15 - Report Drafting"

if $CLAUDE_ENABLED; then
  info "Drafting H1 reports..."
  python3 "$SCRIPT_DIR/claude_triage.py" report "$OUTDIR" "$TARGET" || true
  RCOUNT=$(ls "$OUTDIR/reports/drafts/"*.txt 2>/dev/null | wc -l || echo 0)
  tg phase "$TARGET" "$OUTDIR" "15" "Report Drafting" "$RCOUNT H1-ready reports"
else
  warn "Claude disabled"
  tg phase "$TARGET" "$OUTDIR" "15" "Report Drafting" "Skipped"
fi

# ─────────────────────────────────────────────
#  FINAL SUMMARY
# ─────────────────────────────────────────────
banner "FINAL SUMMARY"

REPORT="$OUTDIR/reports/summary.txt"
RUNTIME=$(elapsed)

cat > "$REPORT" << SUMEOF
===========================================
  Recon Summary - $TARGET
  Date    : $(date)
  Runtime : $RUNTIME
  Claude  : $($CLAUDE_ENABLED && echo enabled || echo disabled)
===========================================

[HOST FUNNEL]
  Subdomains       : $(cnt "$OUTDIR/subdomains/all_subs.txt")
  Live hosts       : $(cnt "$OUTDIR/hosts/live_hosts.txt")
  After sieve      : $(cnt "$OUTDIR/hosts/sieved_hosts.txt")
  Interesting (A+B): $(cnt "$OUTDIR/hosts/interesting_hosts.txt")
  Priority (Tier A): $(cnt "$OUTDIR/hosts/priority_hosts.txt")

[URL STATS]
  Total URLs       : $(cnt "$OUTDIR/urls/all_urls.txt")
  With params      : $(cnt "$OUTDIR/urls/urls_with_params.txt")
  Interesting URLs : $(cnt "$OUTDIR/urls/interesting_urls.txt")
  JS files         : $(cnt "$OUTDIR/js/js_files.txt")

[PORTS]
  Open             : $(cnt "$OUTDIR/hosts/open_ports.txt")
  Non-standard     : $(cnt "$OUTDIR/hosts/nonstandard_ports.txt")

[FINDINGS]
  Nuclei           : $(cnt "$OUTDIR/vulns/nuclei_results.txt")
  XSS              : $(cnt "$OUTDIR/vulns/xss_results.txt")
  CORS             : $(cnt "$OUTDIR/vulns/cors_results.txt")
  Takeovers        : $(cnt "$OUTDIR/vulns/takeover_candidates.txt")
  Sensitive files  : $(cnt "$OUTDIR/vulns/sensitive_files.txt")
  JS secrets       : $(cnt "$OUTDIR/js/potential_secrets.txt")
  JS endpoints     : $(cnt "$OUTDIR/js/endpoints_from_js.txt")

[NON-STANDARD PORTS]
$(cat "$OUTDIR/hosts/nonstandard_ports.txt" 2>/dev/null || echo "  None")

[MISSING TOOLS]
$(if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  for t in "${MISSING_TOOLS[@]}"; do echo "  - $t"; done
else echo "  All tools available"; fi)
SUMEOF

cat "$REPORT"
tg final "$TARGET" "$OUTDIR"

echo ""
ok "Done in $RUNTIME - output: ${BOLD}${OUTDIR}/${NC}"
warn "Only test targets you have explicit written permission to test."
