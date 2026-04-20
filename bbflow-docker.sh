#!/usr/bin/env bash
# bbflow-docker.sh — run bbflow inside Docker without local dependencies
#
# Usage (same as bbflow.sh):
#   ./bbflow-docker.sh doctor
#   ./bbflow-docker.sh hunt --list hosts.txt --probe
#   ./bbflow-docker.sh hunt target.com --only cors,graphql
#   ./bbflow-docker.sh flow target.com
#
# Custom image:
#   BBFLOW_IMAGE=my-registry/bbflow:latest ./bbflow-docker.sh hunt target.com
#
# Override templates / SecLists with host copies (faster, no re-download):
#   BBFLOW_MOUNT_TEMPLATES=1 ./bbflow-docker.sh hunt target.com
set -uo pipefail

IMAGE="${BBFLOW_IMAGE:-ghcr.io/guan4tou2/bbflow:latest}"

command -v docker >/dev/null 2>&1 || { echo "docker not found — install Docker first"; exit 1; }

# ── Forward auth env vars from host if set ───────────────────
ENV_ARGS=()
for VAR in \
    DALFOX_BLIND_URL DALFOX_COOKIE DALFOX_HEADERS \
    FFUF_COOKIE FFUF_HEADER ARJUN_HEADERS ARJUN_COOKIES \
    OSMEDEUS_VPS EXISTING_EMAIL; do
  [[ -n "${!VAR:-}" ]] && ENV_ARGS+=("-e" "${VAR}=${!VAR}")
done

# ── Optional: mount host nuclei-templates + SecLists ─────────
MOUNT_ARGS=()
if [[ "${BBFLOW_MOUNT_TEMPLATES:-0}" == "1" ]]; then
  [[ -d "${HOME}/nuclei-templates" ]] && \
    MOUNT_ARGS+=("-v" "${HOME}/nuclei-templates:/root/nuclei-templates:ro")
  [[ -d "${HOME}/Tools/SecLists" ]] && \
    MOUNT_ARGS+=("-v" "${HOME}/Tools/SecLists:/root/Tools/SecLists:ro")
fi

# ── Resolve --list paths to /workspace-relative ──────────────
# If --list <file> points to a local path, convert to container path
ARGS=()
SKIP_NEXT=0
for ARG in "$@"; do
  if [[ "$SKIP_NEXT" == "1" ]]; then
    if [[ "$ARG" != /* ]]; then
      ARGS+=("/workspace/$ARG")
    else
      ARGS+=("$ARG")
    fi
    SKIP_NEXT=0
    continue
  fi
  [[ "$ARG" == "--list" || "$ARG" == "-l" ]] && SKIP_NEXT=1
  ARGS+=("$ARG")
done

exec docker run --rm -it \
  -v "$(pwd):/workspace" \
  "${MOUNT_ARGS[@]}" \
  "${ENV_ARGS[@]}" \
  "$IMAGE" "${ARGS[@]}"
