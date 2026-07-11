#!/usr/bin/env bash
#
# Live sign test for git-kmssign: signs a short message with an RSA key held in
# Azure Key Vault, via a service principal with the "Key Vault Crypto User" role.
# Produces a detached, armored signature (-s -b -a -u).
#
# Override any value via environment variables. Required:
#   TENANT_ID  APP_ID  PASSWORD  VAULT_URL  KEY_NAME
#
# Example:
#   TENANT_ID=... APP_ID=... PASSWORD=... \
#   VAULT_URL=https://myvault.vault.azure.net/ KEY_NAME=git-signing-cert-01 \
#   CERT_PEM=/tmp/git-signing-crt-01.pem SIGN_EMAIL=you@example.com \
#   ./scripts/live-sign-test.sh
#
set -euo pipefail

IMAGE="${IMAGE:-git-kmssign:dev}"

# Service principal -> DefaultAzureCredential environment variables.
TENANT_ID="${TENANT_ID:-}"   # -> AZURE_TENANT_ID
APP_ID="${APP_ID:-}"         # -> AZURE_CLIENT_ID (SP appId)
PASSWORD="${PASSWORD:-}"     # -> AZURE_CLIENT_SECRET (SP password)

# Key Vault key selection.
VAULT_URL="${VAULT_URL:-}"
KEY_NAME="${KEY_NAME:-}"
KEY_VERSION="${KEY_VERSION:-}"   # empty = latest

# Local public certificate (leaf first) and the email contained in it.
CERT_PEM="${CERT_PEM:-/tmp/git-signing-crt-01.pem}"
SIGN_EMAIL="${SIGN_EMAIL:-you@example.com}"

# Test payload and output file.
MESSAGE="${MESSAGE:-hello from git-kmssign}"
OUT="${OUT:-sig.pem}"

# Validate required values.
missing=()
for v in TENANT_ID APP_ID PASSWORD VAULT_URL KEY_NAME; do
  [[ -n "${!v}" ]] || missing+=("$v")
done
if (( ${#missing[@]} )); then
  echo "ERROR: set required variable(s): ${missing[*]}" >&2
  exit 1
fi
if [[ ! -r "$CERT_PEM" ]]; then
  echo "ERROR: cannot read CERT_PEM=$CERT_PEM" >&2
  exit 1
fi

# Absolute path for the bind mount.
CERT_ABS="$(cd "$(dirname "$CERT_PEM")" && pwd)/$(basename "$CERT_PEM")"

printf '%s\n' "$MESSAGE" | docker run --rm -i \
  -e AZURE_TENANT_ID="$TENANT_ID" \
  -e AZURE_CLIENT_ID="$APP_ID" \
  -e AZURE_CLIENT_SECRET="$PASSWORD" \
  -e GIT_KMSSIGN_VAULT_URL="$VAULT_URL" \
  -e GIT_KMSSIGN_KEY_NAME="$KEY_NAME" \
  -e GIT_KMSSIGN_KEY_VERSION="$KEY_VERSION" \
  -e GIT_KMSSIGN_CERT="/certs/signer.pem" \
  -v "$CERT_ABS:/certs/signer.pem:ro" \
  "$IMAGE" -s -b -a -u "$SIGN_EMAIL" > "$OUT"

echo "Wrote detached armored signature to: $OUT"
head -1 "$OUT"
