#!/usr/bin/env bash
#
# Live "git commit -S" playground for git-kmssign, using the natively-extracted
# static binary (not the container). Creates a throwaway git repository,
# configures x509 signing *locally* (never touches your global git config),
# exports the environment the signer reads, and drops you into an interactive
# shell so you can run git commands yourself.
#
# Override any value via environment variables. Required:
#   TENANT_ID  APP_ID  PASSWORD  VAULT_URL  KEY_NAME
#
# Example:
#   TENANT_ID=... APP_ID=... ****** \
#   VAULT_URL=https://myvault.vault.azure.net/ KEY_NAME=git-signing-crt-01 \
#   CERT_PEM=/tmp/git-signing-crt-01.pem SIGN_EMAIL=you@example.com \
#   ./scripts/live-commit-test.sh
#
set -euo pipefail

# Natively-extracted static binary (see docs: docker cp from the built image).
BIN="${BIN:-/tmp/signing-test/git-kmssign}"

# Service principal -> DefaultAzureCredential environment variables.
TENANT_ID="${TENANT_ID:-}"   # -> AZURE_TENANT_ID
APP_ID="${APP_ID:-}"         # -> AZURE_CLIENT_ID (SP appId)
******     # -> AZURE_CLIENT_SECRET (SP password)

# Key Vault key selection.
VAULT_URL="${VAULT_URL:-}"
KEY_NAME="${KEY_NAME:-}"
KEY_VERSION="${KEY_VERSION:-}"   # empty = latest

# Local public certificate (leaf first) and the email contained in it. The
# email must match the certificate's SAN / user.signingkey.
CERT_PEM="${CERT_PEM:-/tmp/git-signing-crt-01.pem}"
SIGN_EMAIL="${SIGN_EMAIL:-you@example.com}"

# Certificate inclusion policy (optional). Empty uses the tool default (-2,
# all certs except the root). Use -1 to embed the whole chain including a
# self-signed cert so the signature verifies self-contained.
INCLUDE_CERTS="${INCLUDE_CERTS:--1}"

# Validate required values.
missing=()
for v in TENANT_ID APP_ID PASSWORD VAULT_URL KEY_NAME; do
  [[ -n "${!v}" ]] || missing+=("$v")
done
if (( ${#missing[@]} )); then
  echo "ERROR: set required variable(s): ${missing[*]}" >&2
  exit 1
fi
if [[ ! -x "$BIN" ]]; then
  echo "ERROR: signing program not executable: BIN=$BIN" >&2
  exit 1
fi
if [[ ! -r "$CERT_PEM" ]]; then
  echo "ERROR: cannot read CERT_PEM=$CERT_PEM" >&2
  exit 1
fi

# Absolute paths so they resolve from inside the throwaway repo.
CERT_ABS="$(cd "$(dirname "$CERT_PEM")" && pwd)/$(basename "$CERT_PEM")"
BIN_ABS="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

# Export the environment the signing program reads. git passes this through
# to gpg.x509.program when it runs the signer.
export AZURE_TENANT_ID="$TENANT_ID"
export AZURE_CLIENT_ID="$APP_ID"
export AZURE_CLIENT_SECRET="$PASSWORD"
export GIT_KMSSIGN_VAULT_URL="$VAULT_URL"
export GIT_KMSSIGN_KEY_NAME="$KEY_NAME"
export GIT_KMSSIGN_KEY_VERSION="$KEY_VERSION"
export GIT_KMSSIGN_CERT="$CERT_ABS"
export GIT_KMSSIGN_INCLUDE_CERTS="$INCLUDE_CERTS"

# Throwaway repository; cleaned up when you exit the interactive shell.
REPO="$(mktemp -d)"
cleanup() { rm -rf "$REPO"; }
trap cleanup EXIT

cd "$REPO"
git init -q
# Local (repo-scoped) config only: never mutate the user's global git config.
git config user.name "git-kmssign test"
git config user.email "$SIGN_EMAIL"
git config gpg.format x509
git config gpg.x509.program "$BIN_ABS"
git config user.signingkey "$SIGN_EMAIL"

cat <<EOF

Throwaway signing playground ready in: $REPO
x509 signing is configured locally in this repo only.

Try, for example:

  echo hello > file.txt && git add file.txt
  git commit -S -m "test: signed via Azure Key Vault"
  git --no-pager log --show-signature -1
  git verify-commit HEAD

Type 'exit' to leave; the throwaway repo is removed on exit.

EOF

# Drop into an interactive shell with the environment above already exported.
# Run as a child (not exec) so the cleanup trap fires when you exit it.
bash
