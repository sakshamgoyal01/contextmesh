#!/usr/bin/env bash
# infra/k8s/vault/vault-init-ceremony.sh
#
# Vault initialisation ceremony.
# Run ONCE after all 3 vault pods reach Running state.
# Operator must hold the encrypted keys file in a separate secure location
# (e.g. printed + stored in physical safe, or split across 3 different people).
#
# Prerequisites:
#   - kubectl configured for the cluster
#   - gpg key for each key custodian already imported
#   - vault CLI installed and on PATH
#   - VAULT_ADDR exported (https://vault-0.vault-internal:8200 or port-forwarded)
#
# Usage:
#   VAULT_CACERT=/path/to/ca.crt \
#   CUSTODIAN_1_GPG_ID=alice@example.com \
#   CUSTODIAN_2_GPG_ID=bob@example.com \
#   CUSTODIAN_3_GPG_ID=carol@example.com \
#   bash infra/k8s/vault/vault-init-ceremony.sh

set -euo pipefail

# ── Guard ────────────────────────────────────────────────────────────────────
if [[ "${1:-}" != "--i-understand-this-is-a-one-time-operation" ]]; then
  echo "ERROR: You must pass --i-understand-this-is-a-one-time-operation"
  echo "       This script initialises Vault and cannot be re-run on an"
  echo "       already-initialised cluster."
  exit 1
fi

VAULT_ADDR="${VAULT_ADDR:-https://127.0.0.1:8200}"
VAULT_CACERT="${VAULT_CACERT:?VAULT_CACERT must be set to the CA cert path}"
CUSTODIAN_1_GPG_ID="${CUSTODIAN_1_GPG_ID:?Must set CUSTODIAN_1_GPG_ID}"
CUSTODIAN_2_GPG_ID="${CUSTODIAN_2_GPG_ID:?Must set CUSTODIAN_2_GPG_ID}"
CUSTODIAN_3_GPG_ID="${CUSTODIAN_3_GPG_ID:?Must set CUSTODIAN_3_GPG_ID}"

export VAULT_ADDR VAULT_CACERT

CEREMONY_DIR="$(mktemp -d)"
KEYS_FILE="${CEREMONY_DIR}/vault-unseal-keys.json"
ENCRYPTED_DIR="${CEREMONY_DIR}/encrypted"
mkdir -p "${ENCRYPTED_DIR}"

echo "=== ContextMesh Vault Initialisation Ceremony ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Cluster:   $(kubectl config current-context)"
echo "Vault addr: ${VAULT_ADDR}"
echo ""

# ── Step 1: Check Vault is not already initialised ───────────────────────────
INIT_STATUS=$(vault status -format=json 2>/dev/null | jq -r '.initialized' || echo "unknown")
if [[ "${INIT_STATUS}" == "true" ]]; then
  echo "ERROR: Vault is already initialised. Aborting."
  exit 1
fi

echo "[1/6] Vault is not initialised. Proceeding."

# ── Step 2: Initialise with 5 key shares, threshold 3 ───────────────────────
echo "[2/6] Initialising Vault (5 key shares, threshold 3)..."
vault operator init \
  -key-shares=5 \
  -key-threshold=3 \
  -format=json > "${KEYS_FILE}"

echo "      Init complete. Raw keys written to ${KEYS_FILE}"
echo "      DO NOT leave this file on disk after this script completes."

# ── Step 3: Parse keys and root token ────────────────────────────────────────
ROOT_TOKEN=$(jq -r '.root_token' "${KEYS_FILE}")
UNSEAL_KEY_1=$(jq -r '.unseal_keys_b64[0]' "${KEYS_FILE}")
UNSEAL_KEY_2=$(jq -r '.unseal_keys_b64[1]' "${KEYS_FILE}")
UNSEAL_KEY_3=$(jq -r '.unseal_keys_b64[2]' "${KEYS_FILE}")
UNSEAL_KEY_4=$(jq -r '.unseal_keys_b64[3]' "${KEYS_FILE}")
UNSEAL_KEY_5=$(jq -r '.unseal_keys_b64[4]' "${KEYS_FILE}")

# ── Step 4: Encrypt each key for its custodian ───────────────────────────────
echo "[3/6] Encrypting key shares for each custodian..."

echo "${UNSEAL_KEY_1}" | gpg --encrypt --recipient "${CUSTODIAN_1_GPG_ID}" \
  --output "${ENCRYPTED_DIR}/key-share-1.gpg" --yes
echo "${UNSEAL_KEY_2}" | gpg --encrypt --recipient "${CUSTODIAN_1_GPG_ID}" \
  --output "${ENCRYPTED_DIR}/key-share-2-for-custodian1.gpg" --yes
echo "${UNSEAL_KEY_3}" | gpg --encrypt --recipient "${CUSTODIAN_2_GPG_ID}" \
  --output "${ENCRYPTED_DIR}/key-share-3-for-custodian2.gpg" --yes
echo "${UNSEAL_KEY_4}" | gpg --encrypt --recipient "${CUSTODIAN_2_GPG_ID}" \
  --output "${ENCRYPTED_DIR}/key-share-4-for-custodian2.gpg" --yes
echo "${UNSEAL_KEY_5}" | gpg --encrypt --recipient "${CUSTODIAN_3_GPG_ID}" \
  --output "${ENCRYPTED_DIR}/key-share-5-for-custodian3.gpg" --yes

# Root token encrypted for all 3 custodians
echo "${ROOT_TOKEN}" | gpg \
  --encrypt \
  --recipient "${CUSTODIAN_1_GPG_ID}" \
  --recipient "${CUSTODIAN_2_GPG_ID}" \
  --recipient "${CUSTODIAN_3_GPG_ID}" \
  --output "${ENCRYPTED_DIR}/root-token.gpg" --yes

echo "      Encrypted shares written to ${ENCRYPTED_DIR}"

# ── Step 5: Unseal vault-0, vault-1, vault-2 with threshold (3) keys ─────────
echo "[4/6] Unsealing all 3 Vault pods..."

for POD in vault-0 vault-1 vault-2; do
  echo "      Unsealing ${POD}..."
  kubectl exec -n vault "${POD}" -- \
    vault operator unseal -tls-skip-verify "${UNSEAL_KEY_1}" > /dev/null
  kubectl exec -n vault "${POD}" -- \
    vault operator unseal -tls-skip-verify "${UNSEAL_KEY_2}" > /dev/null
  kubectl exec -n vault "${POD}" -- \
    vault operator unseal -tls-skip-verify "${UNSEAL_KEY_3}" > /dev/null
  echo "      ${POD} unsealed."
done

# ── Step 6: Bootstrap Vault (login, enable secrets engines, audit) ────────────
echo "[5/6] Bootstrapping Vault configuration..."
export VAULT_TOKEN="${ROOT_TOKEN}"

# Enable KV v2 at secret/
vault secrets enable -path=secret kv-v2

# Enable audit file sink
vault audit enable file file_path=/vault/audit/vault-audit.log log_raw=false

echo "      KV v2 and audit log enabled."

# ── Step 7: Apply policies and Kubernetes auth (idempotent setup script) ──────
echo "[6/6] Enabling Kubernetes auth method..."
vault auth enable kubernetes || true
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc" \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  token_reviewer_jwt="$(kubectl create token vault -n vault --duration=8760h)"

echo ""
echo "=== Ceremony complete ==="
echo ""
echo "IMPORTANT POST-CEREMONY STEPS:"
echo "1. Copy ${ENCRYPTED_DIR}/ to secure offline storage NOW."
echo "2. Each custodian must receive their .gpg file via secure channel."
echo "3. Delete ${CEREMONY_DIR} from this machine: rm -rf ${CEREMONY_DIR}"
echo "4. Revoke the root token after initial policy setup:"
echo "   VAULT_TOKEN=${ROOT_TOKEN} vault token revoke ${ROOT_TOKEN}"
echo "5. Record ceremony in the ops runbook with:"
echo "   - Date, operator names, cluster name"
echo "   - Encrypted key file SHA256 checksums"
echo ""
echo "Key share checksums (verify these match your offline copies):"
for f in "${ENCRYPTED_DIR}"/*.gpg; do
  sha256sum "${f}"
done
echo ""
echo "DO NOT store the root token or plain-text keys anywhere."
