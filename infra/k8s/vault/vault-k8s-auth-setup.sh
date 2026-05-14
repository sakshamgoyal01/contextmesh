#!/usr/bin/env bash
# infra/k8s/vault/vault-k8s-auth-setup.sh
#
# Idempotent. Safe to re-run after Vault restarts.
# Run from within the cluster (or with a valid VAULT_TOKEN env var).
#
# Prerequisite: vault-init-ceremony.sh has completed and Vault is unsealed.
# Requires: vault CLI, kubectl on PATH, VAULT_TOKEN with policy-write capability.
#
# Usage:
#   VAULT_ADDR=https://vault.vault.svc:8200 \
#   VAULT_CACERT=/path/to/ca.crt \
#   VAULT_TOKEN=<root-or-admin-token> \
#   bash infra/k8s/vault/vault-k8s-auth-setup.sh

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-https://vault.vault.svc:8200}"
VAULT_CACERT="${VAULT_CACERT:?VAULT_CACERT must point to the Vault CA cert}"
VAULT_TOKEN="${VAULT_TOKEN:?VAULT_TOKEN must be set}"
export VAULT_ADDR VAULT_CACERT VAULT_TOKEN

echo "=== Vault Kubernetes Auth + Policy Setup ==="

# ── Ensure K8s auth is enabled ────────────────────────────────────────────────
vault auth enable kubernetes 2>/dev/null || echo "kubernetes auth already enabled"

# Re-configure in case the cluster rotated its service account signing key
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc"

# ── Helper: write policy and K8s auth role ───────────────────────────────────
# write_role <role_name> <namespace> <service_account> <policy_name> <policy_hcl>
write_role() {
  local role_name="$1"
  local namespace="$2"
  local sa="$3"
  local policy_name="$4"
  local policy_hcl="$5"

  echo "Writing policy: ${policy_name}"
  vault policy write "${policy_name}" - <<EOF
${policy_hcl}
EOF

  echo "Writing K8s auth role: ${role_name}"
  vault write "auth/kubernetes/role/${role_name}" \
    bound_service_account_names="${sa}" \
    bound_service_account_namespaces="${namespace}" \
    policies="${policy_name}" \
    ttl=1h \
    max_ttl=4h
}

# ─────────────────────────────────────────────────────────────────────────────
# INGESTION CRAWLERS
# ─────────────────────────────────────────────────────────────────────────────

write_role "crawler-k8s" "contextmesh-ingestion" "crawler-k8s" "contextmesh-crawler-k8s" '
# crawler-k8s: read Kafka credentials only
path "secret/data/kafka-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/kafka-credentials" {
  capabilities = ["read"]
}
'

write_role "crawler-iam" "contextmesh-ingestion" "crawler-iam" "contextmesh-crawler-iam" '
# crawler-iam: read AWS credentials for IAM API calls
path "secret/data/aws-iam-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/aws-iam-credentials" {
  capabilities = ["read"]
}
path "secret/data/kafka-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/kafka-credentials" {
  capabilities = ["read"]
}
'

write_role "crawler-cicd" "contextmesh-ingestion" "crawler-cicd" "contextmesh-crawler-cicd" '
# crawler-cicd: read GitHub webhook secret and Kafka credentials
path "secret/data/github-webhook-secret" {
  capabilities = ["read"]
}
path "secret/metadata/github-webhook-secret" {
  capabilities = ["read"]
}
path "secret/data/kafka-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/kafka-credentials" {
  capabilities = ["read"]
}
'

write_role "crawler-secrets" "contextmesh-ingestion" "crawler-secrets" "contextmesh-crawler-secrets" '
# crawler-secrets: list Vault metadata paths (never reads secret values)
path "secret/metadata/*" {
  capabilities = ["list", "read"]
}
path "secret/data/kafka-credentials" {
  capabilities = ["read"]
}
'

# ─────────────────────────────────────────────────────────────────────────────
# GRAPH SERVICES
# ─────────────────────────────────────────────────────────────────────────────

write_role "graph-consumer" "contextmesh-graph" "graph-consumer" "contextmesh-graph-consumer" '
path "secret/data/postgres-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/postgres-credentials" {
  capabilities = ["read"]
}
path "secret/data/kafka-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/kafka-credentials" {
  capabilities = ["read"]
}
path "secret/data/redis-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/redis-credentials" {
  capabilities = ["read"]
}
'

write_role "trust-scorer" "contextmesh-graph" "trust-scorer" "contextmesh-trust-scorer" '
path "secret/data/postgres-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/postgres-credentials" {
  capabilities = ["read"]
}
path "secret/data/kafka-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/kafka-credentials" {
  capabilities = ["read"]
}
'

write_role "drift-detector" "contextmesh-graph" "drift-detector" "contextmesh-drift-detector" '
path "secret/data/postgres-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/postgres-credentials" {
  capabilities = ["read"]
}
path "secret/data/kafka-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/kafka-credentials" {
  capabilities = ["read"]
}
'

# ─────────────────────────────────────────────────────────────────────────────
# AGENTS
# ─────────────────────────────────────────────────────────────────────────────

write_role "context-agent" "contextmesh-agents" "context-agent" "contextmesh-context-agent" '
path "secret/data/postgres-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/postgres-credentials" {
  capabilities = ["read"]
}
path "secret/data/openai-api-key" {
  capabilities = ["read"]
}
path "secret/metadata/openai-api-key" {
  capabilities = ["read"]
}
'

write_role "drift-agent" "contextmesh-agents" "drift-agent" "contextmesh-drift-agent" '
path "secret/data/postgres-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/postgres-credentials" {
  capabilities = ["read"]
}
path "secret/data/kafka-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/kafka-credentials" {
  capabilities = ["read"]
}
path "secret/data/openai-api-key" {
  capabilities = ["read"]
}
path "secret/metadata/openai-api-key" {
  capabilities = ["read"]
}
'

write_role "remediation-agent" "contextmesh-agents" "remediation-agent" "contextmesh-remediation-agent" '
path "secret/data/github-app-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/github-app-credentials" {
  capabilities = ["read"]
}
path "secret/data/slack-webhook-url" {
  capabilities = ["read"]
}
path "secret/metadata/slack-webhook-url" {
  capabilities = ["read"]
}
path "secret/data/openai-api-key" {
  capabilities = ["read"]
}
path "secret/metadata/openai-api-key" {
  capabilities = ["read"]
}
'

# ─────────────────────────────────────────────────────────────────────────────
# API
# ─────────────────────────────────────────────────────────────────────────────

write_role "trust-api" "contextmesh-api" "trust-api" "contextmesh-trust-api" '
path "secret/data/postgres-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/postgres-credentials" {
  capabilities = ["read"]
}
path "secret/data/jwt-rs256-private-key" {
  capabilities = ["read"]
}
path "secret/metadata/jwt-rs256-private-key" {
  capabilities = ["read"]
}
path "secret/data/redis-credentials" {
  capabilities = ["read"]
}
path "secret/metadata/redis-credentials" {
  capabilities = ["read"]
}
'

# ─────────────────────────────────────────────────────────────────────────────
# Seed placeholder secrets so services can start
# (replace values before production)
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "Seeding placeholder secrets (replace with real values before workloads start)..."

vault kv put secret/kafka-credentials \
  bootstrap_servers="kafka.kafka.svc:9092" \
  ssl_cafile="REPLACE_ME" \
  ssl_certfile="REPLACE_ME" \
  ssl_keyfile="REPLACE_ME"

vault kv put secret/postgres-credentials \
  host="postgres-rw.contextmesh-graph.svc" \
  port="5432" \
  database="contextmesh" \
  username="contextmesh" \
  password="REPLACE_ME" #pragma: allowlist secret`

vault kv put secret/redis-credentials \
  host="redis-master.contextmesh-graph.svc" \
  port="6379" \
  password="REPLACE_ME" #pragma: allowlist secret`

vault kv put secret/openai-api-key \
  api_key="REPLACE_ME" #pragma: allowlist secret`

vault kv put secret/github-webhook-secret \
  secret="REPLACE_ME" #pragma: allowlist secret`

vault kv put secret/github-app-credentials \
  app_id="REPLACE_ME" \
  installation_id="REPLACE_ME" \
  private_key_pem="REPLACE_ME" #pragma: allowlist secret`

vault kv put secret/slack-webhook-url \
  url="REPLACE_ME"

vault kv put secret/jwt-rs256-private-key \
  private_key_pem="REPLACE_ME" public_key_pem="REPLACE_ME" #pragma: allowlist secret`

vault kv put secret/aws-iam-credentials \
  aws_access_key_id="REPLACE_ME" \
  aws_secret_access_key="REPLACE_ME" aws_region="us-east-1" #pragma: allowlist secret`

echo ""
echo "=== Auth setup complete ==="
echo "Verify with: vault auth list && vault policy list"
