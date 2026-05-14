# Vault Initialisation & Unseal Key Ceremony Runbook

## Overview

This document describes the one-time initialisation ceremony for the ContextMesh
HashiCorp Vault HA cluster and the ongoing unseal procedure for pod restarts.

---

## Pre-conditions

Before running the ceremony:

1. All 3 Vault pods (`vault-0`, `vault-1`, `vault-2`) must be in `Running` state
   but will show `0/1 Ready` (Vault is sealed and uninitialised — expected).
2. TLS secret `vault-tls` must exist in the `vault` namespace (created by cert-manager).
3. Three key custodians must be physically present or reachable via secure channel.
   Each must have their GPG public key already imported on the operator's machine.
4. Operator holds a short-lived admin kubeconfig for this cluster only.
5. The ceremony machine must NOT be connected to untrusted networks.

---

## Key Share Design

| Parameter | Value | Rationale |
|---|---|---|
| Key shares | 5 | Each custodian holds at least 1, no single holder can unseal |
| Threshold | 3 | Any 3 of 5 can unseal; tolerates 2 custodian unavailability |
| Distribution | GPG-encrypted per custodian | Keys never transmitted in plain text |

Custodian assignment:
- Custodian 1 (Alice): key shares 1 + 2
- Custodian 2 (Bob): key shares 3 + 4
- Custodian 3 (Carol): key share 5

Any two custodians can unseal (custodian 1 provides 2 keys, any other provides 1).

---

## Ceremony Steps

### Step 1 — Verify Vault is uninitialised

```bash
kubectl exec -n vault vault-0 -- vault status
# Expected: Initialized: false, Sealed: true
```

### Step 2 — Port-forward vault-0

```bash
kubectl port-forward -n vault vault-0 8200:8200 &
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_CACERT=/path/to/vault-ca.crt
```

### Step 3 — Run the ceremony script

```bash
VAULT_ADDR=https://127.0.0.1:8200 \
VAULT_CACERT=/path/to/vault-ca.crt \
CUSTODIAN_1_GPG_ID=alice@example.com \
CUSTODIAN_2_GPG_ID=bob@example.com \
CUSTODIAN_3_GPG_ID=carol@example.com \
bash infra/k8s/vault/vault-init-ceremony.sh \
  --i-understand-this-is-a-one-time-operation
```

The script:
1. Calls `vault operator init -key-shares=5 -key-threshold=3`
2. Encrypts each key share with the corresponding custodian's GPG key
3. Unseals all 3 pods with keys 1, 2, 3 (threshold met)
4. Enables KV v2 and the audit file sink
5. Enables Kubernetes auth method

### Step 4 — Distribute encrypted key files

Each custodian receives their `.gpg` file via a **separate, secure channel**
(Signal, encrypted email, or physical USB hand-off):

```
Alice  → key-share-1.gpg, key-share-2-for-custodian1.gpg
Bob    → key-share-3-for-custodian2.gpg, key-share-4-for-custodian2.gpg
Carol  → key-share-5-for-custodian3.gpg
All 3  → root-token.gpg (encrypted for all three)
```

### Step 5 — Record SHA256 checksums in this runbook

```
# Paste output from ceremony script here:
<sha256_of_each_gpg_file>
```

### Step 6 — Run the auth + policy setup script

```bash
VAULT_ADDR=https://127.0.0.1:8200 \
VAULT_CACERT=/path/to/vault-ca.crt \
VAULT_TOKEN=<root_token> \
bash infra/k8s/vault/vault-k8s-auth-setup.sh
```

### Step 7 — Revoke the root token

```bash
vault token revoke <root_token>
vault token lookup <root_token>
# Expected: Code: 403. Errors: bad token
```

Root token is only needed again for break-glass scenarios. Custodians hold the
encrypted copy.

### Step 8 — Clean up ceremony machine

```bash
rm -rf /tmp/tmp.<ceremony_dir>
history -c
```

---

## Unseal Procedure (after pod restart or cluster reboot)

Vault auto-unseals are intentionally NOT configured. Each restart requires 3
custodians to supply their key shares.

```bash
# Collect decrypted keys from any 3 custodians, then:
kubectl exec -n vault vault-0 -- vault operator unseal <KEY_1>
kubectl exec -n vault vault-0 -- vault operator unseal <KEY_3>
kubectl exec -n vault vault-0 -- vault operator unseal <KEY_5>

kubectl exec -n vault vault-1 -- vault operator unseal <KEY_1>
kubectl exec -n vault vault-1 -- vault operator unseal <KEY_3>
kubectl exec -n vault vault-1 -- vault operator unseal <KEY_5>

kubectl exec -n vault vault-2 -- vault operator unseal <KEY_1>
kubectl exec -n vault vault-2 -- vault operator unseal <KEY_3>
kubectl exec -n vault vault-2 -- vault operator unseal <KEY_5>
```

Verify all three nodes are active:
```bash
kubectl exec -n vault vault-0 -- vault status
kubectl exec -n vault vault-1 -- vault status
kubectl exec -n vault vault-2 -- vault status
```

---

## Break-Glass (lost key shares)

If fewer than 3 custodians are available, Vault cannot be unsealed.
Recovery path: restore from the Raft snapshot backup.

Raft snapshots are taken daily by the CronJob in `infra/k8s/vault/vault-snapshot-cronjob.yaml`
and written to the S3 bucket defined in Terraform (`infra/terraform/`).

```bash
# Restore from snapshot (requires new init + 3 key shares from snapshot era):
vault operator raft snapshot restore <snapshot_file>
```

---

## Audit

Every secret access, login, and policy change is logged to `/vault/audit/vault-audit.log`
and shipped to Loki by the Promtail sidecar.

Query in Grafana:
```logql
{job="vault-audit"} | json | request_path != "" | line_format "{{.type}} {{.auth_display_name}} {{.request_operation}} {{.request_path}}"
```
