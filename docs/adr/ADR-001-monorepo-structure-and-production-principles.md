
# ADR-001: Monorepo Structure, Tool Choices, and Production Principles

**Status:** Accepted
**Date:** 2025-01-13
**Authors:** ContextMesh Platform Team

---

## Context

ContextMesh has 7 services, 3 agents, 1 API, and 1 frontend — all deeply coupled
through shared Avro schemas, a common Vault client, and a single Kafka event bus.
We need a repository strategy and a baseline set of engineering constraints that
are enforced structurally from day one, not added as guidelines after the first
incident.

The platform handles live infrastructure credentials, IAM role relationships, and
Vault secret metadata. A single leaked secret or untyped function returning None
in the trust scorer can silently produce wrong trust scores, which AI agents then
act on. The toolchain must make the wrong thing hard to do.

---

## Decision 1: Monorepo

We use a single Git repository with explicit per-service boundaries.

**Structure:**
```
contextmesh/
├── infra/          # All K8s manifests and Terraform — no kubectl apply in prod
├── services/       # 7 backend services, each independently deployable
├── agents/         # 3 LangChain agents
├── api/            # FastAPI trust-api
├── dashboard/      # React + Vite frontend
├── shared/         # vault_client, kafka_base, observability, graph_client
├── tests/          # unit / integration / e2e / chaos / eval
└── docs/           # ADRs, runbooks, architecture diagrams
```

**Why monorepo:**

Cross-service changes are atomic. When the BaseEntityEvent Avro schema gains a
field, the crawler that produces it, the consumer that reads it, and the trust
scorer that processes it change in one PR. A polyrepo makes this three coordinated
PRs with no atomicity guarantee.

Shared modules stay in sync. `shared/vault_client.py` is imported by all 7
services. In a polyrepo, version drift between services is guaranteed within weeks.

One pre-commit config enforces uniform standards across every file in every
service. No service can opt out.

ArgoCD reads from one source of truth. Every ArgoCD Application manifest points
to a path inside this repo.

**Trade-offs accepted:**

CI pipelines use path-based filtering (`dorny/paths-filter`) so a change to
`services/crawler-k8s/` does not rebuild all 11 services. The tooling complexity
is accepted; the consistency benefit outweighs it.

Per-service `pyproject.toml` files manage Python dependencies independently. The
root `pyproject.toml` is for shared tooling only (black, ruff, mypy, pytest).

**What we ruled out:**

Polyrepo — atomic cross-service changes impossible, shared module drift guaranteed,
pre-commit enforcement fragmented.

---

## Decision 2: Pre-commit Gates

Every commit passes 11 hooks in this exact order. `fail_fast: true` — first
failure stops the chain. Secrets never reach git history under any scenario.

| Order | Hook | Blocks |
|---|---|---|
| 1 | gitleaks | Hardcoded secrets, API keys, private keys, Vault tokens |
| 2 | detect-secrets | Entropy-based detection of anything gitleaks misses |
| 3 | pre-commit-hooks | Trailing whitespace, YAML/JSON/TOML syntax, merge conflicts, files >500KB, LF endings |
| 4 | black | Python formatting — zero config debates |
| 5 | ruff | Lint, import sort, no print statements, type annotation enforcement |
| 6 | mypy | Strict type checking — disallow_untyped_defs, warn_return_any |
| 7 | hadolint | Dockerfile: non-root, no latest tags, COPY not ADD |
| 8 | yamllint | K8s manifest YAML correctness |
| 9 | shellcheck | Shell script correctness |
| 10 | conventional-pre-commit | Commit message format: feat/fix/docs/infra/sec/... |

**Why secrets gates run first:**

A later hook failure reveals no sensitive information. A secrets gate that runs
after a network-touching hook could log the secret in CI output. Ordering is
security policy, not convenience.

**Why mypy runs in pre-commit:**

Catching a type error at commit time costs 4 seconds. Catching it in production
costs hours of incident response. ContextMesh processes live infrastructure state
— a `None` not caught by the type checker produces an incorrect trust score,
which AI agents then act on autonomously. That chain of consequences starts with
a missing type hint.

---

## Decision 3: Tech Stack

| Component | Choice | Version | Why |
|---|---|---|---|
| Graph DB | Apache Age on PostgreSQL | PG 16 + Age 1.5 | Single DB for relational + graph. No separate Neo4j to operate. CloudNativePG handles HA, failover, WAL archiving. Cypher queries work unchanged. |
| Message bus | Apache Kafka | 3.7 | Durable, replayable event log is the source of truth for all graph writes. Schema registry enforces Avro contract between producers and consumers. |
| Secrets | HashiCorp Vault | 1.15 HA Raft | Native K8s auth, dynamic secrets, lease rotation. Raft eliminates Consul dependency. Vault Agent sidecar handles token renewal. |
| Orchestration | MicroK8s | 1.29 | Full K8s semantics on bare metal. All manifests are portable to EKS/GKE without changes. |
| Policy engine | OPA Gatekeeper | 3.15 | Admission webhook — no application-layer workaround can bypass it. |
| Agent framework | LangChain | 0.2.x | ReAct pattern gives observable intermediate steps. Tool registry is independently testable. |
| LLM | GPT-4o | — | Circuit breaker: 3 consecutive API failures → degraded mode → cached answer with staleness warning. |
| API | FastAPI + Strawberry | 0.111 + 0.227 | Async, typed, OpenAPI spec generated automatically. |
| Frontend | React + Vite + TypeScript + Tailwind | 18 + 5 + 5 + 3 | — |
| IaC | Terraform | 1.8 | AWS IAM roles for crawlers, S3 for WAL archiving. |
| Python | 3.12 | — | `tomllib` in stdlib, improved async performance, better error messages. |

**What we ruled out:**

Neo4j — separate database to operate and scale. CloudNativePG + Age gives the
same Cypher queries with PostgreSQL operational maturity.

Offset pagination — row offsets shift when entities are inserted during a page
walk. A crawl that takes 30 seconds can miss entities or return duplicates.
Cursor pagination is stable under concurrent writes. Cursor = base64(entity_id +
timestamp).

Environment variables for secrets — env vars leak into process lists, container
inspection output, and crash dumps. Vault is not optional.

`kubectl apply` in production — direct cluster writes bypass ArgoCD's audit trail.
Every manifest change flows through GitOps.

---

## Decision 4: Production Principles

These are structural constraints. Any PR that violates them is rejected regardless
of test coverage or review approval count.

### Secrets

Vault is the only secret store. No secrets in environment variables. No secrets
in Kubernetes Secrets objects (Vault Agent Injector injects them as in-memory
files). No secrets in ConfigMaps.

`shared/vault_client.py` is the only interface for secret retrieval across all
services. Services never call Vault directly.

### Container security

Every container in every manifest must have:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

No `hostNetwork`, `hostPID`, or `hostIPC`. OPA Gatekeeper enforces this at
admission time — a manifest without these fields never reaches the cluster.

### Resource limits

Every container declares `resources.requests` and `resources.limits`.
Gatekeeper rejects pods without them. No limit = one misbehaving pod can
starve the entire node.

### Testing

Tests are written the same day as the code. No PR merges untested code.

- Unit tests: all external I/O mocked. Pure function correctness.
- Integration tests: real Kafka, real Postgres, real Vault in test namespace.
- E2E tests: full stack against seeded cluster.
- Agent eval: 50 golden scenarios. Pass rate < 90% blocks the PR.
- Coverage floor: 80% across services, agents, api, shared.

### Data integrity

All Kafka events validated against Avro schema before produce and after consume.

All DB writes are idempotent. `event_id = sha256(entity_type + entity_id +
observed_at)`. Same event arriving from two crawlers simultaneously = one graph
write.

All database queries use parameterised statements. No f-strings in SQL.

All graph node writes use optimistic locking (`version` counter). Concurrent
crawler updates do not corrupt graph state.

### API security

JWT RS256 on all endpoints. Two scopes: `read:context` for all GET endpoints,
`write:remediation` for POST /v1/agents/remediate only.

Rate limits: 100 req/min (read), 10 req/min (write). Enforced at ingress.

Remediation gate: any action affecting >5 resources OR trust delta >0.4 requires
Slack approval before execution. A ConfirmationToken is generated, sent to Slack,
and must be returned to the API before the action proceeds. Wrong infrastructure
change is worse than no change.

### GitOps

ArgoCD is the only production deployment mechanism. No `kubectl apply` except
`--dry-run` for manifest validation. Every manifest change is a git commit,
reviewed, and synced by ArgoCD. The audit trail is the git log.

### Observability

Structured logging via structlog in all services. No `print()`. Every log event
is JSON with `service`, `trace_id`, `span_id`, `level`, and entity context fields.

OpenTelemetry traces on all service-to-service calls and all Kafka
produce/consume operations.

Prometheus metrics at `/metrics` on every service. Grafana dashboards committed
to `infra/k8s/monitoring/`.

### Audit trail

Every state-changing API call is written to an audit log table with a hash chain.
Each row's hash includes the previous row's hash. Any modification to a historical
row breaks the chain and is detectable. No external dependency required —
tamper-evidence lives in Postgres.

---

## Consequences

- All engineers install pre-commit, gitleaks, hadolint, and detect-secrets before
  their first commit. CI runs the same hooks — a commit that passes locally passes
  CI.
- The `.secrets.baseline` file is committed and updated whenever new non-secret
  strings trigger the detector.
- Any proposed exception to a production principle requires a new ADR documenting
  the rationale, mitigating controls, and expiry date of the exception. "We'll fix
  it later" is not an ADR.
- The Atlan interview bridge: ContextMesh builds the context and trust layer for
  infrastructure the same way Atlan builds it for data. The `/v1/atlan/enrich`
  endpoint is the same abstraction as Atlan's governance layer, one level below
  the data stack.

---

## References

- [CIS Kubernetes Benchmark v1.8](https://www.cisecurity.org/benchmark/kubernetes)
- [HashiCorp Vault Production Hardening](https://developer.hashicorp.com/vault/tutorials/operations/production-hardening)
- [OPA Gatekeeper Library](https://github.com/open-policy-agent/gatekeeper-library)
- [Apache AGE Documentation](https://age.apache.org/)
- [NIST SP 800-190 Container Security](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
```
