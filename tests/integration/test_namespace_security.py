"""
tests/integration/test_namespace_security.py

Asserts:
- All 7 contextmesh namespaces exist
- Every namespace has a ResourceQuota
- Every namespace has a LimitRange
- PSA labels are set to the correct level (restricted / baseline)
- No ClusterRole uses wildcard verbs ("*")
- No ClusterRole uses wildcard resources ("*") unless it is a known system role
- All ServiceAccounts created by ContextMesh have automountServiceAccountToken=false

Run:
    pytest tests/integration/test_namespace_security.py -v
Pre-requisite:
    KUBECONFIG must point to a cluster where the manifests have been applied.
    pip install kubernetes pytest
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CONTEXTMESH_NAMESPACES = [
    "contextmesh-system",
    "contextmesh-ingestion",
    "contextmesh-graph",
    "contextmesh-agents",
    "contextmesh-api",
    "monitoring",
    "vault",
]

RESTRICTED_NAMESPACES = [
    "contextmesh-system",
    "contextmesh-ingestion",
    "contextmesh-graph",
    "contextmesh-agents",
    "contextmesh-api",
    "vault",
]

BASELINE_NAMESPACES = ["monitoring"]

# ServiceAccounts created by ContextMesh manifests (namespace → [sa names])
CONTEXTMESH_SERVICE_ACCOUNTS: dict[str, list[str]] = {
    "contextmesh-ingestion": ["crawler-k8s", "crawler-iam", "crawler-cicd", "crawler-secrets"],
    "contextmesh-graph": ["graph-consumer", "trust-scorer", "drift-detector"],
    "contextmesh-agents": ["context-agent", "drift-agent", "remediation-agent"],
    "contextmesh-api": ["trust-api"],
    "contextmesh-system": ["argocd-app-watcher"],
}

# ClusterRoles that ContextMesh owns — these must not have wildcard verbs
CONTEXTMESH_CLUSTER_ROLE_PREFIXES = ("contextmesh:",)


@pytest.fixture(scope="session")
def k8s_clients() -> dict[str, Any]:
    """Load kubeconfig and return API clients."""
    kubeconfig = os.environ.get("KUBECONFIG")
    if kubeconfig:
        config.load_kube_config(config_file=kubeconfig)
    else:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

    return {
        "core": client.CoreV1Api(),
        "rbac": client.RbacAuthorizationV1Api(),
    }


# ---------------------------------------------------------------------------
# Task 1 — Namespaces exist
# ---------------------------------------------------------------------------


class TestNamespacesExist:
    def test_all_contextmesh_namespaces_present(self, k8s_clients: dict[str, Any]) -> None:
        core: client.CoreV1Api = k8s_clients["core"]
        existing = {ns.metadata.name for ns in core.list_namespace().items}
        missing = [ns for ns in CONTEXTMESH_NAMESPACES if ns not in existing]
        assert not missing, f"Missing namespaces: {missing}"


# ---------------------------------------------------------------------------
# Task 3 — ResourceQuota and LimitRange present in every namespace
# ---------------------------------------------------------------------------


class TestResourceQuotaAndLimitRange:
    @pytest.mark.parametrize("namespace", CONTEXTMESH_NAMESPACES)
    def test_resource_quota_exists(self, k8s_clients: dict[str, Any], namespace: str) -> None:
        core: client.CoreV1Api = k8s_clients["core"]
        quotas = core.list_namespaced_resource_quota(namespace=namespace)
        assert quotas.items, (
            f"Namespace '{namespace}' has no ResourceQuota. "
            "Every namespace must have CPU/memory ceilings."
        )

    @pytest.mark.parametrize("namespace", CONTEXTMESH_NAMESPACES)
    def test_resource_quota_has_cpu_and_memory(
        self, k8s_clients: dict[str, Any], namespace: str
    ) -> None:
        core: client.CoreV1Api = k8s_clients["core"]
        quotas = core.list_namespaced_resource_quota(namespace=namespace)
        for quota in quotas.items:
            hard: dict[str, str] = quota.spec.hard or {}
            assert (
                "limits.cpu" in hard
            ), f"ResourceQuota '{quota.metadata.name}' in '{namespace}' missing limits.cpu"
            assert (
                "limits.memory" in hard
            ), f"ResourceQuota '{quota.metadata.name}' in '{namespace}' missing limits.memory"
            assert (
                "requests.cpu" in hard
            ), f"ResourceQuota '{quota.metadata.name}' in '{namespace}' missing requests.cpu"
            assert (
                "requests.memory" in hard
            ), f"ResourceQuota '{quota.metadata.name}' in '{namespace}' missing requests.memory"

    @pytest.mark.parametrize("namespace", CONTEXTMESH_NAMESPACES)
    def test_limit_range_exists(self, k8s_clients: dict[str, Any], namespace: str) -> None:
        core: client.CoreV1Api = k8s_clients["core"]
        limit_ranges = core.list_namespaced_limit_range(namespace=namespace)
        assert limit_ranges.items, (
            f"Namespace '{namespace}' has no LimitRange. " "Default container limits must be set."
        )

    @pytest.mark.parametrize("namespace", CONTEXTMESH_NAMESPACES)
    def test_limit_range_has_container_defaults(
        self, k8s_clients: dict[str, Any], namespace: str
    ) -> None:
        core: client.CoreV1Api = k8s_clients["core"]
        limit_ranges = core.list_namespaced_limit_range(namespace=namespace)
        for lr in limit_ranges.items:
            container_limits = [lim for lim in (lr.spec.limits or []) if lim.type == "Container"]
            assert (
                container_limits
            ), f"LimitRange '{lr.metadata.name}' in '{namespace}' has no Container limits"
            for container_limit in container_limits:
                assert container_limit.default, (
                    f"LimitRange '{lr.metadata.name}' in '{namespace}' "
                    "missing default (cpu/memory will be unbounded)"
                )
                assert container_limit.default_request, (
                    f"LimitRange '{lr.metadata.name}' in '{namespace}' " "missing defaultRequest"
                )


# ---------------------------------------------------------------------------
# Task 4 — PodSecurityAdmission labels
# ---------------------------------------------------------------------------


class TestPodSecurityAdmission:
    @pytest.mark.parametrize("namespace", RESTRICTED_NAMESPACES)
    def test_restricted_psa_enforce_label(
        self, k8s_clients: dict[str, Any], namespace: str
    ) -> None:
        core: client.CoreV1Api = k8s_clients["core"]
        ns = core.read_namespace(name=namespace)
        labels: dict[str, str] = ns.metadata.labels or {}
        enforce = labels.get("pod-security.kubernetes.io/enforce")
        assert (
            enforce == "restricted"
        ), f"Namespace '{namespace}' must have PSA enforce=restricted, got '{enforce}'"

    @pytest.mark.parametrize("namespace", BASELINE_NAMESPACES)
    def test_baseline_psa_enforce_label(self, k8s_clients: dict[str, Any], namespace: str) -> None:
        core: client.CoreV1Api = k8s_clients["core"]
        ns = core.read_namespace(name=namespace)
        labels: dict[str, str] = ns.metadata.labels or {}
        enforce = labels.get("pod-security.kubernetes.io/enforce")
        assert (
            enforce == "baseline"
        ), f"Namespace '{namespace}' must have PSA enforce=baseline, got '{enforce}'"

    @pytest.mark.parametrize("namespace", CONTEXTMESH_NAMESPACES)
    def test_psa_version_label_set(self, k8s_clients: dict[str, Any], namespace: str) -> None:
        core: client.CoreV1Api = k8s_clients["core"]
        ns = core.read_namespace(name=namespace)
        labels: dict[str, str] = ns.metadata.labels or {}
        version = labels.get("pod-security.kubernetes.io/enforce-version")
        assert (
            version is not None
        ), f"Namespace '{namespace}' missing pod-security.kubernetes.io/enforce-version label"


# ---------------------------------------------------------------------------
# Task 2 — RBAC: no wildcard verbs/resources in ContextMesh ClusterRoles
# ---------------------------------------------------------------------------


class TestRBACNoWildcards:
    def _contextmesh_cluster_roles(self, rbac: client.RbacAuthorizationV1Api) -> list[Any]:
        all_roles = rbac.list_cluster_role().items
        return [
            role
            for role in all_roles
            if any(
                (role.metadata.name or "").startswith(prefix)
                for prefix in CONTEXTMESH_CLUSTER_ROLE_PREFIXES
            )
        ]

    def test_no_wildcard_verbs_in_contextmesh_cluster_roles(
        self, k8s_clients: dict[str, Any]
    ) -> None:
        rbac: client.RbacAuthorizationV1Api = k8s_clients["rbac"]
        offenders: list[str] = []
        for role in self._contextmesh_cluster_roles(rbac):
            for rule in role.rules or []:
                if "*" in (rule.verbs or []):
                    offenders.append(f"ClusterRole '{role.metadata.name}' has wildcard verb '*'")
        assert not offenders, "\n".join(offenders)

    def test_no_wildcard_resources_in_contextmesh_cluster_roles(
        self, k8s_clients: dict[str, Any]
    ) -> None:
        rbac: client.RbacAuthorizationV1Api = k8s_clients["rbac"]
        offenders: list[str] = []
        for role in self._contextmesh_cluster_roles(rbac):
            for rule in role.rules or []:
                if "*" in (rule.resources or []):
                    offenders.append(
                        f"ClusterRole '{role.metadata.name}' has wildcard resource '*'"
                    )
        assert not offenders, "\n".join(offenders)

    def test_no_wildcard_verbs_in_namespace_roles(self, k8s_clients: dict[str, Any]) -> None:
        rbac: client.RbacAuthorizationV1Api = k8s_clients["rbac"]
        offenders: list[str] = []
        for namespace in CONTEXTMESH_NAMESPACES:
            for role in rbac.list_namespaced_role(namespace=namespace).items:
                for rule in role.rules or []:
                    if "*" in (rule.verbs or []):
                        offenders.append(
                            f"Role '{role.metadata.name}' in '{namespace}' has wildcard verb '*'"
                        )
        assert not offenders, "\n".join(offenders)


# ---------------------------------------------------------------------------
# Task 2 — ServiceAccount tokens not auto-mounted
# ---------------------------------------------------------------------------


class TestServiceAccountTokens:
    @pytest.mark.parametrize(
        "namespace,sa_name",
        [(ns, sa) for ns, sa_list in CONTEXTMESH_SERVICE_ACCOUNTS.items() for sa in sa_list],
    )
    def test_service_account_exists(
        self, k8s_clients: dict[str, Any], namespace: str, sa_name: str
    ) -> None:
        core: client.CoreV1Api = k8s_clients["core"]
        try:
            core.read_namespaced_service_account(name=sa_name, namespace=namespace)
        except ApiException as exc:
            pytest.fail(f"ServiceAccount '{sa_name}' not found in '{namespace}': {exc.reason}")

    @pytest.mark.parametrize(
        "namespace,sa_name",
        [(ns, sa) for ns, sa_list in CONTEXTMESH_SERVICE_ACCOUNTS.items() for sa in sa_list],
    )
    def test_automount_service_account_token_disabled(
        self, k8s_clients: dict[str, Any], namespace: str, sa_name: str
    ) -> None:
        core: client.CoreV1Api = k8s_clients["core"]
        sa = core.read_namespaced_service_account(name=sa_name, namespace=namespace)
        assert sa.automount_service_account_token is False, (
            f"ServiceAccount '{sa_name}' in '{namespace}' "
            "must have automountServiceAccountToken=false"
        )


# ---------------------------------------------------------------------------
# Task 5 — Running pods are non-root
# (Only meaningful once workloads are deployed; skips if namespace is empty)
# ---------------------------------------------------------------------------


class TestPodsRunAsNonRoot:
    @pytest.mark.parametrize("namespace", CONTEXTMESH_NAMESPACES)
    def test_no_pods_run_as_root(self, k8s_clients: dict[str, Any], namespace: str) -> None:
        core: client.CoreV1Api = k8s_clients["core"]
        pods = core.list_namespaced_pod(namespace=namespace).items
        if not pods:
            pytest.skip(f"No pods in '{namespace}' — skipping runtime check")

        offenders: list[str] = []
        for pod in pods:
            pod_name = pod.metadata.name
            pod_sc = pod.spec.security_context or client.V1PodSecurityContext()

            for container in pod.spec.containers:
                c_sc = container.security_context or client.V1ContainerSecurityContext()

                # runAsNonRoot must be True at container level OR pod level
                runs_as_non_root = c_sc.run_as_non_root or pod_sc.run_as_non_root
                if not runs_as_non_root:
                    offenders.append(
                        f"pod/{pod_name} container/{container.name} "
                        f"in '{namespace}': runAsNonRoot not set"
                    )

                # runAsUser 0 is explicitly root — never allowed
                if c_sc.run_as_user == 0:
                    offenders.append(
                        f"pod/{pod_name} container/{container.name} "
                        f"in '{namespace}': runAsUser=0 (root)"
                    )
                if pod_sc.run_as_user == 0:
                    offenders.append(
                        f"pod/{pod_name} in '{namespace}': pod-level runAsUser=0 (root)"
                    )

                # allowPrivilegeEscalation must be false
                if c_sc.allow_privilege_escalation is not False:
                    offenders.append(
                        f"pod/{pod_name} container/{container.name} "
                        f"in '{namespace}': allowPrivilegeEscalation not explicitly false"
                    )

                # readOnlyRootFilesystem must be true
                if not c_sc.read_only_root_filesystem:
                    offenders.append(
                        f"pod/{pod_name} container/{container.name} "
                        f"in '{namespace}': readOnlyRootFilesystem not true"
                    )

        assert not offenders, f"Found {len(offenders)} security violations:\n" + "\n".join(
            offenders
        )
