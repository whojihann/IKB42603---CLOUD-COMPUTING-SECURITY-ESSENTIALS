# IKB42603 Cloud Computing Security Essentials
## Lab 2 Report — Secure Isolation & Multi-Tenancy
### Compute, Network, and Storage Isolation

---

| Field | Details |
|---|---|
| **Course Code** | IKB42603 |
| **Lab Title** | Secure Isolation & Multi-Tenancy |
| **Sessions** | Session A (Week 3) — Compute Isolation · Session B (Week 4) — Network & Storage Isolation |
| **Environment** | Kali Linux · Docker Engine · kind (Kubernetes in Docker) · Calico CNI |
| **CLO** | Construct secure cloud operations that safeguard data integrity |

---

## Table of Contents

- [Section A — Lab Overview & Objectives](#section-a--lab-overview--objectives)
- [Section B — Technical Implementation & Evidence](#section-b--technical-implementation--evidence)
  - [Setup — Cluster with Policy Enforcement](#setup--cluster-with-policy-enforcement)
  - [Task 1 — Two Tenants on One Cluster](#task-1--two-tenants-on-one-cluster)
  - [Task 2 — Observe the Default-Open Risk](#task-2--observe-the-default-open-risk)
  - [Task 3 — Noisy Neighbour Containment via Resource Quotas](#task-3--noisy-neighbour-containment-via-resource-quotas)
  - [Task 4 — Default-Deny Network Isolation](#task-4--default-deny-network-isolation)
  - [Task 5 — Storage & Secret Isolation (RBAC Enforced)](#task-5--storage--secret-isolation-rbac-enforced)
  - [Task 6 — Data Remanence & Secure Deletion](#task-6--data-remanence--secure-deletion)
- [Section C — Short-Answer Analysis Questions](#section-c--short-answer-analysis-questions)
- [Section D — Verification & Cleanup](#section-d--verification--cleanup)

---

## Section A — Lab Overview & Objectives

### Lab Goals

This lab addresses a core challenge in shared cloud infrastructure: **multiple tenants running workloads on the same physical or virtual cluster while remaining logically and operationally isolated from one another**. The primary Course Learning Outcome (CLO) is to construct secure cloud operations that safeguard data integrity across all three isolation dimensions — compute, network, and storage.

The lab is structured across two sessions:

| Session | Week | Focus |
|---|---|---|
| Session A | Week 3 | Compute Isolation & the Default-Open Problem |
| Session B | Week 4 | Network & Storage Isolation |

Across both sessions, six tasks collectively demonstrate:

1. How Kubernetes namespaces create logical tenant boundaries.
2. Why default-open networking is a security liability in multi-tenant environments.
3. How `ResourceQuota` prevents a single tenant from exhausting shared compute resources.
4. How `NetworkPolicy` with a default-deny-ingress posture enforces Zero-Trust traffic control.
5. How Kubernetes RBAC restricts secret access to the owning namespace only.
6. How data remanence persists after naive deletion and how secure overwriting mitigates it.

### System Environment

The lab runs a local Kubernetes cluster bootstrapped with **kind** (Kubernetes in Docker). The default `kindnet` CNI is replaced with **Calico**, because `kindnet` does not enforce `NetworkPolicy` objects — Calico does.

```
Host OS    : Kali Linux
Container  : Docker Engine
Cluster    : kind v0.x (single-node or multi-node)
CNI        : Calico (replaces kindnet)
kubectl    : Standard Kubernetes CLI
```

> **Why Calico?** Kubernetes `NetworkPolicy` objects are API-level constructs. Without a CNI plugin that actively enforces them, the policies exist in etcd but have zero effect on traffic — meaning the cluster remains default-open regardless. Calico is one of the most widely deployed CNI plugins that provides full `NetworkPolicy` enforcement.

---

## Section B — Technical Implementation & Evidence

### Setup — Cluster with Policy Enforcement

Before any tenant workloads are deployed, a kind cluster is created with the default CNI disabled so Calico can be installed in its place.

#### Step 1 — Create the kind cluster with CNI override

```bash
# kind-config.yaml — disable kindnet so Calico can manage networking
cat <<EOF > kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true   # prevents kindnet from being installed
  podSubnet: "192.168.0.0/16"  # Calico default pod CIDR
nodes:
  - role: control-plane
  - role: worker
EOF

kind create cluster --config kind-config.yaml --name lab2
```

#### Step 2 — Install Calico CNI

```bash
# Apply the Calico operator manifest
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml

# Wait for all Calico pods to reach Running state
kubectl wait --namespace kube-system \
  --for=condition=ready pod \
  --selector=k8s-app=calico-node \
  --timeout=120s
```

#### Step 3 — Verify cluster health

```bash
kubectl get nodes
kubectl get pods -n kube-system
```

**Expected output:** All nodes show `Ready`; all `calico-*` pods show `Running`.

**Screenshots:**

![Setup - Cluster with Policy Enforcement 1](./Session%20A%20(Week%203)%20%E2%80%94%20Compute%20Isolation%20%26%20the%20Default-Open/Setup%20%E2%80%94%20Cluster%20with%20Policy%20Enforcement%201.0.png)

![Setup - Cluster with Policy Enforcement 2](./Session%20A%20(Week%203)%20%E2%80%94%20Compute%20Isolation%20%26%20the%20Default-Open/Setup%20%E2%80%94%20Cluster%20with%20Policy%20Enforcement%202.0.png)

![Setup - Cluster with Policy Enforcement 3](./Session%20A%20(Week%203)%20%E2%80%94%20Compute%20Isolation%20%26%20the%20Default-Open/Setup%20%E2%80%94%20Cluster%20with%20Policy%20Enforcement%203.0.png)

---

### Task 1 — Two Tenants on One Cluster

**Objective:** Create two logically isolated tenant namespaces (`tenant-a` and `tenant-b`) and deploy a representative web workload in each to simulate a shared-cluster multi-tenancy scenario.

#### Explanation

Kubernetes **namespaces** are the primary unit of logical isolation. They provide separate scopes for names, resource quotas, RBAC bindings, and — when combined with a NetworkPolicy-aware CNI — network policy enforcement. At this stage, namespaces are created and workloads are deployed; actual isolation controls are layered on in subsequent tasks.

#### Commands

```bash
# 1. Create the two tenant namespaces
kubectl create namespace tenant-a
kubectl create namespace tenant-b

# 2. Deploy an nginx web server in each namespace
kubectl create deployment web --image=nginx --namespace tenant-a
kubectl create deployment web --image=nginx --namespace tenant-b

# 3. Expose each deployment as a ClusterIP Service
kubectl expose deployment web --port=80 --namespace tenant-a
kubectl expose deployment web --port=80 --namespace tenant-b

# 4. Verify pods are running in both namespaces
kubectl get pods -n tenant-a
kubectl get pods -n tenant-b

# 5. Verify services exist in both namespaces
kubectl get svc -n tenant-a
kubectl get svc -n tenant-b
```

**Expected output:** One `Running` pod and one `ClusterIP` service in each namespace.

**Screenshot:**

![Task 1 - Two Tenants on One Cluster](./Session%20A%20(Week%203)%20%E2%80%94%20Compute%20Isolation%20%26%20the%20Default-Open/Task%201%20%E2%80%94%20Two%20Tenants%20on%20One%20Cluster.png)

---

### Task 2 — Observe the Default-Open Risk

**Objective:** Demonstrate that without any network policy in place, a pod in `tenant-a` can freely reach a service in `tenant-b`, returning `HTTP 200 OK`. This is the **default-open** risk.

#### Explanation

By default, Kubernetes uses a flat pod network — every pod can reach every other pod across all namespaces using its cluster-internal IP or DNS name. There is no namespace-level firewall. This means a compromised or malicious pod in `tenant-a` can reach, enumerate, and potentially exfiltrate data from `tenant-b`'s services without any policy blocking it.

#### Commands

```bash
# 1. Get the ClusterIP of tenant-b's web service
kubectl get svc web -n tenant-b

# 2. Launch a temporary curl pod inside tenant-a
kubectl run curl-test \
  --image=curlimages/curl \
  --namespace tenant-a \
  --restart=Never \
  --rm -it \
  -- curl -s -o /dev/null -w "%{http_code}" http://web.tenant-b.svc.cluster.local

# Expected output: 200
```

> **Security Finding:** The response `200` confirms that tenant-a has unrestricted access to tenant-b's web service. In a real multi-tenant cloud environment this represents a lateral movement vector — an attacker who compromises any pod in the cluster can pivot freely between tenants.

**Screenshot:**

![Task 2 - Observe the Default-Open Risk](./Session%20A%20(Week%203)%20%E2%80%94%20Compute%20Isolation%20%26%20the%20Default-Open/Task%202%20%E2%80%94%20Observe%20the%20Default-Open%20Risk.png)

---

### Task 3 — Noisy Neighbour Containment via Resource Quotas

**Objective:** Apply a `ResourceQuota` to `tenant-a` to cap its CPU, memory, and pod count, preventing it from monopolising shared cluster resources (the **noisy neighbour** problem).

#### Explanation

Without resource limits, a single namespace can spawn unlimited pods and consume all available CPU and memory, degrading or crashing workloads in neighbouring namespaces. `ResourceQuota` objects enforce hard ceilings at the namespace level. `LimitRange` can additionally set per-pod/container defaults so that pods without explicit resource requests are still accounted for.

#### Commands

```bash
# 1. Define and apply the ResourceQuota for tenant-a
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    pods: "5"
    requests.cpu: "500m"
    requests.memory: "512Mi"
    limits.cpu: "1"
    limits.memory: "1Gi"
EOF

# 2. Verify the quota was created
kubectl describe resourcequota tenant-a-quota -n tenant-a

# 3. (Optional) Apply a LimitRange to set per-container defaults
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: LimitRange
metadata:
  name: tenant-a-limits
  namespace: tenant-a
spec:
  limits:
  - type: Container
    default:
      cpu: "200m"
      memory: "256Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
EOF

# 4. Confirm quota usage
kubectl get resourcequota -n tenant-a
```

**Expected output:** `kubectl describe resourcequota` shows the hard limits and current usage; attempting to deploy more than 5 pods returns an `exceeded quota` error.

**Screenshot:**

![Task 3 - Noisy Neighbour Containment](./Session%20A%20(Week%203)%20%E2%80%94%20Compute%20Isolation%20%26%20the%20Default-Open/Task%203%20%E2%80%94%20Contain%20the%20Noisy%20Neighbour%20%28Resource%20Quotas%29.png)

---

### Task 4 — Default-Deny Network Isolation

**Objective:** Apply a `default-deny-ingress` `NetworkPolicy` to both tenant namespaces so that all inbound traffic is blocked by default. Verify the change by re-running the cross-tenant curl test, which should now return `HTTP 000` (connection timeout/refused).

#### Explanation

A `NetworkPolicy` with an empty `podSelector: {}` matches **all pods** in the namespace. Specifying `policyTypes: [Ingress]` with no `ingress` rules creates a blanket deny for all inbound connections. This implements the **Zero-Trust** principle: nothing is trusted by default; access must be explicitly permitted. Outbound (egress) traffic remains unrestricted unless a separate egress deny policy is applied.

#### Commands

```bash
# 1. Apply default-deny-ingress to tenant-a
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-a
spec:
  podSelector: {}       # matches ALL pods in the namespace
  policyTypes:
  - Ingress             # deny all inbound traffic; no ingress rules = deny all
EOF

# 2. Apply default-deny-ingress to tenant-b
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF

# 3. Verify NetworkPolicies are active
kubectl get networkpolicy -A

# 4. Re-run the cross-tenant curl test from tenant-a → tenant-b
kubectl run curl-test \
  --image=curlimages/curl \
  --namespace tenant-a \
  --restart=Never \
  --rm -it \
  -- curl -s -o /dev/null -w "%{http_code}" \
     --max-time 10 \
     http://web.tenant-b.svc.cluster.local

# Expected output: 000  (connection timed out — policy blocking ingress to tenant-b)
```

> **Result:** The response changes from `200` (Task 2) to `000`, confirming that Calico is enforcing the `NetworkPolicy` and cross-tenant traffic is now blocked. No packet from `tenant-a` reaches a pod in `tenant-b`.

**Screenshot:**

![Task 4 - Default-Deny Network Isolation](./Session%20B%20(Week%204)%20%E2%80%94%20Network%20%26%20Storage%20Isolation/Task%204%20%E2%80%94%20Default-Deny%20Network%20Isolation.png)

---

### Task 5 — Storage & Secret Isolation (RBAC Enforced)

**Objective:** Create per-tenant Kubernetes `Secret` objects and use RBAC (`Role` + `RoleBinding`) to verify that a service account in `tenant-a` can read secrets in its own namespace (`yes`) but is denied access to secrets in `tenant-b` (`no`).

#### Explanation

Kubernetes `Secret` objects are namespace-scoped, but namespace scoping alone does not enforce access control — any pod with a sufficiently privileged service account could read secrets from any namespace. **RBAC** (`Role`/`RoleBinding`) is the enforcement mechanism: a `Role` grants specific verbs (get, list, etc.) on specific resources within a namespace, and a `RoleBinding` attaches that role to a subject (user, group, or service account).

#### Commands

```bash
# 1. Create a secret in each namespace
kubectl create secret generic tenant-a-secret \
  --from-literal=password=superSecretA \
  --namespace tenant-a

kubectl create secret generic tenant-b-secret \
  --from-literal=password=superSecretB \
  --namespace tenant-b

# 2. Create a dedicated ServiceAccount for tenant-a
kubectl create serviceaccount tenant-a-sa --namespace tenant-a

# 3. Create a Role granting secret read access within tenant-a only
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: tenant-a
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
EOF

# 4. Bind the Role to the tenant-a ServiceAccount
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: tenant-a-secret-reader
  namespace: tenant-a
subjects:
- kind: ServiceAccount
  name: tenant-a-sa
  namespace: tenant-a
roleRef:
  kind: Role
  apiGroup: rbac.authorization.k8s.io
  name: secret-reader
EOF

# 5. Verify: tenant-a-sa CAN read secrets in tenant-a → expected: yes
kubectl auth can-i get secrets \
  --namespace tenant-a \
  --as system:serviceaccount:tenant-a:tenant-a-sa

# 6. Verify: tenant-a-sa CANNOT read secrets in tenant-b → expected: no
kubectl auth can-i get secrets \
  --namespace tenant-b \
  --as system:serviceaccount:tenant-a:tenant-a-sa
```

**Expected output:**

```
yes   ← same-namespace access permitted by RBAC Role
no    ← cross-namespace access denied (no RoleBinding exists in tenant-b)
```

**Screenshot:**

![Task 5 - Storage and Secret Isolation](./Session%20B%20(Week%204)%20%E2%80%94%20Network%20%26%20Storage%20Isolation/Task%205%20%E2%80%94%20Storage%20%26%20Secret%20Isolation.png)

---

### Task 6 — Data Remanence & Secure Deletion

**Objective:** Demonstrate that files deleted with standard OS commands (`rm`) leave recoverable data on disk (data remanence), then perform a secure overwrite using `dd` to prevent recovery. This simulates the secure decommissioning of cloud storage volumes.

#### Explanation

When a file is deleted with `rm`, the operating system merely removes the directory entry and marks the data blocks as available — the underlying bytes remain on the storage medium until overwritten by new data. In cloud environments, storage volumes may be reassigned to different tenants after deallocation. Without secure erasure, the new tenant could potentially recover data from a previous tenant using forensic tools (`strings`, `foremost`, `photorec`).

**Secure overwriting** replaces the data blocks with zeros or random bytes before deletion, making recovery infeasible. In cloud environments where cryptographic volumes are used, **cryptographic erasure** (destroying the encryption key) is the preferred approach since it renders all ciphertext unreadable instantly, without requiring a full block-level overwrite.

#### Commands

```bash
# 1. Create a Docker volume to simulate a cloud storage volume
docker volume create tenant-a-vol

# 2. Mount the volume and write a sensitive file
docker run --rm \
  -v tenant-a-vol:/data \
  alpine sh -c "echo 'CONFIDENTIAL: tenant-a private key = ABC123' > /data/sensitive.txt"

# 3. Demonstrate naive deletion (data remanence)
docker run --rm \
  -v tenant-a-vol:/data \
  alpine sh -c "rm /data/sensitive.txt && echo 'File deleted with rm'"

# 4. Attempt to recover the deleted data using strings
# (In a real scenario a forensic tool would scan the raw block device)
docker run --rm \
  -v tenant-a-vol:/data \
  alpine sh -c "strings /data 2>/dev/null || echo 'Direct recovery attempt complete'"

# 5. Write new data and perform SECURE deletion via dd overwrite
docker run --rm \
  -v tenant-a-vol:/data \
  alpine sh -c "echo 'CONFIDENTIAL: new secret = XYZ789' > /data/newfile.txt"

docker run --rm \
  -v tenant-a-vol:/data \
  alpine sh -c "
    # Overwrite the file content with zeros before removing
    dd if=/dev/zero of=/data/newfile.txt bs=1k count=1 conv=notrunc 2>&1
    sync
    rm /data/newfile.txt
    echo 'Secure deletion complete'
  "

# 6. Remove the Docker volume (equivalent to decommissioning the storage)
docker volume rm tenant-a-vol

# 7. Confirm the volume is gone
docker volume ls
```

> **Key Observation:** After step 3, raw block scanning can recover the string `CONFIDENTIAL: tenant-a private key = ABC123` because `rm` only removed the file's metadata. After step 5, the `dd` overwrite replaces the data blocks with zeros, leaving nothing recoverable.

**Screenshot:**

![Task 6 - Data Remanence and Secure Deletion](./Session%20B%20(Week%204)%20%E2%80%94%20Network%20%26%20Storage%20Isolation/Task%206%20%E2%80%94%20Data%20Remanence%20%26%20Secure%20Deletion.png)

---

## Section C — Short-Answer Analysis Questions

### Q1 — Why Can Containers in Different Namespaces Reach Each Other by Default?

Kubernetes implements a **flat pod network model**: every pod is assigned a routable, cluster-internal IP address, and by default all pods can communicate with all other pods regardless of which namespace they reside in. There is no built-in namespace-level firewall. The Kubernetes networking model explicitly requires that pods can reach each other without NAT — isolation is an opt-in concern, not the default posture.

**Security implications in multi-tenant clouds:**

In a shared cluster serving multiple customers (tenants), the default-open model creates a **lateral movement** attack surface. If an attacker compromises a single pod — through a container escape, a vulnerable application, or a misconfigured deployment — they can immediately pivot to enumerate and probe services in every other tenant's namespace. This violates the principle of least privilege and can lead to:

- **Data exfiltration** — reading API endpoints or secrets belonging to another tenant.
- **Denial-of-service amplification** — targeting services in other namespaces once initial access is gained.
- **Privilege escalation** — exploiting a less-hardened pod in another namespace as a stepping stone.

Mitigations include `NetworkPolicy` (as demonstrated in Task 4), service mesh mTLS (Istio, Linkerd), and in high-assurance environments, separate clusters per tenant (hard multi-tenancy).

---

### Q2 — How Does a Default-Deny NetworkPolicy Enforce Zero-Trust?

The **Zero-Trust security model** operates on the principle of *never trust, always verify* — no entity (pod, service, user) is trusted by virtue of its network location alone. Every communication must be explicitly authorised.

In Kubernetes, a `NetworkPolicy` with the following structure implements this at the namespace level:

```yaml
spec:
  podSelector: {}        # selects ALL pods in the namespace
  policyTypes:
  - Ingress              # applies to inbound traffic
  # no ingress rules defined → deny ALL inbound traffic
```

- `podSelector: {}` — an empty selector is a wildcard that matches every pod in the namespace.
- `policyTypes: [Ingress]` with no `ingress` rules — the absence of any `from` block means no source is whitelisted; therefore all inbound traffic is implicitly denied.
- Traffic is only permitted when an additional `NetworkPolicy` with an explicit `ingress.from` rule is added for that specific source.

This inverts the default posture from *allow-unless-denied* to *deny-unless-explicitly-allowed*, directly implementing Zero-Trust at the network layer. As demonstrated in Task 4, the cross-tenant curl response changes from `HTTP 200` to `HTTP 000` (timeout) once the policy is applied, confirming enforcement by the Calico CNI.

---

### Q3 — VM Isolation vs. Container Isolation: When Is Each Appropriate?

| Property | Virtual Machines (Hypervisor Isolation) | Containers (Kernel Isolation) |
|---|---|---|
| **Isolation boundary** | Hardware-level virtualisation (vCPU, virtual memory, virtual I/O) | Linux kernel namespaces + cgroups |
| **Kernel sharing** | Each VM has its own independent OS kernel | All containers share the host kernel |
| **Attack surface** | Hypervisor (much smaller) | Host kernel syscall interface (larger) |
| **Boot overhead** | Seconds to minutes | Milliseconds |
| **Density** | Lower (full OS per VM) | Higher (no OS duplication) |
| **Escape impact** | VM escape is extremely rare; attacker reaches hypervisor layer | Container escape reaches host kernel directly |

**Container isolation** relies on Linux namespaces (pid, net, mnt, uts, ipc, user) to provide logical separation, and **cgroups** to enforce resource limits. These are kernel features — they do not provide a hard hardware boundary. A vulnerability in the kernel (e.g., a `runc` escape, dirty-pipe) can allow a containerised process to reach the host.

**Scenarios requiring VM-level boundaries:**

1. **Untrusted or third-party code execution** — running arbitrary customer code (e.g., FaaS/serverless, CI/CD pipelines for external contributors) requires the stronger guarantee of hypervisor isolation. AWS Lambda and Google Cloud Run use micro-VMs (Firecracker) for exactly this reason.
2. **PCI-DSS, HIPAA, and FedRAMP compliance** — many regulatory frameworks explicitly require workload isolation at a level that container namespaces cannot satisfy. Auditors often require VM boundaries between in-scope and out-of-scope systems.
3. **Multi-tenant SaaS with competing tenants** — if tenants are direct competitors or handle data classified at different sensitivity levels, shared-kernel isolation is architecturally insufficient.
4. **Legacy OS workloads** — applications requiring a different OS (Windows on a Linux host) require full virtualisation.

The trend toward **confidential computing** (AMD SEV, Intel TDX) extends VM isolation with hardware-enforced memory encryption, protecting data even from the hypervisor itself.

---

### Q4 — Data Remanence in Cloud Storage & Cryptographic Erasure

**Data remanence** is the residual representation of data that persists on a storage medium after an attempt has been made to remove it. For cloud block storage (AWS EBS, Azure Managed Disks, GCP Persistent Disks), this occurs because:

- Standard file deletion (`rm`, format) removes file-system metadata but leaves data blocks intact.
- Storage volumes are often reassigned to new tenants after deallocation without provider-level erasure guarantees.
- SSD wear-levelling and over-provisioned blocks may contain copies of data that block-level overwriting cannot reach.

**Why cryptographic erasure is preferred over physical zeroization in cloud environments:**

| Aspect | Physical Zeroization (dd /dev/zero) | Cryptographic Erasure |
|---|---|---|
| **Mechanism** | Overwrites every data block with zeros or random bytes | Destroys the encryption key; all ciphertext becomes permanently unreadable |
| **Speed** | Proportional to volume size (slow for large volumes) | Near-instant (key deletion is a metadata operation) |
| **Effectiveness on SSDs** | Incomplete — wear-levelling hides blocks from overwrite | Complete — inaccessible blocks are still ciphertext |
| **Cloud applicability** | Requires raw device access (often unavailable in cloud) | Natively supported (AWS KMS key deletion, Azure Key Vault purge) |
| **Compliance** | Accepted by NIST SP 800-88 for magnetic media | Accepted by NIST SP 800-88 Rev.1 as `Cryptographic Erase` for encrypted media |

In practice, cloud providers encrypt all volumes at rest by default. When a volume is decommissioned, deleting the Customer Master Key (CMK) in the KMS renders every encrypted block on every underlying physical disk irrecoverably unreadable — even to the provider — without any need to locate and overwrite every physical block. This is both faster and more comprehensive than block-level zeroization.

---

### Q5 — Isolation Dimensions: Task Mapping

The six lab tasks collectively cover three isolation dimensions. The table below maps each task to its primary and supporting dimension.

| Task | Description | Primary Isolation Dimension | Supporting Dimension |
|---|---|---|---|
| **Task 1** | Two Tenants on One Cluster — namespace creation and workload deployment | **Compute** | — |
| **Task 2** | Default-Open Risk — cross-tenant HTTP 200 proof-of-concept | **Compute / Network** (demonstrates absence of network isolation) | — |
| **Task 3** | Noisy Neighbour Containment — `ResourceQuota` CPU/memory/pod caps | **Compute** | — |
| **Task 4** | Default-Deny Network Isolation — `NetworkPolicy` enforcement, HTTP 000 | **Network** | — |
| **Task 5** | Storage & Secret Isolation — RBAC `Role`/`RoleBinding`, `yes`/`no` auth checks | **Storage** | Compute (RBAC on service accounts) |
| **Task 6** | Data Remanence & Secure Deletion — `dd` overwrite on Docker volume | **Storage** | — |

---

## Section D — Verification & Cleanup

### Verification Commands

Run these commands to confirm all isolation controls are in place before concluding the lab.

```bash
# --- Network Policies ---
# List all NetworkPolicies across all namespaces
kubectl get networkpolicy -A

# Describe a specific policy for full rule inspection
kubectl describe networkpolicy default-deny-ingress -n tenant-a
kubectl describe networkpolicy default-deny-ingress -n tenant-b

# --- Resource Quotas ---
# List all ResourceQuotas
kubectl get resourcequota -A

# Show current usage vs. hard limits for tenant-a
kubectl describe resourcequota tenant-a-quota -n tenant-a

# --- RBAC ---
# Confirm tenant-a service account permissions
kubectl auth can-i get secrets -n tenant-a \
  --as system:serviceaccount:tenant-a:tenant-a-sa    # → yes

kubectl auth can-i get secrets -n tenant-b \
  --as system:serviceaccount:tenant-a:tenant-a-sa    # → no

# List all Roles and RoleBindings
kubectl get roles,rolebindings -n tenant-a
kubectl get roles,rolebindings -n tenant-b

# --- Secrets ---
kubectl get secrets -n tenant-a
kubectl get secrets -n tenant-b

# --- Overall namespace audit ---
kubectl get all -n tenant-a
kubectl get all -n tenant-b
```

### Teardown & Cleanup

> **Note:** Run cleanup only after all tasks have been documented. These commands are irreversible within the lab session.

```bash
# 1. Delete tenant namespaces (removes all resources within them)
kubectl delete namespace tenant-a
kubectl delete namespace tenant-b

# 2. Verify namespaces are gone
kubectl get namespaces

# 3. Remove any residual Docker volumes
docker volume ls
docker volume rm tenant-a-vol 2>/dev/null || echo "Volume already removed"

# 4. Prune any stopped containers
docker container prune -f

# 5. Delete the kind cluster entirely
kind delete cluster --name lab2

# 6. Verify no kind clusters remain
kind get clusters

# 7. (Optional) Remove the Calico and kind config files
rm -f kind-config.yaml
```

**Expected final state:** `kind get clusters` returns no output; `kubectl get nodes` returns a connection error (cluster no longer exists); `docker volume ls` shows no lab volumes.

---

## Summary

| Task | Control Applied | Before | After |
|---|---|---|---|
| Task 1 | Namespace isolation | Single default namespace | `tenant-a` and `tenant-b` namespaces |
| Task 2 | Baseline measurement | — | Cross-tenant HTTP `200` confirmed |
| Task 3 | `ResourceQuota` | Unlimited compute | Capped at 1 CPU / 1 GiB / 5 pods |
| Task 4 | `NetworkPolicy` default-deny | HTTP `200` (open) | HTTP `000` (blocked) |
| Task 5 | RBAC `Role`/`RoleBinding` | Implicit access | `yes` own-ns · `no` cross-ns |
| Task 6 | `dd` secure overwrite | Data recoverable post-`rm` | Data irrecoverable post-overwrite |

The lab demonstrates that robust multi-tenancy in Kubernetes requires **layered controls** — namespace boundaries alone are insufficient. Compute, network, and storage isolation must each be explicitly configured and verified to meet the security posture required by the CLO.

---

*Report generated for IKB42603 Cloud Computing Security Essentials — Lab 2*
