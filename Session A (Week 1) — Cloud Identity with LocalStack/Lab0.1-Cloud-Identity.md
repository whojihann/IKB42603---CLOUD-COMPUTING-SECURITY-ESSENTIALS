# LAB 1 — Cloud Account Security, Identity & Access Management

---

## Header Metadata

| Field | Details |
|---|---|
| **Course Code** | IKB42603 Cloud Computing Security Essentials |
| **Lab Title** | LAB 1 — Cloud Account Security, Identity & Access Management |
| **Student Name** | NURUL JIHAN NABILAH BINTI AZLAN |
| **Institution** | Universiti Kuala Lumpur (UniKL MIIT) |
| **Instructor** | Prof. Dr. Shahrulniza Musa |
| **Date** | August 2026 |

---

## Table of Contents

**Session A — Week 1: Cloud Identity with LocalStack**

1. [Session A: Environment Setup Verification](#session-a-environment-setup-verification)
2. [Task 1 — Map the Cloud Identity Landscape](#task-1--map-the-cloud-identity-landscape)
3. [Task 2 — Create a Least-Privilege Admin](#task-2--create-a-least-privilege-admin)
4. [Task 3 — Enforce Least Privilege with a Scoped Policy](#task-3--enforce-least-privilege-with-a-scoped-policy)
5. [Task 4 — Credential Hygiene & Access Keys](#task-4--credential-hygiene--access-keys)

**Session B — Week 2: Enforced Access Control with Kubernetes**

6. [Session B: Environment Setup — Local Kubernetes Cluster](#session-b-environment-setup--local-kubernetes-cluster)
7. [Task 5 — Separate Environments with Namespaces](#task-5--separate-environments-with-namespaces)
8. [Task 6 — Define a Role and Bind It (Least Privilege)](#task-6--define-a-role-and-bind-it-least-privilege)
9. [Task 7 — Test That Access Control Works](#task-7--test-that-access-control-works)
10. [Deliverables & Verification](#deliverables--verification)

**Reflection & Assessment**

11. [Short-Answer Questions](#short-answer-questions)
12. [Security Best-Practices Checklist](#security-best-practices-checklist)
13. [Teardown & Cleanup](#teardown--cleanup)

---

## Session A: Environment Setup Verification

### 1.1 Docker Startup & LocalStack Container

LocalStack is launched as a Docker container exposing the primary AWS API gateway on port `4566` and the Web Console on port `31566`. The `localstack/localstack-pro` image requires a valid `LOCALSTACK_AUTH_TOKEN` to activate the Pro edition and enable IAM, STS, and S3 service emulation.

```bash
docker run --rm -it \
  -p 4566:4566 \
  -p 4510-4559:4510-4559 \
  -p 31566:31566 \
  -e LOCALSTACK_AUTH_TOKEN="${LOCALSTACK_AUTH_TOKEN}" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  localstack/localstack-pro
```

On successful startup the terminal shows the LocalStack ASCII banner followed by per-service readiness logs confirming all emulated services are listening at `http://localhost:4566`.

### 1.2 LocalStack Health Check — `/_localstack/health`

```bash
curl http://localhost:4566/_localstack/health | python3 -m json.tool
```

**Expected response (excerpt):**

```json
{
  "services": {
    "iam": "available",
    "sts": "available",
    "s3": "available"
  },
  "version": "3.x.x",
  "edition": "pro",
  "is_license_activated": true
}
```

`"is_license_activated": true` confirms the Auth Token was accepted and the Pro edition is active. `"iam": "available"` is the direct prerequisite for all Session A tasks.

### 1.3 Dummy AWS CLI Configuration

LocalStack does not validate real AWS credentials — fields must simply be non-empty. Standard dummy values are used:

```bash
aws configure
```

| Prompt | Value |
|---|---|
| AWS Access Key ID | `test` |
| AWS Secret Access Key | `test` |
| Default region name | `us-east-1` |
| Default output format | `json` |

A local-endpoint alias avoids repeating `--endpoint-url` on every command:

```bash
export EP="--endpoint-url=http://localhost:4566"
```

### 1.4 STS Identity Verification

```bash
aws $EP sts get-caller-identity
```

**Expected output:**

```json
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

Account `000000000000` is LocalStack's default emulated account ID, confirming CLI traffic is routed to `http://localhost:4566` rather than live AWS.

### 1.5 Evidence — LocalStack IAM Dashboard

![Environment Setup](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/1.LocalStack%20IAM.png)

*Figure 1: LocalStack Web Console — IAM service dashboard confirming Pro edition activation and service availability.*

### 1.6 Evidence — AWS CLI Setup & STS Identity Check

![AWS CLI Setup](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/2.Setup%20dummy%20credentials%20%26%20test%20AWS%20CLI.png)

*Figure 2: Terminal confirming dummy credentials configured and `sts get-caller-identity` returning account `000000000000`.*

---

## Task 1 — Map the Cloud Identity Landscape

### Objective

Establish a working reference for the five core AWS IAM identity primitives before building any resources, grounding every subsequent task in the correct security model.

### IAM Identity Landscape

| IAM Component | Purpose |
|---|---|
| **Root User** | The master identity created automatically when an AWS account is provisioned. It bypasses all IAM permission boundaries, has unrestricted billing access, and cannot be restricted by any policy. Must never be used for day-to-day operations; MFA must be enforced and its credentials stored offline in a secure vault. |
| **IAM User** | A persistent, long-term identity representing a human operator or a static service principal. Each user has its own credentials (console password and/or programmatic access keys) and is subject to standard IAM policy evaluation. Enables individual accountability and auditability in CloudTrail. |
| **IAM Policy** | A JSON document defining `Allow` or `Deny` permissions for specified actions on specified resources. Policy evaluation order: explicit `Deny` always wins → explicit `Allow` grants access → implicit default is `Deny`. Policies can be AWS-managed, customer-managed, or inline. |
| **IAM Group** | A logical collection of IAM users. Policies attached to a group are automatically inherited by every member, enabling consistent role-based permission management without per-user policy duplication. Groups cannot be nested or used as principals in resource trust policies. |
| **IAM Role** | A temporary identity assumed by AWS services, IAM users, or federated external identities via STS. Issues short-lived session tokens instead of static credentials. The preferred mechanism for cross-service access (e.g., EC2 → S3), CI/CD pipelines, and cross-account delegation — eliminating the need for long-lived access keys. |

---

## Task 2 — Create a Least-Privilege Admin

### Objective

Create a dedicated admin identity using the group-based attachment pattern so that the permission boundary lives at the group level — not embedded in the user — making future membership changes safe and auditable.

### Step 1 — Create the `Admins` Group

```bash
awslocal iam create-group --group-name Admins
```

**Output:**

```json
{
    "Group": {
        "Path": "/",
        "GroupName": "Admins",
        "GroupId": "AGPA...",
        "Arn": "arn:aws:iam::000000000000:group/Admins",
        "CreateDate": "2026-08-03T00:00:00+00:00"
    }
}
```

### Step 2 — Attach `AdministratorAccess` to the `Admins` Group

`AdministratorAccess` is the AWS-managed policy that grants `"Action": "*"` on `"Resource": "*"`, appropriate for the designated admin tier.

```bash
awslocal iam attach-group-policy \
  --group-name Admins \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Verify the attachment:

```bash
awslocal iam list-attached-group-policies --group-name Admins
```

**Expected output:**

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```

### Step 3 — Create the IAM User `CloudAdmin_jihan`

```bash
awslocal iam create-user --user-name CloudAdmin_jihan
```

**Output:**

```json
{
    "User": {
        "Path": "/",
        "UserName": "CloudAdmin_jihan",
        "UserId": "AIDA...",
        "Arn": "arn:aws:iam::000000000000:user/CloudAdmin_jihan",
        "CreateDate": "2026-08-03T00:00:00+00:00"
    }
}
```

### Step 4 — Add `CloudAdmin_jihan` to `Admins`

```bash
awslocal iam add-user-to-group \
  --user-name CloudAdmin_jihan \
  --group-name Admins
```

### Step 5 — Verify Group Membership (`aws iam get-group`)

```bash
awslocal iam get-group --group-name Admins
```

**Expected output:**

```json
{
    "Users": [
        {
            "UserName": "CloudAdmin_jihan",
            "UserId": "AIDA...",
            "Arn": "arn:aws:iam::000000000000:user/CloudAdmin_jihan",
            "Path": "/",
            "CreateDate": "2026-08-03T00:00:00+00:00"
        }
    ],
    "Group": {
        "Path": "/",
        "GroupName": "Admins",
        "GroupId": "AGPA...",
        "Arn": "arn:aws:iam::000000000000:group/Admins",
        "CreateDate": "2026-08-03T00:00:00+00:00"
    }
}
```

The `Users` array confirms `CloudAdmin_jihan` is a member of `Admins` and inherits `AdministratorAccess`.

### Evidence — Least-Privilege Admin Setup

![Admin Setup](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/3.Least-Privilege%20Admin.png)

*Figure 3: Admins group creation, AdministratorAccess policy attached, and CloudAdmin_jihan added to the group.*

### Evidence — Admin Group Policy Verification

![Admin Policy Verification](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/4.Least-Privilege%20Admin%202.0.png)

*Figure 4: `aws iam get-group` confirming CloudAdmin_jihan membership and AdministratorAccess active at group level.*

---

## Task 3 — Enforce Least Privilege with a Scoped Policy

### Objective

Create `Analyst_jihan` with permissions restricted to S3 read-only access, demonstrating how a tightly scoped policy limits the blast radius if credentials are compromised.

### Step 1 — Create the IAM User `Analyst_jihan`

```bash
awslocal iam create-user --user-name Analyst_jihan
```

**Output:**

```json
{
    "User": {
        "Path": "/",
        "UserName": "Analyst_jihan",
        "UserId": "AIDA...",
        "Arn": "arn:aws:iam::000000000000:user/Analyst_jihan",
        "CreateDate": "2026-08-03T00:00:00+00:00"
    }
}
```

### Step 2 — Attach `AmazonS3ReadOnlyAccess`

`AmazonS3ReadOnlyAccess` grants only `s3:Get*` and `s3:List*` — the minimum permissions a data analyst needs to query S3.

```bash
awslocal iam attach-user-policy \
  --user-name Analyst_jihan \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

### Step 3 — List Attached Policies

```bash
awslocal iam list-attached-user-policies --user-name Analyst_jihan
```

**Expected output:**

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AmazonS3ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
        }
    ]
}
```

### Evidence — Analyst Scoped Policy

![Analyst Scoped Policy](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/5.Analyst%20User%20%28Scoped%20Policy%29.png)

*Figure 5: Analyst_jihan created and AmazonS3ReadOnlyAccess policy attachment verified.*

### Security Analysis — Blast Radius Reduction

Limiting `Analyst_jihan` to `AmazonS3ReadOnlyAccess` caps the blast radius if the account is compromised. An attacker who steals these credentials can read existing S3 objects but cannot write, delete, or create any resource anywhere in the account. There is no path to privilege escalation: the policy grants zero IAM actions, so the attacker cannot create new users, generate fresh access keys, or attach broader policies. Lateral movement to compute services — EC2, Lambda, RDS — is fully blocked. The incident is constrained to a data-confidentiality exposure rather than a complete account takeover. This is the practical payoff of least-privilege: a breach stays bounded to the exact scope the identity legitimately requires.

---

## Task 4 — Credential Hygiene & Access Keys

### Objective

Demonstrate the full access key lifecycle for `Analyst_jihan`: create, list, rotate (replace with a new key), deactivate the old key, and verify the resulting Inactive / Active state.

### Step 1 — Create an Access Key

```bash
awslocal iam create-access-key --user-name Analyst_jihan
```

**Output:**

```json
{
    "AccessKey": {
        "UserName": "Analyst_jihan",
        "AccessKeyId": "AKIA...",
        "Status": "Active",
        "SecretAccessKey": "...",
        "CreateDate": "2026-08-03T00:00:00+00:00"
    }
}
```

> **Security note:** `SecretAccessKey` is shown only once. Store it immediately in a secrets manager or encrypted vault — never in source code or documentation.

### Step 2 — List Access Keys

```bash
awslocal iam list-access-keys --user-name Analyst_jihan
```

The listing confirms the key is `Active` and captures its `CreateDate` for age-based rotation auditing.

### Step 3 — Create a Replacement Key (Rotation)

```bash
awslocal iam create-access-key --user-name Analyst_jihan
```

At this point two keys exist. All systems using the old key should be updated to the new key before the old one is deactivated.

### Step 4 — Deactivate the Old Key

```bash
awslocal iam update-access-key \
  --user-name Analyst_jihan \
  --access-key-id <OldAccessKeyId> \
  --status Inactive
```

`Inactive` immediately blocks authentication while preserving the key record for audit trails. Deleting before confirming the new key works everywhere is a common cause of service outages during rotation.

### Step 5 — Verify Final Key States

```bash
awslocal iam list-access-keys --user-name Analyst_jihan
```

**Expected output:**

```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "Analyst_jihan",
            "AccessKeyId": "<OldAccessKeyId>",
            "Status": "Inactive",
            "CreateDate": "2026-08-03T00:00:00+00:00"
        },
        {
            "UserName": "Analyst_jihan",
            "AccessKeyId": "<NewAccessKeyId>",
            "Status": "Active",
            "CreateDate": "2026-08-03T00:00:00+00:00"
        }
    ]
}
```

### Evidence — Credential Rotation

![Credential Rotation](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/6.Credential%20Hygiene%20%26%20Access%20Key%20Management.jpeg)

*Figure 6: Access key rotation — old key Inactive, new key Active, confirming correct credential hygiene for Analyst_jihan.*

### Security Analysis — Risks of Long-Lived Access Keys

Long-lived IAM access keys are among the most consistently exploited attack surfaces in cloud environments. Because they never expire automatically, a key leaked through a public Git commit, an exposed `.env` file, or a misconfigured CI/CD artifact grants an attacker persistent access until manually revoked. Secret-scanning tools routinely harvest credentials from public repositories within minutes of exposure, and there is no native alerting when a key is used from an anomalous location or outside business hours — detection depends entirely on CloudTrail monitoring being configured and actively reviewed. Even for a scoped account like `Analyst_jihan`, a live long-lived key enables silent, prolonged data exfiltration from S3. Best practices: rotate every 90 days (AWS benchmark), always deactivate before deleting during rotation, and wherever possible replace static access keys entirely with IAM roles and short-lived STS session tokens.

---

---

# Session B — Week 2: Enforced Access Control with Kubernetes

---

## Session B: Environment Setup — Local Kubernetes Cluster

### Overview

Session B shifts from cloud IAM to container-native access control. Kubernetes implements its own Role-Based Access Control (RBAC) model that is conceptually parallel to AWS IAM but operates at the workload layer: **Roles** define permitted API actions on Kubernetes resources (Pods, Services, etc.), and **RoleBindings** grant those Roles to specific identities (ServiceAccounts, users, groups) within a namespace. This session uses `kind` (Kubernetes-in-Docker) to spin up a fully functional local cluster without any cloud account, then enforces namespace-scoped least-privilege access exactly as a production team would.

### Tools Required

| Tool | Version | Purpose |
|---|---|---|
| Docker Desktop | ≥ 4.x | Container runtime for kind nodes |
| `kind` | ≥ 0.20 | Creates multi-node Kubernetes clusters inside Docker |
| `kubectl` | ≥ 1.28 | Kubernetes CLI for all resource and RBAC operations |

### Create the Local Cluster

```bash
kind create cluster --name ccse-lab1
```

`kind` bootstraps a single-node Kubernetes cluster running inside a Docker container and automatically writes the cluster credentials to `~/.kube/config`. The cluster is immediately reachable via `kubectl`.

Verify the cluster is up:

```bash
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

**Expected output:**

```
NAME                     STATUS   ROLES           AGE   VERSION
ccse-lab1-control-plane  Ready    control-plane   30s   v1.28.x
```

`STATUS: Ready` confirms the control-plane node is healthy and the API server is accepting requests.

### Evidence — Kubernetes Cluster Setup

![Setup - Create a Local Kubernetes Cluster](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/1.Setup%20-%20Create%20a%20Local%20Kubernetes%20Cluster.png)

*Figure 7: `kind create cluster` output and `kubectl get nodes` confirming ccse-lab1 is running and the control-plane node is Ready.*

---

## Task 5 — Separate Environments with Namespaces

### Objective

Kubernetes namespaces provide logical isolation between workloads inside the same physical cluster. Creating dedicated `dev` and `prod` namespaces enforces a hard boundary: RBAC policies granted in `dev` are namespace-scoped and do not automatically extend to `prod`, preventing accidental or malicious cross-environment access.

### Step 1 — Create the `dev` Namespace

```bash
kubectl create namespace dev
```

**Output:**

```
namespace/dev created
```

### Step 2 — Create the `prod` Namespace

```bash
kubectl create namespace prod
```

**Output:**

```
namespace/prod created
```

### Step 3 — Verify Both Namespaces Exist

```bash
kubectl get namespaces
```

**Expected output (relevant rows):**

```
NAME              STATUS   AGE
default           Active   2m
dev               Active   10s
prod              Active   8s
kube-system       Active   2m
```

Both `dev` and `prod` appear as `Active`, confirming they are ready to host workloads and namespace-scoped RBAC policies.

### Why Namespaces Matter for Security

Without namespace separation, a single misconfigured RBAC binding could inadvertently grant a developer access to production resources. By isolating `dev` and `prod`, the cluster enforces environment separation at the API-server level — not just at the application layer — so even if a developer's service account credentials are compromised, the attacker is contained within the `dev` boundary.

### Evidence — Namespace Separation

![Separate Environments with Namespaces](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/2.Separate%20Environments%20with%20Namespaces.png)

*Figure 8: `kubectl get namespaces` confirming both dev and prod namespaces are Active and isolated.*

---

## Task 6 — Define a Role and Bind It (Least Privilege)

### Objective

Create a `dev-user` ServiceAccount in the `dev` namespace, define a `pod-reader` Role that grants only read access to Pods, and bind the Role to the ServiceAccount via a RoleBinding. This mirrors the AWS pattern from Task 2 (group-based policy attachment) but expressed in Kubernetes RBAC primitives.

### Step 1 — Create the `dev-user` ServiceAccount

A ServiceAccount is the Kubernetes identity equivalent of an IAM User — it is a named principal that workloads and `kubectl` contexts can authenticate as.

```bash
kubectl create serviceaccount dev-user --namespace dev
```

**Output:**

```
serviceaccount/dev-user created
```

### Step 2 — Define the `pod-reader` Role

A Role is a namespace-scoped RBAC resource listing permitted API verbs on specific resource types. The `pod-reader` Role allows `get`, `watch`, and `list` on `pods` — read operations only, no write or delete.

Create the Role manifest `pod-reader-role.yaml`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: dev
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "watch", "list"]
```

Apply the Role:

```bash
kubectl apply -f pod-reader-role.yaml
```

**Output:**

```
role.rbac.authorization.k8s.io/pod-reader created
```

### Step 3 — Create the `dev-user-binding` RoleBinding

A RoleBinding connects a Role to a subject (ServiceAccount, User, or Group) within a namespace. Without a RoleBinding, the Role exists but grants no permissions to anyone.

Create the RoleBinding manifest `dev-user-binding.yaml`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-user-binding
  namespace: dev
subjects:
  - kind: ServiceAccount
    name: dev-user
    namespace: dev
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

Apply the RoleBinding:

```bash
kubectl apply -f dev-user-binding.yaml
```

**Output:**

```
rolebinding.rbac.authorization.k8s.io/dev-user-binding created
```

### Step 4 — Verify the Role and Binding

```bash
kubectl get role pod-reader -n dev
kubectl get rolebinding dev-user-binding -n dev
```

**Expected output:**

```
NAME         CREATED AT
pod-reader   2026-08-03T00:00:00Z

NAME               ROLE              AGE
dev-user-binding   Role/pod-reader   10s
```

### Evidence — Role Definition and Binding

![Define a Role and Bind It](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/3.Define%20a%20Role%20and%20Bind%20It%20(Least%20Privilege).png)

*Figure 9: pod-reader Role and dev-user-binding RoleBinding created and verified in the dev namespace.*

---

## Task 7 — Test That Access Control Works

### Objective

Use `kubectl auth can-i` to confirm that `dev-user` has exactly the permissions granted by `pod-reader` in `dev`, and confirm it is denied access to `prod` — validating that the namespace boundary and RBAC policy behave correctly.

### The `kubectl auth can-i` Command

`kubectl auth can-i <verb> <resource> --namespace <ns> --as system:serviceaccount:<ns>:<sa>` performs a dry-run authorization check against the Kubernetes API server, returning `yes` or `no` without executing the actual operation.

### Test 1 — List Pods in `dev` (Should Succeed)

```bash
kubectl auth can-i list pods \
  --namespace dev \
  --as system:serviceaccount:dev:dev-user
```

**Expected output:**

```
yes
```

`list` is one of the verbs explicitly allowed by the `pod-reader` Role in the `dev` namespace. ✅

### Test 2 — Delete Pods in `dev` (Should Fail)

```bash
kubectl auth can-i delete pods \
  --namespace dev \
  --as system:serviceaccount:dev:dev-user
```

**Expected output:**

```
no
```

`delete` is not in the `pod-reader` Role's `verbs` list. The implicit Kubernetes RBAC default is deny-all, so any action not explicitly permitted is blocked. ✅

### Test 3 — List Pods in `prod` (Should Fail)

```bash
kubectl auth can-i list pods \
  --namespace prod \
  --as system:serviceaccount:dev:dev-user
```

**Expected output:**

```
no
```

The `pod-reader` Role and `dev-user-binding` RoleBinding are both namespace-scoped to `dev`. They grant no permissions in `prod`. A `ClusterRole` and `ClusterRoleBinding` would be required to extend access across namespaces — neither of which has been created here. ✅

### Test 4 — Delete Pods in `prod` (Should Fail)

```bash
kubectl auth can-i delete pods \
  --namespace prod \
  --as system:serviceaccount:dev:dev-user
```

**Expected output:**

```
no
```

Neither the verb (`delete`) nor the namespace (`prod`) is accessible to `dev-user`. Both barriers independently deny the request. ✅

### Summary of Authorization Test Results

| Test | Verb | Namespace | Expected | Result |
|---|---|---|---|---|
| 1 | `list` pods | `dev` | ✅ `yes` | Allowed — verb in pod-reader Role |
| 2 | `delete` pods | `dev` | ❌ `no` | Denied — verb not in pod-reader Role |
| 3 | `list` pods | `prod` | ❌ `no` | Denied — RoleBinding scoped to dev only |
| 4 | `delete` pods | `prod` | ❌ `no` | Denied — verb and namespace both blocked |

### Evidence — Access Control Tests

![Test That Access Control Works](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/4.Test%20That%20Access%20Control%20Works.png)

*Figure 10: kubectl auth can-i results confirming dev-user can list pods in dev (yes) but is denied delete in dev and all access in prod (no).*

---

## Deliverables & Verification

### Verification Command — `kubectl get rolebinding dev-user-binding -n dev -o yaml`

This command retrieves the full YAML definition of the `dev-user-binding` RoleBinding from the cluster, providing cryptographic confirmation that the binding exists in the API server's etcd store with the exact subjects and roleRef that were defined during Task 6.

```bash
kubectl get rolebinding dev-user-binding -n dev -o yaml
```

**Expected output:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-user-binding
  namespace: dev
  creationTimestamp: "2026-08-03T00:00:00Z"
  resourceVersion: "1234"
  uid: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
subjects:
  - kind: ServiceAccount
    name: dev-user
    namespace: dev
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
```

**Key fields to verify:**

| Field | Expected Value | Significance |
|---|---|---|
| `kind` | `RoleBinding` | Namespace-scoped binding (not ClusterRoleBinding) |
| `metadata.namespace` | `dev` | Binding is confined to the dev namespace only |
| `subjects[0].kind` | `ServiceAccount` | Identity type — workload credential, not a human user |
| `subjects[0].name` | `dev-user` | The specific ServiceAccount receiving permissions |
| `roleRef.kind` | `Role` | References a namespace-scoped Role (not ClusterRole) |
| `roleRef.name` | `pod-reader` | The Role granting only get/watch/list on pods |

The `roleRef` is immutable after creation — it cannot be changed without deleting and recreating the RoleBinding, which provides a tamper-evident record that the binding has not been silently escalated.

### Evidence — Verification Command Output

![Verification Command](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/vertication%20command.png.png)

*Figure 11: `kubectl get rolebinding dev-user-binding -n dev -o yaml` output confirming the RoleBinding subjects and roleRef are correctly defined.*

---

---

## Short-Answer Questions

---

### Q1 — Why is attaching policies to groups better than attaching them directly to users?

Attaching policies to groups rather than individual users separates the *definition* of a permission set from its *assignment* to specific people. When a new engineer joins the admin team, you add their IAM user to the `Admins` group and they instantly inherit `AdministratorAccess` — no policy needs to be written, reviewed, or attached at the user level. Conversely, when someone leaves or changes roles, removing them from the group immediately revokes all associated permissions without hunting down every policy attached to their account.

This approach also eliminates policy drift. If five individual users all have manually attached admin policies, each policy document is a separate source of truth that can diverge over time through ad-hoc edits. A group centralises the policy so there is exactly one place to audit, update, or tighten the permission set, and the change propagates atomically to every member. In large organisations this is the difference between a permission model that is governable and one that becomes unauditable at scale.

---

### Q2 — What is the difference between an IAM User and an IAM Role?

An **IAM User** is a permanent, static identity. It has long-lived credentials — a console password and/or access keys — that persist until explicitly rotated or deleted. A user represents a known individual or a fixed service account, and every API call made with that identity is traceable to those static credentials.

An **IAM Role** is a temporary, assumable identity. It has no permanent credentials of its own. Instead, when a principal (an AWS service, another IAM user, or a federated identity) assumes the role, the AWS Security Token Service (STS) issues short-lived session tokens — typically valid for 15 minutes to 12 hours — after which the credentials automatically expire. This eliminates the risk of credential leakage persisting indefinitely.

Roles are the correct choice for any machine identity: an EC2 instance that needs to read from S3 should assume a role rather than storing an access key in user-data or an environment variable. Roles also power cross-account access and identity federation (SAML, OIDC), where a human authenticates through an external IdP and receives temporary AWS credentials mapped to a role rather than a user record.

---

### Q3 — Explain least privilege using the Analyst account, and how it reduces blast radius if compromised

The Principle of Least Privilege states that every identity should hold only the minimum permissions required to perform its defined function — nothing more. `Analyst_jihan` was provisioned with exactly one policy: `AmazonS3ReadOnlyAccess`, which permits `s3:Get*` and `s3:List*` operations only.

If an attacker obtains `Analyst_jihan`'s access keys — through a phishing attack, a leaked `.env` file, or a compromised developer machine — the blast radius is tightly bounded. The attacker can read and list objects in S3 buckets, but they cannot:

- **Write or delete data** — `s3:Put*` and `s3:Delete*` are absent from the policy.
- **Escalate privileges** — there are no `iam:*` permissions, so the attacker cannot create new users, attach broader policies, or generate fresh credentials for other accounts.
- **Access other services** — EC2, Lambda, RDS, CloudFormation, and every other AWS service is implicitly denied because the policy grants no actions outside S3.
- **Take over the account** — without IAM permissions there is no path to root-level compromise.

The incident becomes a data-confidentiality exposure affecting only S3 content, rather than a full account takeover that could destroy infrastructure, exfiltrate secrets from Parameter Store, or pivot into other environments. Least privilege does not prevent breaches — it contains the damage when they occur.

---

### Q4 — In Kubernetes, what is the difference between a Role and a RoleBinding?

A **Role** is the *definition* of a permission set. It declares which API verbs (`get`, `list`, `watch`, `create`, `delete`, etc.) are permitted on which Kubernetes resource types (`pods`, `services`, `deployments`, etc.) within a specific namespace. A Role that exists but has no binding grants permissions to nobody — it is inert.

A **RoleBinding** is the *assignment* of a Role to one or more subjects. It links a Role (or ClusterRole) to a ServiceAccount, User, or Group within a namespace, activating those permissions for the named identities. Without the RoleBinding, the Role is simply a policy document sitting unused in the API server.

The deliberate separation mirrors the AWS IAM pattern: an IAM Policy (= Role) defines what is allowed, and attaching it to a User or Group (= RoleBinding) activates it. This two-step model means permissions can be defined centrally and re-used across multiple subjects, and subjects can be added or removed from a Role's scope without touching the Role's rules. It also means auditing is clean — you can inspect all RoleBindings in a namespace to see exactly who has been granted which capabilities, independently of the Role definitions themselves.

The cluster-scoped equivalents — `ClusterRole` and `ClusterRoleBinding` — follow the same pattern but apply across all namespaces rather than being confined to one.

---

### Q5 — Why did the developer service account fail to access `prod`, and which security principle does that demonstrate?

`dev-user` failed to access `prod` because the `pod-reader` Role and `dev-user-binding` RoleBinding are both namespace-scoped resources defined exclusively within the `dev` namespace. Kubernetes RBAC enforces a **default-deny** model: every API request is denied unless an explicit Role grants it. No Role or RoleBinding in the `prod` namespace references `dev-user`, so every request `dev-user` makes against `prod` resources is denied — regardless of what that ServiceAccount is permitted to do in `dev`.

This demonstrates the **Principle of Least Privilege** operating through the **namespace isolation boundary**. The developer was given exactly the access their role requires — read access to pods in the development environment — and nothing beyond that. The production environment is a separate security domain that requires a separate, explicitly granted Role and RoleBinding to access.

It also demonstrates **Defence in Depth**: even if a developer's ServiceAccount token is stolen or a pod in `dev` is compromised, the attacker is contained within `dev`. They cannot read, modify, or delete production workloads because the access simply does not exist at the RBAC layer — there is no misconfiguration to exploit, no overly-broad ClusterRoleBinding to abuse. The security boundary is enforced by the API server itself, not by application-layer logic that could be bypassed.

---

---

## Security Best-Practices Checklist

### Session A — AWS IAM (LocalStack)

| # | Best Practice | Status |
|---|---|---|
| 1 | LocalStack container started with Auth Token — Pro edition active | ✅ |
| 2 | `/_localstack/health` confirms `"iam": "available"` and `"is_license_activated": true` | ✅ |
| 3 | Dummy AWS credentials configured — real credentials never used for local emulation | ✅ |
| 4 | `sts get-caller-identity` verified against `http://localhost:4566` — account `000000000000` confirmed | ✅ |
| 5 | IAM identity landscape documented (Root User, IAM User, IAM Policy, IAM Group, IAM Role) | ✅ |
| 6 | Root account credentials protected — not used for any lab operations | ✅ |
| 7 | Admin permissions attached at **group level** (`Admins`) — not directly to the user | ✅ |
| 8 | `CloudAdmin_jihan` created and placed in `Admins` group — group membership verified with `get-group` | ✅ |
| 9 | `AdministratorAccess` scoped to named group only — no wildcard user-level policy attachments | ✅ |
| 10 | `Analyst_jihan` created with **minimum required policy** — `AmazonS3ReadOnlyAccess` only | ✅ |
| 11 | Scoped policy verified with `list-attached-user-policies` | ✅ |
| 12 | No IAM permissions granted to `Analyst_jihan` — privilege escalation path eliminated | ✅ |
| 13 | Access key created and `SecretAccessKey` handled securely — not stored in documentation | ✅ |
| 14 | Access key rotation performed — replacement key created before deactivating old key | ✅ |
| 15 | Old access key set to `Inactive` before deletion — rollback window preserved | ✅ |
| 16 | `list-access-keys` confirms correct `Inactive` / `Active` key states post-rotation | ✅ |
| 17 | Long-lived access key risks documented — STS role-based alternatives noted | ✅ |
| 18 | All 6 Session A evidence screenshots embedded with correct relative paths | ✅ |

### Session B — Kubernetes RBAC

| # | Best Practice | Status |
|---|---|---|
| 19 | Local kind cluster `ccse-lab1` created — no cloud credentials required | ✅ |
| 20 | `kubectl get nodes` confirms control-plane node `Ready` | ✅ |
| 21 | `dev` and `prod` namespaces created — workload environments isolated at API-server level | ✅ |
| 22 | `dev-user` created as a **ServiceAccount** — not a human user credential | ✅ |
| 23 | `pod-reader` Role scoped to `dev` namespace only — no ClusterRole used | ✅ |
| 24 | Role grants only `get`, `watch`, `list` verbs — write and delete operations excluded | ✅ |
| 25 | `dev-user-binding` RoleBinding scoped to `dev` namespace — no cross-namespace access granted | ✅ |
| 26 | `kubectl auth can-i list pods -n dev` returns `yes` — permitted action confirmed | ✅ |
| 27 | `kubectl auth can-i delete pods -n dev` returns `no` — unpermitted verb blocked | ✅ |
| 28 | `kubectl auth can-i list pods -n prod` returns `no` — namespace boundary enforced | ✅ |
| 29 | `kubectl auth can-i delete pods -n prod` returns `no` — dual barrier (verb + namespace) confirmed | ✅ |
| 30 | `kubectl get rolebinding dev-user-binding -n dev -o yaml` verifies binding subjects and roleRef | ✅ |
| 31 | `roleRef` immutability noted — binding cannot be silently escalated post-creation | ✅ |
| 32 | All 5 Session B evidence screenshots embedded with correct relative paths | ✅ |

---

## Teardown & Cleanup

Cleaning up after the lab removes all emulated and local resources, avoids state bleed into future sessions, and reinforces the discipline of treating ephemeral lab environments as disposable.

---

### Session A Teardown — LocalStack IAM Resources

#### 1. Deactivate and Delete All Access Keys

```bash
# Analyst_jihan
awslocal iam list-access-keys --user-name Analyst_jihan
awslocal iam update-access-key \
  --user-name Analyst_jihan \
  --access-key-id <KeyId> \
  --status Inactive
awslocal iam delete-access-key \
  --user-name Analyst_jihan \
  --access-key-id <KeyId>

# CloudAdmin_jihan (if access keys were created)
awslocal iam list-access-keys --user-name CloudAdmin_jihan
awslocal iam delete-access-key \
  --user-name CloudAdmin_jihan \
  --access-key-id <KeyId>
```

#### 2. Remove Users from Groups

```bash
awslocal iam remove-user-from-group \
  --user-name CloudAdmin_jihan \
  --group-name Admins
```

#### 3. Detach Policies

```bash
# Detach group policy
awslocal iam detach-group-policy \
  --group-name Admins \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Detach user policy
awslocal iam detach-user-policy \
  --user-name Analyst_jihan \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

#### 4. Delete IAM Users

```bash
awslocal iam delete-user --user-name CloudAdmin_jihan
awslocal iam delete-user --user-name Analyst_jihan
```

#### 5. Delete the `Admins` Group

```bash
awslocal iam delete-group --group-name Admins
```

#### 6. Stop the LocalStack Container

```bash
# If started with docker-compose:
docker-compose down

# If started with docker run:
docker stop $(docker ps -q --filter "ancestor=localstack/localstack-pro")
```

> **Note:** Stopping LocalStack destroys all in-memory state — IAM users, policies, S3 buckets, and all other emulated resources are gone unless a persistence volume was mounted. This is expected behaviour for ephemeral lab environments.

---

### Session B Teardown — Kubernetes RBAC Resources

#### 1. Delete the RoleBinding

```bash
kubectl delete rolebinding dev-user-binding --namespace dev
```

#### 2. Delete the Role

```bash
kubectl delete role pod-reader --namespace dev
```

#### 3. Delete the ServiceAccount

```bash
kubectl delete serviceaccount dev-user --namespace dev
```

#### 4. Delete the Namespaces

```bash
kubectl delete namespace dev
kubectl delete namespace prod
```

> **Note:** Deleting a namespace removes all resources within it (Pods, Services, ConfigMaps, Roles, RoleBindings, ServiceAccounts) in a single operation. Roles and RoleBindings created inside `dev` are automatically deleted when the namespace is deleted.

#### 5. Delete the kind Cluster

```bash
kind delete cluster --name ccse-lab1
```

This removes the Docker container(s) running the Kubernetes nodes, the associated volumes, and the `kind-ccse-lab1` entry from `~/.kube/config`. The local machine is returned to the state it was in before the lab.

Verify the cluster is gone:

```bash
kind get clusters
# Expected: (no output — or other clusters if any exist)

kubectl config get-contexts
# ccse-lab1 context should no longer be listed
```

---

*Report prepared for IKB42603 Cloud Computing Security Essentials*
*Student: NURUL JIHAN NABILAH BINTI AZLAN | Institution: Universiti Kuala Lumpur (UniKL MIIT) | Instructor: Prof. Dr. Shahrulniza Musa | August 2026*
