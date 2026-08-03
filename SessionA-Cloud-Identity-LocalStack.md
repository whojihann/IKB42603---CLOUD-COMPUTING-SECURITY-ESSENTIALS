# LAB 1: Cloud Account Security, Identity & Access Management
## Session A (Week 1) — Cloud Identity with LocalStack

---

## Header Metadata

| Field | Details |
|---|---|
| **Course Code** | IKB42603 Cloud Computing Security Essentials |
| **Lab Title** | LAB 1: Cloud Account Security, Identity & Access Management |
| **Student Name** | NURUL JIHAN NABILAH BINTI AZLAN |
| **Institution** | UniKL MIIT |
| **Instructor** | Prof. Dr. Shahrulniza Musa |
| **Session** | Session A — Week 1 |
| **Date** | August 3, 2026 |

---

## Table of Contents

1. [Environment Setup Verification](#1-environment-setup-verification)
2. [Task 1 — Map the Cloud Identity Landscape](#2-task-1--map-the-cloud-identity-landscape)
3. [Task 2 — Create a Least-Privilege Admin](#3-task-2--create-a-least-privilege-admin)
4. [Task 3 — Enforce Least Privilege with a Scoped Policy](#4-task-3--enforce-least-privilege-with-a-scoped-policy)
5. [Task 4 — Credential Hygiene & Access Keys](#5-task-4--credential-hygiene--access-keys)
6. [Session A Verification Checklist](#6-session-a-verification-checklist)

---

## 1. Environment Setup Verification

### 1.1 Docker Startup & LocalStack Container

LocalStack is started as a Docker container, exposing the primary API gateway on port `4566` and the Web Console on port `31566`. The container image used is `localstack/localstack-pro`, which requires a valid `LOCALSTACK_AUTH_TOKEN` for activation of the Pro edition and IAM services.

```bash
docker run --rm -it \
  -p 4566:4566 \
  -p 4510-4559:4510-4559 \
  -p 31566:31566 \
  -e LOCALSTACK_AUTH_TOKEN="${LOCALSTACK_AUTH_TOKEN}" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  localstack/localstack-pro
```

Once the container is up, the terminal output shows the LocalStack ASCII banner followed by service readiness logs confirming all emulated AWS services (including IAM) are initialised and listening on `http://localhost:4566`.

### 1.2 LocalStack Health Check — `/_localstack/health`

The health endpoint confirms the container status and which services are running:

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

The critical field is `"is_license_activated": true`, which confirms the Auth Token was accepted and the Pro edition is fully active. The IAM service status of `"available"` is a prerequisite for all subsequent tasks in this lab.

### 1.3 Dummy AWS CLI Configuration

LocalStack does not validate real AWS credentials — it only requires that credential fields are non-empty. Standard dummy values are used:

```bash
aws configure
```

| Prompt | Value Entered |
|---|---|
| AWS Access Key ID | `test` |
| AWS Secret Access Key | `test` |
| Default region name | `us-east-1` |
| Default output format | `json` |

A local endpoint shortcut is also defined to avoid repeating the `--endpoint-url` flag:

```bash
export EP="--endpoint-url=http://localhost:4566"
```

### 1.4 STS Identity Verification — `sts get-caller-identity`

The AWS CLI is tested by calling the STS service against the local endpoint:

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

The `Account` value of `000000000000` is LocalStack's default emulated AWS account ID, confirming the CLI is correctly routing requests to `http://localhost:4566` rather than the live AWS endpoints.

### 1.5 Evidence — Environment Setup & LocalStack IAM Dashboard

The screenshot below shows the LocalStack Web Console with the IAM service dashboard visible, confirming the container is running with the Pro edition active and the IAM service is available for use.

![Environment Setup](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/1.LocalStack%20IAM.png)

*Figure 1: LocalStack Web Console — IAM service dashboard confirming Pro edition activation and service availability.*

### 1.6 Evidence — AWS CLI Setup & STS Identity Check

The screenshot below shows the terminal output of the dummy credential configuration and the successful `sts get-caller-identity` call, confirming end-to-end CLI connectivity to the LocalStack STS endpoint.

![AWS CLI Setup](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/2.Setup%20dummy%20credentials%20%26%20test%20AWS%20CLI.png)

*Figure 2: Terminal confirming dummy AWS credentials configured and `sts get-caller-identity` returning account `000000000000`.*

---

## 2. Task 1 — Map the Cloud Identity Landscape

### 2.1 Objective

Before creating any IAM resources, it is essential to understand the core identity primitives in the AWS IAM model. This task maps each identity component to its technical purpose within the cloud security architecture.

### 2.2 IAM Identity Landscape — Reference Table

| IAM Component | Purpose |
|---|---|
| **Root User** | The initial, unrestricted account identity created when an AWS account is provisioned. It holds full administrative access to all services and billing, bypasses all IAM permission boundaries, and cannot be restricted by IAM policies. Should never be used for day-to-day operations; its credentials must be protected and MFA enforced immediately. |
| **IAM User** | A long-term identity representing a human operator or a service principal within an AWS account. Each IAM user has its own credentials (password and/or access keys) and is subject to IAM policy evaluation. Used to assign individual, auditable access rather than sharing the root account. |
| **IAM Policy** | A JSON document that defines a set of permissions — `Allow` or `Deny` — for specified AWS actions on specified resources. Policies are evaluated at request time: an explicit `Deny` always wins, then an explicit `Allow` grants access, and the implicit default is `Deny`. Policies can be AWS-managed, customer-managed, or inline. |
| **IAM Group** | A logical collection of IAM users. Policies attached to a group are inherited by all members, enabling consistent, role-based permission management at scale. A user can belong to multiple groups; permissions from all groups are combined during policy evaluation. Groups cannot be nested or used as principals in trust policies. |
| **IAM Role** | A temporary identity that can be assumed by AWS services, IAM users, or external federated identities via the AWS Security Token Service (STS). Unlike users, roles do not have permanent credentials — they issue short-lived session tokens. Roles are the preferred mechanism for granting cross-service access (e.g., EC2 assuming an S3 read role) and enabling least-privilege without managing static keys. |

---

## 3. Task 2 — Create a Least-Privilege Admin

### 3.1 Objective

Create a dedicated IAM admin identity that operates under the Principle of Least Privilege (PoLP) — granting full administrative capability via a managed group rather than attaching policies directly to the user.

### 3.2 Step 1 — Create the `Admins` Group

A group is created first so that the admin policy is attached at the group level, making it easier to add or remove admin users in the future without modifying individual user policies.

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

### 3.3 Step 2 — Attach `AdministratorAccess` to the `Admins` Group

The AWS-managed `AdministratorAccess` policy is attached to the `Admins` group. This policy grants full access to all AWS services and resources (`"Action": "*", "Resource": "*"`), which is appropriate for the designated admin group.

```bash
awslocal iam attach-group-policy \
  --group-name Admins \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

No output is returned on success. The operation can be verified with:

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

### 3.4 Step 3 — Create the IAM User `CloudAdmin_jihan`

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

### 3.5 Step 4 — Add `CloudAdmin_jihan` to the `Admins` Group

```bash
awslocal iam add-user-to-group \
  --user-name CloudAdmin_jihan \
  --group-name Admins
```

### 3.6 Step 5 — Verify Group Membership (`aws iam get-group`)

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

The `Users` array confirms `CloudAdmin_jihan` is a member of the `Admins` group and therefore inherits the `AdministratorAccess` policy.

### 3.7 Evidence — Least-Privilege Admin Setup

The screenshot below shows the terminal output for the `Admins` group creation, `AdministratorAccess` policy attachment, `CloudAdmin_jihan` user creation, and group membership addition.

![Admin Setup](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/3.Least-Privilege%20Admin.png)

*Figure 3: Terminal output showing the Admins group creation, AdministratorAccess policy attached, and CloudAdmin_jihan added to the group.*

### 3.8 Evidence — Admin Group Policy Verification

The screenshot below confirms the `get-group` response showing `CloudAdmin_jihan` as a verified member of the `Admins` group, and the attached policy listing confirming `AdministratorAccess` is active at the group level.

![Admin Policy Verification](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/4.Least-Privilege%20Admin%202.0.png)

*Figure 4: `aws iam get-group` output confirming CloudAdmin_jihan's membership in the Admins group with AdministratorAccess policy verified.*

---

## 4. Task 3 — Enforce Least Privilege with a Scoped Policy

### 4.1 Objective

Create a separate IAM user (`Analyst_jihan`) whose permissions are restricted to read-only S3 operations, demonstrating the application of a scoped policy that limits the blast radius in the event of credential compromise.

### 4.2 Step 1 — Create the IAM User `Analyst_jihan`

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

### 4.3 Step 2 — Attach `AmazonS3ReadOnlyAccess` to `Analyst_jihan`

The AWS-managed `AmazonS3ReadOnlyAccess` policy is used, which grants `s3:Get*` and `s3:List*` permissions across all S3 resources. This is the minimum policy required for a data analyst role.

```bash
awslocal iam attach-user-policy \
  --user-name Analyst_jihan \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

### 4.4 Step 3 — List Attached Policies for `Analyst_jihan`

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

### 4.5 Evidence — Analyst Scoped Policy

The screenshot below shows the `Analyst_jihan` user creation, `AmazonS3ReadOnlyAccess` policy attachment, and the `list-attached-user-policies` verification output.

![Analyst Scoped Policy](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/5.Analyst%20User%20%28Scoped%20Policy%29.png)

*Figure 5: Terminal output showing Analyst_jihan created with AmazonS3ReadOnlyAccess — scoped policy attachment verified.*

### 4.6 Security Analysis — Scoped Access and Blast Radius Reduction

Scoping `Analyst_jihan`'s permissions to `AmazonS3ReadOnlyAccess` directly limits the blast radius if the account is compromised. Because the policy only permits `s3:Get*` and `s3:List*` operations, a threat actor who obtains these credentials can read existing S3 objects but cannot modify, delete, or create any resources — not just in S3, but across every other AWS service. There is no path to escalating privileges: the policy grants no IAM actions, so the attacker cannot create new users, generate new access keys for other accounts, or attach broader policies. Lateral movement to compute services like EC2 or Lambda is equally blocked. The damage is effectively bounded to the read exposure of whatever data sits in S3, rather than a full account takeover. This is the practical value of least-privilege — a breach becomes a data confidentiality incident rather than a complete infrastructure compromise.

---

## 5. Task 4 — Credential Hygiene & Access Keys

### 5.1 Objective

Demonstrate the full lifecycle of IAM access key management for `Analyst_jihan`: creation, listing, rotation (creating a replacement key), and deactivation of the old key using `--status Inactive`.

### 5.2 Step 1 — Create an Access Key for `Analyst_jihan`

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

> **Security note:** The `SecretAccessKey` is displayed only once at creation time. It must be stored securely — in a secrets manager or encrypted vault — and never committed to source control or embedded in documentation.

### 5.3 Step 2 — List Access Keys

```bash
awslocal iam list-access-keys --user-name Analyst_jihan
```

**Expected output:**

```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "Analyst_jihan",
            "AccessKeyId": "AKIA...",
            "Status": "Active",
            "CreateDate": "2026-08-03T00:00:00+00:00"
        }
    ]
}
```

The listing confirms the key is active and shows its creation date — useful for auditing key age against a rotation policy (e.g., rotate every 90 days).

### 5.4 Step 3 — Rotate the Key (Create a Replacement)

```bash
awslocal iam create-access-key --user-name Analyst_jihan
```

A second key is created. At this point the user has two active keys. All applications using the old key should be updated to use the new key before the old one is deactivated.

### 5.5 Step 4 — Deactivate the Old Key (`--status Inactive`)

```bash
awslocal iam update-access-key \
  --user-name Analyst_jihan \
  --access-key-id <OldAccessKeyId> \
  --status Inactive
```

Setting the status to `Inactive` preserves the key record for audit purposes while immediately preventing it from authenticating any API calls. This is safer than outright deletion as a first step — it allows rollback if the new key has not been fully propagated to all consumers.

### 5.6 Step 5 — Verify Key Status After Rotation

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

The old key shows `"Status": "Inactive"` and the new key shows `"Status": "Active"`, confirming a successful rotation.

### 5.7 Evidence — Credential Rotation

The screenshot below shows the full access key lifecycle: initial key creation, listing, second key creation for rotation, deactivation of the old key, and the final `list-access-keys` output confirming the Inactive / Active state.

![Credential Rotation](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/6.Credential%20Hygiene%20%26%20Access%20Key%20Management.jpeg)

*Figure 6: Access key rotation workflow — old key deactivated (Inactive), new key active, confirming proper credential hygiene for Analyst_jihan.*

### 5.8 Security Analysis — Risks of Long-Lived Access Keys

Long-lived IAM access keys are one of the most persistent and exploited attack vectors in cloud environments. Unlike passwords, access keys are rarely changed after initial creation, yet they are routinely embedded in source code, CI/CD configuration files, container images, and `.env` files — all of which are frequent targets for secret scanning attacks on public repositories. Once a static key is exposed, an attacker retains access indefinitely until the key is manually rotated or revoked, since the key does not expire on its own. There is no built-in notification when the key is used from an anomalous IP or at an unusual time — detection depends entirely on CloudTrail monitoring and alerting being configured correctly. In the context of `Analyst_jihan`, even though the permissions are scoped to S3 read-only, a compromised long-lived key still allows an attacker to silently exfiltrate data over an extended period. Rotating keys regularly (every 90 days is the AWS benchmark), deactivating rather than immediately deleting keys during rotation, and ultimately replacing long-term keys with IAM roles and short-lived STS tokens wherever possible are the correct mitigations.

---

## 6. Session A Verification Checklist

| # | Deliverable | Task | Status |
|---|---|---|---|
| 1 | LocalStack container started and IAM service available | Environment Setup | ✅ |
| 2 | `/_localstack/health` confirms `"iam": "available"` | Environment Setup | ✅ |
| 3 | `is_license_activated: true` confirmed via health endpoint | Environment Setup | ✅ |
| 4 | Dummy AWS credentials configured via `aws configure` | Environment Setup | ✅ |
| 5 | `sts get-caller-identity` returns account `000000000000` | Environment Setup | ✅ |
| 6 | IAM identity landscape table completed with 5 components | Task 1 | ✅ |
| 7 | Root User, IAM User, IAM Policy, IAM Group, IAM Role defined | Task 1 | ✅ |
| 8 | `Admins` group created in LocalStack IAM | Task 2 | ✅ |
| 9 | `AdministratorAccess` policy attached to `Admins` group | Task 2 | ✅ |
| 10 | `CloudAdmin_jihan` IAM user created | Task 2 | ✅ |
| 11 | `CloudAdmin_jihan` added to `Admins` group | Task 2 | ✅ |
| 12 | `aws iam get-group` confirms `CloudAdmin_jihan` membership | Task 2 | ✅ |
| 13 | `Analyst_jihan` IAM user created | Task 3 | ✅ |
| 14 | `AmazonS3ReadOnlyAccess` attached to `Analyst_jihan` | Task 3 | ✅ |
| 15 | `list-attached-user-policies` confirms scoped policy | Task 3 | ✅ |
| 16 | Blast radius analysis documented for scoped Analyst access | Task 3 | ✅ |
| 17 | Access key created for `Analyst_jihan` | Task 4 | ✅ |
| 18 | `list-access-keys` shows Active key | Task 4 | ✅ |
| 19 | New replacement key created (rotation step) | Task 4 | ✅ |
| 20 | Old key deactivated with `--status Inactive` | Task 4 | ✅ |
| 21 | `list-access-keys` confirms Inactive / Active key states | Task 4 | ✅ |
| 22 | Risks of long-lived access keys documented | Task 4 | ✅ |
| 23 | All 6 evidence screenshots embedded with correct paths | All Tasks | ✅ |

---

*Lab report prepared for IKB42603 Cloud Computing Security Essentials — Session A (Week 1): Cloud Identity with LocalStack.*
*Student: NURUL JIHAN NABILAH BINTI AZLAN | Institution: UniKL MIIT | Instructor: Prof. Dr. Shahrulniza Musa*
