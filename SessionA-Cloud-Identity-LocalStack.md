# Lab 0.1 — LocalStack with Auth Token + Web Console

---

## Header Metadata

| Field | Details |
|---|---|
| **Course Code** | IKB42603 Cloud Computing Security Essentials |
| **Lab Title** | Lab 0.1 — LocalStack with Auth Token + Web Console |
| **Student Name** | NURUL JIHAN NABILAH BINTI AZLAN |
| **Platform** | LocalStack Community / Pro (Auth Token Track) |

---

## Table of Contents

1. [Overview & Objectives](#1-overview--objectives)
2. [Prerequisites & Environment Setup](#2-prerequisites--environment-setup)
3. [Part 1 — Activating LocalStack with Auth Token](#3-part-1--activating-localstack-with-auth-token)
4. [Part 2 — Verifying the LocalStack Web Console & Resource Browser](#4-part-2--verifying-the-localstack-web-console--resource-browser)
5. [Part 3 — Configuring Dummy AWS Credentials & Testing AWS CLI](#5-part-3--configuring-dummy-aws-credentials--testing-aws-cli)
6. [Part 4 — IAM Least-Privilege Admin User Setup](#6-part-4--iam-least-privilege-admin-user-setup)
7. [Part 5 — Least-Privilege Admin 2.0 — Policy Verification](#7-part-5--least-privilege-admin-20--policy-verification)
8. [Part 6 — Analyst User with Scoped Policy](#8-part-6--analyst-user-with-scoped-policy)
9. [Part 7 — Credential Hygiene & Access Key Management](#9-part-7--credential-hygiene--access-key-management)
10. [Part 8 — Teardown & Cleanup](#10-part-8--teardown--cleanup)
11. [Verification Checklist](#11-verification-checklist)
12. [Summary](#12-summary)

---

## 1. Overview & Objectives

### 1.1 Context — Auth-Token Track

> **Note:** Starting from **23 March 2026**, LocalStack requires an **Auth Token** (previously called an API key) for activating the Pro tier and accessing advanced services such as the **Web Console** and **Resource Browser**. This lab follows the **Auth-Token activation track**, which is the current and recommended method for all new LocalStack installations.

This lab demonstrates how to:

- Start LocalStack using a valid **Auth Token** passed via the `LOCALSTACK_AUTH_TOKEN` environment variable.
- Verify activation through the `/_localstack/info` health endpoint.
- Access the **LocalStack Web Console** (port `31566`) and the **Resource Browser**.
- Configure **dummy AWS CLI credentials** for local emulation.
- Create **IAM users**, **least-privilege policies**, and **scoped access keys** using `awslocal`.
- Practice **credential hygiene** — rotating and deactivating access keys.

### 1.2 Learning Objectives

| # | Objective |
|---|---|
| 1 | Start and verify LocalStack using an Auth Token |
| 2 | Use the LocalStack Web Console and Resource Browser |
| 3 | Configure AWS CLI for local endpoint targeting |
| 4 | Create IAM users with least-privilege policies |
| 5 | Test IAM permission boundaries with scoped users |
| 6 | Rotate and deactivate IAM access keys safely |

---

## 2. Prerequisites & Environment Setup

### 2.1 Required Tools

| Tool | Version | Purpose |
|---|---|---|
| Docker Desktop | ≥ 4.x | Runs the LocalStack container |
| AWS CLI v2 | ≥ 2.x | Sends API commands to LocalStack |
| `awslocal` wrapper | latest | Automatically targets `http://localhost:4566` |
| Python / pip | ≥ 3.8 | For `localstack` CLI and `awscli-local` |
| LocalStack Auth Token | valid | Required since March 23 2026 |

### 2.2 Install `awscli-local`

```bash
pip install awscli-local
```

### 2.3 Retrieve Your Auth Token

Log in to [https://app.localstack.cloud](https://app.localstack.cloud) → **Account Settings** → **Auth Token**.

> ⚠️ **Security Note:** Your `LOCALSTACK_AUTH_TOKEN` is a **secret credential**. **NEVER** commit it to Git, share it in screenshots, or hardcode it in any file. Always inject it as an environment variable at runtime.

---

## 3. Part 1 — Activating LocalStack with Auth Token

### 3.1 Export the Auth Token

Open a terminal and export your token before starting LocalStack:

```bash
export LOCALSTACK_AUTH_TOKEN="ls-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
```

> ⚠️ **Security Note:** Never paste your actual token into any shared document, public repository, or screenshot. Use a placeholder such as `ls-...` in all documentation.

### 3.2 Start LocalStack via Docker

```bash
docker run --rm -it \
  -p 4566:4566 \
  -p 4510-4559:4510-4559 \
  -p 31566:31566 \
  -e LOCALSTACK_AUTH_TOKEN="${LOCALSTACK_AUTH_TOKEN}" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  localstack/localstack-pro
```

Alternatively, using `docker-compose.yml`:

```yaml
version: "3.8"
services:
  localstack:
    image: localstack/localstack-pro
    ports:
      - "4566:4566"
      - "4510-4559:4510-4559"
      - "31566:31566"
    environment:
      - LOCALSTACK_AUTH_TOKEN=${LOCALSTACK_AUTH_TOKEN}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

```bash
docker-compose up -d
```

### 3.3 Verify Activation via `/_localstack/info`

```bash
curl http://localhost:4566/_localstack/info | python3 -m json.tool
```

**Expected output (excerpt):**

```json
{
  "version": "3.x.x",
  "edition": "pro",
  "is_license_activated": true,
  "session_id": "...",
  "machine_id": "...",
  "system": "linux",
  "is_docker": true
}
```

The key field to verify is `"is_license_activated": true`.

### 3.4 Evidence Screenshot

The screenshot below shows the LocalStack **IAM** service dashboard visible in the Web Console, confirming the container is running with a valid Auth Token and the Pro edition is active.

![1. LocalStack IAM — Container Activation and Licence Verification](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/1.LocalStack%20IAM.png)

*Figure 1: LocalStack Web Console showing the IAM service is available, confirming Pro edition activation via Auth Token.*

---

## 4. Part 2 — Verifying the LocalStack Web Console & Resource Browser

### 4.1 Access the Web Console

Open a browser and navigate to:

```
http://localhost:31566
```

You should see the **LocalStack Web Console** dashboard listing all available AWS service emulators.

### 4.2 Navigate the Resource Browser

From the Web Console sidebar, select **Resource Browser**. This allows you to:

- View all emulated AWS resources (S3 buckets, IAM users, Lambda functions, etc.)
- Create and manage resources directly through the GUI.
- Inspect resource state in real time.

**Key Web Console URLs:**

| Feature | URL |
|---|---|
| Dashboard | `http://localhost:31566` |
| Resource Browser | `http://localhost:31566/resources` |
| IAM Users | `http://localhost:31566/resources/iam/users` |
| S3 Buckets | `http://localhost:31566/resources/s3` |

> **Note:** The Web Console is a **Pro-only** feature. It is only accessible when `is_license_activated: true` is confirmed.

---

## 5. Part 3 — Configuring Dummy AWS Credentials & Testing AWS CLI

### 5.1 Why Dummy Credentials Are Needed

LocalStack does not validate real AWS credentials — it only requires that credentials are **present and non-empty**. Any dummy values will work.

### 5.2 Configure Dummy Credentials

```bash
aws configure
```

Enter the following dummy values:

```
AWS Access Key ID:     test
AWS Secret Access Key: test
Default region name:   us-east-1
Default output format: json
```

Or set them directly as environment variables:

```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
```

### 5.3 Define the Local Endpoint Shortcut

To avoid typing `--endpoint-url http://localhost:4566` on every command, define an alias:

```bash
export EP="--endpoint-url=http://localhost:4566"
```

### 5.4 Verify Identity with STS

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

This confirms the AWS CLI is successfully communicating with the LocalStack STS endpoint.

### 5.5 Evidence Screenshot

The screenshot below shows the terminal output of `aws $EP sts get-caller-identity` after configuring dummy credentials, confirming the local endpoint is reachable.

![2. Setup Dummy Credentials & Test AWS CLI](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/2.Setup%20dummy%20credentials%20%26%20test%20AWS%20CLI.png)

*Figure 2: Terminal output confirming dummy credential configuration and successful `sts get-caller-identity` call against the LocalStack STS endpoint.*

---

## 6. Part 4 — IAM Least-Privilege Admin User Setup

### 6.1 Principle of Least Privilege

The **Principle of Least Privilege (PoLP)** states that every user, process, or service should have only the **minimum permissions** necessary to perform its intended function. In this part, we create an admin user that has full IAM and service access, but the policy is explicitly defined — avoiding the use of `*:*` wildcards where possible.

### 6.2 Create the IAM Admin User

```bash
awslocal iam create-user --user-name admin-user
```

**Output:**

```json
{
    "User": {
        "UserId": "AIDA...",
        "Arn": "arn:aws:iam::000000000000:user/admin-user",
        "UserName": "admin-user",
        "Path": "/",
        "CreateDate": "2026-03-23T00:00:00+00:00"
    }
}
```

### 6.3 Create a Least-Privilege Admin Policy

Save the following policy document as `admin-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAdminActions",
      "Effect": "Allow",
      "Action": [
        "iam:*",
        "s3:*",
        "ec2:*",
        "lambda:*",
        "sts:GetCallerIdentity",
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}
```

Create the policy in LocalStack IAM:

```bash
awslocal iam create-policy \
  --policy-name LeastPrivilegeAdminPolicy \
  --policy-document file://admin-policy.json
```

### 6.4 Attach the Policy to the Admin User

```bash
awslocal iam attach-user-policy \
  --user-name admin-user \
  --policy-arn arn:aws:iam::000000000000:policy/LeastPrivilegeAdminPolicy
```

### 6.5 Verify Attached Policies

```bash
awslocal iam list-attached-user-policies --user-name admin-user
```

**Expected output:**

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "LeastPrivilegeAdminPolicy",
            "PolicyArn": "arn:aws:iam::000000000000:policy/LeastPrivilegeAdminPolicy"
        }
    ]
}
```

### 6.6 Evidence Screenshot

The screenshot below shows the IAM policy creation and attachment workflow for the `admin-user`, confirming the least-privilege admin policy is successfully associated.

![3. Least-Privilege Admin — User Setup and Policy Attachment](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/3.Least-Privilege%20Admin.png)

*Figure 3: Terminal and/or Web Console view showing the IAM admin user creation and least-privilege policy attachment.*

---

## 7. Part 5 — Least-Privilege Admin 2.0 — Policy Verification

### 7.1 Create an Access Key for the Admin User

```bash
awslocal iam create-access-key --user-name admin-user
```

**Output:**

```json
{
    "AccessKey": {
        "UserName": "admin-user",
        "AccessKeyId": "AKIA...",
        "SecretAccessKey": "...",
        "Status": "Active",
        "CreateDate": "2026-03-23T00:00:00+00:00"
    }
}
```

> ⚠️ **Security Note:** Treat the `SecretAccessKey` as a password. It is shown only **once** at creation time. Store it securely and never commit it to source control.

### 7.2 Simulate the Admin User's Permissions

Set temporary environment variables using the admin user's new keys:

```bash
export AWS_ACCESS_KEY_ID="<AdminUserAccessKeyId>"
export AWS_SECRET_ACCESS_KEY="<AdminUserSecretAccessKey>"
```

### 7.3 Test Allowed Actions

```bash
# Should succeed — IAM:ListUsers is permitted
awslocal iam list-users

# Should succeed — S3:ListBuckets is permitted
awslocal s3 ls
```

### 7.4 Test Denied Actions (Negative Test)

To verify least-privilege boundaries, attempt an action outside the policy scope (e.g., if `cloudwatch:*` is not included):

```bash
awslocal cloudwatch list-metrics
```

**Expected:** `AccessDenied` error — confirming the policy boundary is enforced.

### 7.5 Verify Policy Contents

```bash
awslocal iam get-policy \
  --policy-arn arn:aws:iam::000000000000:policy/LeastPrivilegeAdminPolicy
```

```bash
awslocal iam get-policy-version \
  --policy-arn arn:aws:iam::000000000000:policy/LeastPrivilegeAdminPolicy \
  --version-id v1
```

### 7.6 Evidence Screenshot

The screenshot below demonstrates the admin policy verification, showing the policy version document and permission boundaries enforced for the `admin-user`.

![4. Least-Privilege Admin 2.0 — Policy Verification](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/4.Least-Privilege%20Admin%202.0.png)

*Figure 4: Verification of the least-privilege admin policy document, showing explicit allowed actions and confirming no wildcard `*:*` overreach.*

---

## 8. Part 6 — Analyst User with Scoped Policy

### 8.1 Purpose of a Scoped Policy

An **Analyst User** should have **read-only** access limited to specific services. This models a real-world scenario where a data analyst can query resources but cannot modify infrastructure.

### 8.2 Create the Analyst User

```bash
awslocal iam create-user --user-name analyst-user
```

### 8.3 Create the Scoped Read-Only Policy

Save as `analyst-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": [
        "arn:aws:s3:::*",
        "arn:aws:s3:::*/*"
      ]
    },
    {
      "Sid": "AllowSTSIdentity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
```

Create and attach the policy:

```bash
awslocal iam create-policy \
  --policy-name AnalystScopedPolicy \
  --policy-document file://analyst-policy.json

awslocal iam attach-user-policy \
  --user-name analyst-user \
  --policy-arn arn:aws:iam::000000000000:policy/AnalystScopedPolicy
```

### 8.4 Create Access Keys for the Analyst User

```bash
awslocal iam create-access-key --user-name analyst-user
```

### 8.5 Test the Analyst Scope

Switch to the analyst's credentials and test permissions:

```bash
export AWS_ACCESS_KEY_ID="<AnalystUserAccessKeyId>"
export AWS_SECRET_ACCESS_KEY="<AnalystUserSecretAccessKey>"

# Should succeed — ListBucket is allowed
awslocal s3 ls

# Should FAIL — IAM:ListUsers is NOT in the policy
awslocal iam list-users
```

**Expected for IAM call:** `AccessDenied` — confirms the scoped policy is correctly restricting IAM actions.

### 8.6 Evidence Screenshot

The screenshot below shows the analyst user creation, scoped policy attachment, and the results of permission boundary testing.

![5. Analyst User (Scoped Policy)](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/5.Analyst%20User%20(Scoped%20Policy).png)

*Figure 5: Analyst user with scoped read-only policy applied — showing allowed S3 list operations and denied IAM operations, confirming correct permission scoping.*

---

## 9. Part 7 — Credential Hygiene & Access Key Management

### 9.1 Why Credential Hygiene Matters

Leaked or long-lived credentials are among the **top causes of cloud security breaches**. Best practices include:

- Rotating access keys periodically (every 90 days or less).
- Deactivating keys before deleting them.
- Never storing keys in source code, `.env` files committed to Git, or unencrypted storage.
- Using IAM roles instead of long-term access keys wherever possible.

### 9.2 List All Access Keys for a User

```bash
awslocal iam list-access-keys --user-name admin-user
```

**Output:**

```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "admin-user",
            "AccessKeyId": "AKIA...",
            "Status": "Active",
            "CreateDate": "2026-03-23T00:00:00+00:00"
        }
    ]
}
```

### 9.3 Create a New (Replacement) Access Key

```bash
awslocal iam create-access-key --user-name admin-user
```

> After creating the new key, update all systems/applications using the old key to use the new credentials **before** deactivating the old one.

### 9.4 Deactivate the Old Access Key

```bash
awslocal iam update-access-key \
  --user-name admin-user \
  --access-key-id <OldAccessKeyId> \
  --status Inactive
```

### 9.5 Verify the Key Status

```bash
awslocal iam list-access-keys --user-name admin-user
```

Confirm the old key now shows `"Status": "Inactive"` and the new key shows `"Status": "Active"`.

### 9.6 Delete the Deactivated Key

```bash
awslocal iam delete-access-key \
  --user-name admin-user \
  --access-key-id <OldAccessKeyId>
```

### 9.7 Evidence Screenshot

The screenshot below shows the access key lifecycle — creation, deactivation, and deletion — demonstrating proper credential hygiene practices.

![6. Credential Hygiene & Access Key Management]![6. Credential Hygiene & Access Key Management](./Session%20A%20(Week%201)%20%E2%80%94%20Cloud%20Identity%20with%20LocalStack/6.Credential%20Hygiene%20%26%20Access%20Key.png)

*Figure 6: Access key management workflow — listing active keys, deactivating the old key, and confirming the Inactive status prior to deletion.*

---

## 10. Part 8 — Teardown & Cleanup

### 10.1 Detach Policies from Users

```bash
awslocal iam detach-user-policy \
  --user-name admin-user \
  --policy-arn arn:aws:iam::000000000000:policy/LeastPrivilegeAdminPolicy

awslocal iam detach-user-policy \
  --user-name analyst-user \
  --policy-arn arn:aws:iam::000000000000:policy/AnalystScopedPolicy
```

### 10.2 Delete Access Keys

```bash
# List then delete all keys for each user
awslocal iam list-access-keys --user-name admin-user
awslocal iam delete-access-key --user-name admin-user --access-key-id <KeyId>

awslocal iam list-access-keys --user-name analyst-user
awslocal iam delete-access-key --user-name analyst-user --access-key-id <KeyId>
```

### 10.3 Delete IAM Users

```bash
awslocal iam delete-user --user-name admin-user
awslocal iam delete-user --user-name analyst-user
```

### 10.4 Delete IAM Policies

```bash
awslocal iam delete-policy \
  --policy-arn arn:aws:iam::000000000000:policy/LeastPrivilegeAdminPolicy

awslocal iam delete-policy \
  --policy-arn arn:aws:iam::000000000000:policy/AnalystScopedPolicy
```

### 10.5 Stop the LocalStack Container

```bash
# If started with docker-compose:
docker-compose down

# If started with docker run:
docker stop <container_id>
```

> **Note:** Stopping the LocalStack container destroys all in-memory state (IAM users, policies, S3 buckets, etc.) unless a persistence volume was configured.

---

## 11. Verification Checklist

| # | Task | Status |
|---|---|---|
| 1 | LocalStack container started successfully with Auth Token | ✅ |
| 2 | `/_localstack/info` confirms `is_license_activated: true` | ✅ |
| 3 | LocalStack Web Console accessible at `localhost:31566` | ✅ |
| 4 | Resource Browser visible and functional in Web Console | ✅ |
| 5 | Dummy AWS credentials configured via `aws configure` | ✅ |
| 6 | `aws $EP sts get-caller-identity` returns account `000000000000` | ✅ |
| 7 | `admin-user` created successfully in LocalStack IAM | ✅ |
| 8 | `LeastPrivilegeAdminPolicy` created and attached to `admin-user` | ✅ |
| 9 | Admin policy version verified — no wildcard `*:*` overreach | ✅ |
| 10 | `analyst-user` created with scoped read-only S3 policy | ✅ |
| 11 | Analyst user permission boundary tested — IAM denied, S3 allowed | ✅ |
| 12 | Access key rotation demonstrated — old key deactivated, new key active | ✅ |
| 13 | Old access key deleted after deactivation (credential hygiene) | ✅ |
| 14 | All IAM resources cleaned up after lab completion | ✅ |

---

## 12. Summary

This lab successfully demonstrated the **Auth-Token activation track** for LocalStack Pro (effective since 23 March 2026), covering the full lifecycle of cloud identity management in a local AWS emulation environment.

**Key outcomes:**

1. **LocalStack Activation** — The container was launched with `LOCALSTACK_AUTH_TOKEN` and verified via `/_localstack/info`, confirming Pro edition features including the Web Console and Resource Browser.

2. **AWS CLI Integration** — Dummy credentials were configured and `sts get-caller-identity` confirmed end-to-end connectivity to the local STS endpoint at `http://localhost:4566`.

3. **Least-Privilege IAM** — An `admin-user` was created with an explicitly scoped policy (`LeastPrivilegeAdminPolicy`) granting specific service permissions rather than blanket `*:*` access, demonstrating the **Principle of Least Privilege**.

4. **Scoped Analyst Policy** — An `analyst-user` was created with a tightly scoped read-only S3 policy (`AnalystScopedPolicy`), confirmed by positive (S3 list) and negative (IAM denied) permission tests.

5. **Credential Hygiene** — The access key lifecycle (create → rotate → deactivate → delete) was demonstrated, reinforcing security best practices around credential management in cloud environments.

> ⚠️ **Final Security Reminder:** Always treat `LOCALSTACK_AUTH_TOKEN`, AWS `SecretAccessKey` values, and any IAM credentials as **secrets**. Use environment variables, secrets managers, or `.env` files excluded from version control (`.gitignore`). Never embed secrets in code, documentation, or screenshots shared publicly.

---

*Report generated for IKB42603 Cloud Computing Security Essentials — Session A (Week 1): Cloud Identity with LocalStack.*
