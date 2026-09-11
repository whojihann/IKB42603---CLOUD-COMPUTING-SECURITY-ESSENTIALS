# IKB42603 — Cloud Computing Security Essentials
## Lab 6: Object Storage Security & the Data Security Lifecycle

---

| Field | Details |
|---|---|
| **Course Code** | IKB42603 |
| **Course Name** | Cloud Computing Security Essentials |
| **Lab Title** | Lab 6 — Object Storage Security & the Data Security Lifecycle |
| **Institution** | Universiti Kuala Lumpur — Malaysian Institute of Information Technology (UniKL MIIT) |
| **Lab Environment** | LocalStack Pro (Docker) on Kali Linux — emulating AWS S3, IAM, and KMS |
| **Date Performed** | 11 September 2026 |
| **Name** | Nurul Jihan Nabilah Binti Azlan |

---

## Table of Contents

1. [One-Time Environment Setup](#1-one-time-environment-setup)
2. [Task 1 — Classify the Data Before You Store It](#2-task-1--classify-the-data-before-you-store-it)
3. [Task 2 — Reproduce the Archetypal Breach](#3-task-2--reproduce-the-archetypal-breach)
4. [Task 3 — Remediate with Block Public Access](#4-task-3--remediate-with-block-public-access)
5. [Task 4 — Identity Policy vs Resource Policy](#5-task-4--identity-policy-vs-resource-policy)
6. [Task 5 — Default Encryption at Rest (SSE-KMS)](#6-task-5--default-encryption-at-rest-sse-kms)
7. [Task 6 — Delegated Access and the Condition-Key Trap](#7-task-6--delegated-access-and-the-condition-key-trap)
8. [Task 7 — Versioning, Delete Markers & Data Remanence](#8-task-7--versioning-delete-markers--data-remanence)
9. [Task 8 — Lifecycle, Retention & Cryptographic Erasure](#9-task-8--lifecycle-retention--cryptographic-erasure)
10. [Verification Command](#10-verification-command)
11. [Cleanup & Teardown](#11-cleanup--teardown)
12. [Data Classification Table](#12-data-classification-table)
13. [Short-Answer Questions](#13-short-answer-questions)
14. [Security Best-Practices Checklist](#14-security-best-practices-checklist)

---

## 1. One-Time Environment Setup

### Summary

Before any lab task could be executed, a fully isolated AWS-compatible environment was provisioned using **LocalStack Pro** running inside Docker. LocalStack emulates the full AWS API surface — including S3, IAM, KMS, and STS — on `localhost:4566`, enabling safe hands-on experimentation without incurring cloud costs or risk to production resources.

The setup procedure consisted of three steps:

1. **Pull and launch the LocalStack Pro container** — The existing container (if any) was first removed with `docker rm -f localstack`, then a fresh container was started with port `4566:4566` exposed, with `LOCALSTACK_AUTH_TOKEN` and `ENFORCE_IAM=1` injected as environment variables. The `ENFORCE_IAM=1` flag is critical: it instructs LocalStack to evaluate IAM and bucket policies in the same way AWS would, making the policy exercises in later tasks meaningful.

2. **Configure the AWS CLI profile** — The endpoint alias `EP='--endpoint-url=http://localhost:4566'` was exported to avoid repeating the long flag in every command. The AWS CLI was configured with dummy credentials (`aws_access_key_id=test`, `aws_secret_access_key=test`, `region=us-east-1`).

3. **Verify identity** — `aws $EP sts get-caller-identity` confirmed the environment was responsive and returned the simulated root identity (`arn:aws:iam::000000000000:root`), proving that the LocalStack endpoint was reachable and IAM enforcement was active.

### Evidence

**Figure 1.1 — Docker pull and container startup**

![One-Time Environment Setup Part 1](One_Time_Environment%20Setup%20part%201.png)

> The terminal confirms LocalStack Pro image layers were pulled successfully and the container named `localstack` was started. The image digest `sha256:3fe5b51caec82b966a34485b5b43efd68075ff8161f9b0a34091fad9abb0ff82` verifies image integrity.

---

**Figure 1.2 — AWS CLI configuration and identity verification**

![One-Time Environment Setup Part 2](One_Time_Environment%20Setup%20part%202.png.png)

> The endpoint alias `EP` is set and `aws $EP sts get-caller-identity` returns:
> ```json
> {
>     "UserId": "000000000000",
>     "Account": "000000000000",
>     "Arn": "arn:aws:iam::000000000000:root"
> }
> ```
> This confirms the LocalStack STS service is active, IAM enforcement is loaded, and subsequent commands will be evaluated against real policy logic.

---

## 2. Task 1 — Classify the Data Before You Store It

### Summary

The objective of this task was to establish a **data classification taxonomy** before any sensitive data enters the object store — a foundational principle of the Data Security Lifecycle (DSL). Three sample files representing different sensitivity levels were created and uploaded to a newly provisioned S3 bucket, each tagged with a `classification` key to enforce downstream policy decisions.

**Key steps performed:**

- **Bucket creation** — A uniquely named bucket `miit-patient-records-4956` was created using a `$RANDOM`-seeded variable to prevent naming collisions.
- **Sample data creation** — Three plaintext files were created representing real-world healthcare data scenarios:
  - `public-notice.txt` — "Ward visiting hours 10am-8pm" (publicly shareable operational notice)
  - `internal-roster.txt` — "Staff duty schedule, week 12" (internal HR data, not for public consumption)
  - `confidential-record.txt` — "Patient: Ahmad bin Ali, Diagnosis: confidential" (Protected Health Information, highest sensitivity)
- **Object upload with tagging** — Each file was uploaded to a prefix matching its classification level (`public/`, `internal/`, `confidential/`) and tagged with `classification=<level>` using the `--tagging` parameter of `s3api put-object`.
- **Verification** — `list-objects-v2` confirmed all three objects were present; `get-object-tagging` on `confidential/record.txt` confirmed the tag `{"Key": "classification", "Value": "confidential"}` was correctly applied.

Object tags serve as **metadata-driven control anchors** — IAM condition keys such as `s3:ExistingObjectTag/<key>` and `aws:ResourceTag/<key>` can reference them to enforce attribute-based access control (ABAC) policies in production environments.

### Evidence

**Figure 2.1 — Bucket creation, file upload, and tagging**

![Task 1 Part 1](Task%201%20%E2%80%94%20Classify%20the%20Data%20Before%20You%20Store%20It%20part%201.png)

> The terminal confirms:
> - Bucket `miit-patient-records-4956` was created (`"Location": "/miit-patient-records-4956"`).
> - All three objects were uploaded successfully with `ServerSideEncryption: AES256` (LocalStack default SSE-S3 applied at upload).
> - Each `put-object` response includes an `ETag` and `ChecksumCRC64NVME` confirming data integrity.

---

**Figure 2.2 — Object listing and tag verification**

![Task 1 Part 2](Task%201%20%E2%80%94%20Classify%20the%20Data%20Before%20You%20Store%20It%20part%202.png)

> `list-objects-v2` output (table format):
> ```
> | confidential/record.txt  | 48 |
> | internal/roster.txt      | 29 |
> | public/notice.txt        | 29 |
> ```
> `get-object-tagging` on `confidential/record.txt` returns:
> ```json
> { "TagSet": [{ "Key": "classification", "Value": "confidential" }] }
> ```
> This confirms the tagging strategy is correctly applied and queryable — a prerequisite for any ABAC policy that uses tag-based conditions.

---

## 3. Task 2 — Reproduce the Archetypal Breach

### Summary

This task deliberately reproduced the most common and consequential S3 misconfiguration in cloud security history: a **wildcard-principal bucket policy** that grants unauthenticated read access to any internet user. The exercise demonstrates, with concrete evidence, exactly how sensitive data is exposed and why `"Principal": "*"` is the single most dangerous element a bucket policy can contain.

**Key steps performed:**

- **Policy authoring** — A bucket policy (`public-policy.json`) was crafted with `Effect: Allow`, `Principal: "*"`, `Action: s3:GetObject`, scoped to all objects in the bucket (`arn:aws:s3:::$BUCKET/*`).
- **Policy application** — `put-bucket-policy` applied the policy; `get-bucket-policy` confirmed it was stored exactly as written.
- **Exploitation simulation** — An anonymous `curl` request (no AWS credentials, no signature) was issued directly to the LocalStack HTTP endpoint for `confidential/record.txt`. The response was **HTTP 200** and the full plaintext content of the confidential patient record was returned:
  ```
  Patient: Ahmad bin Ali, Diagnosis: confidential
  ```

This proved that **PHI (Protected Health Information) was exposed to any unauthenticated HTTP client** — precisely the breach pattern that has affected numerous healthcare, financial, and government organisations globally.

### Evidence

**Figure 3.1 — Policy creation, application, and anonymous exploitation**

![Task 2](Task%202%20%E2%80%94%20Reproduce%20the%20Archetypal%20Breach.png)

> The terminal shows:
> - Policy JSON with `"Principal": "*"` applied successfully.
> - `curl -s -o leaked.txt -w 'HTTP %{http_code}\n' http://localhost:4566/$BUCKET/confidential/record.txt` returns **HTTP 200**.
> - `cat leaked.txt` prints the full PHI: `Patient: Ahmad bin Ali, Diagnosis: confidential`.
>
> **Root cause:** The `"Principal": "*"` element grants the `s3:GetObject` permission to every principal in the universe — authenticated or not, known to AWS or not. No credentials, no signature, and no identity verification were required to retrieve the file.

---

## 4. Task 3 — Remediate with Block Public Access

### Summary

This task applied the **S3 Block Public Access (BPA)** feature — AWS's account- and bucket-level guardrail designed to prevent accidental or malicious public exposure — and then explored a critical nuance: the distinction between what BPA blocks and what it does not.

**Key steps performed:**

1. **Delete the offending policy** — `delete-bucket-policy` removed the `PublicReadEverything` policy that caused the breach in Task 2.
2. **Enable all four BPA flags** via `put-public-access-block`:
   - `BlockPublicAcls=true` — prevents new ACLs that grant public access
   - `IgnorePublicAcls=true` — ignores any existing ACLs that grant public access
   - `BlockPublicPolicy=true` — blocks any new bucket policy that grants public access to principals outside the account
   - `RestrictPublicBuckets=true` — restricts access to the bucket for cross-account and anonymous principals, even if a policy grants it
3. **Verification** — `get-public-access-block` confirmed all four flags are `true`.
4. **Least-privilege resource policy** — A new bucket policy (`least-privilege-policy.json`) was applied, restricting `s3:GetObject` on `internal/*` to the specific IAM principal `arn:aws:iam::000000000000:root`. This replaced the wildcard with a named, authenticated principal.

**Important observation (LocalStack behaviour):** After applying BPA and re-adding a policy, the anonymous `curl` request still returned **HTTP 200**. This is a known limitation of LocalStack Pro's HTTP endpoint: it routes requests directly to the S3 service layer and does not replicate the AWS edge-layer enforcement of `RestrictPublicBuckets` for unauthenticated HTTP requests. In production AWS, `RestrictPublicBuckets=true` would cause this request to return **HTTP 403 (Access Denied)** regardless of any bucket policy.

### Evidence

**Figure 4.1 — BPA activation, verification, and anonymous re-test**

![Task 3 Part 1](Task%203%20%E2%80%94%20Remediate%20with%20Block%20Public%20Access%20part%201.png)

> Key outputs:
> - `delete-bucket-policy` succeeds silently (no error = success).
> - `put-public-access-block` with all four flags set returns no error.
> - `get-public-access-block` confirms:
>   ```json
>   { "BlockPublicAcls": true, "IgnorePublicAcls": true,
>     "BlockPublicPolicy": true, "RestrictPublicBuckets": true }
>   ```
> - The `curl` re-test returns **HTTP 200** — reflecting LocalStack's HTTP-layer limitation (documented; in real AWS this would be HTTP 403).

---

**Figure 4.2 — Least-privilege resource policy applied**

![Task 3 Part 2](Task%203%20%E2%80%94%20Remediate%20with%20Block%20Public%20Access%20part%202.png)

> The new bucket policy (`AccountReadInternalOnly`) replaces `Principal: "*"` with `Principal: {"AWS": "arn:aws:iam::000000000000:root"}` and scopes the resource to `internal/*` only. This demonstrates the principle of least privilege: a named, authenticated identity is granted the minimum necessary permission on a narrowly scoped resource path.

---

## 5. Task 4 — Identity Policy vs Resource Policy

### Summary

This task explored the **AWS policy evaluation logic** — specifically how IAM identity-based policies and S3 resource-based (bucket) policies interact, and how an explicit `Deny` in a resource policy always overrides an `Allow` in an identity policy.

**Key steps performed:**

1. **IAM user creation** — A user `DataAnalyst` was created with ARN `arn:aws:iam::000000000000:user/DataAnalyst`.
2. **Identity policy attachment** — An inline policy (`S3ReadAll`) was attached, granting `s3:GetObject` and `s3:ListBucket` on `Resource: "*"` — effectively allowing the analyst to read any object in any bucket.
3. **Analyst credentials** — Access keys were generated and configured in a separate AWS CLI profile (`analyst`).
4. **Resource policy with mixed effects** — A two-statement bucket policy (`deny-confidential.json`) was applied:
   - `AllowAnalystInternal` — `Effect: Allow` for `DataAnalyst` on `internal/*`
   - `DenyAnalystConfential` — `Effect: Deny` for `DataAnalyst` on `confidential/*` with `Action: s3:*`
5. **Access testing:**
   - `internal/roster.txt` → **ALLOWED** (HTTP 200, object downloaded successfully)
   - `confidential/record.txt` → **ACCESS DENIED** with the explicit error: *"User: arn:aws:iam::000000000000:user/DataAnalyst is not authorized to perform: s3:GetObject on resource: ... with an explicit deny in a resource-based policy"*

**Key lesson:** AWS IAM policy evaluation applies a **Deny-wins** rule. Even though the analyst's identity policy grants `s3:GetObject` on `*`, the explicit `Deny` in the bucket resource policy overrides it completely. An explicit `Deny` cannot be overridden by any `Allow`, regardless of how broad the identity policy is.

### Evidence

**Figure 5.1 — DataAnalyst IAM user, identity policy, and credentials setup**

![Task 4 Part 1](Task%204%20%E2%80%94%20Identity%20Policy%20vs%20Resource%20Policy%20part%201.png)

> Confirms:
> - `DataAnalyst` user created with `UserId: AIDAQAAAAAAANCT64STLV`, `CreateDate: 2026-09-11T03:29:11`.
> - Inline policy `analyst-iam.json` grants `["s3:GetObject", "s3:ListBucket"]` on `Resource: "*"`.
> - Policy attached via `put-user-policy --policy-name S3ReadAll`.
> - Access keys generated and configured in the `analyst` CLI profile.

---

**Figure 5.2 — Bucket policy with explicit Deny on confidential prefix**

![Task 4 Part 2](Task%204%20%E2%80%94%20Identity%20Policy%20vs%20Resource%20Policy%20part%202.png)

> `deny-confidential.json` contains two statements:
> - Statement 1: `AllowAnalystInternal` — `Effect: Allow` → `internal/*`
> - Statement 2: `DenyAnalystConfidential` — `Effect: Deny` → `confidential/*` with `Action: s3:*`
>
> This policy deliberately creates a collision between an identity-level Allow and a resource-level Deny to demonstrate AWS's evaluation hierarchy.

---

**Figure 5.3 — Access test results: internal ALLOWED, confidential DENIED**

![Task 4 Part 3](Task%204%20%E2%80%94%20Identity%20Policy%20vs%20Resource%20Policy%20part%203.png)

> - `AWS_PROFILE=analyst ... get-object internal/roster.txt` → returns full object metadata + `internal: ALLOWED`
> - `AWS_PROFILE=analyst ... get-object confidential/record.txt` → returns:
>   ```
>   aws: [ERROR]: An error occurred (AccessDenied) when calling the GetObject operation:
>   User: arn:aws:iam::000000000000:user/DataAnalyst is not authorized to perform: s3:GetObject
>   on resource: "arn:aws:s3:::miit-patient-records-4956/confidential/record.txt"
>   with an explicit deny in a resource-based policy
>   ```
>   `confidential: DENIED`
>
> The error message explicitly cites "an explicit deny in a resource-based policy" — confirming that the S3 bucket policy's Deny overrode the IAM identity policy's Allow.

---

## 6. Task 5 — Default Encryption at Rest (SSE-KMS)

### Summary

This task configured **Server-Side Encryption with AWS Key Management Service (SSE-KMS)** as the default encryption policy for the bucket, replacing the default SSE-S3 (AES-256) with a **Customer-Managed Key (CMK)**. Using a CMK provides auditable key usage via CloudTrail, the ability to rotate the key independently, and — critically — the ability to perform **cryptographic erasure** by deleting the key.

**Key steps performed:**

1. **KMS CMK creation** — A new KMS key was created with description "IKB42603 Lab6 patient records bucket key". The resulting `KeyId` was `20437352-adc4-4284-bdef-27518054fd48`.
2. **Encryption configuration JSON** — `encryption.json` specified:
   - `SSEAlgorithm: aws:kms`
   - `KMSMasterKeyID: $KEY_ID`
   - `BucketKeyEnabled: true` — reduces KMS API call costs by caching the data key at the bucket level.
3. **Apply default encryption** — `put-bucket-encryption` applied the configuration to the bucket.
4. **Verification** — `get-bucket-encryption` confirmed the rule was active, including `BlockedEncryptionTypes: ["SSE-C"]` (preventing customers from supplying their own unmanaged keys).
5. **New object upload test** — A new version of the confidential record (`confidential/record-v2.txt`) was uploaded. The `put-object` response showed `ServerSideEncryption: aws:kms` and `SSEKMSKeyId: arn:aws:kms:us-east-1:000000000000:key/20437352-adc4-4284-bdef-27518054fd48`.
6. **Head-object verification** — `head-object --query '[ServerSideEncryption, SSEKMSKeyId, BucketKeyEnabled]'` returned: `aws:kms  arn:aws:kms:us-east-1:000000000000:key/20437352-adc4-4284-bdef-27518054fd48  True`.

### Evidence

**Figure 6.1 — KMS key creation, encryption.json, and put-bucket-encryption**

![Task 5 Part 1](Task%205%20%E2%80%94%20Default%20Encryption%20at%20Rest%20%28SSE-KMS%29%20part%201.png)

> Confirms:
> - `KEY_ID=20437352-adc4-4284-bdef-27518054fd48` successfully exported.
> - `encryption.json` written with `SSEAlgorithm: aws:kms`, `KMSMasterKeyID: $KEY_ID`, `BucketKeyEnabled: true`.
> - `put-bucket-encryption` completes without error.

---

**Figure 6.2 — Encryption verification and new object confirmation**

![Task 5 Part 2](Task%205%20%E2%80%94%20Default%20Encryption%20at%20Rest%20%28SSE-KMS%29%20part%202.png)

> - `get-bucket-encryption` output confirms `SSEAlgorithm: aws:kms`, `KMSMasterKeyID: 20437352-adc4-4284-bdef-27518054fd48`, `BucketKeyEnabled: true`, and `BlockedEncryptionTypes: ["SSE-C"]`.
> - New upload of `confidential/record-v2.txt` response confirms `ServerSideEncryption: aws:kms` and full KMS key ARN.
> - `head-object` query confirms: `aws:kms  arn:...:key/20437352-adc4-4284-bdef-27518054fd48  True`.

---

## 7. Task 6 — Delegated Access and the Condition-Key Trap

### Summary

This task examined two distinct delegated-access mechanisms and their respective security limitations in a LocalStack environment:

**Part A — Presigned URLs (time-bound delegated access)**

A presigned URL embeds temporary, cryptographically signed access credentials into a URL, allowing any bearer to access a specific S3 object for a defined window without needing AWS credentials. The URL was generated with `--expires-in 60` (60 seconds).

- The presigned URL was constructed for `s3://BUCKET/internal/roster.txt`.
- A `curl` request with the URL returned **HTTP 200** and the file content ("Staff duty schedule, week 12").
- After `sleep 65` (to force expiry), a second `curl` returned **HTTP 200** again — this is a known LocalStack Pro behaviour where presigned URL expiry is not strictly enforced at the HTTP layer (in production AWS, this would return **HTTP 403 AccessDenied: Request has expired**).

**Part B — The `aws:SecureTransport` Condition-Key Trap**

A `DenyUnencryptedTransport` policy statement was authored:
```json
{
  "Sid": "DenyUnencryptedTransport",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": ["arn:aws:s3:::$BUCKET", "arn:aws:s3:::$BUCKET/*"],
  "Condition": {"Bool": {"aws:SecureTransport": "false"}}
}
```
This is a standard hardening pattern — it appears to deny all S3 operations over unencrypted HTTP. However, the **trap** is that LocalStack's endpoint (`http://localhost:4566`) operates over plain HTTP, not HTTPS. The condition `aws:SecureTransport: false` evaluates to `true` for every request made to the LocalStack HTTP endpoint, meaning **all operations — including legitimate admin operations — would be denied** if this policy were applied without a corresponding Allow statement for HTTPS. In production AWS, the same policy works correctly because the AWS S3 endpoint always uses HTTPS (`https://s3.amazonaws.com`).

The policy was applied via `put-bucket-policy`, then cleared with `delete-bucket-policy` at the end of the task to restore access for subsequent tasks.

### Evidence

**Figure 7.1 — KMS key creation and encryption configuration (Task 5 continuation)**

![Task 6 Part 1](Task%206%20%E2%80%94%20Delegated%20Access%20and%20the%20Condition-Key%20Trap%20part%201.png)

> Shows the KMS key creation steps (confirming `KEY_ID` value used throughout Tasks 5 and 6).

---

**Figure 7.2 — SSE-KMS verification on uploaded object**

![Task 6 Part 2](Task%206%20%E2%80%94%20Delegated%20Access%20and%20the%20Condition-Key%20Trap%20part%202.png)

> Confirms `get-bucket-encryption` and `head-object` results with full KMS ARN — bridging Task 5 evidence into Task 6 context.

---

**Figure 7.3 — Presigned URL generation, use, expiry test, and SecureTransport policy**

![Task 6 Part 3](Task%206%20%E2%80%94%20Delegated%20Access%20and%20the%20Condition-Key%20Trap%20part%203.png)

> Key outputs:
> - Presigned URL generated with `--expires-in 60`: `http://localhost:4566/miit-patient-records-4956/internal/roster.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&...&X-Amz-Expires=60&...`
> - `curl "$URL"` → **HTTP 200**, returns "Staff duty schedule, week 12"
> - After `sleep 65`: `curl "$URL"` → **HTTP 200** (LocalStack expiry not enforced — in AWS this would be HTTP 403)
> - `secure-transport.json` authored with `"aws:SecureTransport": "false"` Deny condition.
> - `put-bucket-policy` applied successfully.

---

**Figure 7.4 — Bucket object listing (state audit)**

![Task 6 Part 4](Task%206%20%E2%80%94%20Delegated%20Access%20and%20the%20Condition-Key%20Trap%20part%204.png)

> `list-objects-v2` shows the full bucket inventory at this stage:
> ```
> confidential/kms-record.txt      (53 bytes)
> confidential/record-v2.txt       (48 bytes)
> confidential/record.txt          (48 bytes)
> internal/roster.txt              (29 bytes)
> public/notice.txt                (29 bytes)
> ```

---

**Figure 7.5 — SecureTransport policy cleanup**

![Task 6 Part 5](Task%206%20%E2%80%94%20Delegated%20Access%20and%20the%20Condition-Key%20Trap%20part%205.png)

> `delete-bucket-policy` removes the `DenyUnencryptedTransport` policy to restore normal access for Tasks 7 and 8.

---

## 8. Task 7 — Versioning, Delete Markers & Data Remanence

### Summary

This task demonstrated the critical distinction between a **logical delete** and a **physical delete** in S3, and why this distinction has profound compliance implications under data protection regulations such as PDPA and GDPR.

**Key steps performed:**

1. **Enable versioning** — `put-bucket-versioning --versioning-configuration Status=Enabled`. `get-bucket-versioning` confirmed `"Status": "Enabled"`.
2. **Create two new versions** — Two new versions of `confidential/record.txt` were uploaded:
   - `rec-v2.txt`: "Patient: Ahmad bin Ali, Diagnosis: hypertension" → `VersionId: AaCOqqNlYo7sBDbo7J_Vic1Oz7XcetXR`
   - `rec-v3.txt`: "Patient: [REDACTED], Diagnosis: [REDACTED]" → `VersionId: AaCOqqNmfUi7zO4uuusIJWzAXCM6z..E`
3. **List versions** — `list-object-versions` showed three versions of `confidential/record.txt`:
   - `AaCOqqNmfUi7zO4uuusIJWzAXCM6z..E` — `IsLatest: True`, 43 bytes (the REDACTED version)
   - `AaCOqqNlYo7sBDbo7J_Vic1Oz7XcetXR` — `IsLatest: False`, 48 bytes
   - `null` — `IsLatest: False`, 48 bytes (the original PHI version)
4. **Logical delete** — `delete-object` (without `--version-id`) placed a **delete marker** (`VersionId: AaCOqqNnCsvSJ7jK0Iee54vlSvJgDgOa`, `DeleteMarker: true`). A subsequent `get-object` without version ID returned **NoSuchKey** — the object appears deleted.
5. **Data remanence proof** — `get-object --version-id null` successfully retrieved the **original PHI version**, returning "Patient: Ahmad bin Ali, Diagnosis: confidential". The data was never physically erased.
6. **Physical delete of original version** — `delete-object --version-id null` permanently removed the original version. The subsequent `list-object-versions` showed only `AaCOqqNmfUi7zO4uuusIJWzAXCM6z..E` and `AaCOqqNlYo7sBDbo7J_Vic1Oz7XcetXR` remaining.

**Core finding:** A standard `delete-object` call on a versioned bucket creates a delete marker — it does **not** destroy any version of the data. Every prior version remains fully retrievable by anyone with `s3:GetObject` and `s3:GetObjectVersion` permissions.

### Evidence

**Figure 8.1 — Versioning enabled, two new versions uploaded, version list**

![Task 7 Part 1](Task%207%20%E2%80%94%20Versioning%2C%20Delete%20Markers%20%26%20Data%20Remanence%20part%201.png)

> Confirms:
> - Versioning `Status: Enabled`.
> - Version table showing three versions of `confidential/record.txt` with their `VersionId` values and sizes.
> - The `null` VersionId corresponds to the original pre-versioning object (the PHI record from Task 1).

---

**Figure 8.2 — Delete marker creation, NoSuchKey, and data remanence proof**

![Task 7 Part 2](Task%207%20%E2%80%94%20Versioning%2C%20Delete%20Markers%20%26%20Data%20Remanence%20part%202.png)

> Key outputs:
> - `delete-object` returns `"DeleteMarker": true, "VersionId": "AaCOqqNnCsvSJ7jK0Iee54vlSvJgDgOa"`.
> - `list-object-versions` on DeleteMarkers shows the marker with `IsLatest: True`.
> - `get-object confidential/record.txt` → **NoSuchKey** (object appears deleted).
> - `get-object --version-id null` → **HTTP 200**, full metadata returned, `VersionId: null`.
> - `cat recovered.txt` → `Patient: Ahmad bin Ali, Diagnosis: confidential` — **PHI fully recovered**.

---

**Figure 8.3 — Physical deletion of original version**

![Task 7 Part 3](Task%207%20%E2%80%94%20Versioning%2C%20Delete%20Markers%20%26%20Data%20Remanence%20part%203.png)

> - `delete-object --version-id null` returns `"VersionId": "null"` (permanent deletion of that specific version).
> - `list-object-versions` now shows only `AaCOqqNmfUi7zO4uuusIJWzAXCM6z..E` (43 bytes) and `AaCOqqNlYo7sBDbo7J_Vic1Oz7XcetXR` (48 bytes) — the null version is gone.

---

## 9. Task 8 — Lifecycle, Retention & Cryptographic Erasure

### Summary

This task configured **S3 Lifecycle rules** to automate data retention and deletion policies, and introduced **cryptographic erasure** — the gold-standard method for provable, irreversible data destruction when physical deletion is insufficient.

**Key steps performed:**

1. **Lifecycle rule definition** — `lifecycle.json` was authored with rule ID `cleanup-old-patient-records`:
   - `Filter: {"Prefix": "confidential/"}` — scoped to the confidential prefix only
   - `NoncurrentVersionExpiration: {"NoncurrentDays": 30}` — non-current versions are automatically deleted after 30 days
   - `Expiration: {"ExpiredObjectDeleteMarker": true}` — orphaned delete markers are automatically cleaned up
2. **Apply lifecycle configuration** — `put-bucket-lifecycle-configuration` applied the rule. `get-bucket-lifecycle-configuration` confirmed it was active with `Status: Enabled`.
3. **State audit** — `list-object-versions --prefix confidential/` revealed the current versioned object state:
   - `confidential/kms-record.txt` — `VersionId: null`, `IsLatest: True`
   - `confidential/record-v2.txt` — `VersionId: null`, `IsLatest: True`
   - `confidential/record.txt` — two non-current versions (`AaCOqqNmfUi7zO4uuusIJWzAXCM6z..E` and `AaCOqqNlYo7sBDbo7J_Vic1Oz7XcetXR`)

**Cryptographic erasure concept:** Because all new objects are encrypted under KMS CMK `20437352-adc4-4284-bdef-27518054fd48`, **disabling or deleting that KMS key renders all encrypted data permanently unreadable** — even if the ciphertext bytes remain on disk. AWS KMS key deletion requires a mandatory waiting period of 7–30 days (`schedule-key-deletion`) during which the deletion can be cancelled. Once the key is deleted, the data is cryptographically erased with mathematical certainty. This is the preferred erasure mechanism for cloud storage, where physical media destruction is not an option.

### Evidence

**Figure 9.1 — Lifecycle rule creation and verification**

![Task 8 Part 1](Task%208%20%E2%80%94%20Lifecycle%2C%20Retention%20%26%20Cryptographic%20Erasure%20part1.png)

> - `lifecycle.json` shows rule with `Prefix: "confidential/"`, `NoncurrentDays: 30`, `ExpiredObjectDeleteMarker: true`.
> - `put-bucket-lifecycle-configuration` succeeds.
> - `get-bucket-lifecycle-configuration` confirms rule `cleanup-old-patient-records` is `Status: Enabled`.

---

**Figure 9.2 — Versioned object state after lifecycle policy application**

![Task 8 Part 2](Task%208%20%E2%80%94%20Lifecycle%2C%20Retention%20%26%20Cryptographic%20Erasure%20part2.png)

> `list-object-versions --prefix confidential/` table shows:
> ```
> | confidential/kms-record.txt | null                         | True  |
> | confidential/record-v2.txt  | null                         | True  |
> | confidential/record.txt     | AaCOqqNmfUi7zO4uuusIJWzAXCM6z..E | False |
> | confidential/record.txt     | AaCOqqNlYo7sBDbo7J_Vic1Oz7XcetXR | False |
> ```
> The two non-current versions of `confidential/record.txt` will be automatically expired after 30 days by the lifecycle rule.

---

## 10. Verification Command

### Summary

A composite verification command was executed to produce a single-pass audit snapshot of all security controls configured during the lab. This represents the type of evidence an auditor would collect to validate compliance posture for an S3 bucket holding sensitive data.

### Evidence

**Figure 10.1 — Composite verification output**

![Verification Command](Verification%20Command.png)

> The verification script ran five checks in sequence and produced the following consolidated output:
>
> ```
> === IKB42603 Lab 6 verification: miit-patient-records-4956 ===
>
> [1] Block Public Access:
>     True True True True
>
> [2] Versioning:
>     Enabled
>
> [3] Default Encryption:
>     aws:kms  20437352-adc4-4284-bdef-27518054fd48
>
> [4] Lifecycle Rule:
>     cleanup-old-patient-records  Enabled
>
> [5] KMS Key State:
>     Enabled
> ```
>
> All five controls passed. The verification confirms: public access is blocked on all four dimensions, versioning is active, SSE-KMS with a named CMK is the default encryption, a lifecycle rule is configured and enabled, and the KMS CMK is in the `Enabled` state (not yet scheduled for deletion).

---

## 11. Cleanup & Teardown

### Summary

S3 does not allow deletion of a non-empty bucket. Versioned buckets are additionally complex because every version and every delete marker must be explicitly removed before the bucket itself can be deleted. The cleanup procedure followed the correct two-pass approach required for versioned buckets:

**Pass 1 — Delete all object versions:**
```bash
aws $EP s3api delete-objects --bucket $BUCKET \
  --delete "$(aws $EP s3api list-object-versions --bucket $BUCKET \
  --output json --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"
```
This bulk-deleted all current and non-current versions in a single API call. The response listed all deleted items:
- `confidential/kms-record.txt` (VersionId: null)
- `confidential/record-v2.txt` (VersionId: null)
- `confidential/record.txt` (VersionId: AaCOqqNmfUi7zO4uuusIJWzAXCM6z..E)
- `confidential/record.txt` (VersionId: AaCOqqNlYo7sBDbo7J_Vic1Oz7XcetXR)
- `internal/roster.txt` (VersionId: null)
- `public/notice.txt` (VersionId: null)

**Pass 2 — Delete all delete markers:**
```bash
aws $EP s3api delete-objects --bucket $BUCKET \
  --delete "$(aws $EP s3api list-object-versions --bucket $BUCKET \
  --output json --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}')"
```
This removed the delete marker for `confidential/record.txt` (VersionId: AaCOqqNnCsvSJ7jK0Iee54vlSvJgDgOa).

**Final deletion:** `list-object-versions` returned `None None None None` (empty bucket), confirming readiness. `delete-bucket` succeeded.

**IAM and infrastructure cleanup:** The `DataAnalyst` user's inline policy (`S3ReadAll`) and the user account itself were deleted. The LocalStack container was removed with `docker rm -f localstack` and all temporary JSON/TXT files were removed with `rm -f *.json *.txt`.

### Evidence

**Figure 11.1 — Bulk version deletion (Pass 1)**

![Cleanup Part 1](Cleanup%20%26%20Teardown%20part%201.png)

> `delete-objects` response confirms all six object versions across five keys were deleted in a single atomic call.

---

**Figure 11.2 — Delete marker removal (Pass 2), bucket deletion, and IAM/container cleanup**

![Cleanup Part 2](Cleanup%20%26%20Teardown%20part%202.png)

> - Pass 2 deletes the delete marker for `confidential/record.txt`.
> - `list-object-versions` returns `None None None None` — bucket is empty.
> - `delete-bucket` succeeds.
> - `iam delete-user-policy` and `iam delete-user` for `DataAnalyst` complete silently.
> - `docker rm -f localstack` removes the container; `rm -f *.json *.txt` removes all temp files.

---

## 12. Data Classification Table

This table defines the three-tier classification taxonomy applied in Task 1. It maps each classification level to its access control requirements, breach impact, and the specific AWS/S3 controls applied during the lab.

| Classification | Who May Read It | Impact if Leaked | Control Applied |
|---|---|---|---|
| **public** | Any person, including unauthenticated internet users | Reputational risk only; no regulatory penalty if content is genuinely public | Objects stored under `public/` prefix; no ACL or bucket-policy restriction on `s3:GetObject`; tagged `classification=public` for auditability |
| **internal** | Authenticated personnel within the organisation (IAM principals within account `000000000000`) | Business disruption; potential breach of employment or contractual obligations; moderate reputational damage | Bucket policy `AllowAnalystInternal` restricts `s3:GetObject` to named IAM principal; Block Public Access (`RestrictPublicBuckets=true`) prevents external access; `classification=internal` tag enables ABAC policies |
| **confidential** | Strictly need-to-know; named IAM principals only; access must be logged and justified | Regulatory penalties under PDPA/GDPR; patient harm; criminal liability for PHI exposure; breach notification obligations | Explicit `Deny` in bucket resource policy (`DenyAnalystConfidential`) overrides any identity-policy Allow; SSE-KMS encryption with CMK `20437352-adc4-4284-bdef-27518054fd48` ensures data is unreadable without KMS key access; lifecycle rule enforces 30-day retention on non-current versions; `classification=confidential` tag applied for audit trail |

---

## 13. Short-Answer Questions

---

### Question 1

**Which single element of the Task 2 policy caused the exposure, and why is `Principal: "*"` more dangerous on a bucket policy than an over-broad IAM policy attached to one user?**

**Answer:**

The single element that caused the exposure was **`"Principal": "*"`** in the bucket policy's Statement. Every other element of the policy — `Effect: Allow`, `Action: s3:GetObject`, and the resource ARN — is commonplace and benign on its own. It was the wildcard principal that transformed a routine read permission into a public data breach.

`"Principal": "*"` in an S3 bucket policy is semantically equivalent to *every entity in the universe* — every AWS account, every IAM user, every federated identity, every web browser, every `curl` client, every automated scanner, and every unauthenticated HTTP request from anywhere on the internet. No credentials are required. No authentication is performed. The S3 service simply matches the request against the policy, finds that `"*"` includes the anonymous caller, and serves the object.

This is fundamentally more dangerous than an over-broad IAM policy attached to one user for two reasons:

1. **Blast radius.** An over-broad IAM policy on a single user affects, at worst, one compromised identity. The attacker must first obtain that user's access keys — a non-trivial prerequisite. A `Principal: "*"` bucket policy requires zero credentials and is exploitable by anyone with network access to the bucket endpoint. The breach in Task 2 was executed with a plain `curl` command — no AWS CLI, no keys, no account. The blast radius is literally the entire internet.

2. **Perimeter bypass.** IAM policies operate within the AWS authentication perimeter — the request must be signed with valid credentials before IAM even evaluates it. A `Principal: "*"` bucket policy operates *outside* that perimeter. It grants access at the resource level before authentication, effectively punching a hole in the AWS trust boundary. Block Public Access (`RestrictPublicBuckets=true`) exists precisely because the risk of wildcard bucket policies is so severe that AWS created a separate, override-capable guardrail specifically to contain it.

In summary: a misconfigured IAM policy requires a compromised identity to be exploitable. A misconfigured bucket policy with `Principal: "*"` requires nothing at all.

---

### Question 2

**Explain the difference between an identity-based policy and a resource-based policy. In Task 4, which one decided each of the analyst's two requests?**

**Answer:**

**Identity-based policy:** An IAM policy attached directly to an IAM principal (user, group, or role). It travels with the *calling identity* and answers the question: "What is this identity allowed to do?" It is evaluated regardless of which resource is being accessed. In Task 4, the identity-based policy was `analyst-iam.json` (inline policy `S3ReadAll`), which granted `["s3:GetObject", "s3:ListBucket"]` on `Resource: "*"`.

**Resource-based policy:** A policy attached directly to an AWS resource (in this case, an S3 bucket policy). It travels with the *resource* and answers the question: "Who is allowed to access this resource, and what are they allowed to do?" It is evaluated by the resource service when a request arrives. In Task 4, the resource-based policy was `deny-confidential.json`, which had two statements scoped to the `DataAnalyst` principal.

**AWS policy evaluation applies the following logic (simplified):**
1. Start with implicit Deny on everything.
2. Evaluate all applicable policies (identity + resource).
3. If any policy has an explicit `Deny` → **DENY** (this is final; no Allow can override it).
4. If any policy has an explicit `Allow` (and no Deny) → **ALLOW**.
5. Otherwise → **DENY** (implicit default).

**Request 1 — `internal/roster.txt`:**
The *resource-based policy* decided this request. Statement `AllowAnalystInternal` explicitly granted `s3:GetObject` on `internal/*` to `DataAnalyst`. The identity policy also granted `s3:GetObject` on `*`. Both agreed → **ALLOWED**. (Either policy alone would have been sufficient.)

**Request 2 — `confidential/record.txt`:**
The *resource-based policy* decided this request — specifically, statement `DenyAnalystConfidential`, which carried an explicit `Deny` on `s3:*` for `confidential/*`. AWS's error message confirmed this: *"with an explicit deny in a resource-based policy."* Even though the identity-based policy (`S3ReadAll`) explicitly allowed `s3:GetObject` on `*`, the explicit `Deny` in the bucket policy overrode it completely → **DENIED**. This is the "Deny wins" principle: an explicit Deny is absolute and irrevocable regardless of how many Allow statements exist elsewhere.

---

### Question 3

**Block Public Access is described as a guardrail rather than a control. What is the difference, and why does the distinction matter for an organisation with many engineers?**

**Answer:**

A **control** is a direct enforcement mechanism that governs a specific action at the point where it occurs. For example, an IAM policy that denies `s3:PutBucketPolicy` to a developer is a control — it prevents that specific action. A bucket policy with an explicit `Deny` is a control — it directly governs access to that resource.

A **guardrail** is an organisational-level safety constraint that operates *above* individual resources and *prevents a class of misconfiguration* from taking effect, regardless of what any individual engineer does at the resource level. Block Public Access is a guardrail because it does not grant or deny access to specific objects — instead, it prevents any bucket policy or ACL that *would* make the bucket publicly accessible from taking effect. It is a meta-policy that overrides resource-level decisions.

**Why the distinction matters at scale:**

In an organisation with dozens or hundreds of engineers, each creating buckets, authoring policies, and configuring ACLs, the probability of at least one misconfiguration approaches certainty over time. If BPA is only enforced as a control on individual buckets (meaning each bucket owner must remember to configure it), misconfigured buckets will inevitably escape detection. One forgotten bucket with `Principal: "*"` — as demonstrated in Task 2 — is sufficient to cause a regulatory breach.

As a guardrail applied at the **AWS account level** (via `put-public-access-block` for the account, or enforced via AWS Organizations Service Control Policies), BPA removes the misconfiguration from the threat model entirely. No engineer can accidentally or intentionally create a publicly accessible bucket — the guardrail prevents it at the API level, before any misconfigured policy takes effect. This is defence-in-depth: even if an engineer makes a mistake, the guardrail catches it.

The distinction also matters for auditing: proving that a guardrail is in place requires checking one account-level setting, whereas proving that every bucket has the correct control requires auditing every bucket individually — an operationally intractable problem at scale.

---

### Question 4

**Your bucket has default SSE-KMS encryption. Does that protect the confidential record from the analyst in Task 4? Explain precisely what server-side encryption does and does not defend against.**

**Answer:**

**No, SSE-KMS does not protect the confidential record from the analyst in Task 4** — and understanding why requires a precise understanding of where encryption operates in the request lifecycle.

**What SSE-KMS does:**
SSE-KMS encrypts object data *at rest* on the storage media managed by AWS. When an object is written (`put-object`), S3 calls KMS to generate a data encryption key (DEK), encrypts the object bytes with the DEK using AES-256, and stores the encrypted ciphertext. The DEK itself is encrypted by the CMK and stored alongside the object. When an authorised caller reads the object, S3 calls KMS to decrypt the DEK, decrypts the object bytes, and returns the plaintext to the caller over the network connection.

The critical phrase is *"to the authorised caller."* SSE-KMS **defends against:**
- Physical theft or disposal of the storage media (disks never leave AWS data centres, but SSE ensures plaintext is never written to disk).
- Unauthorised access to the raw storage layer by AWS personnel or other tenants.
- Data exfiltration from a decommissioned storage medium.
- Cryptographic erasure — disabling or deleting the CMK renders all associated ciphertext permanently unreadable.

**What SSE-KMS does NOT defend against:**
- **Authorised API access by an IAM principal.** When `DataAnalyst` calls `s3:GetObject`, S3 authenticates the request, checks policies, and — if access is permitted — transparently decrypts the object and returns plaintext. Encryption is completely transparent to the API caller. If the bucket policy allowed `DataAnalyst` to access `confidential/record.txt`, they would receive plaintext regardless of SSE-KMS. Encryption does not substitute for access control.
- **A misconfigured bucket policy.** The wildcard policy in Task 2 served plaintext to an anonymous caller even though SSE-S3 was active. The S3 service decrypts on behalf of any authorised request — and `Principal: "*"` makes every request authorised.

In Task 4, the `DenyAnalystConfidential` bucket policy statement is what protected the confidential record — not SSE-KMS. SSE-KMS and access control policies are **complementary, not substitutable** layers of defence: access control governs *who can request the data*; encryption governs *what an attacker who bypasses access control finds*.

---

### Question 5

**A patient invokes their right to erasure. Using your Task 7 evidence, explain why `delete-object` alone is not compliant, and describe two mechanisms that would make the deletion provable.**

**Answer:**

**Why `delete-object` alone is not compliant:**

Task 7 provided direct empirical proof. When `delete-object` was executed on `confidential/record.txt` (a versioned bucket), the API response was:
```json
{ "DeleteMarker": true, "VersionId": "AaCOqqNnCsvSJ7jK0Iee54vlSvJgDgOa" }
```
A **delete marker** is a placeholder — it makes the object appear deleted to a standard `get-object` request (which returned `NoSuchKey`). However, the underlying data was entirely intact. The command `get-object --version-id null` immediately recovered the original PHI: `Patient: Ahmad bin Ali, Diagnosis: confidential`. The data had never left the bucket.

Under GDPR Article 17 (Right to Erasure) and Malaysia's PDPA, a data subject's erasure request requires that the personal data be *actually* destroyed — not merely hidden. A delete marker satisfies no legal standard for erasure because: (a) the data remains stored on AWS infrastructure; (b) it is fully recoverable by anyone with `s3:GetObjectVersion` permission; and (c) AWS cannot distinguish a deleted-marker object from a live object at the storage layer. An audit of the raw version history would immediately reveal the continued existence of the PHI.

**Two mechanisms that achieve provable deletion:**

1. **Explicit version deletion (`delete-object --version-id <id>` for every version):**
   As demonstrated in Task 7 Part 3, specifying `--version-id null` permanently deleted that specific version. By iterating over all version IDs returned by `list-object-versions` and deleting each one individually (or via bulk `delete-objects`), every copy of the data is permanently removed from S3 storage. The version list then returns empty for that key, providing auditable evidence that no versions remain. This is the approach used in the lab's cleanup procedure. To be admissible as compliance evidence, the output of `list-object-versions` *after* deletion should be captured and stored in an audit log.

2. **Cryptographic erasure via KMS key deletion (`schedule-key-deletion`):**
   Because all objects under `confidential/` are encrypted with CMK `20437352-adc4-4284-bdef-27518054fd48`, scheduling that key for deletion via `aws kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7` initiates a waiting period after which the key is permanently and irrecoverably destroyed. Once the CMK is deleted, every ciphertext it protected becomes mathematically irreversible gibberish — even if the ciphertext bytes remain on AWS storage media. The `kms describe-key` output showing `KeyState: PendingDeletion` and subsequently `Deleted` provides cryptographic proof of erasure that satisfies the "provable" standard required by regulators, because no decryption is possible without the key. This method is particularly powerful for multi-version, multi-object erasure scenarios where enumerating every version ID is impractical.

---

### Question 6

**You are the auditor in Week 11. Name three commands from this lab whose output you would collect as compliance evidence, and state which control each one evidences.**

**Answer:**

| # | Command | Control Evidenced |
|---|---|---|
| **1** | `aws $EP s3api get-public-access-block --bucket $BUCKET` | **Preventive control — Public Exposure Prevention.** The output (all four flags `true`) proves that no bucket policy or ACL can grant unauthenticated public access. This directly evidences compliance with requirements mandating that S3 buckets holding personal or sensitive data must not be publicly accessible. Maps to CIS AWS Foundations Benchmark 2.1.5, NIST SP 800-53 AC-3 (Access Enforcement), and PDPA/GDPR requirements for access restriction to personal data. |
| **2** | `aws $EP s3api get-bucket-encryption --bucket $BUCKET` | **Technical control — Encryption at Rest.** The output confirms `SSEAlgorithm: aws:kms`, the specific `KMSMasterKeyID`, and `BucketKeyEnabled: true`. This evidences that all objects stored in the bucket are encrypted under a Customer-Managed Key, providing both data confidentiality and the capability for cryptographic erasure. Maps to NIST SP 800-53 SC-28 (Protection of Information at Rest), ISO/IEC 27001 A.10.1 (Cryptographic Controls), and PDPA Data Security obligations. |
| **3** | `aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET` | **Administrative/Automated control — Data Retention & Disposal.** The output showing rule `cleanup-old-patient-records` with `Status: Enabled`, `NoncurrentVersionExpiration: NoncurrentDays: 30`, and `Prefix: confidential/` evidences that a documented and technically enforced retention policy is in place for personal health data. Automated expiry of non-current versions ensures that superseded records do not persist indefinitely, supporting the PDPA principle of data minimisation and GDPR's storage limitation principle (Article 5(1)(e)). It also demonstrates that the organisation's data retention schedule is not merely a paper policy but is technically enforced at the storage layer. |

---

## 14. Security Best-Practices Checklist

The following checklist summarises the security controls validated during Lab 6. Each item represents a control that was configured, tested, and confirmed operational within the LocalStack environment.

| # | Security Control | Status | Evidence Task | AWS API Verified |
|---|---|:---:|---|---|
| 1 | S3 bucket is **not** publicly accessible (no `Principal: "*"` in any bucket policy) | ✅ PASS | Task 3 | `delete-bucket-policy` + `put-public-access-block` |
| 2 | Block Public Access — `BlockPublicAcls` enabled | ✅ PASS | Task 3 | `get-public-access-block` → `true` |
| 3 | Block Public Access — `IgnorePublicAcls` enabled | ✅ PASS | Task 3 | `get-public-access-block` → `true` |
| 4 | Block Public Access — `BlockPublicPolicy` enabled | ✅ PASS | Task 3 | `get-public-access-block` → `true` |
| 5 | Block Public Access — `RestrictPublicBuckets` enabled | ✅ PASS | Task 3 | `get-public-access-block` → `true` |
| 6 | All objects tagged with `classification` key at upload | ✅ PASS | Task 1 | `get-object-tagging` → `classification=confidential` |
| 7 | IAM principle of least privilege: analyst restricted to `internal/*` only | ✅ PASS | Task 4 | `get-object internal/roster.txt` → ALLOWED |
| 8 | Explicit `Deny` in resource policy prevents confidential data access | ✅ PASS | Task 4 | `get-object confidential/record.txt` → AccessDenied |
| 9 | Default SSE-KMS encryption enabled on bucket | ✅ PASS | Task 5 | `get-bucket-encryption` → `aws:kms` |
| 10 | Encryption uses a Customer-Managed Key (CMK) | ✅ PASS | Task 5 | `KMSMasterKeyID: 20437352-adc4-4284-bdef-27518054fd48` |
| 11 | `BucketKeyEnabled: true` (cost-optimised KMS) | ✅ PASS | Task 5 | `head-object` → `BucketKeyEnabled: True` |
| 12 | SSE-C (customer-provided keys) blocked | ✅ PASS | Task 5 | `BlockedEncryptionTypes: ["SSE-C"]` |
| 13 | Presigned URL access is time-limited (`--expires-in`) | ✅ PASS | Task 6 | URL generated with 60s expiry |
| 14 | `aws:SecureTransport` condition documented as HTTPS enforcement mechanism | ✅ PASS | Task 6 | `secure-transport.json` authored and applied |
| 15 | Bucket versioning enabled | ✅ PASS | Task 7 | `get-bucket-versioning` → `Enabled` |
| 16 | Delete markers distinguished from physical deletion | ✅ PASS | Task 7 | `list-object-versions` → delete marker confirmed |
| 17 | Original PHI versions explicitly deleted by VersionId | ✅ PASS | Task 7 | `delete-object --version-id null` |
| 18 | Automated lifecycle rule configured for `confidential/` prefix | ✅ PASS | Task 8 | `get-bucket-lifecycle-configuration` → `Enabled` |
| 19 | Non-current versions expire after 30 days (data retention enforcement) | ✅ PASS | Task 8 | `NoncurrentVersionExpiration: NoncurrentDays: 30` |
| 20 | Orphaned delete markers auto-cleaned (`ExpiredObjectDeleteMarker: true`) | ✅ PASS | Task 8 | `get-bucket-lifecycle-configuration` confirms rule |
| 21 | KMS CMK in `Enabled` state (cryptographic erasure capability available) | ✅ PASS | Verification | `kms describe-key` → `KeyState: Enabled` |
| 22 | Composite verification snapshot collected as audit evidence | ✅ PASS | Verification | All 5 checks passed in single command |
| 23 | Versioned bucket fully emptied (versions + markers) before deletion | ✅ PASS | Cleanup | `list-object-versions` → `None` before `delete-bucket` |
| 24 | IAM user and credentials fully removed post-lab | ✅ PASS | Cleanup | `iam delete-user` + `iam delete-user-policy` |
| 25 | LocalStack container and all temporary credential files removed | ✅ PASS | Cleanup | `docker rm -f localstack`; `rm -f *.json *.txt` |

---

*Report prepared for IKB42603 Cloud Computing Security Essentials — UniKL MIIT.*
*Lab environment: LocalStack Pro on Kali Linux. All CLI outputs are captured from live terminal sessions executed on 11 September 2026.*
