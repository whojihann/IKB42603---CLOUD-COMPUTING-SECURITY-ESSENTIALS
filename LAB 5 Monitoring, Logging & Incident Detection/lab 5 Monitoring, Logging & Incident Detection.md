# Lab 5: Monitoring, Logging & Incident Detection

**Course:** IKB42603 — Cloud Computing Security Essentials
**Name:** Nurul Jihan Nabilah Binti Azlan
**Institution:** Universiti Kuala Lumpur (UniKL MIIT)
**Lab Title:** Lab 5 — Monitoring, Logging & Incident Detection
**Environment:** LocalStack 3.0.0 · Docker · AWS CLI · Kali Linux
**Date Completed:** 7 September 2026

---

## Table of Contents

1. [Executive Summary & Learning Outcomes](#1-executive-summary--learning-outcomes)
2. [Lab Execution & Evidence](#2-lab-execution--evidence)
   - [Setup — Start LocalStack & Configure CloudWatch](#setup--start-localstack--configure-cloudwatch)
   - [Task 1 — Generate Application Logs](#task-1--generate-application-logs)
   - [Task 2 — Centralise Logs (Ship to CloudWatch)](#task-2--centralise-logs-ship-to-cloudwatch)
   - [Task 3 — Query for Security-Relevant Activity](#task-3--query-for-security-relevant-activity)
   - [Task 4 — Tamper-Proof (Hash-Chained) Logs](#task-4--tamper-proof-hash-chained-logs)
   - [Task 5 — Detect the Incident (Correlation)](#task-5--detect-the-incident-correlation)
   - [Task 6 — Incident Response](#task-6--incident-response)
   - [Verification Command](#verification-command)
3. [Incident Report](#3-incident-report)
4. [Short-Answer Questions](#4-short-answer-questions)
5. [Security Best-Practices Checklist](#5-security-best-practices-checklist)

---

## 1. Executive Summary & Learning Outcomes

### Objective

This lab demonstrates the end-to-end implementation of a cloud-native security monitoring and incident-response pipeline. Using **LocalStack** as a locally emulated AWS environment and **Docker** as the container runtime, students built a centralised logging infrastructure, enforced tamper-evident audit trails through SHA-256 hash chaining, applied event-correlation logic to detect a multi-stage attack, and executed a structured incident-response procedure — all without requiring a live AWS account.

The simulated attack scenario involved a threat actor at IP `203.0.113.9` conducting a brute-force attack against the `admin` account, successfully authenticating after four failed login attempts, and subsequently exfiltrating 500 MB of data.

### Alignment to Course Learning Outcomes

| Dimension | Detail |
|-----------|--------|
| **CLO2** | Analyse and apply cloud security monitoring, logging, and audit mechanisms to detect and respond to security incidents |
| **Week 6 Concepts** | Centralised log aggregation, CloudWatch Logs architecture, security event querying, and automated alerting |
| **VBE3 — Integrity** | Tamper-evident hash chaining guarantees the authenticity and non-repudiation of audit log records, directly embodying the integrity pillar of information security |

### Key Skills Demonstrated

- Spinning up a local AWS-equivalent environment (LocalStack) via Docker
- Creating CloudWatch Log Groups and Log Streams programmatically with the AWS CLI
- Authoring structured application log entries mimicking real authentication systems
- Streaming log data to a centralised sink using `put-log-events`
- Performing security-relevant log queries using `grep`, `awk`, `sort`, and `uniq`
- Implementing SHA-256 hash chaining to produce cryptographically verifiable, tamper-proof log chains
- Proving tampering via divergent final-chain hashes after a simulated `sed`-based log modification
- Writing a multi-event correlation script that identifies brute-force → compromise → exfiltration attack chains
- Executing incident containment via `iptables DROP` rules within a Docker-managed network namespace
- Preserving forensic evidence with SHA-256 checksums for chain-of-custody compliance

---

## 2. Lab Execution & Evidence

---

### Setup — Start LocalStack & Configure CloudWatch

#### Theoretical Goal

Before any log data can be shipped or queried, the target log infrastructure must exist. In AWS production environments, CloudWatch Logs provides a fully managed, durable, and queryable log aggregation service. LocalStack replicates this API surface locally on port `4566`, enabling students to practise AWS CLI workflows without incurring cloud costs or requiring network access. This step establishes the log group `/ccse/app` and the log stream `auth` that all subsequent tasks depend on.

#### Commands Executed

```bash
# 1. Start LocalStack container (AWS emulator) in detached mode, mapping port 4566
docker run -d --name localstack -p 4566:4566 localstack/localstack:3.0.0

# 2. Allow LocalStack services to fully initialise before issuing API calls
sleep 8

# 3. Define a reusable endpoint variable to avoid repeating the URL in every command
EP='--endpoint-url=http://localhost:4566'

# 4. Create the CloudWatch Logs group that will house all application log streams
aws $EP logs create-log-group --log-group-name /ccse/app

# 5. Create the specific log stream named 'auth' within the /ccse/app group
aws $EP logs create-log-stream \
    --log-group-name /ccse/app \
    --log-stream-name auth
```

#### Step-by-Step Technical Explanation

| Step | What Happens |
|------|-------------|
| `docker run -d` | Launches LocalStack as a background container. The `-p 4566:4566` flag binds the host's TCP port 4566 to the container's port 4566, making all emulated AWS service endpoints reachable at `http://localhost:4566`. The `3.0.0` tag pins a specific, known-stable version. |
| `sleep 8` | LocalStack's internal service initialisation (including the CloudWatch Logs service) takes a few seconds. Skipping this sleep can cause `ResourceNotFoundException` on the first API call. |
| `EP='...'` | Shell variable assignment stores the endpoint override flag. Every subsequent `aws` command that targets LocalStack prefixes with `$EP`, making the scripts portable and concise. |
| `create-log-group` | Creates a named container for related log streams. The name `/ccse/app` follows a hierarchical slash-delimited convention (organisation/application), mirroring real-world naming standards. |
| `create-log-stream` | Creates a named, ordered sequence of log events within the group. The stream `auth` will receive authentication log events. In production, you might have separate streams per host or per deployment. |

#### Evidence

![Setup — Start LocalStack](./Setup%20—%20Start%20LocalStack.png)

---

### Task 1 — Generate Application Logs

#### Theoretical Goal

Every security investigation begins with raw log data. This task simulates an authentication log (`auth.log`) that a real application's PAM module or SIEM agent would generate. The log captures both legitimate and malicious activity across a compressed time window, providing the raw evidence corpus for all subsequent analysis tasks.

#### Commands Executed

```bash
# Write a simulated authentication log with 7 structured entries
cat > auth.log <<'EOF'
2025-03-01T09:00:01 LOGIN OK   user=ahmad  ip=10.0.0.5
2025-03-01T09:01:10 LOGIN FAIL user=admin  ip=203.0.113.9
2025-03-01T09:01:12 LOGIN FAIL user=admin  ip=203.0.113.9
2025-03-01T09:01:15 LOGIN FAIL user=admin  ip=203.0.113.9
2025-03-01T09:01:18 LOGIN FAIL user=admin  ip=203.0.113.9
2025-03-01T09:01:22 LOGIN OK   user=admin  ip=203.0.113.9
2025-03-01T09:01:40 EXPORT DATA user=admin ip=203.0.113.9 size=500MB
EOF

# Verify the file was written correctly
cat auth.log
```

#### Step-by-Step Technical Explanation

The heredoc (`<<'EOF'`) writes all seven lines atomically to `auth.log`. The single-quoted `'EOF'` delimiter prevents shell expansion inside the block, ensuring timestamps and IP addresses are written literally.

The log models the following attack narrative:

| Timestamp | Event | Significance |
|-----------|-------|--------------|
| `09:00:01` | `LOGIN OK user=ahmad ip=10.0.0.5` | Legitimate internal user login — baseline normal activity |
| `09:01:10` | `LOGIN FAIL user=admin ip=203.0.113.9` | First failed admin login from external IP — possible probe |
| `09:01:12` | `LOGIN FAIL user=admin ip=203.0.113.9` | Second failure within 2 seconds — automated tool pattern |
| `09:01:15` | `LOGIN FAIL user=admin ip=203.0.113.9` | Third failure — brute-force threshold approaching |
| `09:01:18` | `LOGIN FAIL user=admin ip=203.0.113.9` | Fourth failure — 4 attempts in 8 seconds, high-confidence brute force |
| `09:01:22` | `LOGIN OK user=admin ip=203.0.113.9` | Successful login from same attacker IP — account compromised |
| `09:01:40` | `EXPORT DATA user=admin ip=203.0.113.9 size=500MB` | Immediate bulk data exfiltration — 500 MB export 18 seconds post-compromise |

The structured key=value format (`user=`, `ip=`, `size=`) is intentional: it makes the log machine-parseable by `awk`, `grep`, and SIEM ingestion pipelines without a custom parser.

#### Evidence

![Task 1 — Generate Application Logs](./Task%201%20—%20Generate%20Application%20Logs.png)

---

### Task 2 — Centralise Logs (Ship to CloudWatch)

#### Theoretical Goal

Logs stored only on the originating host are a single point of failure — an attacker who compromises the host can delete or alter them. Centralised log shipping to an immutable sink (CloudWatch Logs, a SIEM, or an append-only S3 bucket) severs the attacker's ability to cover their tracks. This task replicates a log-shipper agent (analogous to Fluentd, the CloudWatch Agent, or Filebeat) by using the AWS CLI `put-log-events` API in a shell loop.

#### Commands Executed

```bash
# Initialise timestamp at current epoch time in milliseconds (CloudWatch requirement)
TS=$(date +%s000)

# Iterate over every line in auth.log, shipping each as a separate CloudWatch log event
while IFS= read -r line; do
    aws $EP logs put-log-events \
        --log-group-name /ccse/app \
        --log-stream-name auth \
        --log-events timestamp=$TS,message="$line" >/dev/null
    # Increment timestamp by 1 second per event to maintain event ordering
    TS=$((TS+1000))
done < auth.log

# Retrieve and verify all shipped events from CloudWatch
aws $EP logs get-log-events \
    --log-group-name /ccse/app \
    --log-stream-name auth \
    --query 'events[].message' \
    --output text
```

#### Step-by-Step Technical Explanation

| Component | Explanation |
|-----------|-------------|
| `date +%s000` | Generates the current Unix epoch in **milliseconds** (the `000` suffix appends three zeros). CloudWatch Logs requires millisecond-precision timestamps; submitting second-precision timestamps causes an `InvalidParameterException`. |
| `IFS= read -r line` | `IFS=` prevents leading/trailing whitespace stripping; `-r` prevents backslash interpretation. Both flags ensure log lines are shipped byte-for-byte without modification. |
| `put-log-events` | The AWS CloudWatch Logs API call that appends one or more events to a stream. Each event is a `{timestamp, message}` tuple. The `>/dev/null` suppression hides the `nextSequenceToken` response noise. |
| `TS=$((TS+1000))` | Increments the timestamp by 1,000 ms (1 second) per event. This preserves chronological ordering in the stream, which CloudWatch enforces — out-of-order events with stale timestamps are rejected. |
| `get-log-events` | Reads back all events from the stream. The `--query 'events[].message'` JMESPath expression extracts only the message field from the JSON response, confirming all 7 log lines were received intact. |

The verification output confirmed all seven original log entries were successfully shipped and retrievable from the LocalStack CloudWatch endpoint.

#### Evidence

![Task 2 — Centralise Logs](./Task%202%20—%20Centralise%20Logs%20(Ship%20to%20CloudWatch).png)

---

### Task 3 — Query for Security-Relevant Activity

#### Theoretical Goal

Raw logs contain both noise and signal. Security analysts must be able to extract actionable intelligence — specifically, identifying which source IPs are generating failed authentication events, at what frequency, and against which accounts. This task demonstrates lightweight log querying using standard Unix text-processing tools that are available in any environment, mirroring the filtering logic built into CloudWatch Logs Insights, Splunk, and Elastic SIEM.

#### Commands Executed

```bash
# Extract failed login events, isolate user/IP fields, sort, deduplicate with count
grep "LOGIN FAIL" auth.log | awk '{print $4, $5}' | sort | uniq -c
```

#### Step-by-Step Technical Explanation

The pipeline is composed of four chained tools:

| Stage | Tool & Arguments | Output |
|-------|-----------------|--------|
| 1 | `grep "LOGIN FAIL" auth.log` | Filters the file to only lines containing the string `LOGIN FAIL` — isolates the 4 failed-login events |
| 2 | `awk '{print $4, $5}'` | Extracts whitespace-delimited fields 4 and 5 from each matching line, which correspond to `user=admin` and `ip=203.0.113.9` respectively |
| 3 | `sort` | Lexicographically sorts the extracted field pairs, grouping identical `(user, IP)` combinations together — a prerequisite for `uniq -c` |
| 4 | `uniq -c` | Collapses consecutive identical lines into a single line prefixed with a count |

**Result:**
```
4 user=admin ip=203.0.113.9
```

This single output line communicates the critical intelligence: the `admin` account received **4 failed login attempts** — all originating from the same external IP address `203.0.113.9`. In a production SOC environment, this count crossing a threshold (typically 3–5 within a short window) would trigger an automated alert or a SOAR playbook.

#### Evidence

![Task 3 — Query Security Activity](./Task%203%20—%20Query%20for%20Security-Relevant%20Activity.png)

---

### Task 4 — Tamper-Proof (Hash-Chained) Logs

#### Theoretical Goal

A log file stored as plain text is trivially modifiable — an attacker with write access to the filesystem can alter or delete entries without leaving a trace. Hash chaining solves this by making each log entry's hash depend on the previous entry's hash: any modification to any line produces a completely different hash for that line and all subsequent lines, making tampering detectable by comparing the final hash of the chain. This is the same principle used in blockchain technology and Certificate Transparency logs.

#### Commands Executed

```bash
# ── PHASE 1: Build the original hash chain ──────────────────────────────────

PREV=0
while IFS= read -r line; do
    PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
    printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain

# Inspect the chained log
cat auth.chain

# ── PHASE 2: Simulate tampering ─────────────────────────────────────────────

# Attacker attempts to conceal exfiltration scale by changing 500MB → 5MB
sed 's/500MB/5MB/' auth.log > auth.tampered

# ── PHASE 3: Re-chain the tampered file ─────────────────────────────────────

PREV=0
while IFS= read -r line; do
    PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
    printf '%s | %s\n' "$line" "$PREV"
done < auth.tampered > auth.tampered.chain

# ── PHASE 4: Compare final hashes to prove tampering ────────────────────────

echo "── Original Final Hash ──"
tail -n 1 auth.chain | awk -F'|' '{print $2}'

echo "── Tampered Final Hash ──"
tail -n 1 auth.tampered.chain | awk -F'|' '{print $2}'
```

#### Step-by-Step Technical Explanation

**How the hash chain is constructed:**

At each iteration, the algorithm computes:

```
H(n) = SHA256( H(n-1) || LogLine(n) )
```

Where `||` denotes string concatenation. The seed value `PREV=0` initialises the chain. Each resulting hash `H(n)` is appended to the corresponding log line in `auth.chain`, separated by ` | `.

**The `auth.chain` file (verified output):**

```
2025-03-01T09:00:01 LOGIN OK user=ahmad ip=10.0.0.5     | 425b4c8ff62466c3d37b717cb63ee3129f575088822d7b893a1c4e0eb9cf9b97
2025-03-01T09:01:10 LOGIN FAIL user=admin ip=203.0.113.9 | 07a851809cd3bd6c0dc47acacfaccb977c9fe45a5474eee8e0ce13e51d4d2169
2025-03-01T09:01:12 LOGIN FAIL user=admin ip=203.0.113.9 | eeb9dd08ade1a33ed4e5ac3fdd71a5c83e51b56ce3935b0efbeaa94e572903a3
2025-03-01T09:01:15 LOGIN FAIL user=admin ip=203.0.113.9 | eac0dfd27f28d4f959255a39e8c546eb27405cbf4379dae9e82569520ca1729c
2025-03-01T09:01:18 LOGIN FAIL user=admin ip=203.0.113.9 | eda9647313fd4ededf5a21b3f4b619b21e3b7f922a520b01d771a2defcbd0ffa
2025-03-01T09:01:22 LOGIN OK user=admin ip=203.0.113.9   | 4b5dd28eac034cc9476d4af10dbc50cc554a65a2d74e17cee7622bc2f42d5649
2025-03-01T09:01:40 EXPORT DATA user=admin ip=203.0.113.9 size=500MB | 78e525a226c720a2d96ed67626cf69c56ea77c0a1a4287874eb865b68315e3ed
```

**Tampering simulation:**

`sed 's/500MB/5MB/' auth.log > auth.tampered` modifies only the last log entry, reducing the exfiltration volume from `500MB` to `5MB` — a realistic attack where the adversary wants to minimise the apparent severity of the incident.

**Hash comparison result:**

| Chain | Final SHA-256 Hash |
|-------|--------------------|
| Original (`auth.chain`) | `78e525a226c720a2d96ed67626cf69c56ea77c0a1a4287874eb865b68315e3ed` |
| Tampered (`auth.tampered.chain`) | `10dde913b25b457b101e8e478b1b0efabc229a83932390bc5edff012f460eafb` |

The hashes are completely different — **tampering is proven**. Because SHA-256 is a cryptographic hash function, even a one-bit change in any input (changing `500MB` to `5MB` alters 3 bytes) produces an entirely unpredictable output through the avalanche effect, propagating through every subsequent chain entry. An auditor holding the original final hash `78e525...` can immediately determine that `auth.tampered` does not match, without needing to compare the files line by line.

#### Evidence

![Task 4 — Tamper-Proof Logs](./Task%204%20—%20Tamper-Proof%20(Hash-Chained)%20Logs.png)

---

### Task 5 — Detect the Incident (Correlation)

#### Theoretical Goal

Individual log lines are insufficient to identify sophisticated attacks. A single failed login is noise; four failed logins from the same IP, followed by a successful login from that same IP and an immediate large data export, is a high-confidence attack chain. Event correlation — analysing the relationships between multiple events across time — is the core capability of SIEMs like Splunk, IBM QRadar, and Microsoft Sentinel. This task implements a minimal correlation engine in shell script.

#### Commands Executed

```bash
# Define the attacker IP to correlate against
IP="203.0.113.9"

# Count each event category for this IP
FAILS=$(grep  -c "LOGIN FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN OK.*$IP"  auth.log)
EXPORT=$(grep  -c "EXPORT DATA.*$IP" auth.log)

# Print the aggregated telemetry for this IP
echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"

# Correlation rule: brute-force threshold + successful compromise + exfiltration
if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
    echo 'ALERT: probable brute-force → compromise → data exfiltration'
fi
```

#### Step-by-Step Technical Explanation

**Telemetry aggregation:**

```
IP=203.0.113.9  fails=4  success=1  export=1
```

Each `grep -c` call counts the number of lines matching a combined pattern of event type and IP address, producing integer counters representing the security-relevant activity of that IP across the log corpus.

**Correlation rule logic:**

```
IF (failed_logins ≥ 3) AND (successful_logins ≥ 1) AND (data_exports ≥ 1)
THEN → ALERT: brute-force → compromise → data exfiltration
```

This three-condition AND rule captures a complete Cyber Kill Chain sequence within a single log file:

| Condition | Kill Chain Phase | Value |
|-----------|-----------------|-------|
| `FAILS ≥ 3` | Exploitation (credential attack) | 4 ✓ |
| `SUCCESS ≥ 1` | Installation / Command & Control | 1 ✓ |
| `EXPORT ≥ 1` | Actions on Objectives (exfiltration) | 1 ✓ |

**Output:**
```
ALERT: probable brute-force → compromise → data exfiltration
```

All three conditions evaluate to true, triggering the alert. In a production SOAR integration, this alert would automatically create an incident ticket, page the on-call analyst, and potentially trigger the containment action in Task 6 without human intervention.

#### Evidence

![Task 5 — Detect the Incident](./Task%205%20—%20Detect%20the%20Incident%20(Correlation).png)

---

### Task 6 — Incident Response

#### Theoretical Goal

Detection without response is insufficient. Once an attacker IP is confirmed through correlation, the immediate priority is containment — preventing further malicious activity while preserving all available evidence for forensic analysis. This task implements both objectives: network-level containment via `iptables` and cryptographically secured evidence preservation.

#### Commands Executed

```bash
# ── CONTAINMENT ─────────────────────────────────────────────────────────────

# Run a privileged Alpine container and apply an iptables DROP rule for the attacker IP
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
    'apk add -q iptables; \
     iptables -A INPUT -s 203.0.113.9 -j DROP; \
     iptables -L INPUT -n | tail -2'

# ── EVIDENCE PRESERVATION ────────────────────────────────────────────────────

# Create a date-stamped snapshot of the log file for chain-of-custody
cp auth.log evidence_$(date +%Y%m%d).log

# Generate SHA-256 checksums for all evidence files
sha256sum evidence_*.log > evidence.sha256

# Display the checksum file contents
cat evidence.sha256

# ── INTEGRITY VERIFICATION ───────────────────────────────────────────────────

# Verify the evidence file has not been modified since checksum generation
sha256sum -c evidence.sha256
```

#### Step-by-Step Technical Explanation

**Containment via iptables:**

| Component | Explanation |
|-----------|-------------|
| `docker run --rm` | Runs a disposable container that is automatically removed after the command completes, keeping the host clean |
| `--cap-add=NET_ADMIN` | Grants the container the Linux capability required to modify `iptables` rules. Without this, the kernel refuses `iptables` modifications from within a container |
| `alpine` | A minimal 5 MB Linux image with `apk` package manager, sufficient for the `iptables` tool |
| `apk add -q iptables` | Silently installs the `iptables` package into the container's ephemeral filesystem |
| `iptables -A INPUT -s 203.0.113.9 -j DROP` | **Appends** (`-A`) a rule to the `INPUT` chain that **drops** (`-j DROP`) all inbound packets from source IP `203.0.113.9`. `DROP` is silent (no RST/ICMP response), making the host invisible to the attacker rather than merely unreachable |
| `iptables -L INPUT -n | tail -2` | Lists the INPUT chain rules without DNS resolution (`-n`) to verify the DROP rule was applied. The confirmed output: `DROP all -- 203.0.113.9 0.0.0.0/0` |

**Evidence preservation:**

| Command | Purpose |
|---------|---------|
| `cp auth.log evidence_$(date +%Y%m%d).log` | Creates `evidence_20260907.log` — a timestamped, immutable snapshot of the log at the time of incident response. The date suffix satisfies chain-of-custody naming conventions |
| `sha256sum evidence_*.log > evidence.sha256` | Computes the SHA-256 digest of the evidence file and writes it to `evidence.sha256`. This file serves as the cryptographic seal |
| `cat evidence.sha256` | Displays: `b8a4ba3efa415089202566a75f06288ee2d7c375d8d72997e4fa4c0c99126eaa  evidence_20260907.log` |
| `sha256sum -c evidence.sha256` | Re-computes the hash of `evidence_20260907.log` and compares it against the stored digest. Output: `evidence_20260907.log: OK` — confirms the evidence file is unmodified |

The SHA-256 checksum in `evidence.sha256` can be presented in court or to a compliance auditor as proof that the evidence has not been altered since the time of collection.

#### Evidence

![Task 6 — Incident Response](./Task%206%20—%20Incident%20Response.png)

---

### Verification Command

#### Theoretical Goal

The final verification step confirms the end-to-end integrity of the entire lab pipeline: that the log data shipped in Task 2 is durably stored in LocalStack's CloudWatch emulation, and that the evidence file collected in Task 6 remains cryptographically intact. This step mirrors the post-incident audit review performed by a compliance officer or forensic investigator.

#### Commands Executed

```bash
# Verify CloudWatch log group exists and check stored byte count
aws --endpoint-url=http://localhost:4566 logs describe-log-groups

# Verify the evidence file integrity using the stored SHA-256 checksum
sha256sum -c evidence.sha256
```

#### Verified Output

**CloudWatch Log Groups:**
```json
{
    "logGroups": [
        {
            "logGroupName": "/ccse/app",
            "creationTime": 1788755503742,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:us-east-1:000000000000:log-group:/ccse/app:*",
            "storedBytes": 397
        }
    ]
}
```

**Evidence integrity check:**
```
evidence_20260907.log: OK
```

The `storedBytes: 397` value confirms that the 7 log events (totalling 397 bytes of message data) were durably persisted in the LocalStack CloudWatch emulation. The `OK` status confirms the evidence file is unmodified and suitable for submission as forensic evidence.

#### Evidence

![Verification Command](./Verification%20Command.png)

---

## 3. Incident Report

**Classification:** Confidential — Internal Security Incident
**Reference:** INC-2026-0907-001
**Date/Time of Detection:** 2026-09-07 (log events originating 2025-03-01T09:00 UTC)
**Analyst:** Lab Student, IKB42603 — UniKL MIIT
**Status:** Contained

---

### Detection

The incident was identified by the automated multi-event correlation script (Task 5), which analysed `auth.log` for activity associated with source IP `203.0.113.9`. The rule triggered upon observing the complete attack trifecta for a single IP: **4 failed login attempts** against the `admin` account (threshold: ≥ 3), followed by **1 successful login** from the same IP at `09:01:22`, and **1 data export event** of `500 MB` at `09:01:40` — occurring just 18 seconds after the successful authentication. No individual event, viewed in isolation, would have raised an alert; only the combination of all three signals within the same source-IP context confirmed a high-confidence incident.

### Analysis

The attack followed a textbook **brute-force credential attack leading to privilege escalation and data exfiltration**:

- **Attack Vector:** External network (IP `203.0.113.9`, publicly routable under RFC 5737 documentation range). The 8-second window across 4 login failures (09:01:10 to 09:01:18) is consistent with an automated credential-stuffing or password-spray tool rather than manual attempts.
- **Vulnerability Exploited:** Absence of account lockout policy and rate-limiting on the authentication endpoint. The `admin` account accepted a successful login immediately after 4 consecutive failures without any enforced delay or lockout.
- **Privilege Level:** The compromised account was `admin` — the highest-privilege account — granting immediate access to bulk data export functionality.
- **Impact:** 500 MB of data was exfiltrated within 18 seconds of compromise, indicating pre-positioned knowledge of the target data location, suggesting either prior reconnaissance or insider knowledge of the directory structure.

### Containment

Immediate containment was achieved by inserting a **network-level DROP rule** for the attacker's source IP. The command:

```bash
iptables -A INPUT -s 203.0.113.9 -j DROP
```

was applied via a privileged Docker container (`--cap-add=NET_ADMIN`), silently discarding all further inbound packets from `203.0.113.9` with no TCP RST or ICMP unreachable response. The rule was verified in the `iptables -L INPUT -n` output (`DROP all -- 203.0.113.9 0.0.0.0/0`). The `admin` account should additionally be suspended and its credentials rotated as a parallel containment measure.

### Evidence & Integrity

A date-stamped forensic snapshot of `auth.log` was created as `evidence_20260907.log` immediately following containment, preserving the log state before any potential remediation activity could alter the file. A SHA-256 cryptographic digest was computed and stored in `evidence.sha256`:

```
b8a4ba3efa415089202566a75f06288ee2d7c375d8d72997e4fa4c0c99126eaa  evidence_20260907.log
```

Subsequent verification with `sha256sum -c evidence.sha256` returned `evidence_20260907.log: OK`, confirming the evidence file's authenticity and suitability for chain-of-custody submission. The centralised CloudWatch log copy (`/ccse/app` stream `auth`, `storedBytes: 397`) provides a secondary, independently preserved evidence source that was never accessible to the attacker.

### Lessons Learned

1. **Automated SOAR Response:** The detection-to-containment gap (manual execution) must be eliminated. Integrating the correlation script with a SOAR platform (e.g., AWS Lambda triggered by a CloudWatch Logs metric filter) would enable sub-second automated IP blocking upon alert trigger.
2. **Append-Only Centralised Log Shipping:** Logs should be shipped to CloudWatch (or an S3 Object Lock bucket) in real time, not post-incident. Append-only architecture ensures that even if the host is compromised, the attacker cannot retroactively purge centrally stored events.
3. **Mandatory MFA on Administrative Endpoints:** The `admin` account must require multi-factor authentication. Even with a correct password, a brute-force attacker would be unable to complete authentication without the second factor, breaking the attack chain at the `LOGIN OK` stage.

---

## 4. Short-Answer Questions

---

### Q1 — Difference Between a Log and an Event

A **log** is a durable, static, sequential record of what happened within a system, written to a persistent storage medium (file, database, or cloud service) for later retrieval. Logs are retrospective in nature: they describe historical activity and are intended for auditing, compliance, debugging, and forensic analysis. A log entry does not inherently trigger any action — it simply exists as a record.

An **event** is a real-time, actionable notification that something significant has occurred. Events are consumed immediately by monitoring systems, correlation engines, or SOAR platforms and may trigger automated responses. Events are ephemeral by nature and are typically derived from or converted from log entries.

**From this lab:**

- **Task 1 (Log):** The `auth.log` file is a classic log — a static flat file containing 7 timestamped entries recording authentication and data-export activity. It does nothing on its own. An administrator must actively query it (Task 3), or a shipper must forward it (Task 2) before it yields any security value.

- **Task 5 (Event):** The output `ALERT: probable brute-force → compromise → data exfiltration` is an event. It was generated by the correlation script in real time, is actionable (it triggered the containment in Task 6), and is tied to a specific moment in the analysis workflow. In a production environment, this event would be published to an SNS topic, a PagerDuty alert, or a SIEM incident queue, prompting immediate human or automated response.

The key distinction is **passivity vs. reactivity**: logs record; events respond.

---

### Q2 — Importance of Tamper-Proof Audit Logs and SHA-256 Hash Chaining

**Why tamper-proof logs matter:**

Audit logs are the primary evidentiary foundation for security investigations, compliance audits, and legal proceedings. An adversary who gains write access to a compromised host can delete log entries recording their actions, alter timestamps to obscure timelines, or reduce exfiltration volumes to minimise apparent impact — as demonstrated in Task 4's `sed 's/500MB/5MB/'` simulation. Without integrity protection, logs are not trustworthy evidence.

Regulatory frameworks mandate tamper-evident logging: PCI-DSS Requirement 10.5 requires log protection from modifications; ISO 27001 Annex A.12.4.2 mandates log administrator activity protection; SOC 2 Trust Service Criteria CC7.2 requires monitoring for unauthorised changes.

**How SHA-256 hash chaining detects modifications:**

Hash chaining creates a **cryptographic dependency** between every log entry, such that modifying any entry invalidates all entries that follow it. The algorithm used in Task 4 is:

```
H(0)  = 0                           (seed/genesis value)
H(n)  = SHA256( H(n-1) || Line(n) ) (each entry depends on all prior entries)
```

SHA-256 is a **one-way, collision-resistant** cryptographic hash function. Its key properties relevant here are:

- **Determinism:** The same input always produces the same 256-bit output
- **Avalanche effect:** A one-bit change in input produces an entirely different output (demonstrated: changing `500MB` to `5MB` changed the final hash from `78e525...` to `10dde9...`)
- **Pre-image resistance:** It is computationally infeasible to construct a modified log entry that produces the same hash as the original
- **Collision resistance:** It is computationally infeasible to find two different inputs that produce the same hash

An auditor who holds the original final hash `78e525a226c720a2d96ed67626cf69c56ea77c0a1a4287874eb865b68315e3ed` can re-compute the chain over any version of `auth.log` and immediately determine whether it matches — without comparing files line by line. Any discrepancy proves tampering occurred, even if only a single byte was changed anywhere in the entire file.

---

### Q3 — How Multi-Event Correlation Identifies Complex Attack Scenarios

Single-line log inspection has a fundamental limitation: it provides no context about what happened before or after the event being examined. A single `LOGIN FAIL` entry is noise — systems generate thousands of these legitimately every day due to typos, expired credentials, and automated scripts. A single `LOGIN OK` is expected. A single `EXPORT DATA` event may be routine administrative activity.

**Why single-line inspection fails:**

An analyst reviewing only the `LOGIN OK user=admin ip=203.0.113.9` event would see a routine successful login. An analyst reviewing only the `EXPORT DATA size=500MB` event might assume a scheduled backup. Neither individual event, absent its context, meets an alerting threshold.

**How multi-event correlation captures the full attack chain:**

The Task 5 correlation script operates at the **IP-level aggregation** layer, computing counters for each event type associated with a specific source IP and then evaluating a compound logical rule:

```
FAILS=4  (brute-force phase)
SUCCESS=1 (compromise phase)
EXPORT=1  (exfiltration phase)
```

Only when all three conditions are simultaneously true for the same IP does the alert fire. This **temporal and contextual correlation** across all log entries produces a signal that no individual event could. The correlation model maps directly to the MITRE ATT&CK framework:

| ATT&CK Tactic | Technique | Log Evidence |
|---------------|-----------|-------------|
| Credential Access | T1110 — Brute Force | 4× `LOGIN FAIL` from same IP |
| Initial Access | T1078 — Valid Accounts | `LOGIN OK` from same IP post-failures |
| Exfiltration | T1048 — Exfiltration Over Alternative Protocol | `EXPORT DATA size=500MB` |

Production SIEMs extend this principle to correlate events across multiple log sources (firewall, DNS, endpoint, identity), multiple hosts, and extended time windows (hours or days), enabling detection of slow-and-low attacks that single-source, single-window rules would miss entirely.

---

### Q4 — Mapping of Incident Response Lifecycle Steps

The lab executed four of the six NIST SP 800-61 incident response lifecycle phases:

| Phase | Lab Activity | Technical Objective |
|-------|-------------|---------------------|
| **Detect** | Task 5 correlation script produces `ALERT: probable brute-force → compromise → data exfiltration` | Automated identification of the attack chain by correlating FAILS ≥ 3 + SUCCESS ≥ 1 + EXPORT ≥ 1 for IP `203.0.113.9`, eliminating reliance on manual log review |
| **Contain** | Task 6 `iptables -A INPUT -s 203.0.113.9 -j DROP` via privileged Docker container | Network-layer isolation of the threat actor, preventing further data exfiltration, lateral movement, or command-and-control communication while avoiding service disruption to legitimate users |
| **Collect Evidence** | Task 6 `cp auth.log evidence_20260907.log` + `sha256sum evidence_*.log > evidence.sha256` | Creation of a forensically sound, date-stamped log snapshot with cryptographic integrity verification, establishing a chain of custody compliant with digital forensics standards (ACPO, RFC 3227) |
| **Document** | Task 6 `sha256sum -c evidence.sha256` confirms `OK`; CloudWatch `describe-log-groups` confirms `storedBytes: 397` | Formal verification that both the local evidence file and the centralised cloud copy are intact, producing auditable proof of the incident response actions taken |

**Phases not in scope for this lab (noted for completeness):**

- **Eradicate:** Removing the attacker's persistence mechanisms (backdoors, new admin accounts, cron jobs) and patching the exploited vulnerability (missing account lockout / MFA)
- **Recover:** Restoring the system to normal operations with enhanced controls, verifying clean state, and resuming production traffic

The complete cycle, including eradication and recovery, would complete the NIST SP 800-61 post-incident activity phase and feed lessons learned back into the organisation's security posture.

---

### Q5 — Dual Purpose of Cloud Telemetry: Security Monitoring vs. Regulatory Compliance

Cloud telemetry — the continuous collection, aggregation, and analysis of logs, metrics, and traces from cloud workloads — simultaneously serves two distinct but mutually reinforcing organisational objectives:

**Security Monitoring (Operational Use)**

From a security operations perspective, cloud telemetry enables:

- **Real-time threat detection:** Streaming log events to a correlation engine allows sub-second detection of brute-force attacks, privilege escalation, lateral movement, and data exfiltration — as demonstrated across Tasks 3–5
- **Incident response acceleration:** Centralised logs (Task 2) provide the single source of truth for forensic investigation, eliminating time wasted collecting logs from individual hosts
- **Attack surface visibility:** Aggregated telemetry reveals patterns invisible at the host level — port scanning across subnets, credential-stuffing campaigns targeting multiple accounts, or slow-and-low exfiltration disguised within normal traffic volumes
- **Tamper detection:** Hash-chained logs (Task 4) ensure that even a compromised host cannot silently alter the evidence of the attacker's presence

**Regulatory Compliance Auditing (Governance Use)**

From a compliance perspective, the same telemetry infrastructure satisfies mandatory audit and logging requirements across multiple frameworks:

| Framework | Specific Requirement Satisfied by This Lab |
|-----------|---------------------------------------------|
| **PCI-DSS v4.0** | Req. 10.2 (log all access to cardholder data), Req. 10.3 (protect logs from destruction/modification — hash chaining), Req. 10.4 (review logs daily — correlation scripts) |
| **ISO 27001:2022** | Annex A.8.15 (logging), A.8.16 (monitoring activities), A.5.28 (collection of evidence — evidence preservation with SHA-256) |
| **SOC 2 Type II** | CC6.1 (logical access controls — authentication logging), CC7.2 (monitoring for anomalies — event correlation), CC7.3 (evaluation of security events — incident report) |
| **GDPR Article 32** | Technical measures to ensure integrity and confidentiality of processing — tamper-proof logs satisfy the integrity requirement for audit trails involving personal data |

The critical insight is that **the same technical artifact** — a centralised, tamper-evident, queryable log store — simultaneously supports the SOC analyst's daily threat hunting workflow and the compliance officer's quarterly audit evidence package. Organisations that treat these as separate workstreams incur duplicated effort; those that design their telemetry architecture to serve both audiences from a single pipeline achieve both security and compliance at lower operational cost.

---

## 5. Security Best-Practices Checklist

| # | Best Practice | Implementation in Lab | Status |
|---|--------------|----------------------|--------|
| 1 | **Log Centralisation** — All security-relevant log events are shipped from the originating host to a centralised, independently managed log store that is not accessible to the systems being monitored | `auth.log` streamed to LocalStack CloudWatch `/ccse/app` stream `auth` via `put-log-events` loop (Task 2). Verified by `describe-log-groups` showing `storedBytes: 397` (Verification). Central store confirmed operational and separate from the log-generating host. | ✅ **Compliant** |
| 2 | **Log Queryability** — Security-relevant events can be extracted, filtered, and aggregated programmatically to identify threat indicators without manual line-by-line review | `grep "LOGIN FAIL" auth.log \| awk '{print $4,$5}' \| sort \| uniq -c` pipeline extracted the attacker's identity in a single command (Task 3). CloudWatch `get-log-events` with JMESPath query confirmed remote queryability (Task 2). | ✅ **Compliant** |
| 3 | **Tamper-Evidence** — Log integrity is cryptographically guaranteed such that any unauthorised modification is detectable, satisfying non-repudiation and chain-of-custody requirements | SHA-256 hash chain built over `auth.log` → `auth.chain` with seed-chained hashing (Task 4). Tampering simulation (`sed 's/500MB/5MB/'`) produced divergent final hash (`78e525...` vs `10dde9...`), proving detection capability. Evidence file protected with `sha256sum` verification returning `OK`. | ✅ **Compliant** |
| 4 | **Event Correlation** — Multi-event correlation rules identify complex, multi-stage attack sequences (e.g., brute-force → compromise → exfiltration) that single-event alerting cannot detect | Correlation script aggregated FAILS=4, SUCCESS=1, EXPORT=1 per IP. Compound rule `FAILS≥3 AND SUCCESS≥1 AND EXPORT≥1` fired `ALERT: probable brute-force → compromise → data exfiltration` (Task 5). Single-event review of any individual log line would not have triggered an alert. | ✅ **Compliant** |
| 5 | **Incident Response Execution** — Upon detection, containment is immediate (network-level blocking), evidence is preserved with cryptographic integrity, and the incident is formally documented | `iptables DROP` rule for `203.0.113.9` applied via Docker `NET_ADMIN` container (Task 6). `evidence_20260907.log` snapshot created and sealed with SHA-256 checksum. Incident formally documented with detection, analysis, containment, evidence, and lessons-learned sections (Section 3). | ✅ **Compliant** |

**Overall Compliance Score: 5 / 5 — All Best Practices Satisfied**

---

## Appendix — File Artefacts Produced

| File | Description | Integrity |
|------|-------------|-----------|
| `auth.log` | Original 7-entry simulated authentication log | Source file |
| `auth.chain` | Hash-chained version of `auth.log` (SHA-256 per line) | Final hash: `78e525a226...` |
| `auth.tampered` | Modified log with `500MB → 5MB` (tampering simulation) | Intentionally altered |
| `auth.tampered.chain` | Hash chain of tampered file | Final hash: `10dde913b2...` |
| `evidence_20260907.log` | Forensic snapshot of `auth.log` at time of IR | `b8a4ba3efa...` |
| `evidence.sha256` | SHA-256 checksum file for chain of custody | Verified `OK` |

---

*Report prepared for IKB42603 Cloud Computing Security Essentials — UniKL MIIT.*
*All commands executed in a LocalStack 3.0.0 environment on Kali Linux. No live AWS resources were used.*
