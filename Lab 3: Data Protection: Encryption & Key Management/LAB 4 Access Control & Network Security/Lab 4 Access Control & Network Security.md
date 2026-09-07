# LAB 4 — Access Control & Network Security

> **Course:** IKB42603 Cloud Computing Security Essentials

---

| Field          | Details                                      |
|----------------|----------------------------------------------|
| **Student**    | Nurul Jihan Nabilah Binti Azlan              |
| **Student ID** | 52215225220                                  |
| **Course**     | IKB42603 Cloud Computing Security Essentials |
| **Module**     | Lab 4 — Access Control & Network Security    |

---

## Table of Contents

1. [Executive Summary & Learning Outcomes](#executive-summary--learning-outcomes)
2. [Session A: Access Control (Tasks 1–3)](#session-a-access-control-tasks-13)
   - [Task 1: Authentication — Password-Protected Service](#task-1-authentication--password-protected-service)
   - [Task 2: Multi-Factor Authentication (MFA / TOTP)](#task-2-multi-factor-authentication-mfa--totp)
   - [Task 3: Authorization — Kubernetes RBAC Roles](#task-3-authorization--kubernetes-rbac-roles)
3. [Session B: Network Security & Hardening (Tasks 4–6)](#session-b-network-security--hardening-tasks-46)
   - [Task 4: Network Segmentation (Three-Tier Architecture)](#task-4-network-segmentation-three-tier-architecture)
   - [Task 5: Host Firewall Rules (Default-Deny via iptables)](#task-5-host-firewall-rules-default-deny-via-iptables)
   - [Task 6: Container & Host Hardening](#task-6-container--host-hardening)
4. [Verification Commands & Proof](#verification-commands--proof)
5. [Short-Answer Questions & Deliverables](#short-answer-questions--deliverables)
6. [Security Best-Practices Checklist](#security-best-practices-checklist)
7. [Teardown & Cleanup Commands](#teardown--cleanup-commands)

---

## Executive Summary & Learning Outcomes

This lab explores the three foundational pillars of cloud workload security:

- **WHO gets in** — controlled through authentication mechanisms (password + MFA).
- **WHAT they can reach** — enforced through authorisation policies (Kubernetes RBAC).
- **WHAT an intruder could exploit** — minimised through network segmentation, host firewalling, and container hardening.

By the end of this lab, the following outcomes were achieved:

| # | Learning Outcome |
|---|-----------------|
| 1 | Distinguish between **Authentication (AuthN)** and **Authorization (AuthZ)** in practice. |
| 2 | Implement **HTTP Basic Auth** with Nginx as a lightweight identity gate. |
| 3 | Add a **Time-Based One-Time Password (TOTP)** second factor using `oathtool`. |
| 4 | Define and verify **Kubernetes RBAC** Roles, ServiceAccounts, and RoleBindings. |
| 5 | Architect a **three-tier network** with Docker to isolate frontend, application, and database tiers. |
| 6 | Apply **default-deny iptables** rules and reason about their equivalence to cloud security groups. |
| 7 | Harden a Docker container using Linux capabilities, read-only filesystems, and non-root users. |
| 8 | Perform a **Trivy vulnerability scan** on a container image and interpret the findings. |

> **Key Principle:** Defence-in-depth — no single control is sufficient. Layering AuthN, AuthZ, network policy, and hardening significantly raises the cost of a successful attack.

---

## Session A: Access Control (Tasks 1–3)

### Task 1: Authentication — Password-Protected Service

#### Concept

**Authentication (AuthN)** answers the question: *"Who are you?"* Before granting any access, a system must verify the claimed identity. In this task, Nginx is configured to enforce **HTTP Basic Authentication**, requiring a valid username and password before serving any content.

#### Steps & Commands

**1. Install required packages**

```bash
sudo apt-get update
sudo apt-get install -y nginx apache2-utils
```

**2. Create the password file**

```bash
# Create a password file with user 'admin'
sudo htpasswd -c /etc/nginx/.htpasswd admin
# Enter and confirm a strong password when prompted
```

**3. Configure Nginx to require authentication**

Edit `/etc/nginx/sites-available/default` (or a custom site config):

```nginx
server {
    listen 80;
    server_name localhost;

    location / {
        auth_basic           "Restricted Area";
        auth_basic_user_file /etc/nginx/.htpasswd;
        root /var/www/html;
        index index.html;
    }
}
```

**4. Reload Nginx**

```bash
sudo nginx -t          # Test configuration syntax
sudo systemctl reload nginx
```

**5. Verify the behaviour**

```bash
# Expected: 401 Unauthorized — no credentials provided
curl -I http://localhost/

# Expected: 200 OK — valid credentials accepted
curl -I -u admin:yourpassword http://localhost/
```

#### Results Explained

| HTTP Status | Meaning | Condition |
|-------------|---------|-----------|
| **401 Unauthorized** | The server requires authentication that was not provided or was incorrect. The `WWW-Authenticate` header is returned, prompting the client to supply credentials. | Request sent without credentials, or with wrong credentials. |
| **200 OK** | Authentication succeeded; the resource is returned normally. | Valid `Authorization: Basic <base64>` header supplied. |

> **Note:** HTTP Basic Auth transmits credentials encoded in Base64, which is **not encryption**. In production, this must always be served over **HTTPS (TLS)** to prevent credential interception.

#### Screenshot

![Task 1 - Authentication](Task%201%20%E2%80%94%20Authentication%20a%20Password-Protected%20Service.png)

---

### Task 2: Multi-Factor Authentication (MFA / TOTP)

#### Concept

A password alone is a **single factor** — something you *know*. **Multi-Factor Authentication (MFA)** adds at least one additional factor. This task implements **TOTP (Time-Based One-Time Password)** per [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238), which generates a 6-digit code that is valid for only **30 seconds** using a shared secret and the current Unix timestamp.

The second factor is something you *have* (the shared secret / authenticator app), meaning an attacker who steals the password alone cannot authenticate.

#### Steps & Commands

**1. Install oathtool**

```bash
sudo apt-get install -y oathtool libpam-oath
```

**2. Generate a Base32 shared secret**

```bash
# Generate a random 20-byte secret and encode it as Base32
SECRET=$(head -c 20 /dev/urandom | base64 | tr -d '=' | head -c 32)
echo "Shared Secret: $SECRET"
```

**3. Generate a TOTP code on demand**

```bash
# Generate the current TOTP code (valid for ~30 seconds)
oathtool --base32 --totp "$SECRET"
```

**4. Simulate verification**

```bash
# Store secret for a user
echo "$SECRET" | sudo tee /etc/users.oath
sudo chmod 600 /etc/users.oath

# Validate a supplied OTP (replace 123456 with the live code)
oathtool --base32 --totp "$SECRET"
```

**5. Scan the secret as a QR code (optional — for authenticator app enrollment)**

```bash
sudo apt-get install -y qrencode
qrencode -t ANSI "otpauth://totp/LabUser?secret=$SECRET&issuer=IKB42603Lab" 
```

#### How TOTP Works

```
TOTP(secret, T) = HOTP(secret, floor(UnixTime / 30))
```

| Component | Description |
|-----------|-------------|
| `secret` | Shared Base32 key known to both server and authenticator. |
| `T` | Current Unix timestamp divided by the 30-second window. |
| `HOTP` | HMAC-SHA1 truncated to 6 digits. |

Because the code changes every 30 seconds and is derived from the current time, it is **replay-resistant** — a captured OTP is useless moments after it is used.

#### Attacks Defeated by MFA

| Attack Type | Defeated? | Reason |
|-------------|-----------|--------|
| Password spraying | ✅ | Second factor unknown to attacker |
| Credential stuffing | ✅ | Leaked password databases are insufficient |
| Phishing (password only) | ✅ | TOTP code expires before attacker can reuse it |
| Brute force | ✅ | 10⁶ space with 30-second window is impractical |

#### Screenshot

![Task 2 - MFA](Task%202%20%E2%80%94%20Add%20a%20Second%20Factor%20MFA%20and%20TOTP.png)

---

### Task 3: Authorization — Kubernetes RBAC Roles

#### Concept

**Authorization (AuthZ)** answers: *"What are you allowed to do?"* Authentication must succeed first; then, the system decides which resources and actions the authenticated identity may access. Kubernetes enforces this through **Role-Based Access Control (RBAC)**, which grants permissions to **ServiceAccounts** via **Roles** and **RoleBindings**.

#### Steps & Commands

**1. Create a local Kind cluster**

```bash
# Install Kind (Kubernetes IN Docker)
# https://kind.sigs.k8s.io/docs/user/quick-start/
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind

# Bootstrap a single-node cluster
kind create cluster --name lab4-cluster
```

**2. Create a dedicated Namespace**

```bash
kubectl create namespace app
```

**3. Create a ServiceAccount**

```bash
kubectl create serviceaccount dev-sa -n app
```

**4. Define a Role (least-privilege — Pods only)**

```yaml
# role-dev.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: app
  name: dev-role
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
```

```bash
kubectl apply -f role-dev.yaml
```

**5. Bind the Role to the ServiceAccount**

```yaml
# rolebinding-dev.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-rb
  namespace: app
subjects:
  - kind: ServiceAccount
    name: dev-sa
    namespace: app
roleRef:
  kind: Role
  apiRef: rbac.authorization.k8s.io
  name: dev-role
```

```bash
kubectl apply -f rolebinding-dev.yaml
```

**6. Verify permissions with `kubectl auth can-i`**

```bash
# Should return: yes
kubectl auth can-i get pods \
  --namespace app \
  --as system:serviceaccount:app:dev-sa

# Should return: no  (not granted)
kubectl auth can-i delete pods \
  --namespace app \
  --as system:serviceaccount:app:dev-sa

# Should return: no  (wrong namespace)
kubectl auth can-i get pods \
  --namespace default \
  --as system:serviceaccount:app:dev-sa
```

#### RBAC Architecture Summary

```
ServiceAccount (dev-sa)
        │
        └──[ RoleBinding: dev-rb ]──► Role (dev-role)
                                            │
                                            └── pods: get, list, watch
                                                (namespace: app only)
```

> **Principle of Least Privilege:** `dev-sa` can only read Pod objects within the `app` namespace. It cannot create, delete, or access any other resource or namespace — even within the same cluster.

#### Screenshot

![Task 3 - RBAC Roles](Task%203%20%E2%80%94%20Authorization%20RBAC%20Roles.png)

---

## Session B: Network Security & Hardening (Tasks 4–6)

### Task 4: Network Segmentation (Three-Tier Architecture)

#### Concept

Network segmentation divides infrastructure into isolated zones, limiting **lateral movement** — an attacker who compromises one tier cannot directly reach another tier's services if they reside on separate network segments. This mirrors the classic three-tier application model:

| Tier | Container | Network(s) | Role |
|------|-----------|------------|------|
| **Frontend** | `web` | `frontend-net` only | Serves public HTTP traffic |
| **Application** | `app` | `frontend-net` + `backend-net` | Business logic; bridges tiers |
| **Database** | `db` | `backend-net` only | Stores sensitive data |

#### Steps & Commands

**1. Create isolated Docker networks**

```bash
docker network create frontend-net
docker network create backend-net
```

**2. Start the three-tier containers**

```bash
# Web tier — exposed on port 8080, frontend-net only
docker run -d --name web \
  --network frontend-net \
  nginx:alpine

# App tier — bridges both networks
docker run -d --name app \
  --network frontend-net \
  alpine sleep infinity
docker network connect backend-net app

# DB tier — backend-net only, NOT reachable from frontend
docker run -d --name db \
  --network backend-net \
  alpine sleep infinity
```

**3. Verify isolation**

```bash
# From 'web' → 'db': BLOCKED (different network segment)
docker exec web ping -c 2 db
# Expected: ping: bad address 'db' (name not resolved — no shared network)

# From 'app' → 'db': REACHABLE (both on backend-net)
docker exec app ping -c 2 db
# Expected: 64 bytes from db ...
```

#### Segmentation Matrix

| Source → Destination | Network Path | Result |
|----------------------|--------------|--------|
| `web` → `app` | frontend-net | ✅ Reachable |
| `app` → `db` | backend-net | ✅ Reachable |
| `web` → `db` | No shared network | ❌ **BLOCKED** |

> **Security Impact:** If the `web` container is compromised (e.g., via a web application exploit), the attacker has no network path to `db`. The database tier is completely invisible from the frontend network.

#### Screenshot

![Task 4 - Network Segmentation](Task%204%20%E2%80%94%20Network%20Segmentation%20(Three-Tier).png)

---

### Task 5: Host Firewall Rules (Default-Deny via iptables)

#### Concept

A **default-deny** (also called *allowlist* or *whitelist*) firewall policy drops all traffic unless explicitly permitted. This is the opposite of a default-allow policy and directly implements the **Principle of Least Privilege** at the network layer.

In cloud environments, this maps directly to **Security Group** and **Network ACL** behaviour:

| Concept | On-Host | Cloud Equivalent |
|---------|---------|-----------------|
| Default-deny policy | `iptables -P INPUT DROP` | Security Group — implicit deny all |
| Explicit ACCEPT rule | `iptables -A INPUT -p tcp --dport 443 -j ACCEPT` | Security Group inbound rule: TCP 443 |
| Stateful tracking | `--state ESTABLISHED,RELATED` | Security Groups are stateful by default |

#### Steps & Commands

**1. Inspect the current iptables state**

```bash
sudo iptables -L -n -v
```

**2. Allow established/related connections (stateful allowance)**

```bash
sudo iptables -A INPUT -m state \
  --state ESTABLISHED,RELATED -j ACCEPT
```

**3. Allow loopback interface (required for local services)**

```bash
sudo iptables -A INPUT -i lo -j ACCEPT
```

**4. Explicitly allow HTTPS (port 443)**

```bash
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

**5. Set the default policy to DROP (activates default-deny)**

```bash
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
# OUTPUT is typically left as ACCEPT for outbound connections
```

**6. Verify the ruleset**

```bash
sudo iptables -L INPUT -n -v --line-numbers
```

Expected output:

```
Chain INPUT (policy DROP)
num  target  prot  opt  in   out  source     destination
1    ACCEPT  all   --   *    *    0.0.0.0/0  0.0.0.0/0   state RELATED,ESTABLISHED
2    ACCEPT  all   --   lo   *    0.0.0.0/0  0.0.0.0/0
3    ACCEPT  tcp   --   *    *    0.0.0.0/0  0.0.0.0/0   tcp dpt:443
```

**7. Save rules (persist across reboot)**

```bash
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```

> **Warning:** Always ensure SSH (port 22) is ACCEPTED before setting the default policy to DROP, otherwise you will lock yourself out of a remote machine. Add: `sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT` before step 5.

#### Screenshot

![Task 5 - Firewall Rules](Task%205%20%E2%80%94%20Firewall%20Rules%20(Default-Deny).png)

---

### Task 6: Container & Host Hardening

#### Concept

Container hardening reduces the **attack surface** of a running workload. Even if an attacker achieves code execution inside a container, hardening limits what they can do:

- **Drop Linux capabilities** — removes kernel-level privileges not needed by the application.
- **Read-only root filesystem** — prevents writing malicious files or persistent backdoors.
- **Non-root user** — limits damage to what UID 1000 can access.
- **No new privileges** — prevents privilege escalation via setuid binaries.
- **Trivy scanning** — proactively identifies known vulnerabilities in the image before deployment.

#### Steps & Commands — Hardened Container

```bash
docker run -d \
  --name hardened \
  --user 1000:1000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  nginx:alpine
```

#### Hardening Flags Explained

| Flag | Attack Surface Removed |
|------|------------------------|
| `--user 1000:1000` | Prevents root-level host damage if container is escaped. Files owned by root on the host remain inaccessible. |
| `--read-only` | Eliminates write-based persistence (dropping webshells, modifying binaries, writing cron jobs). |
| `--cap-drop ALL` | Removes all Linux capabilities (e.g., `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`). Container cannot reconfigure networking, load kernel modules, or escalate privileges. |
| `--security-opt no-new-privileges` | Blocks privilege escalation via setuid/setgid binaries and seccomp profile transitions. |
| `--tmpfs /tmp` | Provides a writable in-memory scratch space with `noexec` (cannot execute binaries from `/tmp`) and `nosuid` (no setuid allowed). |

#### Screenshot — Hardened Container

![Task 6 - Container Hardening](Task%206%20%E2%80%94%20Container%20or%20Host%20Hardening%20part%201.png)

---

#### Trivy Vulnerability Scanning

**Trivy** is an open-source, comprehensive vulnerability scanner for container images, filesystems, and IaC configurations.

**1. Install Trivy**

```bash
# Add Trivy APT repository
sudo apt-get install -y wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
  sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | \
  sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy
```

**2. Scan the target image**

```bash
# Scan nginx:alpine for HIGH and CRITICAL CVEs
trivy image --severity HIGH,CRITICAL nginx:alpine
```

**3. Generate a structured JSON report**

```bash
trivy image \
  --format json \
  --output trivy-report.json \
  nginx:alpine
```

**4. Scan a running container's filesystem**

```bash
trivy fs --security-checks vuln /
```

#### Interpreting Trivy Output

| Severity | Meaning | Action |
|----------|---------|--------|
| **CRITICAL** | Remote code execution or full system compromise possible | Patch immediately / replace base image |
| **HIGH** | Significant impact; often privilege escalation or data exposure | Patch within sprint cycle |
| **MEDIUM** | Limited impact; requires additional conditions | Schedule for next release |
| **LOW** | Minimal risk in typical configurations | Track and remediate opportunistically |

> **Best Practice:** Integrate Trivy into your CI/CD pipeline (e.g., GitHub Actions, GitLab CI) to **gate deployments** on image scan results. Use `--exit-code 1` to fail the build on CRITICAL findings.

#### Screenshot — Trivy Scan Results

![Task 6 - Trivy Scan](Task%206%20%E2%80%94%20Container%20or%20Host%20Hardening%20part%202.png)

---

## Verification Commands & Proof

### Kubernetes RoleBinding Verification

Inspect the full RoleBinding object to confirm the correct ServiceAccount, Role, and namespace bindings:

```bash
kubectl get rolebinding dev-rb -n app -o yaml
```

Expected output:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-rb
  namespace: app
subjects:
  - kind: ServiceAccount
    name: dev-sa
    namespace: app
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: dev-role
```

---

### Docker Container Hardening Verification

Confirm that **all Linux capabilities have been dropped** from the running container:

```bash
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'
```

Expected output:

```json
["ALL"]
```

Verify read-only filesystem and security options:

```bash
docker inspect hardened --format '{{json .HostConfig.ReadonlyRootfs}}'
# Expected: true

docker inspect hardened --format '{{json .HostConfig.SecurityOpt}}'
# Expected: ["no-new-privileges"]
```

Verify non-root user:

```bash
docker inspect hardened --format '{{json .Config.User}}'
# Expected: "1000:1000"
```

---

## Short-Answer Questions & Deliverables

### Q1: Explain the difference between Authentication and Authorization using Tasks 1 and 3.

**Authentication (AuthN)** is the process of *verifying identity* — confirming that the entity attempting access is who they claim to be. In **Task 1**, Nginx enforces HTTP Basic Authentication: the client must present a valid username and password. Until that verification succeeds, the server returns `401 Unauthorized` regardless of what resource is being requested. The server does not yet know *what* the user wants to do; it only cares about *who they are*.

**Authorization (AuthZ)** occurs *after* authentication and governs *what an authenticated identity is permitted to do*. In **Task 3**, Kubernetes RBAC assumes the identity of the ServiceAccount `dev-sa` is already established. The Role `dev-role` then defines the specific actions (verbs: `get`, `list`, `watch`) on specific resources (`pods`) within a specific namespace (`app`). Even though `dev-sa` is a valid, authenticated identity, it receives a `Forbidden` (403) response if it attempts to `delete` a pod or access a different namespace — because it is not *authorised* for those actions.

**In summary:** AuthN is the gate check ("show me your ID"), and AuthZ is the access policy behind the gate ("your ID lets you into room A but not room B").

---

### Q2: Why is MFA so effective, and which attacks does it defeat?

MFA is effective because it introduces **independent authentication factors** from different categories:

- **Something you know:** Password, PIN
- **Something you have:** TOTP code (authenticator app, hardware token)
- **Something you are:** Biometric (fingerprint, face scan)

An attacker must compromise *multiple independent channels simultaneously*, which is exponentially harder than compromising a single factor.

**Attacks defeated by TOTP-based MFA:**

| Attack | Why It Fails Against MFA |
|--------|--------------------------|
| **Credential stuffing** | Stolen password databases are useless without the rotating TOTP code. |
| **Password spraying** | Even a correct guessed password is rejected without the second factor. |
| **Phishing** | Real-time phishing proxies can capture TOTP codes, but they expire in ≤30 seconds, making reuse impractical in most scenarios. |
| **Brute force** | The 10⁶ TOTP keyspace combined with a 30-second expiry window makes brute force statistically infeasible. |
| **Password database breach** | Breached hashes, once cracked, still do not yield the TOTP secret (stored separately). |

**Remaining limitation:** Sophisticated real-time phishing attacks (adversary-in-the-middle proxies like Evilginx) can relay TOTP codes in real time. This is why **FIDO2/WebAuthn hardware keys** are considered phishing-resistant and preferred for high-assurance scenarios.

---

### Q3: How does network segmentation limit the damage of a compromised web server?

In the three-tier architecture established in Task 4, the `web` container is intentionally connected only to `frontend-net`. The `db` container exists exclusively on `backend-net`. There is **no shared network segment** between `web` and `db`.

If the `web` container is compromised (e.g., via a Remote Code Execution vulnerability in the web application), the attacker's blast radius is contained:

1. **No DNS resolution:** `db` is not discoverable from `frontend-net` — name resolution fails.
2. **No IP routing:** Docker's network isolation means packets from `frontend-net` cannot reach `backend-net` subnets.
3. **Lateral movement blocked:** The attacker cannot pivot from the web tier to the database tier without first compromising the `app` container (which bridges both networks).

The `app` container acts as a **controlled bridge** — it is the only entity permitted to communicate with both tiers, and it does so over a well-defined API surface. This mirrors the cloud security pattern of placing databases in **private subnets** with no internet gateway route, accessible only from application-tier security groups.

**Real-world analogy:** A compromised cashier terminal in a retail store can read payment card data presented to it, but cannot walk into the bank vault because there is no physical path connecting the checkout floor to the vault — even though both exist within the same building.

---

### Q4: What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?

A **default-deny policy** (`iptables -P INPUT DROP`) establishes that **all traffic is implicitly blocked unless a rule explicitly permits it**. This is fundamentally different from a default-allow policy, where traffic is permitted unless explicitly blocked.

**What it achieves:**

- Any port not explicitly opened is automatically closed — zero reliance on operators remembering to block specific ports.
- New services that start unexpectedly (malware, misconfigured daemons) are not automatically reachable from the network.
- Reduces the attack surface to exactly the set of explicitly approved communications.

**Relationship to cloud security groups:**

AWS Security Groups, Azure NSGs, and GCP Firewall Rules all implement a **stateful default-deny** model:
- Inbound traffic is **denied by default** — all inbound rules are allowlist entries.
- Outbound traffic is typically **allowed by default** (with options to restrict).
- Rules are stateful: an established outbound connection automatically allows the corresponding inbound response traffic.

The `iptables` implementation in Task 5 mirrors this exactly: the `ESTABLISHED,RELATED` rule provides stateful tracking equivalent to cloud security group stateful behaviour, and `--dport 443 -j ACCEPT` mirrors adding an inbound rule for port 443 in a cloud security group.

| iptables Rule | Cloud Security Group Equivalent |
|---------------|---------------------------------|
| `-P INPUT DROP` | Implicit deny (no rules = no access) |
| `-A INPUT --dport 443 -j ACCEPT` | Inbound rule: Protocol TCP, Port 443, Source 0.0.0.0/0 |
| `-m state --state ESTABLISHED,RELATED -j ACCEPT` | Stateful connection tracking (automatic in SGs) |

---

### Q5: List three hardening measures applied and the attack surface each one removes.

**Measure 1: `--cap-drop ALL` (Drop All Linux Capabilities)**

Linux capabilities divide the monolithic root privilege into discrete units. By dropping all capabilities, the container process loses the ability to:
- Reconfigure network interfaces (`CAP_NET_ADMIN`)
- Load or unload kernel modules (`CAP_SYS_MODULE`)
- Mount filesystems (`CAP_SYS_ADMIN`)
- Modify system time (`CAP_SYS_TIME`)
- Bypass file permission checks (`CAP_DAC_OVERRIDE`)

*Attack surface removed:* Kernel-level exploitation and container escape via capability abuse. An attacker with code execution inside the container cannot leverage these primitives to break out to the host.

---

**Measure 2: `--read-only` (Read-Only Root Filesystem)**

The container's root filesystem is mounted read-only. The process cannot write to any part of the filesystem except explicitly declared `--tmpfs` mounts.

*Attack surface removed:* Persistence mechanisms. Common post-exploitation techniques — dropping a webshell, modifying `/etc/cron.d`, replacing a binary with a backdoored version, writing to `/etc/ld.so.preload` — all require filesystem write access. A read-only filesystem makes these techniques impossible.

---

**Measure 3: `--user 1000:1000` (Non-Root User)**

The container process runs as UID/GID 1000 rather than UID 0 (root).

*Attack surface removed:* Privilege escalation and host damage via container escape. If a container escape vulnerability is exploited (e.g., a kernel CVE), the attacker's privileges on the host are limited to those of UID 1000 — a non-privileged user — rather than root. Additionally, files owned by root on the host remain inaccessible, Docker socket abuse is less impactful, and many post-exploitation tools that assume root access fail.

---

## Security Best-Practices Checklist

```
Session A: Access Control
```

- [x] HTTP Basic Authentication configured and enforced on Nginx
- [x] Password file stored outside web root with restricted permissions (`chmod 640`)
- [x] 401 Unauthorized confirmed for unauthenticated requests
- [x] 200 OK confirmed for authenticated requests
- [x] TOTP shared secret generated with cryptographically random source (`/dev/urandom`)
- [x] TOTP secret stored with restricted file permissions (`chmod 600`)
- [x] OTP verified as time-limited and non-replayable (30-second window)
- [x] Kubernetes Kind cluster created with isolated context
- [x] Dedicated namespace (`app`) created for workload isolation
- [x] ServiceAccount (`dev-sa`) created — no use of `default` ServiceAccount
- [x] Role defined with minimum required verbs only (`get`, `list`, `watch`)
- [x] RoleBinding scoped to a single namespace (not ClusterRoleBinding)
- [x] `kubectl auth can-i` verified both permitted and denied actions

```
Session B: Network Security & Hardening
```

- [x] Separate Docker networks created for frontend and backend tiers
- [x] Database container attached exclusively to `backend-net`
- [x] Web container confirmed unable to reach database container
- [x] Application container verified as the sole bridge between tiers
- [x] iptables default INPUT policy set to `DROP`
- [x] iptables default FORWARD policy set to `DROP`
- [x] Stateful `ESTABLISHED,RELATED` rule added before DROP policy
- [x] Loopback interface (`lo`) explicitly allowed
- [x] Only required port (443) explicitly permitted
- [x] Firewall rules persisted across reboot (`netfilter-persistent save`)
- [x] Container running as non-root user (`--user 1000:1000`)
- [x] Read-only root filesystem applied (`--read-only`)
- [x] All Linux capabilities dropped (`--cap-drop ALL`)
- [x] Privilege escalation blocked (`--security-opt no-new-privileges`)
- [x] Writable tmpfs with `noexec,nosuid` for scratch space
- [x] Trivy vulnerability scan performed on target image
- [x] CRITICAL and HIGH CVEs reviewed and documented

---

## Teardown & Cleanup Commands

Run the following commands to cleanly remove all lab artefacts and return the environment to its original state.

### 1. Remove Docker Containers

```bash
# Stop and remove all lab containers
docker stop web app db hardened 2>/dev/null || true
docker rm   web app db hardened 2>/dev/null || true
```

### 2. Remove Docker Networks

```bash
docker network rm frontend-net backend-net 2>/dev/null || true
```

### 3. Verify Docker Cleanup

```bash
# Confirm no lab containers remain
docker ps -a --filter name=web \
              --filter name=app \
              --filter name=db \
              --filter name=hardened

# Confirm networks removed
docker network ls
```

### 4. Delete Kind Kubernetes Cluster

```bash
kind delete cluster --name lab4-cluster
```

### 5. Flush iptables Rules (Restore Default-Allow)

```bash
# Flush all rules
sudo iptables -F
sudo iptables -X

# Reset default policies to ACCEPT
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Clear persisted rules if iptables-persistent is installed
sudo netfilter-persistent flush
```

### 6. Remove Nginx Auth Configuration

```bash
sudo rm -f /etc/nginx/.htpasswd
sudo systemctl reload nginx
```

### 7. Remove Trivy Reports

```bash
rm -f trivy-report.json
```

### 8. Full Cleanup Script

Save the following as `cleanup.sh` and run `bash cleanup.sh` for a one-shot teardown:

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "[*] Stopping and removing Docker containers..."
docker stop web app db hardened 2>/dev/null || true
docker rm   web app db hardened 2>/dev/null || true

echo "[*] Removing Docker networks..."
docker network rm frontend-net backend-net 2>/dev/null || true

echo "[*] Deleting Kind cluster..."
kind delete cluster --name lab4-cluster 2>/dev/null || true

echo "[*] Flushing iptables rules..."
sudo iptables -F
sudo iptables -X
sudo iptables -P INPUT   ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT  ACCEPT

echo "[*] Cleaning up Nginx auth..."
sudo rm -f /etc/nginx/.htpasswd
sudo systemctl reload nginx 2>/dev/null || true

echo "[*] Removing scan reports..."
rm -f trivy-report.json

echo "[+] Cleanup complete."
```

---

*This report was produced as part of a practical lab exercise for IKB42603 Cloud Computing Security Essentials. All configurations demonstrated are for educational purposes in an isolated lab environment.*
