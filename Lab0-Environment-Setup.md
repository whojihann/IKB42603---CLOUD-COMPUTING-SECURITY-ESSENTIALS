# 🖥️ Lab 0 — Environment Setup

---

| Field            | Details                            |
|------------------|------------------------------------|
| **Course Code**  | IKB42603                           |
| **Course Name**  | Cloud Security Engineering         |
| **Lab Title**    | Lab 0 — Environment Setup          |
| **Student Name** | Nurul Jihan Nabilah Binti Azlan    |
| **Platform**     | Kali Linux                         |
| **Date**         | August 1, 2026                     |

---

## 📑 Table of Contents

1. [Objective](#1-objective)
2. [Prerequisites](#2-prerequisites)
3. [Step 1 — Verify Docker Installation](#3-step-1--verify-docker-installation)
4. [Step 2 — Verify AWS CLI Installation](#4-step-2--verify-aws-cli-installation)
5. [Step 3 — Verify kind & kubectl Installation](#5-step-3--verify-kind--kubectl-installation)
6. [Step 4 — Verify Helper Tools](#6-step-4--verify-helper-tools)
7. [Step 5 — Run LocalStack Container & Health Check](#7-step-5--run-localstack-container--health-check)
8. [Step 6 — Start, Stop & Remove LocalStack](#8-step-6--start-stop--remove-localstack)
9. [Step 7 — Create Kubernetes Cluster with kind](#9-step-7--create-kubernetes-cluster-with-kind)
10. [Step 8 — Verify Kubernetes Nodes](#10-step-8--verify-kubernetes-nodes)
11. [Step 9 — One-Time AWS CLI Configuration for LocalStack](#11-step-9--one-time-aws-cli-configuration-for-localstack)
12. [Verification Checklist](#12-verification-checklist)
13. [Summary](#13-summary)

---

## 1. Objective

The goal of this lab is to set up and verify a **local cloud security development environment** on Kali Linux. By the end of this lab, all the following core tools must be installed, running, and verified:

- **Docker** — container engine used to run LocalStack
- **AWS CLI** — command-line interface for interacting with AWS services (local & cloud)
- **kind** — Kubernetes-in-Docker, used to spin up local K8s clusters
- **kubectl** — Kubernetes CLI for cluster management
- **LocalStack** — a fully functional local AWS cloud stack for offline development & testing
- **Helper Tools** — `openssl` and `oathtool` for cryptographic and MFA operations

---

## 2. Prerequisites

Before starting, ensure the following are available on your system:

- Kali Linux (or any Debian-based distro)
- Internet connection for pulling Docker images
- `sudo` / root privileges
- Terminal access

**Tools verified in this lab:**

| Tool        | Expected Version        |
|-------------|------------------------|
| Docker      | 28.5.2+dfsg4           |
| AWS CLI     | 2.36.10                |
| kind        | 0.23.0                 |
| kubectl     | v1.36.3                |
| OpenSSL     | 3.6.2                  |
| oathtool    | 2.6.14                 |
| LocalStack  | 3.0.0 (community)      |
| Kubernetes  | v1.30.0 (node)         |

---

## 3. Step 1 — Verify Docker Installation

Docker is the container runtime used to run LocalStack and other containerised services throughout the course.

**Command:**

```bash
docker --version
```

**Expected Output:**

```
Docker version 28.5.2+dfsg4, build 9cc6dea35e9a963f281434761c656fba4ac43aed
```

**Evidence:**

![Step 1 — Docker Version](./Lab0-Environment-Setup/1.%20docker.png)

> 💡 **Tip:** If Docker is not installed, run `sudo apt install docker.io -y` and then `sudo systemctl enable --now docker`.

---

## 4. Step 2 — Verify AWS CLI Installation

The AWS CLI is used to interact with both real AWS services and the LocalStack emulator using the same commands.

**Command:**

```bash
aws --version
```

**Expected Output:**

```
aws-cli/2.36.10 Python/3.14.6 Linux/6.19.14+kali-amd64 exe/x86_64.kali.2026
```

**Evidence:**

![Step 2 — AWS CLI Version](./Lab0-Environment-Setup/2.awscli.png)

> 💡 **Tip:** AWS CLI v2 is required. Install via the official AWS installer if not present:
> ```bash
> curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
> unzip awscliv2.zip && sudo ./aws/install
> ```

---

## 5. Step 3 — Verify kind & kubectl Installation

**kind** (Kubernetes in Docker) is used to create local Kubernetes clusters. **kubectl** is the CLI tool to manage those clusters.

**Commands:**

```bash
kind --version
kubectl version --client
```

**Expected Output:**

```
kind version 0.23.0

Client Version: v1.36.3
Kustomize Version: v5.8.1
```

**Evidence:**

![Step 3 — kind and kubectl Versions](./Lab0-Environment-Setup/3.kind-kubectl.png)

> 💡 **Tip:** Install kind via:
> ```bash
> go install sigs.k8s.io/kind@v0.23.0
> ```
> Install kubectl via:
> ```bash
> sudo apt install kubectl -y
> ```

---

## 6. Step 4 — Verify Helper Tools

Two helper tools are required for cryptographic operations and MFA token generation used in later labs.

### 4.1 — OpenSSL

```bash
openssl version
```

**Expected Output:**

```
OpenSSL 3.6.2 7 Apr 2026 (Library: OpenSSL 3.6.2 7 Apr 2026)
```

### 4.2 — oathtool (OATH Toolkit)

```bash
oathtool --version
```

**Expected Output:**

```
oathtool (OATH Toolkit) 2.6.14
Copyright (C) 2009-2026 Simon Josefsson.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
```

**Evidence:**

![Step 4 — Helper Tools: OpenSSL and oathtool](./Lab0-Environment-Setup/4.Helper_Tools.png)

> 💡 **Tip:** Install oathtool via `sudo apt install oathtool -y` if missing.

---

## 7. Step 5 — Run LocalStack Container & Health Check

LocalStack provides a fully functional local AWS cloud stack. It is deployed as a Docker container and exposes all AWS-compatible API endpoints on port `4566`.

### 5.1 — Start the LocalStack Container

```bash
docker run -d --name localstack -p 4566:4566 localstack/localstack:3.0.0
```

> ⚠️ **Note:** The `-d` flag runs the container in detached (background) mode. Port `4566` is the unified LocalStack gateway endpoint.

### 5.2 — Confirm Container is Running

```bash
docker ps
```

**Expected Output (truncated):**

```
CONTAINER ID   IMAGE                       COMMAND                  CREATED         STATUS
6a67bb06db18   localstack/localstack:3.0.0 "docker-entrypoint.sh"  12 seconds ago  Up 11 seconds (health: starting)
PORTS: 4510-4559/tcp, 5678/tcp, 0.0.0.0:4566->4566/tcp   NAMES: localstack
```

### 5.3 — Health Check via curl

```bash
curl http://localhost:4566/_localstack/health
```

**Expected Output (key fields):**

```json
{
  "services": {
    "acm": "available",
    "apigateway": "available",
    "cloudformation": "available",
    "cloudwatch": "available",
    "dynamodb": "available",
    "ec2": "available",
    "iam": "available",
    "lambda": "available",
    "s3": "available",
    "sns": "available",
    "sqs": "available",
    "ssm": "available",
    "sts": "available"
  },
  "edition": "community",
  "version": "3.0.0"
}
```

**Evidence:**

![Step 5 — LocalStack Running and Health Check](./Lab0-Environment-Setup/5.LocalStack_Container_Running_%26_Health_Check.png)

> ✅ All services showing `"available"` confirms LocalStack is fully operational.

---

## 8. Step 6 — Start, Stop & Remove LocalStack

These are the day-to-day lifecycle commands for managing the LocalStack container.

### Stop the Container

```bash
docker stop localstack
```

### Start the Container Again

```bash
docker start localstack
```

### Remove the Container (Force)

```bash
docker rm -f localstack
```

**Evidence:**

![Step 6 — Start, Stop and Remove LocalStack](./Lab0-Environment-Setup/6.Start_%26_Stop_Local_Environment.png)

> ⚠️ **Note:** `docker rm -f localstack` will **destroy** the container and all its state. Use `stop` / `start` to preserve the container between sessions.

---

## 9. Step 7 — Create Kubernetes Cluster with kind

A local Kubernetes cluster named **ccse** is created using kind. This cluster will be used in subsequent labs for deploying containerised workloads.

### 7.1 — Create the Cluster

```bash
kind create cluster --name ccse
```

**Expected Output:**

```
Creating cluster "ccse" ...
 ✓ Ensuring node image (kindest/node:v1.30.0) 🖼
 ✓ Preparing nodes 📦
 ✓ Writing configuration 📜
 ✓ Starting control-plane 🕹
 ✓ Installing CNI 🔌
 ✓ Installing StorageClass 💾
Set kubectl context to "kind-ccse"
You can now use your cluster with:

kubectl cluster-info --context kind-ccse
```

### 7.2 — Verify Cluster Info

```bash
kubectl cluster-info --context kind-ccse
```

**Expected Output:**

```
Kubernetes control plane is running at https://127.0.0.1:36537
CoreDNS is running at https://127.0.0.1:36537/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
```

**Evidence:**

![Step 7 — Create Kubernetes Cluster with kind](./Lab0-Environment-Setup/7.Kubenetes.png)

> 💡 **Tip:** The context `kind-ccse` is automatically set. You can verify the active context anytime with `kubectl config current-context`.

---

## 10. Step 8 — Verify Kubernetes Nodes

After the cluster is up, confirm that the control-plane node is in a `Ready` state.

**Command:**

```bash
kubectl get nodes
```

**Expected Output:**

```
NAME                 STATUS   ROLES           AGE     VERSION
ccse-control-plane   Ready    control-plane   4m58s   v1.30.0
```

**Evidence:**

![Step 8 — kubectl get nodes](./Lab0-Environment-Setup/8.Kubenetes%202.0.png)

> ✅ `STATUS: Ready` confirms the Kubernetes control-plane node is healthy and accepting workloads.

---

## 11. Step 9 — One-Time AWS CLI Configuration for LocalStack

AWS CLI must be configured with dummy credentials and pointed to the LocalStack endpoint for all local AWS operations. This is a **one-time setup**.

### 9.1 — Configure Dummy Credentials

```bash
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1
```

> ⚠️ **Note:** LocalStack does not validate real AWS credentials. The values `test` / `test` are conventional placeholders used with LocalStack Community edition.

### 9.2 — Set the LocalStack Endpoint Variable

```bash
EP='--endpoint-url=http://localhost:4566'
```

> 💡 **Tip:** Setting `EP` as a shell variable saves you from typing `--endpoint-url=http://localhost:4566` with every AWS CLI command.

### 9.3 — Verify with STS get-caller-identity

```bash
aws $EP sts get-caller-identity
```

**Expected Output:**

```json
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

**Evidence:**

![Step 9 — One-Time AWS CLI Configuration](./Lab0-Environment-Setup/9.one_time_AWS_CLI.png)

> ✅ A valid JSON response from `sts get-caller-identity` confirms AWS CLI is correctly talking to the LocalStack endpoint.

---

## 12. Verification Checklist

Use this checklist to confirm every component of the lab environment is correctly set up before proceeding to Lab 1.

| #  | Component                        | Command                                        | Status |
|----|----------------------------------|------------------------------------------------|--------|
| 1  | Docker installed                 | `docker --version`                             | ✅     |
| 2  | AWS CLI v2 installed             | `aws --version`                                | ✅     |
| 3  | kind installed                   | `kind --version`                               | ✅     |
| 4  | kubectl installed                | `kubectl version --client`                     | ✅     |
| 5  | OpenSSL installed                | `openssl version`                              | ✅     |
| 6  | oathtool installed               | `oathtool --version`                           | ✅     |
| 7  | LocalStack container running     | `docker ps`                                    | ✅     |
| 8  | LocalStack health check passes   | `curl http://localhost:4566/_localstack/health`| ✅     |
| 9  | Kubernetes cluster created       | `kind create cluster --name ccse`              | ✅     |
| 10 | Kubernetes node Ready            | `kubectl get nodes`                            | ✅     |
| 11 | AWS CLI configured for LocalStack| `aws configure set ...`                        | ✅     |
| 12 | STS identity verified            | `aws $EP sts get-caller-identity`              | ✅     |

---

## 13. Summary

Lab 0 successfully established a complete **local cloud security development environment** on Kali Linux. All required tools — Docker, AWS CLI v2, kind, kubectl, OpenSSL, and oathtool — were installed and version-verified. LocalStack `3.0.0 (community)` was deployed as a Docker container with all AWS services reporting `available`. A local Kubernetes cluster named `ccse` was provisioned using kind, with the control-plane node confirmed `Ready` on Kubernetes `v1.30.0`. Finally, the AWS CLI was configured with dummy credentials and validated against the LocalStack endpoint using `sts get-caller-identity`.

The environment is fully operational and ready for subsequent labs in **IKB42603 — Cloud Security Engineering**.

---

*Report generated from lab evidence screenshots — IKB42603 Lab 0, August 2026.*
