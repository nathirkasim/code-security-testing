# TigerGate Code Security Clean Baseline Repository

This repository serves as a baseline, zero-finding test suite for **TigerGate Code Security**. It contains realistic, production-ready source code and infrastructure configurations across multiple programming languages and environments, strictly adhering to secure coding guidelines and industry standards.

When scanned by TigerGate Code Security, this repository should produce **ZERO security findings** across SAST, SCA, Secrets Detection, IaC Security, and Container Security scanners.

---

## Repository Structure & Covered Ecosystems

```
clean-repo/
├── README.md                           # Repository documentation
├── .gitignore                          # Excluded files and secret preventions
├── .github/
│   └── workflows/
│       └── ci.yml                      # Secure GitHub Actions workflow
├── config/
│   └── app-config.json                 # Secure application JSON configuration
├── k8s/
│   └── deployment.yaml                 # Secure Kubernetes manifest
├── docker/
│   └── Dockerfile                      # Hardened container image build
├── terraform/
│   ├── main.tf                         # Secure Terraform AWS infrastructure
│   ├── variables.tf                    # Variable definitions with validation
│   └── outputs.tf                      # Infrastructure outputs
├── python/
│   ├── pyproject.toml                  # Python project metadata
│   ├── requirements.txt                # SCA-verified Python dependencies
│   └── app/
│       ├── __init__.py
│       ├── main.py                     # Safe FastAPI REST API
│       └── security_utils.py           # Secure password hashing & path validation
├── nodejs/
│   ├── package.json                    # Clean Node.js dependencies
│   └── src/
│       ├── server.js                   # Safe Express server with Helmet & CORS
│       └── authService.ts              # Typed TypeScript secure token service
├── java/
│   ├── pom.xml                         # Maven dependencies (up-to-date, secure)
│   └── src/
│       └── main/
│           └── java/
│               └── com/
│                   └── example/
│                       └── cleanrepo/
│                           ├── CleanRepoApplication.java  # Spring Boot entry point
│                           ├── UserService.java           # Parameterized DB access
│                           └── XmlParserUtil.java         # XXE-hardened XML parser
└── go/
    ├── go.mod                          # Go module definition
    ├── main.go                         # Safe Go HTTP service & TLS config
    └── utils/
        └── secure_storage.go           # Safe filepath handling & crypto/rand
```

---

## Security Practices Implemented

### 1. Static Application Security Testing (SAST)
- **Parameterized SQL Queries**: Implemented in Python (SQLite/SQLAlchemy placeholders), JavaScript (prepared statements), Java (`PreparedStatement`), and Go (`db.QueryContext`). Eliminates SQL injection (CWE-89).
- **Cross-Site Scripting (XSS) Prevention**: All web responses return structured JSON with appropriate content-type headers (`application/json`) and secure HTTP headers (`Helmet` in Node.js, security headers in Python/Go/Spring Boot).
- **Path Traversal Defense**: All file access in Python and Go performs strict canonical path resolution (`pathlib.Path.resolve()`, `filepath.Clean()`) and verifies that targets remain bounded inside designated root directories.
- **XXE Prevention**: Java XML parsing uses `DocumentBuilderFactory` with `http://apache.org/xml/features/disallow-doctype-decl` set to `true`, preventing XML External Entity attacks.
- **Safe Cryptography**: Utilizes Argon2id / BCrypt for password hashing and AES-256-GCM / SHA-256 / `crypto/rand` / Python `secrets` for cryptographic operations. Obsolete algorithms (MD5, SHA1, DES) are avoided.

### 2. Infrastructure as Code (IaC) Security
- **AWS S3 Bucket Hardening**: Includes server-side encryption with KMS, explicit `aws_s3_bucket_public_access_block` enabling all 4 block settings, versioning enabled, and logging configured.
- **Least-Privilege IAM**: IAM roles follow principle of least privilege, targeting specific AWS ARNs and action sets without wildcard permissions.
- **Restricted Security Groups**: Ingress rules restrict traffic strictly to safe ports/sources, preventing public access to SSH or database ports.

### 3. Container Security (Dockerfile & K8s)
- **Non-Root Execution**: Container runs under a low-privilege `appuser` user and group.
- **Multi-Stage Build**: Keeps image footprint minimal and removes build-time toolchains.
- **Kubernetes Security Context**: Enforces `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, and drops all Linux capabilities (`drop: ["ALL"]`).

### 4. Secret Detection Baseline
- Zero hardcoded passwords, tokens, API keys, certificates, or private key blocks.
- Uses standard environment variables for configuration inputs.

### 5. Software Composition Analysis (SCA)
- All package manifests (`requirements.txt`, `package.json`, `pom.xml`, `go.mod`) specify secure, well-maintained, up-to-date dependency versions without known vulnerabilities.
