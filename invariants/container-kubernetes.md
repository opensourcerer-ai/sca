# Container and Kubernetes Security Invariants (v1)

## Overview

This file defines security invariants for container and Kubernetes security aligned with:
- **NIST SP 800-190**: Application Container Security Guide
- **CIS Kubernetes Benchmark**: v1.8.0
- **NSA/CISA**: Kubernetes Hardening Guidance
- **Kubernetes Pod Security Standards**: Restricted, Baseline, Privileged
- **OWASP Kubernetes Top 10**: K01-K10
- **NIST SP 800-53 Rev 5**: CM-7, SC-39, AC-6, SC-2

**SCA Identifier Range**: SCA-850 to SCA-899 (Infrastructure and deployment)

---

## CRITICAL: Running Container as Root (SCA-851, CIS 5.2.2)

**Standard**: SCA-851, CIS Docker Benchmark 5.2.2, NIST SP 800-190, OWASP K03

**Finding**: Containers running with root user (UID 0) instead of non-root user

**Detection Patterns**:

### Dockerfile
```dockerfile
# CRITICAL: No USER directive - defaults to root
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y nginx

# CRITICAL: Running as root (UID 0)
CMD ["nginx", "-g", "daemon off;"]
```

### Kubernetes Pod
```yaml
# CRITICAL: No securityContext specified
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx:latest
    # Missing: securityContext.runAsNonRoot
```

**Risks**:
- Container breakout gains root on host
- Easier privilege escalation
- Full filesystem access if volumes mounted
- Can bind to privileged ports (<1024)

**Remediation**:

### Dockerfile - Create Non-Root User
```dockerfile
# GOOD: Run as non-root user
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y nginx

# Create non-root user
RUN useradd -r -u 1000 -g nginx nginx

# Change ownership of necessary directories
RUN chown -R nginx:nginx /var/log/nginx /var/lib/nginx

# Switch to non-root user
USER 1000

# Nginx needs to listen on port > 1024
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
```

### Kubernetes Pod Security Context
```yaml
# GOOD: Enforce non-root user
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  securityContext:
    runAsNonRoot: true    # CRITICAL: Enforce non-root
    runAsUser: 1000       # Specific UID
    runAsGroup: 1000      # Specific GID
    fsGroup: 1000         # Volume ownership

  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
```

**NIST Controls**: AC-6 - Least Privilege, SC-39 - Process Isolation

---

## CRITICAL: Privileged Container (SCA-852, CIS 5.2.5)

**Standard**: SCA-852, CIS Docker Benchmark 5.2.5, NIST SP 800-190, OWASP K03

**Finding**: Container running in privileged mode with full host access

**Detection Patterns**:

### Docker Run
```bash
# CRITICAL: Privileged mode
docker run --privileged -it ubuntu bash

# Container has full access to host devices and can:
# - Load kernel modules
# - Access all devices
# - Bypass seccomp, AppArmor, SELinux
# - Mount filesystems
```

### Kubernetes Pod
```yaml
# CRITICAL: Privileged container
apiVersion: v1
kind: Pod
metadata:
  name: debug-pod
spec:
  containers:
  - name: debug
    image: ubuntu
    securityContext:
      privileged: true  # CRITICAL: Full host access
```

**Remediation**:

```yaml
# GOOD: Use capabilities instead of privileged
apiVersion: v1
kind: Pod
metadata:
  name: network-pod
spec:
  containers:
  - name: network-tool
    image: nicolaka/netshoot
    securityContext:
      # NOT privileged
      privileged: false

      # Only add specific capabilities needed
      capabilities:
        add:
        - NET_ADMIN      # For network operations
        - NET_RAW        # For raw sockets
        drop:
        - ALL           # Drop all others
```

**NIST Controls**: AC-6 - Least Privilege, CM-7 - Least Functionality

---

## CRITICAL: Host Path Mounts (SCA-853, CIS 5.2.1)

**Standard**: SCA-853, CIS Docker Benchmark 5.2.1, NIST SP 800-190, OWASP K04

**Finding**: Mounting sensitive host paths into containers

**Detection Patterns**:

### Docker Compose
```yaml
# CRITICAL: Mounting entire root filesystem
services:
  app:
    image: myapp
    volumes:
      - /:/host  # CRITICAL: Entire host filesystem

# CRITICAL: Mounting Docker socket
services:
  app:
    image: myapp
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # CRITICAL: Docker API access
```

### Kubernetes
```yaml
# CRITICAL: Mounting sensitive host paths
apiVersion: v1
kind: Pod
metadata:
  name: dangerous-pod
spec:
  containers:
  - name: app
    image: myapp
    volumeMounts:
    - name: host-root
      mountPath: /host
    - name: docker-sock
      mountPath: /var/run/docker.sock

  volumes:
  - name: host-root
    hostPath:
      path: /                # CRITICAL: Entire host
      type: Directory
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock  # CRITICAL: Docker socket
```

**Dangerous Host Paths**:
- `/`: Entire filesystem
- `/var/run/docker.sock`: Docker API (container escape)
- `/etc`: System configuration
- `/proc`: Process information
- `/sys`: System information
- `/dev`: Devices
- `/boot`: Boot files
- `/root`: Root home directory

**Remediation**:

```yaml
# GOOD: Use specific paths with read-only when possible
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  containers:
  - name: app
    image: myapp
    volumeMounts:
    # Only mount specific needed directory
    - name: config
      mountPath: /etc/app/config
      readOnly: true  # Read-only mount

    # Use PersistentVolumes instead of hostPath
    - name: data
      mountPath: /var/app/data

  volumes:
  - name: config
    hostPath:
      path: /opt/app/config  # Specific path only
      type: Directory

  - name: data
    persistentVolumeClaim:
      claimName: app-data-pvc  # Use PVC, not hostPath

---
# Block hostPath in Pod Security Policy
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  # Prevent hostPath volumes
  volumes:
  - 'configMap'
  - 'emptyDir'
  - 'projected'
  - 'secret'
  - 'downwardAPI'
  - 'persistentVolumeClaim'
  # hostPath NOT in list
```

**NIST Controls**: AC-6 - Least Privilege, SC-39 - Process Isolation

---

## HIGH: Excessive Capabilities (SCA-854, CIS 5.2.7)

**Standard**: SCA-854, CIS Docker Benchmark 5.2.7, NIST SP 800-190

**Finding**: Containers with unnecessary Linux capabilities

**Linux Capabilities** (subset):
- **CAP_SYS_ADMIN**: Mount filesystems, system admin operations
- **CAP_NET_ADMIN**: Network administration
- **CAP_SYS_MODULE**: Load kernel modules
- **CAP_SYS_PTRACE**: Trace processes
- **CAP_DAC_OVERRIDE**: Bypass file permissions
- **CAP_CHOWN**: Change file ownership

**Detection Patterns**:

```yaml
# HIGH: Granting all capabilities
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: myapp
    securityContext:
      capabilities:
        add:
        - ALL  # CRITICAL: All capabilities
```

**Remediation**:

```yaml
# GOOD: Drop all, add only what's needed
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: myapp
    securityContext:
      capabilities:
        drop:
        - ALL          # Drop all capabilities
        add:
        - NET_BIND_SERVICE  # Only add what's needed (bind to port <1024)

---
# For network troubleshooting
apiVersion: v1
kind: Pod
metadata:
  name: netshoot
spec:
  containers:
  - name: netshoot
    image: nicolaka/netshoot
    securityContext:
      capabilities:
        drop:
        - ALL
        add:
        - NET_ADMIN  # Network troubleshooting
        - NET_RAW    # Ping, traceroute
```

**NIST Controls**: CM-7 - Least Functionality

---

## HIGH: Missing Security Policies (SCA-855, NSA/CISA)

**Standard**: SCA-855, NSA/CISA Kubernetes Hardening, Pod Security Standards

**Finding**: No seccomp, AppArmor, or SELinux profiles applied

**Detection Patterns**:

```yaml
# HIGH: No security policies
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: myapp
    # Missing: securityContext with security policies
```

**Remediation**:

### Seccomp (Secure Computing Mode)
```yaml
# GOOD: Apply seccomp profile
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault  # Use container runtime default profile

  containers:
  - name: app
    image: myapp
    securityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: profiles/audit.json  # Custom profile
```

### AppArmor
```yaml
# GOOD: Apply AppArmor profile
apiVersion: v1
kind: Pod
metadata:
  name: app
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: runtime/default
spec:
  containers:
  - name: app
    image: myapp
```

### SELinux
```yaml
# GOOD: Apply SELinux context
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  securityContext:
    seLinuxOptions:
      level: "s0:c123,c456"
      role: "system_r"
      type: "container_t"
      user: "system_u"

  containers:
  - name: app
    image: myapp
```

**NIST Controls**: SC-39 - Process Isolation, CM-7 - Least Functionality

---

## HIGH: Secrets in Container Images (SCA-856, OWASP K05)

**Standard**: SCA-856, OWASP Kubernetes K05, NIST SP 800-190

**Finding**: Hardcoded secrets in Dockerfiles or container images

**Detection Patterns**:

### Dockerfile
```dockerfile
# CRITICAL: Hardcoded credentials
FROM ubuntu:22.04

ENV DATABASE_PASSWORD=SuperSecret123  # CRITICAL
ENV API_KEY=sk_live_abc123xyz         # CRITICAL

COPY private_key.pem /app/            # CRITICAL: Private key in image

RUN echo "password123" > /etc/db.conf  # CRITICAL
```

### Build Arguments (Leaked in Image History)
```dockerfile
# HIGH: Build args are visible in image history
ARG DATABASE_PASSWORD
RUN echo "DB_PASSWORD=${DATABASE_PASSWORD}" >> /app/config.sh
# docker history shows this!
```

**Remediation**:

### Use Kubernetes Secrets
```yaml
# GOOD: Use Kubernetes secrets
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
stringData:
  database-password: "SuperSecret123"
  api-key: "sk_live_abc123xyz"

---
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: myapp
    env:
    # Inject secrets from Secret object
    - name: DATABASE_PASSWORD
      valueFrom:
        secretKeyRef:
          name: app-secrets
          key: database-password

    - name: API_KEY
      valueFrom:
        secretKeyRef:
          name: app-secrets
          key: api-key

---
# Or mount as files
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: myapp
    volumeMounts:
    - name: secrets
      mountPath: /etc/secrets
      readOnly: true

  volumes:
  - name: secrets
    secret:
      secretName: app-secrets
```

### Multi-stage Build to Remove Secrets
```dockerfile
# GOOD: Multi-stage build
FROM ubuntu:22.04 AS builder

# Use secret mount (not in final image)
RUN --mount=type=secret,id=github_token \
    export GITHUB_TOKEN=$(cat /run/secrets/github_token) && \
    git clone https://github.com/private/repo

# Build stage
RUN make build

# Final image - secrets not included
FROM ubuntu:22.04
COPY --from=builder /app/build /app/
USER 1000
CMD ["/app/server"]
```

**NIST Controls**: SC-28 - Protection of Information at Rest, IA-5(7) - No embedded authenticators

---

## HIGH: Missing Network Policies (SCA-857, CIS 5.3.2)

**Standard**: SCA-857, CIS Kubernetes Benchmark 5.3.2, OWASP K06

**Finding**: No network policies restricting pod-to-pod traffic

**Detection**: Look for absence of NetworkPolicy resources

**Default Behavior**: Without NetworkPolicy, all pods can communicate with all pods

**Remediation**:

```yaml
# GOOD: Default deny all ingress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}  # Applies to all pods in namespace
  policyTypes:
  - Ingress

---
# GOOD: Allow specific traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend

  policyTypes:
  - Ingress

  ingress:
  # Allow from frontend pods only
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080

---
# GOOD: Egress restrictions
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend

  policyTypes:
  - Egress

  egress:
  # Allow DNS
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53

  # Allow to database
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
```

**NIST Controls**: SC-7 - Boundary Protection, AC-4 - Information Flow Enforcement

---

## HIGH: Overly Permissive RBAC (SCA-858, CIS 5.1.5)

**Standard**: SCA-858, CIS Kubernetes Benchmark 5.1.5, OWASP K07

**Finding**: Service accounts with excessive Kubernetes API permissions

**Detection Patterns**:

```yaml
# CRITICAL: Cluster admin to all service accounts
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin  # CRITICAL: Full cluster access
subjects:
- kind: Group
  name: system:serviceaccounts  # CRITICAL: All service accounts
  apiGroup: rbac.authorization.k8s.io

---
# HIGH: Wildcard permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dangerous-role
rules:
- apiGroups: ["*"]        # CRITICAL: All API groups
  resources: ["*"]        # CRITICAL: All resources
  verbs: ["*"]            # CRITICAL: All operations
```

**Remediation**:

```yaml
# GOOD: Least privilege RBAC
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: production

---
# GOOD: Specific permissions only
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
# Only read ConfigMaps
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]

# Only read Secrets (specific ones)
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["app-secrets"]  # Specific secret only
  verbs: ["get"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-rolebinding
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: app-role
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: production

---
# GOOD: Use pod with service account
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: production
spec:
  serviceAccountName: app-sa
  automountServiceAccountToken: false  # Don't auto-mount if not needed

  containers:
  - name: app
    image: myapp
```

**Audit RBAC**:
```bash
# Check who has cluster-admin
kubectl get clusterrolebindings -o json | \
  jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name'

# Check for wildcard permissions
kubectl get roles,clusterroles -A -o json | \
  jq -r '.items[] | select(.rules[]? | .verbs[]? == "*") | .metadata.name'
```

**NIST Controls**: AC-6 - Least Privilege, AC-3 - Access Enforcement

---

## MEDIUM: Missing Resource Limits (SCA-859, CIS 5.2.11)

**Standard**: SCA-859, CIS Kubernetes Benchmark 5.2.11, NIST SP 800-190

**Finding**: Containers without CPU/memory limits allowing resource exhaustion

**Detection Patterns**:

```yaml
# MEDIUM: No resource limits
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: myapp
    # Missing: resources.limits
```

**Remediation**:

```yaml
# GOOD: Set resource limits
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: myapp
    resources:
      requests:
        memory: "128Mi"
        cpu: "100m"
      limits:
        memory: "256Mi"  # Hard limit
        cpu: "500m"      # Hard limit

---
# GOOD: Enforce with LimitRange
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: production
spec:
  limits:
  - default:
      memory: 512Mi
      cpu: 500m
    defaultRequest:
      memory: 256Mi
      cpu: 100m
    type: Container

---
# GOOD: Enforce with ResourceQuota
apiVersion: v1
kind: ResourceQuota
metadata:
  name: namespace-quota
  namespace: production
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
```

**NIST Controls**: SC-5 - Denial of Service Protection

---

## MEDIUM: Insecure Container Registry (SCA-860, NIST SP 800-190)

**Standard**: SCA-860, NIST SP 800-190, OWASP K05

**Finding**: Pulling images from untrusted registries without verification

**Detection Patterns**:

```yaml
# MEDIUM: Public registry without digest pinning
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: nginx:latest  # CRITICAL: Mutable tag, not digest-pinned
```

**Remediation**:

```yaml
# GOOD: Use digest pinning
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    # Pin to specific digest (immutable)
    image: nginx@sha256:ab123def456...

    # Or use private registry with specific tag
    image: registry.company.com/nginx:1.25.3

---
# GOOD: Use ImagePullPolicy
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always  # Always pull to get latest security patches

  # Use imagePullSecrets for private registry
  imagePullSecrets:
  - name: registry-credentials

---
# GOOD: Enforce with admission controller
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: image-policy
webhooks:
- name: image-policy.company.com
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  failurePolicy: Fail
  # Webhook validates:
  # 1. Image comes from approved registry
  # 2. Image digest is pinned
  # 3. Image has been scanned for vulnerabilities
```

**NIST Controls**: SA-12 - Supply Chain Protection, SI-7 - Software Integrity

---

## MEDIUM: Pod Security Standards Not Enforced (SCA-861, K8s PSS)

**Standard**: SCA-861, Kubernetes Pod Security Standards, NSA/CISA

**Finding**: Cluster not enforcing Pod Security Standards

**Pod Security Standards**:
- **Privileged**: Unrestricted (allow all)
- **Baseline**: Minimally restrictive (prevent known privilege escalations)
- **Restricted**: Heavily restricted (hardening best practices)

**Remediation**:

```yaml
# GOOD: Enable Pod Security Standards at namespace level
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    # Enforce restricted policy
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest

    # Audit baseline violations
    pod-security.kubernetes.io/audit: baseline
    pod-security.kubernetes.io/audit-version: latest

    # Warn on baseline violations
    pod-security.kubernetes.io/warn: baseline
    pod-security.kubernetes.io/warn-version: latest

---
# Example: Pod that passes restricted policy
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: production
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault

  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true

    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
      requests:
        memory: "128Mi"
        cpu: "100m"
```

**NIST Controls**: CM-7 - Least Functionality, AC-6 - Least Privilege

---

## Summary Table

| Finding | Severity | Standard | NIST Control | Remediation Priority |
|---------|----------|----------|--------------|---------------------|
| Running container as root | Critical | SCA-851, CIS 5.2.2 | AC-6, SC-39 | Immediate |
| Privileged container | Critical | SCA-852, CIS 5.2.5 | AC-6, CM-7 | Immediate |
| Host path mounts | Critical | SCA-853, CIS 5.2.1 | AC-6, SC-39 | Immediate |
| Excessive capabilities | High | SCA-854, CIS 5.2.7 | CM-7 | High |
| Missing security policies | High | SCA-855, NSA/CISA | SC-39, CM-7 | High |
| Secrets in images | High | SCA-856, OWASP K05 | SC-28, IA-5(7) | High |
| Missing network policies | High | SCA-857, CIS 5.3.2 | SC-7, AC-4 | High |
| Overly permissive RBAC | High | SCA-858, CIS 5.1.5 | AC-6, AC-3 | High |
| Missing resource limits | Medium | SCA-859, CIS 5.2.11 | SC-5 | Medium |
| Insecure registry | Medium | SCA-860, NIST SP 800-190 | SA-12, SI-7 | Medium |
| PSS not enforced | Medium | SCA-861, K8s PSS | CM-7, AC-6 | Medium |

---

## Compliance Mapping

### NIST SP 800-190 (Application Container Security)
- Image security
- Registry security
- Orchestrator security
- Container runtime security
- Host OS security

### CIS Kubernetes Benchmark v1.8.0
- 5.1.x: RBAC and Service Accounts
- 5.2.x: Pod Security Policies
- 5.3.x: Network Policies and CNI
- 5.7.x: General Policies

### NSA/CISA Kubernetes Hardening Guidance
- Pod Security
- Network Separation
- Authentication and Authorization
- Audit Logging
- Upgrading and Patching

### Kubernetes Pod Security Standards
- **Restricted**: Default for production workloads
- **Baseline**: Minimum security (prevent known escalations)
- **Privileged**: Unrestricted (system pods only)

### OWASP Kubernetes Top 10
- **K01**: Insecure Workload Configurations
- **K03**: Overly Permissive RBAC
- **K04**: Policy Enforcement
- **K05**: Inadequate Logging
- **K06**: Broken Authentication
- **K07**: Missing Network Segmentation

### NIST SP 800-53 Rev 5
- **AC-3**: Access Enforcement
- **AC-6**: Least Privilege
- **CM-7**: Least Functionality
- **SC-2**: Application Partitioning
- **SC-5**: Denial of Service Protection
- **SC-7**: Boundary Protection
- **SC-28**: Protection of Information at Rest
- **SC-39**: Process Isolation

---

## Testing

### Automated Checks
```bash
# Check for privileged pods
kubectl get pods -A -o jsonpath='{range .items[?(@.spec.containers[*].securityContext.privileged==true)]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'

# Check for root users
kubectl get pods -A -o json | \
  jq -r '.items[] | select(.spec.securityContext.runAsNonRoot!=true) | "\(.metadata.namespace)/\(.metadata.name)"'

# Check for host path mounts
kubectl get pods -A -o json | \
  jq -r '.items[] | select(.spec.volumes[]?.hostPath) | "\(.metadata.namespace)/\(.metadata.name)"'

# Check RBAC for cluster-admin
kubectl get clusterrolebindings -o json | \
  jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name'

# Check for pods without resource limits
kubectl get pods -A -o json | \
  jq -r '.items[] | select(.spec.containers[].resources.limits==null) | "\(.metadata.namespace)/\(.metadata.name)"'

# Scan images for vulnerabilities
trivy image nginx:latest
grype nginx:latest
```

### Manual Review
1. Review all Dockerfiles for USER directives
2. Check Kubernetes manifests for securityContext
3. Verify NetworkPolicy resources exist
4. Audit RBAC roles and bindings
5. Check Pod Security Standards enforcement
6. Review image sources and digests

### Security Scanning Tools
- **Trivy**: Container image vulnerability scanner
- **Grype**: Vulnerability scanner for container images
- **Falco**: Runtime security monitoring
- **KubeSec**: Kubernetes security risk analysis
- **Kubescape**: Kubernetes security compliance
- **OPA Gatekeeper**: Policy enforcement
- **Kyverno**: Kubernetes native policy management

---

## Implementation Checklist

### Container Security
- [ ] All images run as non-root (USER directive)
- [ ] No privileged containers
- [ ] No host path mounts (or strictly controlled)
- [ ] Capabilities dropped to minimum
- [ ] Seccomp/AppArmor/SELinux profiles applied
- [ ] No secrets in images (multi-stage builds)
- [ ] Images from trusted registries only
- [ ] Digest pinning for production images

### Kubernetes Security
- [ ] Pod Security Standards enforced (restricted for prod)
- [ ] Network Policies defined (default deny)
- [ ] RBAC follows least privilege
- [ ] Service accounts scoped per application
- [ ] Resource limits set on all containers
- [ ] Admission controllers enabled
- [ ] Audit logging enabled
- [ ] Secrets encrypted at rest
- [ ] Regular image scanning in CI/CD

### Monitoring & Response
- [ ] Falco or similar runtime security monitoring
- [ ] Centralized logging (EFK/ELK stack)
- [ ] Metrics collection (Prometheus)
- [ ] Security event alerting
- [ ] Regular security assessments
