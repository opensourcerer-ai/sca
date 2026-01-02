# Network Security Invariants (v1)

## Overview

This file defines security invariants for network communication security in application code aligned with:
- **NIST SP 800-52 Rev 2**: Guidelines for TLS Implementations
- **NIST SP 800-77**: Guide to IPsec VPNs
- **NIST SP 800-81-2**: Secure Domain Name System (DNS) Deployment Guide
- **OWASP**: A01:2021 (Broken Access Control), A05:2021 (Security Misconfiguration), A10:2021 (SSRF)
- **PCI-DSS**: Requirement 4.x (Protect cardholder data during transmission)
- **CWE-319**: Cleartext Transmission of Sensitive Information
- **CWE-918**: Server-Side Request Forgery (SSRF)

**Scope**: Analysis of network-related code in repositories (not infrastructure-level network configs).

---

## CRITICAL: Insecure Protocol Usage (CWE-319, NIST SC-8)

**Standard**: CWE-319, SCA-870, OWASP A02:2021, NIST SP 800-52 Rev 2, PCI-DSS 4.1

**Finding**: Application uses HTTP instead of HTTPS, or other unencrypted protocols

**Detection Patterns**:

### Python
```python
# CRITICAL: HTTP for sensitive data
import requests

# Credentials sent over HTTP
response = requests.post('http://api.example.com/login', 
                        json={'username': user, 'password': password})

# API keys over HTTP
headers = {'Authorization': f'Bearer {api_key}'}
response = requests.get('http://api.example.com/data', headers=headers)

# Database connection without SSL
import psycopg2
conn = psycopg2.connect(
    host='db.example.com',
    port=5432,
    database='mydb',
    user='admin',
    password='secret'
    # Missing: sslmode='require'
)

# Redis without TLS
import redis
r = redis.Redis(host='redis.example.com', port=6379, db=0)
# Missing: ssl=True
```

### JavaScript/TypeScript
```javascript
// CRITICAL: HTTP API calls
const axios = require('axios');

// Credentials over HTTP
axios.post('http://api.example.com/login', {
  username: user,
  password: password
});

// WebSocket without TLS
const ws = new WebSocket('ws://api.example.com/stream');  // Should be wss://

// Fetch without HTTPS
fetch('http://api.example.com/sensitive-data')
  .then(response => response.json());
```

### Java
```java
// CRITICAL: HTTP URL
URL url = new URL("http://api.example.com/data");
HttpURLConnection conn = (HttpURLConnection) url.openConnection();

// Database without SSL
String jdbcUrl = "jdbc:mysql://db.example.com:3306/mydb";
// Missing: ?useSSL=true&requireSSL=true

// MongoDB without TLS
MongoClient mongoClient = new MongoClient(
    new MongoClientURI("mongodb://db.example.com:27017/mydb")
    // Missing: ?ssl=true
);
```

### Go
```go
// CRITICAL: HTTP client
resp, err := http.Get("http://api.example.com/data")

// Database without TLS
db, err := sql.Open("postgres", 
    "host=db.example.com port=5432 user=admin password=secret dbname=mydb")
// Missing: sslmode=require

// gRPC without TLS
conn, err := grpc.Dial("api.example.com:50051", grpc.WithInsecure())  // CRITICAL
```

### Configuration Files
```yaml
# CRITICAL: application.yml with HTTP
app:
  api:
    url: http://api.example.com  # Should be https://

# CRITICAL: .env with unencrypted connection strings
DATABASE_URL=postgresql://user:pass@db.example.com:5432/mydb
# Missing: ?sslmode=require

REDIS_URL=redis://redis.example.com:6379
# Missing: rediss:// (TLS)
```

**Exception**: HTTP to localhost/127.0.0.1 for development is acceptable if documented.

**Remediation**:

```python
# GOOD: HTTPS with certificate verification
import requests

# Enforce HTTPS
response = requests.post('https://api.example.com/login',
                        json={'username': user, 'password': password},
                        verify=True)  # Verify SSL certificate (default)

# Database with SSL/TLS required
import psycopg2
conn = psycopg2.connect(
    host='db.example.com',
    port=5432,
    database='mydb',
    user='admin',
    password='secret',
    sslmode='require',  # Require SSL
    sslrootcert='/path/to/ca.pem'  # Verify server certificate
)

# Redis with TLS
import redis
r = redis.Redis(
    host='redis.example.com',
    port=6380,
    db=0,
    ssl=True,
    ssl_cert_reqs='required',
    ssl_ca_certs='/path/to/ca.pem'
)
```

**NIST Controls**: SC-8 - Transmission Confidentiality and Integrity, SC-8(1) - Cryptographic protection

---

## CRITICAL: TLS/SSL Certificate Validation Bypass (CWE-295, NIST SC-8)

**Standard**: CWE-295, SCA-871, OWASP A02:2021, NIST SP 800-52 Rev 2, PCI-DSS 4.1

**Finding**: Code disables SSL/TLS certificate verification

**Detection Patterns**:

### Python
```python
# CRITICAL: Disable certificate verification
import requests
requests.get('https://api.example.com', verify=False)  # CRITICAL

# CRITICAL: Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CRITICAL: Custom context without verification
import ssl
context = ssl._create_unverified_context()  # CRITICAL
urllib.request.urlopen('https://api.example.com', context=context)

# CRITICAL: Disable hostname checking
import ssl
context = ssl.create_default_context()
context.check_hostname = False  # CRITICAL
context.verify_mode = ssl.CERT_NONE  # CRITICAL
```

### JavaScript/Node.js
```javascript
// CRITICAL: Disable certificate validation
const https = require('https');

const agent = new https.Agent({
  rejectUnauthorized: false  // CRITICAL
});

https.get('https://api.example.com', { agent }, callback);

// CRITICAL: Process-wide SSL disable
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';  // CRITICAL

// CRITICAL: Axios with disabled verification
axios.get('https://api.example.com', {
  httpsAgent: new https.Agent({
    rejectUnauthorized: false
  })
});
```

### Java
```java
// CRITICAL: Trust all certificates
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}  // CRITICAL
    }
};

SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, trustAllCerts, new SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

// CRITICAL: Disable hostname verification
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);  // CRITICAL
```

### Go
```go
// CRITICAL: Skip TLS verification
import "crypto/tls"

tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},  // CRITICAL
}
client := &http.Client{Transport: tr}
```

### C#/.NET
```csharp
// CRITICAL: Disable certificate validation
ServicePointManager.ServerCertificateValidationCallback += 
    (sender, cert, chain, sslPolicyErrors) => true;  // CRITICAL

// CRITICAL: HttpClient with disabled validation
var handler = new HttpClientHandler();
handler.ServerCertificateCustomValidationCallback = 
    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;  // CRITICAL
```

**Remediation**:

```python
# GOOD: Proper certificate verification
import requests
import certifi

# Use system CA bundle (default)
response = requests.get('https://api.example.com', verify=True)

# Or specify CA bundle explicitly
response = requests.get('https://api.example.com', 
                       verify=certifi.where())

# For custom CA (internal PKI)
response = requests.get('https://internal-api.company.com',
                       verify='/etc/ssl/certs/company-ca-bundle.pem')

# Enforce TLS 1.2+
import ssl
context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
```

**NIST Controls**: SC-8 - Transmission Confidentiality, SC-13 - Cryptographic Protection, IA-5(2) - PKI-based authentication

---

## CRITICAL: Weak TLS Configuration (CWE-327, NIST SC-8)

**Standard**: CWE-327, SCA-872, NIST SP 800-52 Rev 2, PCI-DSS 4.1

**Finding**: Application uses deprecated TLS versions or weak cipher suites

**Detection Patterns**:

### Python
```python
# CRITICAL: TLS 1.0/1.1 allowed
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # CRITICAL: TLS 1.0
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)  # CRITICAL: TLS 1.1

# CRITICAL: SSLv2/SSLv3
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)  # May allow SSLv2/SSLv3

# HIGH: Weak cipher suites
context.set_ciphers('DES-CBC3-SHA')  # 3DES
context.set_ciphers('RC4-SHA')  # RC4
```

### JavaScript/Node.js
```javascript
// CRITICAL: Allow TLS 1.0/1.1
const tls = require('tls');

const options = {
  minVersion: 'TLSv1',  // CRITICAL: Should be TLSv1.2
  maxVersion: 'TLSv1.3'
};

// CRITICAL: Weak cipher suites
const server = tls.createServer({
  ciphers: 'DES-CBC3-SHA:RC4-SHA'  // CRITICAL
});
```

### Java
```java
// CRITICAL: SSLv3, TLS 1.0/1.1
SSLContext context = SSLContext.getInstance("SSLv3");  // CRITICAL
SSLContext context = SSLContext.getInstance("TLSv1");  // CRITICAL
SSLContext context = SSLContext.getInstance("TLSv1.1");  // CRITICAL

// HIGH: Weak cipher suites
SSLSocket socket = (SSLSocket) factory.createSocket();
socket.setEnabledCipherSuites(new String[] {
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",  // 3DES
    "TLS_RSA_WITH_RC4_128_SHA"  // RC4
});
```

### Go
```go
// CRITICAL: TLS 1.0/1.1
import "crypto/tls"

config := &tls.Config{
    MinVersion: tls.VersionTLS10,  // CRITICAL: Should be TLS12
    MaxVersion: tls.VersionTLS13,
}

// HIGH: Weak cipher suites
config.CipherSuites = []uint16{
    tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,  // 3DES
    tls.TLS_RSA_WITH_RC4_128_SHA,  // RC4
}
```

### Configuration Files
```yaml
# CRITICAL: Weak TLS in nginx.conf
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;  # CRITICAL: Includes TLS 1.0/1.1
ssl_ciphers 'DES-CBC3-SHA:RC4-SHA';  # CRITICAL: Weak ciphers

# CRITICAL: Apache httpd.conf
SSLProtocol all -SSLv3  # CRITICAL: Allows TLS 1.0/1.1
SSLCipherSuite HIGH:MEDIUM:!aNULL  # May include weak ciphers
```

**NIST SP 800-52 Rev 2 Requirements**:
- ✅ TLS 1.2 or TLS 1.3 only
- ❌ No TLS 1.0, TLS 1.1, SSLv2, SSLv3
- ✅ FIPS 140-2 validated cryptographic modules
- ✅ Strong cipher suites (ECDHE, AES-GCM, ChaCha20-Poly1305)
- ❌ No NULL, EXPORT, DES, 3DES, RC4, MD5-based ciphers

**Remediation**:

```python
# GOOD: TLS 1.2+ with strong ciphers
import ssl

# Use defaults (TLS 1.2+ on modern Python)
context = ssl.create_default_context()

# Explicit TLS 1.2 minimum
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3

# Strong cipher suites (NIST-approved)
context.set_ciphers(
    'ECDHE-ECDSA-AES256-GCM-SHA384:'
    'ECDHE-RSA-AES256-GCM-SHA384:'
    'ECDHE-ECDSA-AES128-GCM-SHA256:'
    'ECDHE-RSA-AES128-GCM-SHA256:'
    'ECDHE-ECDSA-CHACHA20-POLY1305:'
    'ECDHE-RSA-CHACHA20-POLY1305'
)

# Disable compression (CRIME attack)
context.options |= ssl.OP_NO_COMPRESSION
```

**NIST Controls**: SC-8 - Transmission Confidentiality, SC-13 - Cryptographic Protection

---

## CRITICAL: Server-Side Request Forgery (SSRF) (CWE-918, OWASP A10)

**Standard**: CWE-918, SCA-873, OWASP A10:2021, NIST SP 800-53 SI-10

**Finding**: Application makes HTTP requests to URLs controlled by user input without validation

**Detection Patterns**:

### Python
```python
# CRITICAL: Direct URL from user input
import requests

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)  # CRITICAL: No validation
    return response.content

# CRITICAL: URL parameter injection
def fetch_api_data(user_id):
    url = f"https://api.example.com/users/{user_id}/profile"
    # If user_id = "../admin" -> https://api.example.com/users/../admin/profile
    response = requests.get(url)
    return response.json()

# CRITICAL: Redirect following
response = requests.get(user_url, allow_redirects=True)  # Can be redirected to internal IPs
```

### JavaScript/Node.js
```javascript
// CRITICAL: User-controlled URL
const axios = require('axios');

app.get('/proxy', async (req, res) => {
  const url = req.query.url;
  const response = await axios.get(url);  // CRITICAL
  res.send(response.data);
});

// CRITICAL: URL construction from user input
const fetch = require('node-fetch');

const userId = req.params.id;
const url = `https://api.example.com/users/${userId}`;
fetch(url);  // Path traversal possible
```

### Java
```java
// CRITICAL: User-controlled URL
@GetMapping("/fetch")
public String fetchUrl(@RequestParam String url) throws IOException {
    URL obj = new URL(url);  // CRITICAL: No validation
    HttpURLConnection con = (HttpURLConnection) obj.openConnection();
    // ...
}
```

### Go
```go
// CRITICAL: User-controlled URL
func fetchHandler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    resp, err := http.Get(url)  // CRITICAL
    // ...
}
```

**Common SSRF Targets**:
- Cloud metadata services: `http://169.254.169.254/latest/meta-data/`
- Internal services: `http://localhost:8080`, `http://192.168.1.1`
- File protocol: `file:///etc/passwd`
- LDAP/SMB: `ldap://internal-ldap`, `\\internal-smb\share`

**Remediation**:

```python
# GOOD: URL validation and allowlist
import requests
from urllib.parse import urlparse
import ipaddress

ALLOWED_SCHEMES = {'https'}  # Only HTTPS
ALLOWED_DOMAINS = {'api.example.com', 'cdn.example.com'}  # Allowlist

def is_safe_url(url: str) -> bool:
    """Validate URL against SSRF attacks"""
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False
        
        # Check domain allowlist
        if parsed.hostname not in ALLOWED_DOMAINS:
            return False
        
        # Resolve hostname to IP
        import socket
        ip_str = socket.gethostbyname(parsed.hostname)
        ip = ipaddress.ip_address(ip_str)
        
        # Block private IP ranges (RFC 1918, RFC 4193, etc.)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
        
        # Block cloud metadata IPs
        if ip_str == '169.254.169.254':  # AWS/Azure/GCP metadata
            return False
        
        return True
    except Exception:
        return False

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    
    if not is_safe_url(url):
        abort(400, "Invalid or unsafe URL")
    
    # Disable redirects to prevent redirect-based SSRF
    response = requests.get(url, allow_redirects=False, timeout=5)
    
    # Check response redirect
    if response.is_redirect:
        location = response.headers.get('Location')
        if not is_safe_url(location):
            abort(400, "Unsafe redirect detected")
    
    return response.content
```

**NIST Controls**: SI-10 - Information Input Validation, AC-4 - Information Flow Enforcement

---

## HIGH: Insecure Server Binding (CWE-200, NIST SC-7)

**Standard**: CWE-200, SCA-874, NIST SP 800-53 SC-7

**Finding**: Server binds to all interfaces (0.0.0.0) instead of specific interface

**Detection Patterns**:

### Python (Flask/Django)
```python
# HIGH: Bind to all interfaces
app.run(host='0.0.0.0', port=5000)  # Accessible from network

# HIGH: Django settings.py
ALLOWED_HOSTS = ['*']  # Allows any host
```

### JavaScript/Node.js
```javascript
// HIGH: Bind to all interfaces
const express = require('express');
const app = express();

app.listen(3000, '0.0.0.0');  // HIGH: Exposed to network

// HIGH: No host specified (defaults to 0.0.0.0)
app.listen(3000);  // HIGH
```

### Java (Spring Boot)
```java
// HIGH: application.properties
server.address=0.0.0.0  // HIGH: Bind to all interfaces
```

### Go
```go
// HIGH: Bind to all interfaces
http.ListenAndServe(":8080", handler)  // HIGH: Binds to 0.0.0.0:8080
http.ListenAndServe("0.0.0.0:8080", handler)  // HIGH
```

### Configuration Files
```yaml
# HIGH: docker-compose.yml
services:
  web:
    ports:
      - "5000:5000"  # HIGH: Exposes to all interfaces

# GOOD: Bind to localhost only
services:
  web:
    ports:
      - "127.0.0.1:5000:5000"  # Only accessible locally
```

**Remediation**:

```python
# GOOD: Development - bind to localhost
if app.config['ENV'] == 'development':
    app.run(host='127.0.0.1', port=5000)  # Localhost only

# GOOD: Production - use reverse proxy
# Don't expose application directly, use nginx/Apache as reverse proxy
# Application listens on localhost, proxy handles external requests

# Django settings.py
ALLOWED_HOSTS = ['example.com', 'www.example.com']  # Specific domains

# Flask with environment-based binding
import os

host = os.environ.get('FLASK_HOST', '127.0.0.1')  # Default localhost
port = int(os.environ.get('FLASK_PORT', 5000))

if __name__ == '__main__':
    app.run(host=host, port=port, debug=False)
```

**NIST Controls**: SC-7 - Boundary Protection, SC-7(5) - Deny by default

---

## HIGH: Missing Network Timeouts (CWE-400, NIST SC-5)

**Standard**: CWE-400, SCA-875, NIST SP 800-53 SC-5

**Finding**: Network operations without timeout configuration

**Detection Patterns**:

### Python
```python
# HIGH: No timeout
import requests
response = requests.get('https://api.example.com')  # No timeout

# HIGH: Infinite timeout
import socket
sock = socket.socket()
sock.connect(('api.example.com', 80))  # No timeout

# HIGH: Database without timeout
import psycopg2
conn = psycopg2.connect(
    host='db.example.com',
    database='mydb'
    # Missing: connect_timeout=10
)
```

### JavaScript/Node.js
```javascript
// HIGH: No timeout
const axios = require('axios');
axios.get('https://api.example.com');  // No timeout

// HIGH: HTTP request without timeout
const http = require('http');
http.get('http://api.example.com', (res) => {
  // No timeout
});

// HIGH: WebSocket without timeout
const ws = new WebSocket('wss://api.example.com');
// No connection timeout
```

### Java
```java
// HIGH: No timeout
URL url = new URL("https://api.example.com");
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
// Missing: conn.setConnectTimeout(10000)
// Missing: conn.setReadTimeout(10000)

// HIGH: RestTemplate without timeout
RestTemplate restTemplate = new RestTemplate();
// Missing timeout configuration
```

### Go
```go
// HIGH: No timeout
resp, err := http.Get("https://api.example.com")
// Uses default client with no timeout

// HIGH: Custom client without timeout
client := &http.Client{}  // No timeout
resp, err := client.Get("https://api.example.com")
```

**Remediation**:

```python
# GOOD: Timeouts configured
import requests

# Connection and read timeout
response = requests.get('https://api.example.com', 
                       timeout=(5, 30))  # (connect, read) in seconds

# Database with timeout
import psycopg2
conn = psycopg2.connect(
    host='db.example.com',
    database='mydb',
    connect_timeout=10,
    options='-c statement_timeout=30000'  # 30 seconds
)

# Socket with timeout
import socket
sock = socket.socket()
sock.settimeout(10)  # 10 seconds
sock.connect(('api.example.com', 80))
```

```javascript
// GOOD: Axios with timeout
const axios = require('axios');

const client = axios.create({
  timeout: 30000,  // 30 seconds
  timeoutErrorMessage: 'Request timed out'
});

client.get('https://api.example.com');
```

```go
// GOOD: HTTP client with timeout
import "time"

client := &http.Client{
    Timeout: 30 * time.Second,
}

resp, err := client.Get("https://api.example.com")
```

**NIST Controls**: SC-5 - Denial of Service Protection

---

## MEDIUM: Hardcoded IP Addresses/Hostnames (SCA-876, NIST CM-7)

**Standard**: SCA-876, NIST SP 800-53 CM-7

**Finding**: Hardcoded network endpoints in source code

**Detection Patterns**:

### All Languages
```python
# MEDIUM: Hardcoded IP address
API_URL = "https://192.168.1.100:8080/api"

# MEDIUM: Hardcoded hostname
DB_HOST = "prod-db-01.internal.company.com"

# MEDIUM: Hardcoded service endpoint
REDIS_HOST = "10.0.2.45"
REDIS_PORT = 6379
```

```javascript
// MEDIUM: Hardcoded in code
const API_BASE = 'https://api.production.example.com';

// MEDIUM: Hardcoded database
const dbConfig = {
  host: '192.168.50.10',
  port: 5432
};
```

**Exception**: localhost/127.0.0.1 for development is acceptable.

**Remediation**:

```python
# GOOD: Environment variables
import os

API_URL = os.environ.get('API_URL', 'https://api.example.com')
DB_HOST = os.environ.get('DB_HOST', 'localhost')
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))

# GOOD: Configuration file
import json

with open('config.json') as f:
    config = json.load(f)

API_URL = config['api']['url']
DB_HOST = config['database']['host']
```

**NIST Controls**: CM-7 - Least Functionality, CM-6 - Configuration Settings

---

## MEDIUM: DNS Rebinding Vulnerability (CWE-346, SCA-877)

**Standard**: CWE-346, SCA-877, NIST SP 800-81-2

**Finding**: Application doesn't validate Host header or DNS resolution

**Detection Patterns**:

### Python (Flask/Django)
```python
# MEDIUM: No Host header validation
@app.route('/api/data')
def get_data():
    # Attacker can set Host: evil.com
    # Application responds with data to evil domain
    return jsonify(data)

# MEDIUM: Django without ALLOWED_HOSTS
ALLOWED_HOSTS = []  # Empty = accepts any host
```

### JavaScript/Node.js
```javascript
// MEDIUM: No Host header validation
app.get('/api/data', (req, res) => {
  // req.headers.host can be attacker-controlled
  res.json(data);
});
```

**Remediation**:

```python
# GOOD: Django ALLOWED_HOSTS
ALLOWED_HOSTS = ['example.com', 'www.example.com']

# GOOD: Flask host validation
@app.before_request
def validate_host():
    allowed_hosts = {'example.com', 'www.example.com', 'localhost'}
    if request.host not in allowed_hosts:
        abort(400, "Invalid Host header")
```

**NIST Controls**: SI-10 - Information Input Validation

---

## MEDIUM: Insecure WebSocket Configuration (CWE-319, SCA-878)

**Standard**: CWE-319, SCA-878, OWASP A02:2021

**Finding**: WebSocket connections without TLS or authentication

**Detection Patterns**:

### JavaScript
```javascript
// MEDIUM: Unencrypted WebSocket
const ws = new WebSocket('ws://api.example.com/stream');  // Should be wss://

// MEDIUM: No authentication
const ws = new WebSocket('wss://api.example.com/stream');
// No token or auth mechanism
```

### Python
```python
# MEDIUM: WebSocket server without TLS
import asyncio
import websockets

async def handler(websocket, path):
    # No authentication check
    async for message in websocket:
        await websocket.send(f"Echo: {message}")

start_server = websockets.serve(handler, "0.0.0.0", 8765)
# Missing: ssl parameter
```

**Remediation**:

```javascript
// GOOD: Secure WebSocket with auth
const token = localStorage.getItem('authToken');
const ws = new WebSocket(`wss://api.example.com/stream?token=${token}`);

ws.onopen = () => {
  // Send authentication message
  ws.send(JSON.stringify({
    type: 'auth',
    token: token
  }));
};
```

```python
# GOOD: WebSocket with TLS and auth
import ssl
import asyncio
import websockets
import jwt

async def handler(websocket, path):
    # Authenticate first message
    auth_msg = await websocket.recv()
    auth_data = json.loads(auth_msg)
    
    try:
        payload = jwt.decode(auth_data['token'], SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
    except jwt.InvalidTokenError:
        await websocket.close(1008, "Authentication failed")
        return
    
    # Authenticated session
    async for message in websocket:
        await websocket.send(f"Echo: {message}")

# TLS configuration
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain('cert.pem', 'key.pem')

start_server = websockets.serve(handler, "localhost", 8765, ssl=ssl_context)
```

**NIST Controls**: SC-8 - Transmission Confidentiality, IA-2 - Identification and Authentication

---

## MEDIUM: Insecure gRPC Configuration (CWE-319, SCA-879)

**Standard**: CWE-319, SCA-879, NIST SP 800-52 Rev 2

**Finding**: gRPC service without TLS or weak configuration

**Detection Patterns**:

### Python
```python
# MEDIUM: gRPC without TLS
import grpc

# Server without TLS
server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
server.add_insecure_port('[::]:50051')  # MEDIUM: No TLS

# Client without TLS
channel = grpc.insecure_channel('api.example.com:50051')  # MEDIUM
```

### Go
```go
// MEDIUM: gRPC without TLS
import "google.golang.org/grpc"

// Server without TLS
lis, _ := net.Listen("tcp", ":50051")
s := grpc.NewServer()
s.Serve(lis)  // MEDIUM: No TLS

// Client without TLS
conn, err := grpc.Dial("api.example.com:50051", grpc.WithInsecure())  // MEDIUM
```

**Remediation**:

```python
# GOOD: gRPC with TLS and mTLS
import grpc
from grpc import ssl_server_credentials, ssl_channel_credentials

# Server with TLS
server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

# Load server certificate and key
with open('server.crt', 'rb') as f:
    server_cert = f.read()
with open('server.key', 'rb') as f:
    server_key = f.read()

# Mutual TLS: require client certificates
with open('ca.crt', 'rb') as f:
    ca_cert = f.read()

server_credentials = ssl_server_credentials(
    [(server_key, server_cert)],
    root_certificates=ca_cert,
    require_client_auth=True  # mTLS
)

server.add_secure_port('[::]:50051', server_credentials)

# Client with TLS
with open('ca.crt', 'rb') as f:
    ca_cert = f.read()

with open('client.crt', 'rb') as f:
    client_cert = f.read()

with open('client.key', 'rb') as f:
    client_key = f.read()

credentials = ssl_channel_credentials(
    root_certificates=ca_cert,
    private_key=client_key,
    certificate_chain=client_cert
)

channel = grpc.secure_channel('api.example.com:50051', credentials)
```

**NIST Controls**: SC-8 - Transmission Confidentiality, IA-5(2) - PKI-based authentication

---

## LOW: Verbose Network Error Messages (CWE-209, SCA-880)

**Standard**: CWE-209, SCA-880, OWASP A05:2021

**Finding**: Network errors exposing internal implementation details

**Detection Patterns**:

```python
# LOW: Exposing full exception
@app.route('/api/data')
def get_data():
    try:
        response = requests.get('http://internal-api:8080/data')
        return response.json()
    except Exception as e:
        return jsonify({'error': str(e)}), 500  # LOW: Exposes internal URLs, stack traces
```

**Remediation**:

```python
# GOOD: Generic error messages
import logging

@app.route('/api/data')
def get_data():
    try:
        response = requests.get('http://internal-api:8080/data', timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.Timeout:
        logging.error("API timeout when fetching data")
        return jsonify({'error': 'Service temporarily unavailable'}), 503
    except requests.RequestException as e:
        logging.error(f"API error: {e}")  # Log internally
        return jsonify({'error': 'Internal server error'}), 500  # Generic to user
```

**NIST Controls**: SI-11 - Error Handling

---

## Summary Table

| Finding | Severity | Standard | NIST Control | SCA ID |
|---------|----------|----------|--------------|---------|
| Insecure protocol usage (HTTP) | Critical | CWE-319, PCI-DSS 4.1 | SC-8 | SCA-870 |
| TLS certificate validation bypass | Critical | CWE-295, NIST SP 800-52 | SC-8, SC-13 | SCA-871 |
| Weak TLS configuration | Critical | CWE-327, PCI-DSS 4.1 | SC-8, SC-13 | SCA-872 |
| Server-Side Request Forgery (SSRF) | Critical | CWE-918, OWASP A10 | SI-10, AC-4 | SCA-873 |
| Insecure server binding | High | CWE-200 | SC-7 | SCA-874 |
| Missing network timeouts | High | CWE-400 | SC-5 | SCA-875 |
| Hardcoded IP/hostnames | Medium | - | CM-7, CM-6 | SCA-876 |
| DNS rebinding vulnerability | Medium | CWE-346 | SI-10 | SCA-877 |
| Insecure WebSocket config | Medium | CWE-319 | SC-8, IA-2 | SCA-878 |
| Insecure gRPC config | Medium | CWE-319 | SC-8, IA-5(2) | SCA-879 |
| Verbose network error messages | Low | CWE-209 | SI-11 | SCA-880 |

---

## Compliance Mapping

### NIST SP 800-53 Rev 5 Controls
- **SC-8**: Transmission Confidentiality and Integrity
- **SC-8(1)**: Cryptographic Protection
- **SC-13**: Cryptographic Protection
- **SC-5**: Denial of Service Protection
- **SC-7**: Boundary Protection
- **SI-10**: Information Input Validation
- **SI-11**: Error Handling
- **IA-2**: Identification and Authentication
- **IA-5(2)**: PKI-based Authentication
- **CM-6**: Configuration Settings
- **CM-7**: Least Functionality

### NIST Special Publications
- **SP 800-52 Rev 2**: Guidelines for TLS Implementations
- **SP 800-77**: Guide to IPsec VPNs
- **SP 800-81-2**: Secure DNS Deployment Guide

### PCI-DSS v4.0
- **4.1**: Encryption of cardholder data in transit
- **4.2**: Never send unprotected PANs

### OWASP Top 10 2021
- **A02:2021**: Cryptographic Failures
- **A05:2021**: Security Misconfiguration
- **A10:2021**: Server-Side Request Forgery (SSRF)

---

## Testing

### Automated Checks
```bash
# Search for HTTP usage
git grep -iE "http://|requests.get\('http:|fetch\('http:" --and --not -e localhost --not -e 127.0.0.1

# Search for certificate validation bypass
git grep -iE "verify\s*=\s*False|rejectUnauthorized.*false|InsecureSkipVerify.*true"

# Search for weak TLS
git grep -iE "TLSv1\b|SSLv|PROTOCOL_TLS(?!v1_[23])"

# Search for SSRF patterns
git grep -E "requests\.(get|post)\([^)]*request\.(args|json|form)" 

# Search for 0.0.0.0 bindings
git grep -E "0\.0\.0\.0|host\s*=\s*['\"]0\.0\.0\.0"

# Search for missing timeouts
git grep -E "requests\.(get|post)\([^)]*\)" | grep -v timeout
```

### Manual Review
1. Test all API endpoints for HTTPS enforcement
2. Verify certificate validation is not bypassed
3. Check TLS configuration (minimum version, cipher suites)
4. Test SSRF protection with internal IPs and metadata URLs
5. Review server binding configuration
6. Verify all network operations have timeouts
7. Test WebSocket/gRPC authentication and encryption
8. Review error messages for information disclosure

---

## Remediation Priority

1. **Immediate** (Critical):
   - SCA-870: Enforce HTTPS for all sensitive data
   - SCA-871: Remove certificate validation bypasses
   - SCA-872: Upgrade to TLS 1.2+ with strong ciphers
   - SCA-873: Implement SSRF protection

2. **High** (Within 30 days):
   - SCA-874: Bind services to specific interfaces
   - SCA-875: Add timeouts to all network operations

3. **Medium** (Within 90 days):
   - SCA-876 to SCA-879: Configuration hardening

4. **Low** (As needed):
   - SCA-880: Improve error handling
