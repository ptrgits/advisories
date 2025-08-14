## **Summary**
A **Transport Layer Security (TLS)** misconfiguration vulnerability was discovered in the **Grafana Pyroscope** project.  
In the function `NewInClusterK8sClient`, the `tls.Config` structure was configured with an **insecure minimum TLS version** (`tls.VersionTLS10`). TLS 1.0 has been deprecated due to multiple cryptographic weaknesses and is no longer considered secure for protecting sensitive communications. This vulnerability allows potential **downgrade attacks**, enabling attackers to negotiate older, insecure TLS protocols and exploit known flaws to decrypt or tamper with communications between components.

**TLS (Transport Layer Security)** is the foundation for securing communications over the internet. Secure versions (TLS 1.2 and TLS 1.3) protect against eavesdropping, message forgery, and data tampering.  
However, legacy versions such as **TLS 1.0** and **TLS 1.1** are vulnerable to multiple well-known attacks:

- **POODLE** (Padding Oracle On Downgraded Legacy Encryption)  
- **BEAST** (Browser Exploit Against SSL/TLS)  
- **RC4 Weaknesses** (biases allowing plaintext recovery)  
- **Protocol Downgrade Attacks**  

The insecure configuration in Pyroscope’s Kubernetes resolver client can allow these obsolete protocols to be used, exposing communications to interception or manipulation.


## **Vulnerable Code**
```go
// File: pkg/metastore/discovery/kuberesolver/kubernetes.go
// Function: NewInClusterK8sClient

tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS10, // ❌ Insecure: allows TLS 1.0
}
```
By setting `MinVersion` to `tls.VersionTLS10`, the application allows negotiation of insecure protocol versions.


## Proof of Concept (PoC)

### **Exploitation Scenario**
An attacker with a man-in-the-middle (MITM) position between the Pyroscope instance and its Kubernetes API could:
1. Intercept the TLS handshake.
2. Force a downgrade to **TLS 1.0**.
3. Exploit weaknesses in the older protocol to:
   - Recover plaintext data.
   - Inject malicious payloads.
   - Disrupt secure communication channels.



### BurpSuite Exploit
Using **BurpSuite**, you can intercept and modify the TLS handshake to force the client to negotiate TLS 1.0.

**Steps:**
1. Configure BurpSuite as a proxy between Pyroscope and the K8s API.
2. Enable **"SSL Pass Through"** and **"Force Downgrade to TLS 1.0"** in Burp's TLS settings.
3. Monitor the handshake negotiation to confirm that TLS 1.0 is being accepted.
4. Capture and analyze decrypted traffic to confirm lack of confidentiality.

**Burp Raw Request:**
```
CONNECT kubernetes.default.svc.cluster.local:443 HTTP/1.1
Host: kubernetes.default.svc.cluster.local:443
Proxy-Connection: keep-alive
```
Burp modifies handshake to:
```
ClientHello (TLS 1.0)
```
Server responds with:
```
ServerHello (TLS 1.0)
```
Data channel is now using deprecated and vulnerable encryption.


## **Impact**
- **Confidentiality Breach:** Attackers can decrypt sensitive data in transit.
- **Integrity Violation:** Attackers can modify API requests/responses without detection.
- **Downgrade Attacks:** Enables exploitation of obsolete cryptographic flaws.
- **Compliance Issues:** Fails PCI DSS, HIPAA, and NIST 800-52r2 TLS requirements.


## References
- [Wikipedia: Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security)  
- [Mozilla: Security/Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS)  
- [OWASP: Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)  
- [PCI DSS v4.0 Requirements for TLS](https://www.pcisecuritystandards.org/)  
