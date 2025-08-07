# Advisory Report: ownCloud OCIS gRPC Client Allows Insecure TLS Connections by Default

## Summary
A security misconfiguration has been identified in the `ownCloud OCIS` project, specifically in the gRPC client initialization logic. The code allows insecure TLS communication by setting `InsecureSkipVerify: true`, which disables certificate verification, making the application vulnerable to **Man-in-the-Middle (MitM)** attacks. This insecure configuration should never be enabled in production environments.

* **Project**: [ownCloud OCIS](https://github.com/owncloud/ocis)
* **Vulnerable File**: `ocis-pkg/service/grpc/client.go`
* **Vulnerable Line(s)**: [Line 77-80](https://github.com/owncloud/ocis/blob/dff22670e8f61cd5bb9d8cc0bb3cf67e5f97e979/ocis-pkg/service/grpc/client.go#L77-L80)
* **Impact**: Man-in-the-Middle attacks due to disabled certificate verification
* **Severity**: High


## Details
The vulnerability exists in the logic used by `NewClient` to initialize a TLS connection to a gRPC server. When the `insecure` flag is enabled in the configuration, the client is instantiated with the following TLS setting:

```go
InsecureSkipVerify: true
```

This disables server certificate validation, effectively allowing an attacker to impersonate the gRPC server and intercept or modify the data in transit without detection. This is a critical issue, especially if used in production environments.

This issue is located in the following function:

```go
func NewClient(config *clientConfig) (*grpc.ClientConn, error) {
    tlsConfig := &tls.Config{
        InsecureSkipVerify: config.Insecure,
    }
    // ... connection logic
}
```
The root of the problem is the reliance on the `Insecure` boolean flag, which may be mistakenly enabled in a production build.


## Proof of Concept (PoC)
### 1. Vulnerable Code Location:

[client.go#L77-L80](https://github.com/owncloud/ocis/blob/dff22670e8f61cd5bb9d8cc0bb3cf67e5f97e979/ocis-pkg/service/grpc/client.go#L77-L80)

```go
tlsConfig := &tls.Config{
    InsecureSkipVerify: config.Insecure,
}
```

### 2. CLI Execution with Insecure Flag:

```bash
./ocis server --insecure
```

This command will initialize the gRPC client with TLS certificate verification disabled.

### 3. BurpSuite HTTP Request Example:

Though this is a gRPC client, if the application proxies or exposes REST APIs through HTTPS, this is how an attacker could intercept TLS traffic.

```
GET /ocs/v2.php/cloud/user HTTP/1.1
Host: ocis.local
User-Agent: BurpSuite
Accept: */*
Connection: close
```

Using a self-signed certificate or proxy CA, this request would be accepted without TLS verification.

## Vulnerable Exploit Scenario
1. An attacker positions themselves on the same network as the target (e.g., via ARP spoofing).
2. The victim launches the OCIS server with `--insecure` flag.
3. The attacker intercepts the TLS handshake using a fake certificate.
4. Sensitive gRPC communication (authentication tokens, file paths, etc.) is intercepted or modified.



## Impact
This vulnerability exposes users to **MitM attacks**, allowing attackers to:

* Intercept or manipulate encrypted gRPC traffic
* Steal authentication credentials
* Corrupt file operations or inject malicious commands if access control is bypassed

The insecure TLS flag (`InsecureSkipVerify: true`) removes all protection offered by HTTPS/TLS. This could lead to full compromise of confidentiality and integrity in network communication.

---

## Recommendation
The insecure TLS mode should be completely removed or heavily restricted to test-only environments. The recommended fix:
* Remove the `insecure` flag from production builds
* Add validation to fail or panic if `InsecureSkipVerify: true` is enabled outside test mode
