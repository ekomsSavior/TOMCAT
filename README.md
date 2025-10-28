**Apache Tomcat CVE Assessment & Exploitation Framework**

![Screenshot_2025-10-28_09_43_35](https://github.com/user-attachments/assets/a687a7ce-a5c2-4f8b-9c3e-ea91fd5a48fe)

TOMCAT is a testing tool for identifying and exploiting directory traversal vulnerabilities in Apache Tomcat servers. This framework combines detection for both recent and historical CVEs with practical exploitation capabilities, taking you from initial reconnaissance to full system compromise.

**Supported Vulnerabilities**

*CVE-2025-55752*
- Affected Versions: Tomcat 10.1.0-M1 to 10.1.29, 11.0.0-M1 to 11.0.0-M18
- Impact: Directory traversal allowing arbitrary file read
- Vector: Specially crafted URL encoding bypass

*CVE-2020-17530* 
- Affected Versions: Tomcat 7.0.0 to 7.0.108, 8.5.0 to 8.5.60, 9.0.0 to 9.0.40
- Impact: Directory traversal via rewrite misconfiguration
- Vector: Double URL encoding attacks

**Features**

- Dual CVE detection with intelligent payload selection
- Tomcat version fingerprinting and vulnerability correlation  
- Multiple operational modes (stealth, assessment, full exploitation)
- Automated file exfiltration of sensitive system and configuration files
- RCE assessment via PUT method testing
- JSP webshell deployment and multi-platform reverse shells
- Comprehensive reporting with actionable next steps

**Installation**

```bash
git clone https://github.com/ekomsSavior/TOMCAT
cd TOMCAT

pip3 install requests urllib3
```

**Usage**

```bash 
python3 tomcat.py
```

**Platform Support**

This tool works across all major platforms:
- **Linux** (Kali, Ubuntu, etc.) - Primary development platform
- **Windows** - Requires Python 3.6+ and same dependencies
- **macOS** - Native support with homebrew Python

Windows users may need to install Python from python.org and use Command Prompt or PowerShell.

**Usage Guide**

When you launch the scanner, you'll be guided through an interactive menu:

![Screenshot_2025-10-28_09_48_43 (1)](https://github.com/user-attachments/assets/52c204c4-fb70-45d1-a0ef-f20a553130b1)

1. **Target Configuration**
   - Enter the full Tomcat server URL (http/https, IP or domain)
   - The tool verifies connectivity and Tomcat indicators

2. **Operational Mode Selection**
   - *Vulnerability Assessment*: Safe scanning only, no exploitation
   - *Assessment + RCE Check*: Adds PUT method testing for potential code execution
   - *Full Exploitation*: Complete assessment with file exfiltration and shell deployment
   - *Stealth Mode*: Slower, less noisy scanning for monitored environments

3. **Scan Execution**
   The tool automatically:
   - Fingerprints Tomcat version and correlates with known affected versions
   - Tests multiple traversal payloads for both CVEs
   - Provides real-time feedback on each test
   - Confirms vulnerabilities with file content validation

![Screenshot_2025-10-28_09_49_24 (1)](https://github.com/user-attachments/assets/c709d392-a9d8-49f9-b893-e721a4f8951f)

4. **Exploitation Phase** (if selected)
   - Automatically attempts to read sensitive files (/etc/passwd, web.xml, configuration files)
   - Tests PUT method availability for potential webshell upload
   - If PUT enabled, deploys command shells or reverse shells
   - Saves exfiltrated data to local files for analysis

**Reverse Shell Capabilities**

TOMCAT framework includes comprehensive RCE exploitation through multiple vectors:

**PUT Method Exploitation**
- Automated detection of enabled PUT methods
- JSP webshell deployment for command execution
- Multi-platform reverse shell generation
- Persistent backdoor installation

**Reverse Shell Types Supported**

*Unix/Linux Targets*
- Bash reverse shells with full TTY allocation
- Python-based shells for environments with limited binaries
- Netcat-based fallbacks when available

*Windows Targets* 
- PowerShell reverse shells with AMSI bypass techniques
- Base64 encoded payloads for command line evasion
- Full interactive PowerShell sessions

**Reverse Shell Deployment Process**

When you select "Full Exploitation" mode:

1. **PUT Method Assessment**
   - Automatic OPTIONS request analysis
   - Direct PUT method testing with cleanup
   - Authentication requirement detection

2. **Webshell Upload**
   - Randomly named JSP files to avoid detection
   - Command execution validation
   - File permission verification

3. **Reverse Shell Triggering**
   - Listener configuration prompts
   - Payload generation based on target OS
   - Manual trigger control for operator timing

**Example Reverse Shell Workflow**

```
[+] Checking PUT method availability...
[+] PUT method enabled (direct test)

[+] Attempting webshell upload...
[+] Webshell uploaded: https://target:8080/cmd_28374.jsp

[+] Uploading reverse shell...
[+] Reverse shell uploaded: https://target:8080/rev_49261.jsp
[!] Start listener: nc -nvlp 4444
[!] Press Enter to trigger reverse shell...

[+] Reverse shell triggered! Check your listener.
```

**Listener Setup Examples**

```bash
# Netcat listener (Linux/Mac)
nc -nvlp 4444

# Powercat listener (Windows) 
powercat -l -p 4444

# Socat listener (Enhanced features)
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

**What's Happening Under the Hood**

*Reconnaissance Phase*
- Basic connectivity checks and service validation
- Server header analysis and Tomcat fingerprinting
- Content-based version detection from error pages and management interfaces

*Vulnerability Assessment* 
- Sequential payload testing with multiple encoding techniques
- Live analysis of HTTP responses for successful file read indicators
- Correlation between detected version and relevant CVE payloads

![Screenshot_2025-10-28_09_49_29 (1)](https://github.com/user-attachments/assets/0ebfccc1-cc61-4778-b119-a6f25240720e)

*Exploitation Engine*
- Intelligent file path construction for maximum traversal depth
- Adaptive payload selection based on initial scan results
- Multi-platform shellcode generation (Unix/Windows/Python)
- Safe file handling and evidence preservation

**Example Output Breakdown**

```
[+] Scanning for CVE-2025-55752...
  Testing: Double dot slash encoding
    [+] VULNERABLE! CVE-2025-55752 - Found /etc/passwd
    [+] Payload: ....//....//....//....//....//etc/passwd
    [+] File preview:
      root:x:0:0:root:/root:/bin/bash
      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

This shows successful vulnerability confirmation with:
- Specific CVE identification
- Working payload used
- File content validation

**Advanced RCE Features**

*Webshell Persistence*
- Multiple webshell deployment locations
- Configuration file modification for persistence
- Service installation on compromised hosts

*Evasion Techniques*
- Random JSP filenames to avoid pattern detection
- Obfuscated command execution
- Traffic encryption capabilities

*Post-Exploitation*
- Automatic privilege escalation checks
- Network reconnaissance from compromised host
- Lateral movement assessment

**Legal Disclaimer**

TOMCAT is designed for authorized security testing only. 
Users must ensure they have explicit permission to test target systems. 
Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. 
The developer assumes no liability for misuse of this tool.

![Screenshot 2025-10-14 111008](https://github.com/user-attachments/assets/cefb729e-77e9-4a8a-83ba-0a6928d13b05)

https://instagram.com/ekoms.is.my.savior

