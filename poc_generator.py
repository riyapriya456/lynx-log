"""
Lynx VAPT - Proof of Concept Generator

Generates exploitable PoC code for vulnerabilities:
- cURL commands
- Python exploit scripts
- Browser-based PoC (HTML)
- Reproduction steps
- CVSS scoring

Author: Lynx Team
"""

import re
import json
import html
import base64
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse, parse_qs


@dataclass
class PoC:
    """A proof of concept."""
    vuln_type: str
    title: str
    curl_command: str
    python_script: str
    html_poc: str
    steps: List[str]
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    owasp_category: str


# CVSS v3.1 scoring data
VULN_CVSS_DATA = {
    "SQL Injection": {
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection"
    },
    "XSS": {
        "score": 6.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection"
    },
    "DOM/Reflected XSS": {
        "score": 6.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection"
    },
    "Command Injection": {
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection"
    },
    "SSTI": {
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1336",
        "owasp": "A03:2021 - Injection"
    },
    "SSRF": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-918",
        "owasp": "A10:2021 - SSRF"
    },
    "Open Redirect": {
        "score": 4.7,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "cwe": "CWE-601",
        "owasp": "A01:2021 - Broken Access Control"
    },
    "IDOR": {
        "score": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-639",
        "owasp": "A01:2021 - Broken Access Control"
    },
    "JWT Vulnerability": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-347",
        "owasp": "A02:2021 - Cryptographic Failures"
    },
    "File Upload": {
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-434",
        "owasp": "A04:2021 - Insecure Design"
    },
    "LFI": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control"
    },
    "XXE": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-611",
        "owasp": "A05:2021 - Security Misconfiguration"
    },
    "CORS Misconfiguration": {
        "score": 5.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-942",
        "owasp": "A05:2021 - Security Misconfiguration"
    },
    "CSRF": {
        "score": 4.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "cwe": "CWE-352",
        "owasp": "A01:2021 - Broken Access Control"
    },
    "Default": {
        "score": 5.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "owasp": "A01:2021 - Broken Access Control"
    }
}


class PoCGenerator:
    """
    Generates Proof of Concept code for vulnerabilities.
    """
    
    def __init__(self):
        self.pocs: List[PoC] = []
    
    def generate(
        self,
        vuln_type: str,
        url: str,
        payload: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        body: Optional[str] = None,
        cookies: Optional[Dict] = None,
        details: str = ""
    ) -> PoC:
        """
        Generate a complete PoC for a vulnerability.
        
        Args:
            vuln_type: Type of vulnerability
            url: Target URL
            payload: Payload used
            method: HTTP method
            headers: Request headers
            body: Request body
            cookies: Cookies
            details: Additional details
        
        Returns:
            PoC object with all exploit code
        """
        headers = headers or {}
        cookies = cookies or {}
        
        # Get CVSS data
        cvss_data = VULN_CVSS_DATA.get(vuln_type, VULN_CVSS_DATA["Default"])
        
        # Generate cURL command
        curl_cmd = self._generate_curl(url, method, headers, body, cookies)
        
        # Generate Python script
        python_script = self._generate_python(
            vuln_type, url, method, headers, body, cookies, payload
        )
        
        # Generate HTML PoC
        html_poc = self._generate_html(
            vuln_type, url, method, headers, body, payload
        )
        
        # Generate reproduction steps
        steps = self._generate_steps(
            vuln_type, url, method, payload, details
        )
        
        poc = PoC(
            vuln_type=vuln_type,
            title=f"{vuln_type} at {urlparse(url).netloc}",
            curl_command=curl_cmd,
            python_script=python_script,
            html_poc=html_poc,
            steps=steps,
            cvss_score=cvss_data["score"],
            cvss_vector=cvss_data["vector"],
            cwe_id=cvss_data["cwe"],
            owasp_category=cvss_data["owasp"]
        )
        
        self.pocs.append(poc)
        return poc
    
    def _generate_curl(
        self,
        url: str,
        method: str,
        headers: Dict,
        body: Optional[str],
        cookies: Dict
    ) -> str:
        """Generate cURL command."""
        parts = [f"curl -X {method}"]
        
        # Add headers
        for key, value in headers.items():
            parts.append(f"-H '{key}: {value}'")
        
        # Add cookies
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            parts.append(f"-H 'Cookie: {cookie_str}'")
        
        # Add body
        if body:
            parts.append(f"-d '{body}'")
        
        # Add URL (quoted)
        parts.append(f"'{url}'")
        
        return " \\\n  ".join(parts)
    
    def _generate_python(
        self,
        vuln_type: str,
        url: str,
        method: str,
        headers: Dict,
        body: Optional[str],
        cookies: Dict,
        payload: str
    ) -> str:
        """Generate Python exploit script."""
        script = f'''#!/usr/bin/env python3
"""
{vuln_type} Exploit PoC
Generated by Lynx VAPT

Target: {url}
Payload: {payload[:100]}
"""

import requests
import sys

# Disable SSL warnings (for testing only)
import urllib3
urllib3.disable_warnings()


def exploit(target_url):
    """
    Exploit the {vuln_type} vulnerability.
    """
    
    headers = {json.dumps(headers, indent=8)}
    
    cookies = {json.dumps(cookies, indent=8)}
    
'''
        
        if method.upper() == "GET":
            script += f'''    response = requests.get(
        target_url,
        headers=headers,
        cookies=cookies,
        verify=False,
        timeout=30
    )
'''
        else:
            body_repr = repr(body) if body else "None"
            script += f'''    data = {body_repr}
    
    response = requests.{method.lower()}(
        target_url,
        headers=headers,
        cookies=cookies,
        data=data,
        verify=False,
        timeout=30
    )
'''
        
        script += '''
    print(f"[*] Status Code: {response.status_code}")
    print(f"[*] Response Length: {len(response.text)}")
    
    # Check for success indicators
    indicators = ['''
        
        # Add vulnerability-specific indicators
        if "SQL" in vuln_type:
            script += '''
        "syntax error", "mysql", "postgresql", "ORA-",
        "SQL", "database", "query"'''
        elif "XSS" in vuln_type:
            script += '''
        "<script>", "alert(", "onerror", "javascript:"'''
        elif "Command" in vuln_type or "RCE" in vuln_type:
            script += '''
        "uid=", "root:", "bin/", "Windows"'''
        else:
            script += '''
        "error", "success", "admin"'''
        
        script += '''
    ]
    
    for indicator in indicators:
        if indicator.lower() in response.text.lower():
            print(f"[+] VULNERABLE! Found indicator: {indicator}")
            return True
    
    print("[-] No clear indicator found. Manual verification needed.")
    return False


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "''' + url + '''"
    print(f"[*] Targeting: {target}")
    exploit(target)
'''
        
        return script
    
    def _generate_html(
        self,
        vuln_type: str,
        url: str,
        method: str,
        headers: Dict,
        body: Optional[str],
        payload: str
    ) -> str:
        """Generate HTML PoC page."""
        escaped_url = html.escape(url)
        escaped_payload = html.escape(payload)
        
        if "XSS" in vuln_type or "CORS" in vuln_type:
            # XSS/CORS PoC
            return f'''<!DOCTYPE html>
<html>
<head>
    <title>{vuln_type} PoC - Lynx VAPT</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #e94560; }}
        .result {{ background: #16213e; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        button {{ background: #e94560; color: white; border: none; padding: 10px 20px; 
                 border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #ff6b6b; }}
        pre {{ background: #0f0f23; padding: 15px; overflow-x: auto; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>🔓 {vuln_type} Proof of Concept</h1>
    <p><strong>Target:</strong> {escaped_url}</p>
    <p><strong>Payload:</strong> <code>{escaped_payload}</code></p>
    
    <button onclick="runExploit()">▶ Run Exploit</button>
    
    <div id="result" class="result" style="display:none;">
        <h3>Result:</h3>
        <pre id="output"></pre>
    </div>
    
    <script>
        function runExploit() {{
            document.getElementById('result').style.display = 'block';
            var output = document.getElementById('output');
            output.textContent = 'Executing exploit...\\n';
            
            // CORS-based fetch (for CORS misconfiguration)
            fetch('{escaped_url}', {{
                method: 'GET',
                credentials: 'include'
            }})
            .then(response => response.text())
            .then(data => {{
                output.textContent += 'Response received:\\n' + data.substring(0, 500);
            }})
            .catch(error => {{
                output.textContent += 'Error: ' + error.message;
            }});
        }}
    </script>
</body>
</html>'''
        
        elif "CSRF" in vuln_type:
            # CSRF PoC
            parsed = urlparse(url)
            if body:
                form_fields = ""
                try:
                    params = parse_qs(body)
                    for key, values in params.items():
                        for value in values:
                            form_fields += f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value)}" />\n'
                except Exception:
                    form_fields = f'<input type="hidden" name="data" value="{html.escape(body)}" />'
            else:
                form_fields = ""
            
            return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - Lynx VAPT</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This page automatically submits a form to the target.</p>
    
    <form id="csrf_form" action="{escaped_url}" method="{method}">
        {form_fields}
    </form>
    
    <script>
        // Auto-submit on page load
        // document.getElementById('csrf_form').submit();
        
        // Or click button to submit:
        console.log('CSRF form ready. Uncomment auto-submit or add a button.');
    </script>
</body>
</html>'''
        
        else:
            # Generic PoC
            return f'''<!DOCTYPE html>
<html>
<head>
    <title>{vuln_type} PoC - Lynx VAPT</title>
    <style>
        body {{ font-family: monospace; margin: 40px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #e94560; }}
        pre {{ background: #0f0f23; padding: 15px; overflow-x: auto; }}
        a {{ color: #4ecdc4; }}
    </style>
</head>
<body>
    <h1>🔓 {vuln_type} PoC</h1>
    <p><strong>Target:</strong> <a href="{escaped_url}">{escaped_url}</a></p>
    <p><strong>Payload:</strong></p>
    <pre>{escaped_payload}</pre>
    
    <h2>Exploitation</h2>
    <p>Click the link below to trigger the vulnerability:</p>
    <p><a href="{escaped_url}" target="_blank">Execute Payload →</a></p>
    
    <h2>cURL Command</h2>
    <pre>curl '{escaped_url}'</pre>
</body>
</html>'''
    
    def _generate_steps(
        self,
        vuln_type: str,
        url: str,
        method: str,
        payload: str,
        details: str
    ) -> List[str]:
        """Generate reproduction steps."""
        steps = [
            f"1. Navigate to the target application",
            f"2. Identify the vulnerable endpoint: {url}",
            f"3. Inject the following payload: {payload[:100]}",
        ]
        
        if "SQL" in vuln_type:
            steps.extend([
                "4. Observe SQL error messages or altered behavior",
                "5. Extract data using UNION-based or blind techniques",
                "6. Escalate to full database access if possible"
            ])
        elif "XSS" in vuln_type:
            steps.extend([
                "4. Observe the payload being reflected in the response",
                "5. Confirm JavaScript execution in browser console",
                "6. Demonstrate cookie theft or session hijacking"
            ])
        elif "Command" in vuln_type or "RCE" in vuln_type:
            steps.extend([
                "4. Observe command output in response",
                "5. Attempt to execute system commands (id, whoami)",
                "6. Escalate to reverse shell if possible"
            ])
        elif "SSRF" in vuln_type:
            steps.extend([
                "4. Confirm the server makes requests to attacker-controlled server",
                "5. Attempt to access internal services (127.0.0.1, 169.254.169.254)",
                "6. Exfiltrate sensitive data from internal network"
            ])
        else:
            steps.extend([
                "4. Observe the application's response to the payload",
                "5. Confirm the vulnerability is exploitable",
                "6. Document the impact and potential data exposure"
            ])
        
        if details:
            steps.append(f"Additional notes: {details[:200]}")
        
        return steps
    
    def get_cvss_data(self, vuln_type: str) -> Dict[str, Any]:
        """Get CVSS data for a vulnerability type."""
        return VULN_CVSS_DATA.get(vuln_type, VULN_CVSS_DATA["Default"])
    
    def generate_report_section(self, vuln: Dict) -> str:
        """Generate a report section for a vulnerability."""
        poc = self.generate(
            vuln_type=vuln.get("type", "Unknown"),
            url=vuln.get("url", ""),
            payload=vuln.get("payload", ""),
            method=vuln.get("method", "GET"),
            details=vuln.get("details", "")
        )
        
        return f"""
## {poc.title}

**CVSS Score:** {poc.cvss_score} ({poc.cvss_vector})
**CWE:** {poc.cwe_id}
**OWASP:** {poc.owasp_category}

### Reproduction Steps
{"".join(f"{step}\\n" for step in poc.steps)}

### cURL Command
```bash
{poc.curl_command}
```

### Python Exploit
```python
{poc.python_script[:1500]}...
```
"""


# Global instance
poc_generator = PoCGenerator()


def generate_poc(
    vuln_type: str,
    url: str,
    payload: str,
    **kwargs
) -> PoC:
    """
    Convenience function to generate a PoC.
    """
    return poc_generator.generate(vuln_type, url, payload, **kwargs)
