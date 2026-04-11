import os
import datetime
import html
import urllib.parse
import re
from jinja2 import Environment, FileSystemLoader, select_autoescape
from common import console, VERSION

VULN_DB = {
    "SQL Injection": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)",
        "impact_cat": "Data Integrity & Confidentiality",
        "summary": "The application allows untrusted user input to interfere with database queries. This was found in a URL parameter or form field. It is dangerous because it allows attackers to view, modify, or delete database data.",
        "technical": "The application constructs SQL queries by concatenating user input directly into the query string without validation or parameterization. This allows an attacker to inject malicious SQL tokens to alter the query logic.",
        "impact_analysis": "Technical: Full database compromise, data exfiltration, authentication bypass.\nBusiness: Severe data breach, regulatory fines (GDPR/CCPA), loss of customer trust.",
        "risk_justification": "Rated P1 (Critical) due to high impact (data loss) and high exploitability (often automated).",
        "remediation": "Use parameterized queries (Prepared Statements) for all database access. Validate and sanitize all user inputs.",
        "validation": "Retest with the same payload. Ensure the application returns a standard error or handles the input safely without executing the SQL.",
        "references": "OWASP Top 10: A03:2021-Injection, CWE-89"
    },
    "Reflected XSS": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1 Medium)",
        "impact_cat": "Client-Side Injection",
        "summary": "The application reflects user input in the HTTP response without proper escaping. Found in a URL parameter. Dangerous as it allows execution of malicious scripts in the victim's browser.",
        "technical": "The application takes data from the request (e.g., query parameter) and outputs it to the DOM or HTML body without HTML entity encoding. This allows <script> tags or event handlers to execute.",
        "impact_analysis": "Technical: Session hijacking, cookie theft, redirection to phishing sites.\nBusiness: Account takeover of users, reputation damage.",
        "risk_justification": "Rated P2 (High) as it requires user interaction (phishing) but can lead to full account compromise.",
        "remediation": "Sanitize all user inputs and use proper HTML entity encoding when rendering user data. Implement a strong Content Security Policy (CSP).",
        "validation": "Retest with the same payload. Ensure the application HTML-encodes the output or blocks the request.",
        "references": "OWASP Top 10: A03:2021-Injection, CWE-79"
    },
    "CMS Vulnerability": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L (5.3 Medium)",
        "impact_cat": "Security Misconfiguration",
        "summary": "A vulnerability or misconfiguration was detected in the Content Management System (CMS).",
        "technical": "The scanner identified a CMS (e.g., WordPress, Shopify) and found exposed version info, login pages, or known paths.",
        "impact_analysis": "Technical: Information disclosure, potential for known exploits.\nBusiness: Increased attack surface.",
        "risk_justification": "Rated P3/P4 depending on the finding.",
        "remediation": "Update CMS to latest version, hide version headers, and restrict access to admin panels.",
        "validation": "Verify the finding manually.",
        "references": "OWASP Top 10: A06:2021-Vulnerable and Outdated Components"
    },
    "403 Bypass": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N (5.3 Medium)",
        "impact_cat": "Security Misconfiguration",
        "summary": "Access control bypass detected on a restricted endpoint (403/401).",
        "technical": "The scanner successfully accessed a restricted page by manipulating HTTP headers (e.g., X-Forwarded-For) or the URL structure.",
        "impact_analysis": "Technical: Unauthorized access to admin panels or internal APIs.\nBusiness: Data breach, unauthorized actions.",
        "risk_justification": "Rated P1 (Critical) if sensitive data is exposed.",
        "remediation": "Configure the web server to ignore unauthorized proxy headers and enforce strict URL matching.",
        "validation": "Reproduce with the specific header or URL modification.",
        "references": "OWASP Top 10: A01:2021-Broken Access Control"
    },
    "Secret Leaked": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5 High)",
        "impact_cat": "Information Disclosure",
        "summary": "A sensitive secret (API Key, Access Token, Private Key) was found hardcoded in the response. Found in the HTML source or JS file. Dangerous as it allows unauthorized access to third-party services or internal systems.",
        "technical": "Developers have accidentally committed secrets to the codebase or included them in client-side assets. The scanner identified a pattern matching a known secret format.",
        "impact_analysis": "Technical: Unauthorized API access, potential data leakage, billing abuse.\nBusiness: Financial loss, data breach, unauthorized access to cloud resources.",
        "risk_justification": "Rated P1 (Critical) if the key is active and high-privilege. P2/P3 if low privilege.",
        "remediation": "Revoke the exposed key immediately. Remove the key from the code and use environment variables or a secrets manager. Rotate all related secrets.",
        "validation": "Verify the key is no longer in the source code. Attempt to use the revoked key to ensure it is invalid.",
        "references": "OWASP Top 10: A05:2021-Security Misconfiguration, CWE-798"
    },
    # ==================== JS ANALYZER FINDINGS ====================
    "API Endpoint Found": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (4.0 Medium)",
        "impact_cat": "Information Disclosure",
        "summary": "API endpoints were discovered in JavaScript files. These endpoints reveal the application's API structure and may include internal or undocumented routes.",
        "technical": "The JavaScript analyzer extracted URLs from fetch(), axios, and other HTTP client calls. These endpoints may include REST APIs, GraphQL endpoints, and WebSocket connections.",
        "impact_analysis": "Technical: Attack surface mapping, potential for unauthorized API access.\nBusiness: Internal APIs may expose sensitive functionality.",
        "risk_justification": "Rated P4 (Informational) - useful for reconnaissance and further testing.",
        "remediation": "Ensure all discovered endpoints have proper authentication and authorization. Consider API gateway protection.",
        "validation": "Test each endpoint for proper access controls and authentication requirements.",
        "references": "OWASP API Security Top 10"
    },
    "Client Storage Usage": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (4.0 Medium)",
        "impact_cat": "Information Disclosure",
        "summary": "The application uses client-side storage (localStorage, sessionStorage, cookies) to store data. Sensitive data stored here may be accessible to attackers via XSS.",
        "technical": "The scanner identified localStorage.setItem(), sessionStorage.setItem(), and cookie operations in JavaScript. Data stored client-side is accessible via browser DevTools.",
        "impact_analysis": "Technical: If XSS exists, stored tokens/data can be exfiltrated.\nBusiness: Session hijacking, data theft if sensitive info is stored.",
        "risk_justification": "Rated P4 (Informational) unless sensitive data like tokens are stored without httpOnly protection.",
        "remediation": "Avoid storing sensitive data in localStorage. Use httpOnly cookies for session tokens. Encrypt sensitive data before storing.",
        "validation": "Check browser DevTools > Application > Storage for sensitive values.",
        "references": "OWASP Cheat Sheet: HTML5 Security"
    },
    "React Application Analysis": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (3.0 Low)",
        "impact_cat": "Information Disclosure",
        "summary": "React-specific patterns were detected in the application's JavaScript. This includes routing, state management, and component logic.",
        "technical": "The analyzer identified React patterns including useEffect hooks, useState, Redux dispatch, React Router paths, and custom hooks.",
        "impact_analysis": "Technical: Application structure disclosure, potential hidden routes discovery.\nBusiness: Enhanced understanding of application logic.",
        "risk_justification": "Rated P4 (Informational) - useful for understanding application architecture.",
        "remediation": "Review React patterns for security implications. Ensure sensitive logic is server-side.",
        "validation": "Manually review identified patterns for security concerns.",
        "references": "React Security Best Practices"
    },
    "Client-Side Access Control": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N (5.3 Medium)",
        "impact_cat": "Broken Access Control",
        "summary": "Client-side access control logic was detected. These checks can be bypassed as they execute in the user's browser.",
        "technical": "The scanner found conditional logic checking tokens, roles, or permissions in JavaScript. Client-side checks should never be the sole access control mechanism.",
        "impact_analysis": "Technical: Complete bypass of client-side restrictions.\nBusiness: Unauthorized access to restricted features.",
        "risk_justification": "Rated P4 (Informational) for detection, but may be P2 if server lacks validation.",
        "remediation": "Always implement server-side access control. Client-side checks should be UX-only.",
        "validation": "Attempt to access restricted features by modifying client-side variables.",
        "references": "OWASP Top 10: A01:2021-Broken Access Control"
    },
    "JS Vulnerability: eval Usage": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.0 Critical)",
        "impact_cat": "Code Injection",
        "summary": "The JavaScript code uses eval() which can execute arbitrary code. If user input reaches eval(), it leads to Remote Code Execution.",
        "technical": "eval() parses and executes a string as JavaScript code. If an attacker can control the string, they can execute arbitrary code in the browser context.",
        "impact_analysis": "Technical: XSS, data theft, session hijacking, malware delivery.\nBusiness: Full client-side compromise, reputation damage.",
        "risk_justification": "Rated P1 (Critical) if user input can reach eval(). P2 otherwise.",
        "remediation": "Remove eval() usage. Use JSON.parse() for JSON data. Avoid dynamic code execution.",
        "validation": "Trace data flow to eval() and test with controlled payloads.",
        "references": "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"
    },
    "JS Vulnerability: innerHTML Assignment": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1 Medium)",
        "impact_cat": "Client-Side Injection",
        "summary": "The code assigns to innerHTML which can execute scripts if the content contains HTML. This is a common XSS vector.",
        "technical": "innerHTML parses the assigned string as HTML. If the string contains <script> tags or event handlers, they will execute.",
        "impact_analysis": "Technical: DOM-based XSS, script injection.\nBusiness: Session hijacking, phishing attacks.",
        "risk_justification": "Rated P2 (High) - common and easily exploitable XSS vector.",
        "remediation": "Use textContent instead of innerHTML. If HTML is needed, sanitize with DOMPurify.",
        "validation": "Test by injecting HTML payloads into the data source.",
        "references": "CWE-79: Improper Neutralization of Input During Web Page Generation"
    },
    "JS Vulnerability: Prototype Pollution": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N (7.2 High)",
        "impact_cat": "Object Manipulation",
        "summary": "The code directly accesses __proto__ or prototype properties which can lead to prototype pollution attacks.",
        "technical": "Prototype pollution allows attackers to inject properties into Object.prototype, affecting all objects in the application.",
        "impact_analysis": "Technical: Property injection, potential RCE in Node.js, logic bypass.\nBusiness: Application compromise, security control bypass.",
        "risk_justification": "Rated P2 (High) due to widespread impact when exploited.",
        "remediation": "Use Object.create(null) for dictionaries. Validate object keys. Use Object.freeze().",
        "validation": "Test with __proto__ pollution payloads.",
        "references": "CWE-1321: Improperly Controlled Modification of Object Prototype Attributes"
    },
    "DEFAULT": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L (5.0 Medium)",
        "impact_cat": "Security Misconfiguration",
        "summary": "A security issue was identified in the application configuration or logic.",
        "technical": "The application fails to implement standard security controls or validation.",
        "impact_analysis": "Technical: Varies based on vulnerability.\nBusiness: Increased attack surface.",
        "risk_justification": "Rated based on standard severity mapping.",
        "remediation": "Apply security best practices relevant to the specific issue.",
        "validation": "Retest to confirm the issue is resolved.",
        "references": "OWASP Top 10"
    },
    "Local File Inclusion": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5 High)",
        "impact_cat": "Input Validation",
        "summary": "The application allows reading arbitrary files from the server via path traversal.",
        "technical": "User input is used in file operations without proper validation, allowing directory traversal sequences.",
        "impact_analysis": "Technical: Source code disclosure, credential theft, system file access.\nBusiness: Data breach, compliance violations.",
        "risk_justification": "Rated P2 (High) due to direct file system access.",
        "remediation": "Validate file paths against a whitelist. Use indirect references. Never use user input directly in file operations.",
        "validation": "Retest with path traversal payloads. Verify server rejects unauthorized paths.",
        "references": "CWE-22, OWASP Top 10: A01:2021"
    },
    "CSRF Missing": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N (6.5 Medium)",
        "impact_cat": "Broken Access Control",
        "summary": "State-changing forms lack anti-CSRF tokens, allowing cross-site request forgery attacks.",
        "technical": "POST forms do not include CSRF tokens, allowing attackers to forge requests on behalf of authenticated users.",
        "impact_analysis": "Technical: Unauthorized actions performed as authenticated user.\nBusiness: Account compromise, data manipulation.",
        "risk_justification": "Rated P2 for sensitive forms, P3 otherwise.",
        "remediation": "Implement anti-CSRF tokens in all state-changing forms. Use SameSite cookie attribute.",
        "validation": "Create an HTML form that submits to the vulnerable endpoint. Verify the action completes without a valid token.",
        "references": "CWE-352, OWASP Top 10: A01:2021"
    },
    "Potential SSRF": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N (8.6 High)",
        "impact_cat": "Server-Side Request Forgery",
        "summary": "The application may fetch user-supplied URLs, enabling access to internal resources.",
        "technical": "User-controlled URLs are used in server-side requests without proper validation.",
        "impact_analysis": "Technical: Internal network scanning, cloud metadata access, service enumeration.\nBusiness: Critical infrastructure exposure.",
        "risk_justification": "Rated P2 (High) due to potential internal access.",
        "remediation": "Validate all user-supplied URLs. Block internal IP ranges. Use allowlists for permitted domains.",
        "validation": "Supply internal URLs (127.0.0.1, metadata endpoints) and check for responses.",
        "references": "CWE-918, OWASP Top 10: A10:2021"
    },
    "Potential IDOR": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5 Medium)",
        "impact_cat": "Broken Access Control",
        "summary": "Modifying object references may allow unauthorized access to other users' data.",
        "technical": "The application uses user-supplied IDs to access resources without proper authorization checks.",
        "impact_analysis": "Technical: Unauthorized data access across user accounts.\nBusiness: Privacy violations, regulatory fines.",
        "risk_justification": "Rated P2 (High) when sensitive data exposed.",
        "remediation": "Implement proper authorization checks. Verify user ownership of requested resources. Use indirect references.",
        "validation": "Access resources with modified IDs. Verify proper authorization is enforced.",
        "references": "CWE-639, OWASP Top 10: A01:2021"
    },
    "Open Redirect": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1 Medium)",
        "impact_cat": "Input Validation",
        "summary": "The application redirects users to attacker-controlled URLs.",
        "technical": "Redirect parameters accept arbitrary URLs without validation.",
        "impact_analysis": "Technical: Phishing attacks, credential theft.\nBusiness: Reputation damage, user trust loss.",
        "risk_justification": "Rated P3 (Medium) - requires user interaction.",
        "remediation": "Validate redirect URLs against an allowlist. Use relative URLs.",
        "validation": "Supply external URLs in redirect parameters and verify redirection occurs.",
        "references": "CWE-601"
    },
    "DOM/Reflected XSS (Selenium Verified)": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H (9.6 Critical)",
        "impact_cat": "Code Injection",
        "summary": "XSS payload executed in browser, verified by Selenium WebDriver.",
        "technical": "User input is reflected in the page and executed as JavaScript without sanitization.",
        "impact_analysis": "Technical: Full account takeover, session hijacking, malware delivery.\nBusiness: Complete user compromise, reputation damage.",
        "risk_justification": "Rated P1 (Critical) - verified exploitation.",
        "remediation": "Sanitize all user inputs. Implement CSP. Use textContent instead of innerHTML.",
        "validation": "Retest with same payload. Verify alert dialog no longer appears.",
        "references": "CWE-79, OWASP Top 10: A03:2021"
    },
    "Information Disclosure": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3 Medium)",
        "impact_cat": "Information Disclosure",
        "summary": "Sensitive information disclosed in responses.",
        "technical": "Version information, stack traces, debug data, or sensitive comments found in responses.",
        "impact_analysis": "Technical: Enables targeted attacks.\nBusiness: Increased risk of exploitation.",
        "risk_justification": "Rated P3 (Medium) to P4 (Low) depending on content.",
        "remediation": "Remove debug data, version info, and sensitive comments from responses.",
        "validation": "Review responses for information leakage.",
        "references": "CWE-200"
    },
    "Cookie Security": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3 Medium)",
        "impact_cat": "Security Misconfiguration",
        "summary": "Cookies lack proper security attributes.",
        "technical": "Session cookies missing HttpOnly, Secure, or SameSite attributes.",
        "impact_analysis": "Technical: Session hijacking via XSS or MITM.\nBusiness: Account compromise.",
        "risk_justification": "Rated P3 (Medium) - defense in depth.",
        "remediation": "Set HttpOnly, Secure, and SameSite on all session cookies.",
        "validation": "Verify cookie attributes in Set-Cookie headers.",
        "references": "CWE-614"
    }
}


class Reporter:
    def __init__(self, context):
        self.context = context
        self.template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

    def _sanitize_filename(self, name: str) -> str:
        """Remove dangerous characters from filename to prevent path traversal"""
        # Remove path traversal attempts and dangerous characters
        safe = re.sub(r'[\\/:*?"<>|]', '_', name)
        # Limit length to prevent filesystem issues
        return safe[:100]

    def _normalize_steps(self, steps):
        if not steps:
            return []
        if isinstance(steps, str):
            return [line.strip("- ").strip() for line in steps.splitlines() if line.strip()]
        if isinstance(steps, (list, tuple)):
            normalized = []
            for step in steps:
                if step is None:
                    continue
                text = str(step).strip()
                if text:
                    normalized.append(text)
            return normalized
        return [str(steps)]

    def _normalize_finding(self, finding: dict) -> dict:
        if not isinstance(finding, dict):
            return {}

        normalized = dict(finding)
        normalized["confidence"] = float(normalized.get("confidence", 0.6) or 0.6)
        normalized["reproduction_steps"] = self._normalize_steps(normalized.get("reproduction_steps"))

        evidence = normalized.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        normalized["evidence"] = evidence

        normalized["evidence_excerpt"] = normalized.get("response_excerpt") or evidence.get("response_excerpt") or normalized.get("details", "")
        normalized["observed_behavior"] = normalized.get("observed_behavior") or evidence.get("observed_behavior") or normalized.get("details", "")
        normalized["request_method"] = normalized.get("request_method") or evidence.get("request_method") or "GET"
        normalized["verification"] = normalized.get("verification") or evidence.get("verification") or "heuristic"
        return normalized

    def _finding_key(self, finding: dict) -> str:
        finding_type = finding.get("type", "Unknown")
        url = finding.get("url", "")
        payload = finding.get("payload", "")
        scanner = finding.get("scanner", "")
        return f"{finding_type}|{url}|{payload}|{scanner}"

    def _group_findings(self, vulns: list) -> dict:
        grouped = {}
        seen = set()
        for raw in vulns:
            finding = self._normalize_finding(raw)
            if not finding:
                continue
            key = self._finding_key(finding)
            if key in seen:
                continue
            seen.add(key)
            finding_type = finding.get('type', 'Unknown')
            grouped.setdefault(finding_type, []).append(finding)

        severity_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
        return dict(sorted(
            grouped.items(),
            key=lambda item: min(
                (severity_order.get(f.get("severity", "P4"), 99) for f in item[1]),
                default=99
            )
        ))

    def generate_report(self) -> str:
        try:
            template = self.env.get_template("report_template.html")
             
            vulns = self.context.findings
            target = self.context.target
            ai_summary = self.context.ai_summary
            normalized_vulns = [self._normalize_finding(v) for v in vulns if isinstance(v, dict)]
            grouped_findings = self._group_findings(normalized_vulns)
            deduped_vulns = [finding for findings in grouped_findings.values() for finding in findings]
            stats = {
                "P1": sum(1 for v in deduped_vulns if v.get('severity') == 'P1'),
                "P2": sum(1 for v in deduped_vulns if v.get('severity') == 'P2'),
                "P3": sum(1 for v in deduped_vulns if v.get('severity') == 'P3'),
                "P4": sum(1 for v in deduped_vulns if v.get('severity') == 'P4'),
                "Total": len(deduped_vulns),
                "AverageConfidence": round(
                    sum(v.get("confidence", 0.6) for v in deduped_vulns) / len(deduped_vulns), 2
                ) if deduped_vulns else 0.0,
            }

            html_content = template.render(
                target=target,
                date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                version=VERSION,
                stats=stats,
                grouped_findings=grouped_findings,
                vuln_db=VULN_DB,
                ai_summary=ai_summary,
                report_summary={
                    "total_findings": len(deduped_vulns),
                    "average_confidence": stats["AverageConfidence"],
                },
            )

            # Safely generate filename
            netloc = urllib.parse.urlparse(target).netloc
            safe_netloc = self._sanitize_filename(netloc)
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{safe_netloc}_{timestamp}.html"
            
            # Ensure file is created in current directory only
            filepath = os.path.join(os.getcwd(), filename)
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            return filename
            
        except Exception as e:
            console.print(f"[bold red]Error generating report:[/bold red] {e}")
            import traceback
            traceback.print_exc()
            return None
