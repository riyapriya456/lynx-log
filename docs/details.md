# 🔍 JavaScript Analyzer Scanner - Complete Documentation

> **A comprehensive JavaScript security analysis tool for the Lynx VAPT Framework**

The JavaScript Analyzer Scanner is a powerful module that performs deep analysis of JavaScript files to discover security issues, extract valuable information, and identify potential vulnerabilities in modern web applications.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [How It Works](#how-it-works)
4. [Detection Capabilities](#detection-capabilities)
5. [Use Cases](#use-cases)
6. [Output Format](#output-format)
7. [Integration Guide](#integration-guide)
8. [Security Benefits](#security-benefits)

---

## Overview

Modern web applications heavily rely on JavaScript for their functionality. This creates unique security challenges:

- **Exposed Secrets**: API keys, tokens, and credentials often end up in client-side code
- **Hidden Endpoints**: Internal APIs and admin routes may be discoverable through JS analysis
- **Client-Side Vulnerabilities**: XSS, prototype pollution, and other JS-specific vulnerabilities
- **Logic Disclosure**: Business logic and access control mechanisms are visible to attackers

The JS Analyzer Scanner addresses these challenges by performing automated, comprehensive analysis of all JavaScript files associated with a target.

---

## Key Features

### 🎯 Dual Input Mode
| Mode | Description | Example |
|------|-------------|---------|
| **Direct JS URL** | Analyze a single JavaScript file | `python lynx.py -u "https://example.com/bundle.js" --scanners js_analyzer` |
| **Website Crawl** | Discover and analyze all JS files from a webpage | `python lynx.py -u "https://example.com" --scanners js_analyzer --crawl` |

The scanner automatically detects the input type based on URL patterns.

---

### 🔐 Secret & API Key Detection

Detects **40+ types** of secrets and credentials:

#### Cloud Provider Credentials
| Secret Type | Pattern Example |
|-------------|-----------------|
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | Keys matching AWS secret format |
| Google API Key | `AIzaSyC...` |
| Azure Storage | Connection strings |
| GCP Service Account | Service account JSON |

#### Authentication Tokens
| Token Type | Pattern Example |
|------------|-----------------|
| GitHub Token | `ghp_xxxxxxxxxxxx` |
| GitLab Token | `glpat-xxxxxxxxxx` |
| Slack Token | `xoxb-xxxxxxxxxx` |
| JWT Token | `eyJhbGciOiJ...` |
| Bearer Token | `Bearer xxxxx` |

#### Payment & Financial
| Secret Type | Pattern Example |
|-------------|-----------------|
| Stripe API Key | `sk_live_xxxxxxxxxx` |
| PayPal Client ID | PayPal credentials |

#### Database & Infrastructure
| Secret Type | Pattern Example |
|-------------|-----------------|
| MongoDB URI | `mongodb://user:pass@host` |
| PostgreSQL URI | `postgres://...` |
| Redis URI | `redis://...` |

#### Generic Patterns
- API Keys with common naming patterns
- Hardcoded passwords
- Base64-encoded credentials
- Private keys (RSA, EC, DSA)

---

### 🌐 Endpoint Extraction

Discovers **all types of API endpoints**:

| Endpoint Type | Description |
|---------------|-------------|
| **REST APIs** | `/api/v1/users`, `/v2/products` |
| **GraphQL** | `/graphql`, `/gql` endpoints |
| **WebSocket** | `wss://` and `ws://` URLs |
| **Fetch/Axios** | URLs from fetch() and axios calls |
| **XMLHttpRequest** | Legacy AJAX endpoints |
| **Dynamic URLs** | Template literals and concatenated URLs |

**Example Findings:**
```
- /api/v1/users (REST API)
- /api/admin/dashboard (REST API)  
- wss://realtime.example.com/socket (WebSocket)
- /graphql (GraphQL)
```

---

### ⚛️ React-Specific Analysis

**For React applications**, the scanner detects:

| Pattern | Description | Security Relevance |
|---------|-------------|-------------------|
| **useEffect API Calls** | Data fetching in effects | Identifies API integration points |
| **useState** | State management | Shows data flow patterns |
| **Redux Dispatch** | State actions | Exposes action types and logic |
| **Router Paths** | Application routes | Reveals hidden pages/admin areas |
| **Custom Hooks** | Reusable logic | May contain auth/API logic |
| **Context Providers** | Global state | Shows data sharing patterns |
| **Lazy Loading** | Code splitting | Identifies additional JS bundles |

**Why This Matters:**
- Discover admin routes: `/dashboard`, `/admin`, `/internal`
- Find authentication flow logic
- Identify state that controls access

---

### 💾 Storage Method Detection

Tracks all **client-side storage operations**:

| Storage Type | Operations Detected |
|--------------|---------------------|
| **localStorage** | setItem, getItem, removeItem |
| **sessionStorage** | setItem, getItem |
| **Cookies** | document.cookie, js-cookie library |
| **IndexedDB** | Database open operations |

**Security Implications:**
- Sensitive tokens stored in localStorage
- Session data without httpOnly flag
- Unencrypted PII in client storage

**Example Output:**
```
Storage Operations Found:
- localStorage.setItem("authToken", ...) 
- sessionStorage.setItem("user_data", ...)
- Cookies.set("session_id", ...)
```

---

### 🛡️ Vulnerability Detection

Detects **25+ vulnerability patterns**:

#### Critical (P1)
| Vulnerability | Pattern | Risk |
|---------------|---------|------|
| **eval() Usage** | `eval(userInput)` | Remote Code Execution |
| **Hardcoded Secrets** | `password = "secret123"` | Credential Exposure |
| **Private Keys** | PEM-formatted keys | Full System Compromise |

#### High (P2)
| Vulnerability | Pattern | Risk |
|---------------|---------|------|
| **innerHTML Assignment** | `el.innerHTML = data` | XSS |
| **document.write** | `document.write(html)` | XSS |
| **Prototype Pollution** | `__proto__` access | Object Manipulation |
| **postMessage Issues** | No origin verification | Cross-Origin Attacks |
| **Function Constructor** | `new Function(code)` | Code Injection |

#### Medium (P3)
| Vulnerability | Pattern | Risk |
|---------------|---------|------|
| **Insecure Randomness** | `Math.random()` | Predictable Values |
| **HTTP URLs** | Non-HTTPS links | Data Interception |
| **Open Redirect** | URL params in location | Phishing |
| **CORS Wildcard** | `Access-Control-Allow-Origin: *` | Data Theft |
| **Debugger Statement** | `debugger` | Development Code |

#### Low (P4)
| Vulnerability | Pattern | Risk |
|---------------|---------|------|
| **Console Logging** | `console.log()` | Information Leak |
| **TODO Comments** | Unfinished code | Quality Issue |
| **Alert Dialogs** | `alert()`, `confirm()` | UX/Debug Code |

---

### 🔄 Request Condition Analysis

Identifies **client-side access control logic** (bypass targets):

| Condition Type | Pattern Example | Bypass Potential |
|----------------|-----------------|------------------|
| **Auth Token Check** | `if (token) { ... }` | Token manipulation |
| **Role-Based Access** | `if (isAdmin) { ... }` | Role tampering |
| **Feature Flags** | `if (config.feature) { ... }` | Flag override |
| **Environment Check** | `process.env.API_URL` | Env discovery |
| **Rate Limit Logic** | `rateLimit()` | Client bypass |

**Why This Matters:**
> Client-side checks can ALWAYS be bypassed. Finding these patterns reveals what the server should be enforcing.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                     INPUT HANDLING                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│    URL Input ──► Is .js file? ──► YES ──► Direct Fetch          │
│                      │                                           │
│                      NO                                          │
│                      ▼                                           │
│               Crawl HTML Page                                    │
│                      │                                           │
│                      ▼                                           │
│           Extract <script src="...">                             │
│                      │                                           │
│                      ▼                                           │
│            Collect All JS URLs                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ANALYSIS ENGINE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  For each JS file:                                               │
│    ├── Secret Scanner (40+ regex patterns)                      │
│    ├── Endpoint Extractor (REST, GraphQL, WS)                   │
│    ├── Storage Detector (localStorage, cookies)                 │
│    ├── React Analyzer (hooks, routes, state)                    │
│    ├── Vulnerability Scanner (eval, XSS, etc.)                  │
│    └── Condition Analyzer (auth checks, roles)                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     OUTPUT GENERATION                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  • Deduplicated findings                                         │
│  • Severity classification (P1-P4)                               │
│  • Line number hints                                             │
│  • Code context snippets                                         │
│  • Reproducibility instructions                                  │
│  • Remediation guidance                                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Use Cases

### 🔴 Bug Bounty Hunting

**Scenario:** Find sensitive information and vulnerabilities in a target's JavaScript

```bash
# Analyze all JS files on target
python lynx.py -u "https://target.com" --scanners js_analyzer --crawl

# Analyze specific bundle
python lynx.py -u "https://target.com/static/js/main.abc123.js" --scanners js_analyzer
```

**What You'll Find:**
- Leaked API keys and tokens
- Hidden admin endpoints
- Internal API documentation URLs
- Debug code and test credentials

---

### 🟡 Penetration Testing

**Scenario:** Map attack surface and identify entry points

```bash
python lynx.py -u "https://client-app.com" --scanners js_analyzer --crawl
```

**Useful Outputs:**
- All API endpoints for fuzzing
- Authentication flow logic
- Client-side access control to bypass
- WebSocket endpoints for testing

---

### 🟢 Security Code Review

**Scenario:** Review a React application for security issues

```bash
python lynx.py -u "https://staging.company.com" --scanners js_analyzer --crawl
```

**Checklist Items Covered:**
- [ ] No hardcoded secrets
- [ ] No dangerous DOM operations
- [ ] Proper localStorage usage
- [ ] Server-side validation for all client checks

---

### 🔵 DevSecOps Integration

**Scenario:** Automated security scanning in CI/CD

```bash
# In CI pipeline - scan production bundle
python lynx.py -u "https://cdn.company.com/app.bundle.js" --scanners js_analyzer
```

**Alerts On:**
- Any P1/P2 findings fail the build
- Secret leaks trigger immediate notification
- New endpoints detected for documentation

---

## Output Format

### Console Output
```
[JSAnalyzerScanner] Starting JavaScript analysis...
[JSAnalyzerScanner] Found JS: https://example.com/bundle.js
[JSAnalyzerScanner] Analyzing: https://example.com/bundle.js
[P1] Secret Leaked found in ZONE_C!
[P2] JS Vulnerability: innerHTML Assignment found in ZONE_C!
[P4] API Endpoint Found found in ZONE_C!
[JSAnalyzerScanner] JavaScript analysis complete.
```

### Report Finding Example

```json
{
  "type": "Secret Leaked",
  "severity": "P1",
  "url": "https://example.com/bundle.js",
  "details": "**AWS Access Key** found in JavaScript file.\n\n**Value:** `AKIAIOSFODNN7EXAMPLE`\n**Location:** ~Line 1547\n**Context:** `const aws = { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey...`\n**Reproducibility:** Search for 'AKIAIOSFODNN7EX...' in the JS file.",
  "remediation": "Remove hardcoded AWS Access Key. Use environment variables or a secrets manager.",
  "scanner": "JSAnalyzerScanner"
}
```

---

## Integration Guide

### Basic Usage

```bash
# Scan with JS analyzer only
python lynx.py -u "https://target.com" --scanners js_analyzer --crawl

# Include JS analyzer with other scanners
python lynx.py -u "https://target.com" --scanners xss,sqli,js_analyzer --crawl
```

### Programmatic Usage

```python
from scanners import JSAnalyzerScanner
from core import ScanContext

# Initialize scanner
scanner = JSAnalyzerScanner(context)

# Run analysis
await scanner.run()

# Access findings via context.findings
```

### Custom Pattern Addition

Add custom patterns by modifying `js_analyzer.py`:

```python
# In __init__
self.secret_patterns["Custom Token"] = r'CUSTOM_[A-Z0-9]{32}'
```

---

## Security Benefits

### For Organizations

| Benefit | Description |
|---------|-------------|
| **Prevent Data Breaches** | Catch leaked credentials before attackers |
| **Reduce Attack Surface** | Identify and remove unnecessary endpoints |
| **Compliance** | Meet requirements for secret management |
| **Code Quality** | Remove debug code from production |

### For Security Researchers

| Benefit | Description |
|---------|-------------|
| **Faster Recon** | Automated extraction of attack surface |
| **Higher Impact Findings** | Focus on secrets and critical vulns |
| **Better Reports** | Detailed context and PoC for each finding |
| **Comprehensive Coverage** | Don't miss hidden endpoints or logic |

### For Developers

| Benefit | Description |
|---------|-------------|
| **Pre-Production Checks** | Catch issues before deployment |
| **Security Awareness** | Learn about common JS security mistakes |
| **Code Review Aid** | Automated security checklist |

---

## False Positive Handling

The scanner includes intelligent filtering:

- **Placeholder Detection**: Skips `YOUR_API_KEY`, `xxx`, `example`, `test` values
- **CDN Filtering**: Optionally excludes known CDN URLs
- **Duplicate Removal**: Deduplicates findings by value and location
- **Context Validation**: Verifies patterns are in actual code, not comments

---

## Limitations

| Limitation | Workaround |
|------------|------------|
| **Minified Code** | Line numbers are approximate |
| **Dynamic Loading** | May miss runtime-loaded scripts |
| **Obfuscated Code** | Reduced pattern matching accuracy |
| **SPA Routing** | Crawl with `--crawl` flag for better coverage |

---

## Version History

| Version | Changes |
|---------|---------|
| **1.0.0** | Initial release with full feature set |

---

## Contributing

To add new detection patterns:

1. Identify the pattern category (secrets, endpoints, vulns, etc.)
2. Add regex pattern to appropriate dictionary in `__init__`
3. Test against known samples
4. Submit for review

---

## License

Part of the Lynx VAPT Framework. See main LICENSE file.

---

> **📧 Questions?** Open an issue or reach out to the Lynx team.
