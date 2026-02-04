import asyncio
import httpx
from dataclasses import dataclass
from typing import List, Dict
import re

@dataclass
class Vulnerability:
    url: str
    type: str  # "SQLi", "BOLA", "Exposure", "Misconfig", "InfoLeak"
    severity: str # "High", "Medium", "Low"
    details: str
    evidence: str = ""
    asvs: str = "" # e.g. "4.0.2"
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            from datetime import datetime
            self.timestamp = datetime.now().strftime("%H:%M:%S")

class SecurityScanner:
    def __init__(self, identity_manager=None, max_concurrency=20):
        self.mgr = identity_manager
        self.findings: List[Vulnerability] = []
        self.client = httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True)
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self._regex_patterns = None

    async def close(self):
        await self.client.aclose()

    async def scan_url(self, url: str, active_checks=True, personas=None, pre_res=None) -> List[Vulnerability]:
        """Runs all checks on a single URL with concurrency control."""
        async with self.semaphore:
            vulns = []
            try:
                # 1. Passive Checks (Info Leak, Headers)
                if pre_res:
                    res = pre_res
                else:
                    res = await self.client.get(url)
                
                # Run detectors with error boundaries
                detectors = [
                    (self.check_exposure, [url, res]),
                    (self.check_sensitive_keywords, [url, res]),
                    (self.check_headers, [url, res]),
                    (self.check_verbose_error, [url, res]),
                    (self.check_technology, [url, res]),
                ]
                
                for detect_func, args in detectors:
                    try:
                        vulns.extend(detect_func(*args))
                    except Exception as e:
                        print(f"[!] Detector Error ({detect_func.__name__}): {e}")

                vulns.extend(self.check_path_suggestions(url))
                
                # 2. Heuristic: Sensitive Files (if active_checks)
                if active_checks:
                    try:
                        vulns.extend(await self.check_backup_files(url))
                        vulns.extend(await self.fuzz_sqli(url))
                        vulns.extend(await self.fuzz_xss(url))
                    except Exception as e:
                        print(f"[!] Active Fuzzer Error: {e}")
                        
            except httpx.RequestError as e:
                print(f"[-] Connection failed for {url}: {e}")
            except Exception as e:
                print(f"[!!] Critical Scan Exception for {url}: {e}")

            self.findings.extend(vulns)
            return vulns

    def check_exposure(self, url: str, res: httpx.Response) -> List[Vulnerability]:
        """Checks for massive generic responses."""
        found = []
        status = res.status_code
        body_len = len(res.content)
        
        if 200 <= status < 300 and body_len > 50000:
            found.append(Vulnerability(
                url=url,
                type="[API3:2023] Excessive Data Exposure",
                severity="Medium",
                details=f"Huge generic response ({body_len} bytes). Risk of data dump.\nAnalysis Tip: Check for PII or excessive database dumps in the body.",
                evidence=f"Size: {body_len} bytes",
                asvs="13.1.3"
            ))
        return found

    def check_verbose_error(self, url: str, res: httpx.Response) -> List[Vulnerability]:
        """Flags 4xx/5xx responses that are too chatty."""
        found = []
        if res.status_code >= 400:
            text = res.text.lower()
            
            # 1. Path-Specific 500 Alerts (e.g. Broken Docs)
            if res.status_code >= 500:
                if any(x in url.lower() for x in ["api-docs", "swagger", "openapi", "v3/api-docs"]):
                    found.append(Vulnerability(
                        url=url,
                        type="[API8:2023] Server Misconfiguration",
                        severity="Medium",
                        details="The documentation service (Swagger/OpenAPI) is returning 500.\nAnalysis Tip: Try fuzzing the version number (v1->v2) or accessing /api-docs.json directly.",
                        evidence=f"HTTP {res.status_code}",
                        asvs="14.4.3"
                    ))

            # 2. Size Check: Standard 404 is usually small (<300 bytes)
            if len(text) > 1000: 
                found.append(Vulnerability(
                    url=url,
                    type="[API8:2023] Verbose Error",
                    severity="Low",
                    details=f"Error {res.status_code} response is large ({len(text)} bytes).\nAnalysis Tip: Inspect for stack traces or internal IP addresses.",
                    evidence=res.text
                ))
            # 3. Stack Trace / Debug Keywords
            keywords = ["stack trace", "traceback", "at line", "syntax error", "debug", "exception"]
            for k in keywords:
                if k in text:
                    found.append(Vulnerability(
                        url=url,
                        type="[API8:2023] Stack Trace Leak",
                        severity="High",
                        details=f"Error response contains debug info: '{k}'\nAnalysis Tip: Use this stack trace to map the backend architecture.",
                        evidence=f"Found '{k}'",
                        asvs="14.3.3"
                    ))
                    break
        return found
        
    def check_sensitive_keywords(self, url: str, res: httpx.Response) -> List[Vulnerability]:
        """Scans response body for Token, Client ID, User ID, etc."""
        found = []
        text = res.text
        
        # Regex patterns for high confidence findings
        # Compile regex once for performance
        if self._regex_patterns is None:
            self._regex_patterns = {
                "JWT Token": re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
                "Private Key": re.compile(r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----"),
                "AWS Key": re.compile(r"AKIA[0-9A-Z]{16}"),
                "Generic API Key": re.compile(r"(api_key|apikey|access_token)[\"']?\s*[:=]\s*[\"'][a-zA-Z0-9_\-]{20,}[\"']"),
                # PII Patterns (Stricter)
                "Email Address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
                "Social Security Number (US)": re.compile(r"\b(?!000|666|9\d{2})[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b"),
                "Credit Card": re.compile(r"\b(?:\d{4}[- ]){3}\d{4}\b|\b\d{16}\b"),
                "Phone Number": re.compile(r"\b\+?1?[-.]?\(?([2-9]\d{2})\)?[-.]?(\d{3})[-.]?(\d{4})\b"),
                # Auto Specific
                "VIN (Vehicle ID)": re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")
            }
        
        # 0. Heuristics (BOLA / SSRF) based on URL/Params
        # BOLA: Check for numeric IDs in path (e.g. /users/1234)
        if re.search(r"/\d{3,}/", url) or re.search(r"=[0-9]{3,}", url):
             found.append(Vulnerability(
                url=url, 
                type="[API1:2023] Potential BOLA", 
                severity="Info", 
                details="URL contains numeric ID pattern. Good candidate for IDOR/BOLA testing.",
                evidence=url,
                asvs="1.2.3"
            ))
            
        # SSRF: Check for URLs in query params (e.g. ?webhook=http...)
        if re.search(r"=(http|https|ftp)://", url):
             found.append(Vulnerability(
                url=url, 
                type="[API7:2023] Potential SSRF", 
                severity="Medium", 
                details="URL parameter contains a full URI. High risk of Server-Side Request Forgery.",
                evidence=url,
                asvs="12.1.1"
            ))
        
        for name, pattern in self._regex_patterns.items():
            matches = pattern.findall(text)
            validated_matches = []
            
            for m in matches:
                # Handle tuple results from regex groups (like phone)
                val = m if isinstance(m, str) else "".join(m)
                
                # Validation Logic
                if name == "Credit Card":
                    clean_num = re.sub(r"\D", "", val)
                    if not self._luhn_check(clean_num): continue
                    
                if name == "Social Security Number (US)":
                    # Additional check for invalid SSN ranges (000, 666, 900-999 area numbers)
                    # and 00 group numbers or 0000 serial numbers
                    if "000-" in val or "-00-" in val or "-0000" in val: continue
                    
                validated_matches.append(val)
                
            if validated_matches:
                evidence = validated_matches[0]
                
                sev = "Medium"
                if name in ["Private Key", "AWS Key", "JWT Token"]: sev = "Critical"
                elif name in ["Social Security Number (US)", "Credit Card", "VIN (Vehicle ID)"]: sev = "High"
                
                found.append(Vulnerability(
                    url=url,
                    type=f"[API3:2023] PII Exposure ({name})",
                    severity=sev,
                    details=f"Response contains {len(validated_matches)} validated instance(s) of {name}.",
                    evidence=f"Sample: {str(evidence)[:50]}...",
                    asvs="13.1.1"
                ))
                
        # Simple Keyword Checks (Lower confidence/Info)
        is_docs = any(x in url.lower() for x in ["api-docs", "swagger", "openapi"])
        
        keywords = ["client_id", "client_secret", "user_id", "password", "admin", "db_password"]
        lower_text = text.lower()
        for k in keywords:
            if k in lower_text:
                if is_docs: continue
                # Reduce noise on common words
                if k == "password" and "enter password" in lower_text: continue
                
                found.append(Vulnerability(
                    url=url,
                    type="[API3:2023] Sensitive Keyword",
                    severity="Medium" if "secret" in k or "password" in k else "Low",
                    details=f"Response contains sensitive key: '{k}'\nAnalysis Tip: Check if this value is redacted or exposed in plain text.",
                    evidence=f"Found keyword '{k}'",
                    asvs="13.1.1"
                ))
        return found

    def _luhn_check(self, num_str):
        # Luhn Algorithm for Credit Card Validation
        sum_ = 0
        is_second = False
        for digit in reversed(num_str):
            d = int(digit)
            if is_second:
                d *= 2
                if d > 9: d -= 9
            sum_ += d
            is_second = not is_second
        return (sum_ % 10) == 0

    def check_headers(self, url: str, res: httpx.Response) -> List[Vulnerability]:
        found = []
        headers = res.headers
        if 'Strict-Transport-Security' not in headers:
            found.append(Vulnerability(url, "[API8:2023] Missing HSTS", "Low", "Missing HSTS Header"))
        if 'X-Powered-By' in headers:
             found.append(Vulnerability(url, "[API8:2023] Info Leak", "Low", f"Server reveals tech: {headers['X-Powered-By']}"))
        return found
        
    def check_technology(self, url: str, res: httpx.Response) -> List[Vulnerability]:
        """Fingerprints the tech stack (Frameworks, Servers)."""
        found = []
        headers = res.headers
        text = res.text.lower()
        
        techs = []
        
        # 1. Header Fingerprints
        if "x-powered-by" in headers: techs.append(headers["x-powered-by"])
        if "server" in headers: techs.append(headers["server"])
        if "x-aspnet-version" in headers: techs.append("ASP.NET")
        if "x-spring-boot" in headers: techs.append("Spring Boot")
        
        # 2. Body / Cookie Fingerprints
        cookies = str(res.cookies).lower()
        if "jsessionid" in cookies: techs.append("Java/JSP")
        if "phpsessid" in cookies: techs.append("PHP")
        if "laravel_session" in cookies: techs.append("Laravel")
        if "django" in text or "csrftoken" in cookies: techs.append("Django")
        if "express" in text: techs.append("Express.js")
        
        unique_techs = list(set(techs))
        if unique_techs:
             found.append(Vulnerability(
                 url=url,
                 type="[API9:2023] Improper Inventory",
                 severity="Info",
                 details=f"Detected Stack: {', '.join(unique_techs)}",
                 evidence=f"Headers/Body match"
             ))
        return found
        
    def check_path_suggestions(self, url: str) -> List[Vulnerability]:
        """Heuristic to suggest hidden/alternate paths based on current URL."""
        found = []
        path = url.split("?")[0]
        if path.endswith("/"): path = path[:-1]
        
        suggestions = []
        
        # 1. Versioning Prediction
        v_match = re.search(r"/(v[0-9]+)/", path)
        if v_match:
            current_v = v_match.group(1)
            v_num = int(current_v[1:])
            suggestions.append(path.replace(current_v, f"v{v_num + 1}"))
            if v_num > 1:
                suggestions.append(path.replace(current_v, f"v{v_num - 1}"))
        
        # 2. Common Hidden Pointers
        base_path = "/".join(path.split("/")[:-1])
        suggestions.append(f"{base_path}/admin")
        suggestions.append(f"{base_path}/debug")
        suggestions.append(f"{base_path}/status")
        suggestions.append(f"{base_path}/config")
        suggestions.append(f"{base_path}/test")
        
        # 3. Documentation Pointers (if not already on one)
        if "api-docs" not in path.lower():
            suggestions.append(f"{base_path}/v3/api-docs")
            suggestions.append(f"{base_path}/swagger-ui.html")
            
        unique_sug = list(set(suggestions))
        # Limit noise: only return up to 3 most relevant
        for sug in unique_sug[:3]:
             if sug != path:
                found.append(Vulnerability(
                    url=url,
                    type="[API8:2023] Security Misconfiguration",
                    severity="Medium",
                    details=f"The server is leaking specific version numbers or technology stacks (e.g. Server: Apache/2.4.41).",
                    evidence=f"Predicted Target: {sug}"
                ))
        return found
        
    async def check_backup_files(self, url: str) -> List[Vulnerability]:
        # Quick check for .env or .bak
        found = []
        base = url.split("?")[0]
        if base.endswith("/"): base = base[:-1]
        
        files = [".env", ".git/HEAD", "robots.txt"]
        for f in files:
            target = f"{base}/{f}"
            try:
                res = await self.client.get(target)
                if res.status_code == 200:
                    found.append(Vulnerability(
                        url=target,
                        type="[API9:2023] Exposed Asset",
                        severity="High" if ".env" in f else "Low",
                        details=f"Found accessible file: {f}\nAnalysis Tip: Download this file immediately and scan for secrets/credentials.",
                        evidence=f"Status 200 OK",
                        asvs="14.5.1"
                    ))
            except: pass
        return found

    async def fuzz_sqli(self, url: str) -> List[Vulnerability]:
        if "?" not in url: return []
        found = []
        payloads = ["'", "\"", " OR 1=1"]
        
        for p in payloads:
            fuzzed_url = url + p
            try:
                res = await self.client.get(fuzzed_url)
                if res.status_code == 500 or "syntax" in res.text.lower() or "mysql" in res.text.lower():
                    found.append(Vulnerability(url, "[API8:2023] SQL Injection Effect", "Critical", f"Payload '{p}' triggered error.\nAnalysis Tip: Use SQLMap or manual Union-based injection on this parameter.", res.text, asvs="5.3.4"))
                    break
            except: pass
        return found
        
    async def fuzz_xss(self, url: str) -> List[Vulnerability]:
        if "?" not in url: return []
        found = []
        # Basic Reflected XSS check
        canary = "XSS_TEST_123"
        payload = f"<script>console.log('{canary}')</script>"
        fuzzed_url = url + f"&q={payload}" # Append to end roughly
        
        try:
            res = await self.client.get(fuzzed_url)
            if payload in res.text:
                found.append(Vulnerability(url, "Reflected XSS", "High", "Payload reflected in response body.", payload))
        except: pass
        return found
