import json
import base64
import re
import datetime
import urllib.parse
from dataclasses import dataclass

@dataclass
class Secret:
    type: str # "JWT", "API Key", etc.
    value: str
    decoded: str = "" # JSON string of claims if JWT
    issuer: str = "Unknown"  # Azure, Okta, etc.
    classification: str = "Opaque" # Bearer, Basic, etc.
    context: str = "Unknown" # User, System/App, etc.
    analytics: dict = None # Key-value metadata for the analyst (UPN, Scopes, Exp)
    raw_header: str = ""
    none_alg_token: str = "" # Generated vulnerable token

class TokenAnalyzer:
    def analyze(self, text: str) -> list[Secret]:
        secrets = []
        
        # 1. JWT Detection
        # Regex: Header.Payload.Signature
        jwt_pattern = r"(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})"
        jwts = re.findall(jwt_pattern, text)
        for token in set(jwts): # Unique
            pretty, analytics, subtype, context, header_json, none_token = self._decode_jwt(token)
            
            label = "JWT (Generic)"
            if subtype: label = f"JWT: {subtype}"
            
            secrets.append(Secret(
                type=label, 
                value=token, 
                decoded=pretty,
                issuer=subtype or "Unknown",
                classification="Bearer",
                context=context or "User",
                analytics=analytics,
                raw_header=header_json,
                none_alg_token=none_token
            ))

        # 2. Specific API Keys (Heuristic)
        key_patterns = [
            (r"(sk_live_[0-9a-zA-Z]{24})", "Stripe Secret Key"),
            (r"(rk_live_[0-9a-zA-Z]{24})", "Stripe Publishable Key"),
            (r"(xox[baprs]-([0-9a-zA-Z]{10,48}))", "Slack Token"),
            (r"(AIza[0-9A-Za-z-_]{35})", "Google API Key"),
            (r"(AKIA[0-9A-Z]{16})", "AWS Access Key"),
            (r"(EAACEdEose0cBA[0-9A-Za-z]+)", "Facebook Access Token"),
            (r"([1-9][0-9]+-[0-9a-zA-Z]{40})", "Twitter Access Token"),
            (r"(Basic [a-zA-Z0-9=:_\+\/-]{20,})", "Basic Auth Header"),
            (r"(Bearer [a-zA-Z0-9-._~+/]{20,})", "Generic Bearer Token"),
            (r"(ghp_[0-9a-zA-Z]{36})", "GitHub Personal Access Token")
        ]
        
        for pat, label in key_patterns:
            matches = re.findall(pat, text)
            for m in set(matches):
                val = m[0] if isinstance(m, tuple) else m
                # Heuristic for classification
                classification = "Opaque"
                if "Basic" in label: classification = "Basic"
                elif "Bearer" in label: classification = "Bearer"
                elif "Token" in label or "Key" in label: classification = "API Key"
                
                issuer = "Unknown"
                if "Stripe" in label: issuer = "Stripe"
                elif "Slack" in label: issuer = "Slack"
                elif "Google" in label: issuer = "Google"
                elif "AWS" in label: issuer = "AWS"
                elif "Facebook" in label: issuer = "Facebook"
                elif "Twitter" in label: issuer = "Twitter"
                elif "GitHub" in label: issuer = "GitHub"

                secrets.append(Secret(
                    type=label, 
                    value=val, 
                    decoded="N/A (Opaque String)",
                    issuer=issuer,
                    classification=classification,
                    analytics={"Insight": "Opaque API Key found in body/headers."}
                ))
                
        return secrets

    def _decode_jwt(self, token):
        try:
            # Split into parts
            parts = token.split(".")
            if len(parts) != 3: return "", {}, None, "Unknown", "", ""
            
            header_b64 = parts[0]
            payload_b64 = parts[1]
            
            # Decode Header
            header_data = base64.urlsafe_b64decode(header_b64 + '=' * (-len(header_b64) % 4))
            header_json = json.loads(header_data)
            
            alg = header_json.get("alg", "HS256")
            if alg.lower() == "none":
                analytics["🚨 Critical"] = "Token uses 'alg: none'. Attackers can forge this token easily!"
                analytics["SOC Clue"] = "Change the signature part of this token to empty and see if the API accepts it. If it does, you can be any user!"
            
            if "kid" in header_json:
                analytics["Insight"] = f"Key ID (kid) found: {header_json['kid']}. Check for 'KID Injection' vulnerabilities."
            if "jku" in header_json or "jwk" in header_json:
                analytics["⚠️ Warning"] = "Token contains external key references (jku/jwk). This is a target for SSRF/Key Confusion."
                analytics["SOC Clue"] = "Can you point the 'jku' URL to a server you control? If so, you might bypass signature verification."
            alg = header_json.get("alg", "Unknown")
            
            # Decode Payload
            payload_data = base64.urlsafe_b64decode(payload_b64 + '=' * (-len(payload_b64) % 4))
            claims = json.loads(payload_data)
            pretty = json.dumps(claims, indent=2)
            
            # --- Generate None Algorithm Payload ---
            # 1. Take original header, change alg -> none
            h_none = header_json.copy()
            h_none["alg"] = "none"
            h_none_b64 = base64.urlsafe_b64encode(json.dumps(h_none).encode()).decode().rstrip("=")
            # 2. Reassemble without signature
            none_token = f"{h_none_b64}.{payload_b64}."
            
            # --- Deep Analysis ---
            subtype = "Unknown Provider"
            hunt_tips = []
            
            # 1. Identity Provider (IdP) & Automotive Context Detection
            iss = claims.get("iss", "")
            if "sts.windows.net" in iss or "microsoftonline" in iss:
                subtype = "Entra ID (Azure AD)"
                hunt_tips.append("• **Entra ID Found**: Check `scp` (Scope) for over-privileged API access.")
            elif "okta.com" in iss:
                subtype = "Okta"
            elif "cognito-idp" in iss:
                subtype = "AWS Cognito"
            elif "auth0.com" in iss:
                subtype = "Auth0"
            
            # Automotive Industry White-Label Patterns
            auto_indicators = ["vehicle", "telemetry", "vin", "vcl", "fleet", "tbox"]
            if any(x in str(claims).lower() for x in auto_indicators):
                subtype = f"Auto-API ({subtype or 'Generic'})"
                hunt_tips.append("• **Automotive Context**: Detected vehicle-specific identifiers or telematics fields.")
            
            # --- Context Detection (User vs App) ---
            context = "User"
            if "upn" in claims or "unique_name" in claims or "email" in claims:
                context = "User"
            elif "appid" in claims or claims.get("idtyp") == "app" or "oid" in claims and "upn" not in claims:
                context = "Service Principal / App"
            
            # --- Key Analytics for Analyst ---
            analytics = {}
            analytics["Algorithm"] = alg
            analytics["Identity Type"] = context
            # Identity
            if "upn" in claims: analytics["User (UPN)"] = claims["upn"]
            elif "unique_name" in claims: analytics["User (Name)"] = claims["unique_name"]
            elif "sub" in claims: analytics["Subject (sub)"] = claims["sub"]
            
            # Authorization
            # Authorization & Scope Interrogation (Automotive Focus)
            raw_scopes = claims.get("scp", claims.get("scope", ""))
            if isinstance(raw_scopes, str):
                scopes = raw_scopes.split(" ")
            elif isinstance(raw_scopes, list):
                scopes = raw_scopes
            else:
                scopes = []

            if scopes:
                analytics["Scopes"] = ", ".join(scopes)
                # Sensitive Automotive Scopes
                crit_scopes = {
                    "unlock": "🚨 Critical: Vehicle Entry/Control",
                    "lock": "🚨 Critical: Vehicle Entry/Control",
                    "start": "🚨 Critical: Engine Control",
                    "stop": "🚨 Critical: Engine Control",
                    "telemetry:read": "📊 High: Fleet/User Surveillance",
                    "location:read": "📍 High: Real-time Tracking",
                    "profile:read": "👤 Medium: PII Exposure",
                    "admin": "☢️ Critical: System Administration"
                }
                for s in scopes:
                    for trigger, desc in crit_scopes.items():
                        if trigger in s.lower():
                            analytics[f"Scope Alert: {s}"] = desc
                            hunt_tips.append(f"• **Sensitive Scope**: `{s}` allows `{desc}`. Verify if this token should have this power.")

            if "roles" in claims: analytics["Roles"] = str(claims["roles"])
            elif "groups" in claims: analytics["Groups"] = str(claims["groups"])
            
            # Validity
            if "exp" in claims:
                exp_ts = claims["exp"]
                dt = datetime.datetime.fromtimestamp(exp_ts)
                analytics["Expires"] = dt.strftime('%Y-%m-%d %H:%M:%S')
                
                now = datetime.datetime.now().timestamp()
                ttl = int(exp_ts - now)
                if ttl > 0:
                    analytics["TTL"] = f"{ttl}s (Active)"
                else:
                    analytics["TTL"] = f"{abs(ttl)}s ago (Expired)"
            
            # Tenant
            if "tid" in claims: analytics["Tenant ID"] = claims["tid"]
            if "iss" in claims: analytics["Issuer"] = claims["iss"]
            
            return pretty, analytics, subtype, context, json.dumps(header_json, indent=2), none_token
        except Exception as e:
            return f"Error decoding: {e}", {}, None, "Unknown", "", ""

import json
import re
import urllib.parse
from typing import List, Set

class AttackSurfaceAnalyzer:
    """Analyzes URLs and JSON bodies for modification targets and PII."""
    
    def __init__(self):
        self.email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@(?![A-Za-z0-9.-]*host)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        self.vin_pattern = r"\b[A-HJ-NPR-Z0-9]{17}\b"
        self.phone_pattern = re.compile(r"(?:\+1[-. ]?)?\(?[2-9][0-9]{2}\)?[-. ]?[2-9][0-9]{2}[-. ]?[0-9]{4}\b")
        self.ssn_pattern = re.compile(r"\b(?!000|666|9\d{2})[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b")
        self.internal_ip_pattern = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
        self.path_pattern = re.compile(r"(?:\/home\/[a-z0-9_-]+|\/var\/www\/[a-z0-9_-]+|C:\\Users\\[a-z0-9_-]+|[a-z0-9_-]+\.conf|[a-z0-9_-]+\.ini)", re.IGNORECASE)
    
    def extract_urls(self, text: str, base_url: str) -> Set[str]:
        """Recursive Spider: Extracts valid API endpoints from response text."""
        found = set()
        
        # 1. Regex for Absolute URLs (http/https)
        # We look for typical API patterns, ignoring images/css if possible
        abs_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"\'<>]*'
        matches = re.findall(abs_pattern, text)
        for m in matches:
            # Clean trailing chars often caught by regex in JSON
            m = m.rstrip(".,\"')}")
            if any(ext in m.lower() for ext in [".png", ".jpg", ".css", ".js", ".svg", ".ico", ".woff"]):
                continue
            found.add(m)
            
        # 2. Heuristic for Relative Paths in JSON keys (e.g. "url": "/v1/user")
        # We only trust specific keys to avoid noise
        if "{" in text: # fast check for JSON-ish
            try:
                data = json.loads(text)
                self._recurse_links(data, base_url, found)
            except: pass
            
        return found

    def _recurse_links(self, data, base_url, found):
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str):
                    # Check if value looks like a path
                    if v.startswith("/") and len(v) > 1 and " " not in v:
                        # Key heuristics: "url", "href", "link", "next", "self"
                        if any(x in k.lower() for x in ["url", "href", "link", "next", "path", "uri"]):
                            full = urllib.parse.urljoin(base_url, v)
                            found.add(full)
                elif isinstance(v, (dict, list)):
                    self._recurse_links(v, base_url, found)
        elif isinstance(data, list):
            for item in data:
                self._recurse_links(item, base_url, found)

    def analyze_url(self, url: str) -> list[str]:
        findings = []
        decoded_url = urllib.parse.unquote(url)
        
        # Parse URL parameters for BOLA/IDOR checks
        parsed_url = urllib.parse.urlparse(decoded_url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        # 1. PII detection
        if self.email_pattern.search(url):
            findings.append(f"👤 **[API2:2023] PII in URL (Email)**: Found email in path or params.\n   -> **SOC Clue**: Why is an email address being sent in the URL? Is it encrypted?")
        
        # 2. BOLA detection
        for k, v_list in params.items():
            # Take the first value if it's a list
            v = v_list[0] if v_list else ""
            if any(x in k.lower() for x in ["id", "uuid", "guid", "code", "pk", "key", "account", "user"]):
                if len(str(v)) > 0:
                    findings.append(f"🎯 **[API1:2023] BOLA Target**: Variable `{k}`=`{v}` found.\n   -> **SOC Clue**: If you change this number to a different ID, can you see someone else's data?")
        
        # 3. PII/Sensitive IDs in URL
        vins = re.findall(self.vin_pattern, decoded_url.upper())
        for v in vins:
            findings.append(f"🚗 **[API1:2023] Sensitive ID Found (VIN)**: `{v}`\n   -> **SOC Clue**: Can we swap this VIN for another vehicle to access its records?")
            
        # 2. PII: Emails
        # More strict pattern to avoid catching "@host" parts of URLs
        emails = self.email_pattern.findall(decoded_url)
        for e in emails:
            findings.append(f"👤 **[API2:2023] PII (Email) Detected**: `{e}`\n   -> **SOC Clue**: Is this email necessary in the URL? Could it be used for account enumeration?")

        # 3. PII: US Phone Numbers & SSN
        # (123) 456-7890 or 123-456-7890 or +1...
        phones = self.phone_pattern.findall(decoded_url)
        for p in phones:
            findings.append(f"📱 **[API2:2023] PII (Phone Number) Detected**: `{p}`\n   -> **SOC Clue**: Is this phone number required in the URL? Could it be used for enumeration?")
            
        ssns = self.ssn_pattern.findall(decoded_url)
        for s in ssns:
            # Mask mostly finding
            masked = s[:3] + "-XX-XXXX"
            findings.append(f"🛑 **[API2:2023] PII (SSN) Detected**: `{masked}` (High Risk!)\n   -> **SOC Clue**: This is critical PII. Why is it in the URL? Is it encrypted?")

        # 10. Advanced Pentesting: Cloud Metadata / Internal Leaks
        int_ips = self.internal_ip_pattern.findall(decoded_url)
        for ip in set(int_ips):
            findings.append(f"📡 **Beyond Top 10: Internal IP Leak**: Found `{ip}` in URL.\n   -> **SOC Clue**: Why is an internal server IP visible to the outside? Can we access this server directly?")
        
        if "169.254.169.254" in decoded_url:
            findings.append(f"☁️ **Beyond Top 10: Cloud Metadata Service**: Target is pointing to `169.254.169.254`!\n   -> **SOC Clue**: This is the 'holy grail' for SSRF. If the server fetches this URL, it might leak AWS/Azure credentials.")

        return findings

    def analyze_body(self, text: str) -> list[str]:
        findings = []
        try:
            data = json.loads(text)
            # Documentation Check: If it's Swagger/OpenAPI, we adjust heuristics to avoid false positives
            is_docs = "openapi" in data or "swagger" in data
            self._recurse(data, "", findings, is_docs)
        except:
            pass # Not JSON
        return findings

    def _recurse(self, data, path, findings, is_docs=False):
        if isinstance(data, dict):
            for k, v in data.items():
                new_path = f"{path}.{k}" if path else k
                self._check_field(k, v, new_path, findings, is_docs)
                self._recurse(v, new_path, findings, is_docs)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._recurse(item, f"{path}[{i}]", findings, is_docs)

    def _check_field(self, key, value, path, findings, is_docs=False):
        k = key.lower()
        v_str = str(value).lower()
        
        # Documentation Filter: Ignore structural metadata 
        if is_docs:
            # Common OpenAPI paths that should NOT trigger PII/BOLA alerts
            # These are definitions, not live data leaks.
            doc_structs = ["paths.", "components.", "definitions.", "info.", "servers.", "tags.", "parameters."]
            if any(path.startswith(struct) for struct in doc_structs):
                # We still want to catch actual SECRETS if they somehow ended up in docs
                # But generic 'name', 'url', 'id' in docs are metadata.
                return
        if k in ["error", "message", "detail", "exception", "reason", "fault"]:
            val_str = str(value).lower()
            if "cookie" in val_str and "null" in val_str:
                findings.append(f"🍪 **[API2:2023] Auth Hint**: `{path}` explicitly mentions a missing Cookie.\n   -> **SOC Clue**: The server is literally telling us it needs a cookie. Check the 'Headers' tab to see which ones are missing.")
            elif "auth" in val_str or "token" in val_str or "login" in val_str or "unauthorized" in val_str:
                findings.append(f"🔑 **[API2:2023] Auth Hint**: `{path}` contains authentication details.\n   -> **SOC Clue**: Read this message carefully. It often explains why your access was denied (e.g. 'Token Expired').")

        # 1. BOLA / IDOR detection
        if "id" in k and "guid" not in k and "session" not in k:
            if isinstance(value, int):
                findings.append(f"🎯 **[API1:2023] BOLA/IDOR Target**: `{path}` = `{value}`\n   -> **SOC Clue**: Try `{value+1}` or `{value-1}`. Can you access other records?")
            elif isinstance(value, str) and len(value) > 0:
                findings.append(f"🎯 **[API1:2023] ID Vector**: `{path}`\n   -> **SOC Clue**: Swap with another valid ID. Can you bypass authorization?")

        if k in ["role", "scope", "permissions", "admin", "is_admin", "group"]:
             findings.append(f"👑 **[API5:2023] Privilege Escalation Vector**: `{path}` = `{value}`\n   -> **SOC Clue**: Can we change this value to 'admin' or 'superuser' to get more power?")
        if k in ["url", "uri", "callback", "webhook", "redirect", "image_url"]:
             findings.append(f"🔗 **[API7:2023] SSRF/Redirect Vector**: `{path}`\n   -> **SOC Clue**: What happens if we change this to `http://localhost` or an internal server?")
        if k in ["status", "state", "enabled", "active"] and isinstance(value, bool):
             findings.append(f"🚦 **[API6:2023] Business Logic Vector**: `{path}`\n   -> **SOC Clue**: If we flip this to `{not value}`, does it unlock something for free?")
        
        # 4. Financial & Price Manipulation
        if k in ["price", "amount", "total", "cost", "discount", "balance", "credit", "debit", "currency"]:
             findings.append(f"💰 **Pro Intelligence: Financial Manipulation**: `{path}` = `{value}`\n   -> **SOC Clue**: Can you change this value to `0.00` or `-1.00` to bypass payments or get credit?")

        # 5. Mass Assignment / Logical Flags
        if k in ["debug", "verified", "premium", "paid", "subscription", "tier", "quota", "balance", "limit"]:
             findings.append(f"🚩 **[API6:2023] Logic Flag**: `{path}` = `{value}`\n   -> **SOC Clue**: Toggle `true`/`false` or change numbers in PUT/POST requests. Does it change behavior, grant access, or increase your 'quota'?")

        # 5. Advanced Infrastructure/Path Detection
        if isinstance(value, str):
            if self.internal_ip_pattern.search(value):
                findings.append(f"📡 **Beyond Top 10: Internal IP Leak**: `{path}` contains an internal IP.\n   -> **SOC Clue**: This is a major clue for internal networking. Use this IP in other API calls to find hidden servers.")
            if self.path_pattern.search(value):
                findings.append(f"📂 **Beyond Top 10: Path Leak**: `{path}` looks like a server file path.\n   -> **SOC Clue**: If you can download this file, it might contain credentials or source code.")
            if "graphql" in k or "__schema" in v_str or "introspection" in v_str:
                findings.append(f"🕸️ **Beyond Top 10: GraphQL Insight**: `{path}` relates to GraphQL.\n   -> **SOC Clue**: Can you run an introspection query to see the whole database schema?")

        # Common Ignore Keys (Timestamps, Technical Metadata) needed for all checks
        ignore_keys = ["time", "date", "created", "updated", "expires", "version", "etag", "trace", "span", "duration", "offset", "limit", "page", "size", "http", "openapi", "swagger", "title", "description", "operationId", "url", "ref", "schema", "code", "status", "instance", "request", "correlation", "link", "count", "total", "num", "id_token", "access_token", "error", "message", "detail", "type", "exception", "path"]
        
        # Heuristic for Unix Timestamps (Seconds or Millis)
        is_timestamp = any(x in k.lower() for x in ignore_keys)
        if not is_timestamp and (isinstance(value, int) or (isinstance(value, str) and value.isdigit())):
            try:
                val_int = int(value)
                # Rough range check: 1990 (600M) to 2100 (4.1B)
                if 600000000 < val_int < 4100000000:
                    is_timestamp = True
                # Also check millis: 1e12 to 1e13
                elif 600000000000 < val_int < 4100000000000:
                    is_timestamp = True
            except: pass

        # 5. Scalar Content Checks (Only check strings/numbers, skip massive nested objects)
        if isinstance(value, (dict, list)):
            return

        # Improved Regex Patterns (Matching analyze_url)
        # These patterns are now instance attributes, so we use self.pattern
        
        username_fields = ["username", "user", "handle", "login", "alias", "owner", "creator", "display_name"]
        pii_fields = ["name", "firstname", "lastname", "surname", "address", "street", "city", "state", "zip", "postal", "phone", "mobile", "ssn", "dob", "birth", "passport", "tax_id"]
        
        # 16-Digit Numeric Check (CC/Serial)
        if isinstance(value, str) and re.match(cc_pattern, v_str) and not is_timestamp:
             findings.append(f"💳 **Sensitive ID (16 Digits)**: `{path}` = `{value}`\n   -> Suggestion: High-risk numeric ID. Check for PII disclosure or IDOR.")
        
        # VIN Check
        elif isinstance(value, str) and (re.match(vin_pattern, v_str.upper()) or re.match(short_vin_pattern, v_str.upper())):
             v_type = "Standard VIN" if len(v_str) == 17 else "Short Identifier"
             findings.append(f"🚗 **Vehicle/Asset ID ({v_type})**: `{path}` = `{value}`\n   -> Suggestion: High-value asset. Swapping this ID is the primary BOLA vector.")
        
        # SSN Check
        elif isinstance(value, str) and re.search(ssn_pattern, v_str) and not is_timestamp:
             findings.append(f"🛑 **PII (SSN)**: `{path}` = `XXX-XX-XXXX`\n   -> Suggestion: Critical PII leak. Immediate redaction required.")

        # Email Check
        elif isinstance(v_str, str) and re.search(email_pattern, v_str) and not is_timestamp:
            e_match = re.search(email_pattern, v_str).group(0)
            domain_type = "Personal" if any(x in e_match.lower() for x in ["@gmail.", "@outlook.", "@hotmail.", "@yahoo."]) else "Corporate"
            findings.append(f"📧 **PII (Email)**: `{path}` = `{value}`\n   -> Suggestion: {domain_type} identity leakage. Check for Excessive Data Exposure.")
            
        # Phone Check
        elif isinstance(v_str, str) and re.search(phone_pattern, v_str) and not is_timestamp:
            # Final safety against timestamps that look like phones
            if not v_str.startswith("17") and not v_str.startswith("16"):
                findings.append(f"📱 **PII (Phone)**: `{path}` = `{value}`\n   -> Suggestion: Direct contact info leakage. Report as PII Disclosure.")

        # General PII Check
        elif k in pii_fields:
             findings.append(f"👤 **PII Data Found**: `{path}` ({key}) = `{value}`\n   -> Suggestion: Check why the API is returning personal info on this endpoint.")
             
        # Persona Identifier
        if k in username_fields:
             findings.append(f"👤 **Persona Identifier**: `{path}` = `{value}`\n   -> Suggestion: Target for identity swapping (BOLA).")
        # Heuristic Check: String with digits, but restrict false positives
        elif (isinstance(value, str) and len(v_str) > 3 
              and any(char.isdigit() for char in v_str) 
              and not v_str.startswith("http") 
              and not v_str.startswith("/")  # Exclude paths
              and not is_timestamp 
              and not any(x in k.lower() for x in ["id", "token", "key", "secret", "auth"])): # Skip already tagged id/token
              
              # Check if value looks like a date (2026-...)
              is_date_value = re.match(r"^\d{4}-\d{2}-\d{2}", v_str)
              if not is_date_value:
                  findings.append(f"🎯 **Object Reference**: `{path}` = `{value}`\n   -> Suggestion: Swapping this value may bypass authorization via IDOR.")
