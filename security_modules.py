import re
import jwt
import requests
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class SecurityScanner:
    @staticmethod
    def check_headers(headers: Dict[str, str]) -> List[str]:
        """Checks for missing security headers."""
        missing = []
        required = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options"
        ]
        for req in required:
            if req not in headers and req.lower() not in headers:
                missing.append(f"Missing {req}")
        return missing

    @staticmethod
    def scan_pii(text: str) -> List[str]:
        """Scans response text for PII patterns."""
        findings = []
        patterns = {
            "Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "SSN": r'\d{3}-\d{2}-\d{4}',
            "API Key": r'(?i)(api_key|apikey|access_token)[\"\']?\s*[:=]\s*[\"\']?([a-zA-Z0-9]{20,})',
            "Phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        }
        for name, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                 findings.append(f"Found {len(matches)} potential {name}(s)")
        return findings

    @staticmethod
    def analyze_token(token: str) -> Dict[str, Any]:
        """Decodes JWT without verifying signature to inspect claims."""
        try:
            # Handle Bearer prefix
            if token.lower().startswith("bearer "):
                token = token.split(" ")[1]
            
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            return {
                "valid_format": True,
                "header": header,
                "payload": payload,
                "alg": header.get("alg"),
                "risk": "High" if header.get("alg") == "none" else "Low"
            }
        except Exception as e:
            return {"valid_format": False, "error": str(e)}

    @staticmethod
    def fuzz_url_injection(url: str) -> List[str]:
        """Generates SQLi/XSS fuzz vectors for a given URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        fuzzed_urls = []
        
        payloads = ["'", "\"", "<script>alert(1)</script>", " OR 1=1"]
        
        for key in params:
            for payload in payloads:
                # Create a copy of params to modify
                new_params = params.copy()
                # Inject payload into the first value of the param
                new_params[key] = [new_params[key][0] + payload]
                
                # Reconstruct URL
                query_string = urlencode(new_params, doseq=True)
                new_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path, 
                    parsed.params, query_string, parsed.fragment
                ))
                fuzzed_urls.append(new_url)
                
        return fuzzed_urls
