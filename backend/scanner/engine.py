import re
import socket
import time
from typing import Dict, List, Optional, Any
import httpx
from backend.core.security import (
    SecurityValidationError,
    is_ip_prohibited,
    resolve_and_verify_ip,
)

# Safe, strictly limited ports to check (HTTP, HTTPS, common web/admin services)
SAFE_PORTS_TO_CHECK = [80, 443, 8080, 8443]
MAX_RESPONSE_BYTES = 64 * 1024

# Required/recommended security headers to assess
SECURITY_HEADERS = {
    "strict-transport-security": "Missing HSTS (Strict-Transport-Security) header prevents browsers from enforcing HTTPS.",
    "x-content-type-options": "Missing X-Content-Type-Options: nosniff exposes clients to MIME-type confusion attacks.",
    "x-frame-options": "Missing X-Frame-Options or Content-Security-Policy frame-ancestors makes the site vulnerable to clickjacking.",
    "content-security-policy": "Missing Content-Security-Policy header increases risk of cross-site scripting (XSS) and data injection."
}


class SecurityScanner:
    def __init__(self, target_domain: str, timeout: float = 4.0, deadline: Optional[float] = None):
        self.target_domain = target_domain
        self.timeout = timeout
        self.deadline = deadline

    def _remaining(self) -> float:
        if self.deadline is None:
            return self.timeout
        return max(0.0, self.deadline - time.monotonic())

    def check_port_open(self, ip_address: str, port: int) -> bool:
        """Safely checks if a limited standard service port is responsive with a quick timeout."""
        if port not in SAFE_PORTS_TO_CHECK:
            return False
        prohibited, _ = is_ip_prohibited(ip_address)
        if prohibited:
            return False

        remaining = self._remaining()
        if remaining <= 0:
            return False
        
        try:
            with socket.create_connection((ip_address, port), timeout=min(1.5, remaining)):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def scan_http_service(self, hostname: str, port: int, use_tls: bool = False) -> Dict[str, Any]:
        """
        Safely probes an HTTP/HTTPS service, capturing status, headers, title,
        redirect behavior, and common configuration issues.
        """
        scheme = "https" if use_tls else "http"
        url = f"{scheme}://{hostname}:{port}/" if (port != 80 and port != 443) else f"{scheme}://{hostname}/"
        
        result: Dict[str, Any] = {
            "url": url,
            "port": port,
            "use_tls": use_tls,
            "accessible": False,
            "status_code": None,
            "headers": {},
            "title": None,
            "redirects_to_https": False,
            "missing_headers": [],
            "directory_listing": False,
            "error": None
        }

        if port not in SAFE_PORTS_TO_CHECK or use_tls != (port in (443, 8443)):
            result["error"] = "Unsupported service probe."
            return result

        remaining = self._remaining()
        if remaining <= 0:
            result["error"] = "Scan time limit reached."
            return result

        try:
            # Resolve and validate every answer, then connect to one of those exact
            # addresses. The URL uses the IP so the HTTP client cannot resolve the
            # hostname again and be redirected to a private address by DNS rebinding.
            ips = resolve_and_verify_ip(hostname, self.target_domain, timeout=min(2.0, remaining))
            if not ips:
                result["error"] = "No public IP resolved."
                return result

            remaining = self._remaining()
            if remaining <= 0:
                result["error"] = "Scan time limit reached."
                return result

            selected_ip = ips[0]
            url_ip = f"[{selected_ip}]" if ":" in selected_ip else selected_ip
            connect_url = f"{scheme}://{url_ip}:{port}/"
            default_port = 443 if use_tls else 80
            host_header = hostname if port == default_port else f"{hostname}:{port}"
            headers = {
                "Host": host_header,
                "User-Agent": "ExposureGraph-Security-Scanner/1.0",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
                "Accept-Encoding": "identity",
                "Connection": "close",
            }
            request_options = {"extensions": {"sni_hostname": hostname}} if use_tls else {}

            # Probes never follow redirects. Proxy environment variables are ignored
            # so the validated destination is also the actual TCP destination.
            with httpx.Client(
                timeout=httpx.Timeout(max(0.1, min(self.timeout, self._remaining()))),
                verify=True,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream("GET", connect_url, headers=headers, **request_options) as resp:
                    result["accessible"] = True
                    result["status_code"] = resp.status_code
                    result["headers"] = dict(resp.headers)

                    body_bytes = bytearray()
                    for chunk in resp.iter_bytes():
                        remaining = MAX_RESPONSE_BYTES - len(body_bytes)
                        if remaining <= 0:
                            break
                        body_bytes.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            break
                    body = bytes(body_bytes).decode(resp.encoding or "utf-8", errors="replace")

                    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        result["title"] = title_match.group(1).strip()[:100]

                    result["directory_listing"] = "Index of /" in body or "<title>Index of" in body

                    if not use_tls and resp.status_code in (301, 302, 307, 308):
                        location = resp.headers.get("location", "")
                        result["redirects_to_https"] = location.lower().startswith("https://")

                    response_headers = {name.lower() for name in resp.headers}
                    for header in SECURITY_HEADERS:
                        if header not in response_headers:
                            result["missing_headers"].append(header)

        except SecurityValidationError as exc:
            result["error"] = str(exc)
        except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as exc:
            result["error"] = type(exc).__name__
        except Exception as exc:
            # Do not persist raw exception text from an untrusted remote response.
            result["error"] = type(exc).__name__

        return result

    def evaluate_findings(self, asset: Dict[str, Any], http_results: List[Dict[str, Any]], tls_info: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Produces concrete, evidence-backed findings from discovery & scanner measurements.
        """
        findings: List[Dict[str, Any]] = []
        host = asset.get("hostname") or asset.get("identifier")

        # 1. Check TLS validity
        if tls_info:
            if not tls_info.get("valid", False):
                findings.append({
                    "title": "TLS Certificate Validation Failed",
                    "affected_asset": host,
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "evidence": f"TLS certificate validation failed for {host}: {tls_info.get('error', 'certificate validation error')}",
                    "explanation": "An invalid, self-signed, or expired certificate triggers browser warnings and risks MITM interception.",
                    "remediation": "Renew the TLS certificate using a trusted Certificate Authority such as Let's Encrypt or your cloud provider ACM."
                })
        else:
            https_probe = next(
                (
                    service for service in http_results
                    if service.get("port") == 443
                    and service.get("probe_state") == "unreachable"
                ),
                None,
            )
            if https_probe:
                findings.append({
                    "title": "HTTPS Did Not Respond to the Scan",
                    "affected_asset": host,
                    "severity": "INFO",
                    "confidence": "LOW",
                    "evidence": f"A bounded TCP connection attempt to {host}:443 did not complete.",
                    "explanation": "HTTPS was not confirmed during this scan. Filtering, temporary network issues, or an unavailable service can cause this result; it does not by itself prove that the site serves unencrypted data.",
                    "remediation": "Verify that the host is intended to provide HTTPS and that port 443 is reachable from the public internet."
                })

        # 2. Check HTTP to HTTPS redirect
        http_service = next((s for s in http_results if s["port"] in (80, 8080) and not s["use_tls"]), None)
        if http_service and http_service.get("accessible"):
            if not http_service.get("redirects_to_https") and http_service.get("status_code") == 200:
                findings.append({
                    "title": "Plain HTTP Service Without HTTPS Redirect",
                    "affected_asset": host,
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "evidence": f"HTTP request to {http_service['url']} returned status {http_service['status_code']} without redirecting to https://",
                    "explanation": "Serving resources over plain HTTP without automatic redirect to HTTPS risks downgrade attacks.",
                    "remediation": "Configure your reverse proxy/web server (e.g. Nginx, Cloudflare) to issue a permanent 301 redirect from HTTP to HTTPS."
                })

        # 3. Check Directory Listing
        for s in http_results:
            if s.get("directory_listing"):
                findings.append({
                    "title": "Exposed Directory Listing",
                    "affected_asset": host,
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "evidence": f"Directory index discovered at {s['url']}: Response contains 'Index of /'",
                    "explanation": "Directory listings reveal sensitive file names, backup files, source code, and configuration assets to attackers.",
                    "remediation": "Disable directory browsing in your web server configuration (e.g., 'Options -Indexes' in Apache, or remove autoindex in Nginx)."
                })

        # 4. Check Staging / Dev / Admin Exposed Subdomains
        staging_keywords = ["dev", "staging", "test", "admin", "internal", "portal"]
        for kw in staging_keywords:
            if f"{kw}." in host or host.startswith(f"{kw}-"):
                findings.append({
                    "title": f"Publicly Resolvable {kw.capitalize()}-Named Host",
                    "affected_asset": host,
                    "severity": "INFO",
                    "confidence": "LOW",
                    "evidence": f"Subdomain '{host}' is publicly resolvable and accessible via public DNS.",
                    "explanation": "The hostname contains an environment-like label. Naming alone does not confirm that the environment is sensitive or insecure.",
                    "remediation": "Review whether this environment should be public and verify that it uses production-grade access controls."
                })
                break

        # 5. Check Missing Security Headers
        https_service = next((s for s in http_results if s.get("use_tls") and s.get("accessible")), None)
        if https_service and https_service.get("missing_headers"):
            missing = https_service["missing_headers"]
            if "strict-transport-security" in missing:
                findings.append({
                    "title": "Missing HSTS (Strict-Transport-Security) Header",
                    "affected_asset": host,
                    "severity": "LOW",
                    "confidence": "HIGH",
                    "evidence": f"Response headers from {https_service['url']} lack 'Strict-Transport-Security'",
                    "explanation": "HSTS ensures modern browsers strictly communicate over HTTPS, mitigating SSL-stripping attacks.",
                    "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to response headers."
                })
            
            other_missing = [h for h in missing if h != "strict-transport-security"]
            if other_missing:
                findings.append({
                    "title": f"Missing Defensive HTTP Headers: {', '.join(other_missing)}",
                    "affected_asset": host,
                    "severity": "LOW",
                    "confidence": "HIGH",
                    "evidence": f"Headers missing on {https_service['url']}: {', '.join(other_missing)}",
                    "explanation": "Defensive headers like X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy guard against MIME sniffing and clickjacking.",
                    "remediation": "Configure web server or edge CDN to send standard hardening headers on all responses."
                })

        return findings

