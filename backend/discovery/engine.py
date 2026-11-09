import re
import socket
import ssl
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import dns.resolver
from backend.core.security import (
    SecurityValidationError,
    is_in_scope,
    is_ip_prohibited,
    resolve_and_verify_ip,
)
from backend.core.config import settings

# Common non-invasive subdomains for initial passive/DNS enumeration
COMMON_PREFIXES = [
    "www", "api", "app", "dev", "staging", "admin", "mail",
    "portal", "auth", "vpn", "test", "docs", "status", "blog"
]


class DiscoveryService:
    def __init__(self, target_domain: str, deadline: Optional[float] = None):
        self.target_domain = target_domain.lower().strip()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 2.0
        self.deadline = deadline
        self.query_outcomes: List[Dict[str, Any]] = []
        self.hostname_outcomes: List[Dict[str, Any]] = []
        self.hostname_candidates = 0

    def _remaining(self) -> float:
        if self.deadline is None:
            return 2.0
        return max(0.0, self.deadline - time.monotonic())

    def resolve_dns_records(self, hostname: str, include_mail_records: bool = False) -> Dict[str, List[str]]:
        """Resolve address records for hosts and mail/name-server records for the root only."""
        records: Dict[str, List[str]] = {
            "A": [],
            "AAAA": [],
            "CNAME": [],
            "MX": [],
            "NS": []
        }
        
        record_types = ["A", "AAAA", "CNAME"]
        if include_mail_records:
            record_types.extend(("MX", "NS"))
        for record_type in record_types:
            private_records_filtered = 0
            remaining = self._remaining()
            if remaining <= 0:
                self.query_outcomes.append({
                    "hostname": hostname,
                    "record_type": record_type,
                    "state": "not_attempted",
                    "result": "unknown",
                    "record_count": 0,
                    "detail": "The assessment time limit was reached before this DNS query.",
                })
                break
            self.resolver.timeout = min(2.0, remaining)
            try:
                answers = self.resolver.resolve(hostname, record_type, lifetime=remaining)
                for rdata in answers:
                    if record_type == "A":
                        value = str(rdata.address)
                        if not is_ip_prohibited(value)[0]:
                            records[record_type].append(value)
                        else:
                            private_records_filtered += 1
                    elif record_type == "AAAA":
                        value = str(rdata.address)
                        if not is_ip_prohibited(value)[0]:
                            records[record_type].append(value)
                        else:
                            private_records_filtered += 1
                    elif record_type == "CNAME":
                        records[record_type].append(str(rdata.target).rstrip("."))
                    elif record_type == "MX":
                        records[record_type].append(str(rdata.exchange).rstrip("."))
                    else:
                        records[record_type].append(str(rdata.target).rstrip("."))
                record_count = len(records[record_type])
                self.query_outcomes.append({
                    "hostname": hostname,
                    "record_type": record_type,
                    "state": "completed",
                    "result": "records_found" if record_count else (
                        "private_addresses_filtered" if private_records_filtered else "no_records"
                    ),
                    "record_count": record_count,
                    "private_records_filtered": private_records_filtered,
                    **({"detail": f"{private_records_filtered} private or non-public address record(s) were filtered from the public-scope inventory."} if private_records_filtered else {}),
                })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # A negative DNS response is a completed query with no records,
                # never a confirmed asset.
                self.query_outcomes.append({
                    "hostname": hostname,
                    "record_type": record_type,
                    "state": "completed",
                    "result": "no_records",
                    "record_count": 0,
                    "detail": "DNS returned no record for this name and type.",
                })
            except Exception as exc:
                # Keep failures distinct from negative DNS answers and avoid
                # persisting raw resolver messages.
                self.query_outcomes.append({
                    "hostname": hostname,
                    "record_type": record_type,
                    "state": "failed",
                    "result": "unknown",
                    "record_count": 0,
                    "detail": f"DNS query failed ({type(exc).__name__}).",
                })
                continue

        return records

    def enumerate_subdomains(self) -> List[Dict[str, Any]]:
        """
        Enumerates root domain and common subdomains via DNS queries safely.
        Returns list of discovered asset structures.
        """
        discovered: List[Dict[str, Any]] = []
        self.query_outcomes = []
        self.hostname_outcomes = []
        hostnames_to_check = [self.target_domain]
        prefix_limit = max(0, min(settings.max_subdomains, len(COMMON_PREFIXES)))
        for prefix in COMMON_PREFIXES[:prefix_limit]:
            sub = f"{prefix}.{self.target_domain}"
            hostnames_to_check.append(sub)
        self.hostname_candidates = len(hostnames_to_check)

        for index, host in enumerate(hostnames_to_check):
            if self._remaining() <= 0:
                for not_attempted_host in hostnames_to_check[index:]:
                    self.hostname_outcomes.append({
                        "hostname": not_attempted_host,
                        "state": "not_attempted",
                        "result": "unknown",
                        "record_counts": {},
                        "detail": "The assessment time limit was reached before hostname discovery.",
                    })
                break
            if not is_in_scope(host, self.target_domain):
                self.hostname_outcomes.append({
                    "hostname": host,
                    "state": "skipped",
                    "result": "unknown",
                    "record_counts": {},
                    "detail": "The hostname was outside the requested scope.",
                })
                continue

            first_query = len(self.query_outcomes)
            records = self.resolve_dns_records(host, include_mail_records=(host == self.target_domain))
            queries = self.query_outcomes[first_query:]
            query_states = [query["state"] for query in queries]
            if not query_states:
                host_state = "not_attempted"
            elif all(state == "completed" for state in query_states):
                host_state = "completed"
            elif all(state in {"failed", "not_attempted"} for state in query_states):
                host_state = "failed" if "failed" in query_states else "not_attempted"
            else:
                host_state = "incomplete"

            # An asset exists if it has any A, AAAA, or CNAME records
            has_asset_records = bool(records["A"] or records["AAAA"] or records["CNAME"])
            self.hostname_outcomes.append({
                "hostname": host,
                "state": host_state,
                "result": "records_found" if has_asset_records else (
                    "private_addresses_filtered"
                    if any(query.get("private_records_filtered", 0) for query in queries)
                    else "no_public_asset_records" if host_state == "completed" else "unknown"
                ),
                "record_counts": {record_type: len(values) for record_type, values in records.items()},
                "query_failures": sum(state == "failed" for state in query_states),
            })
            if has_asset_records:
                asset_type = "DOMAIN" if host == self.target_domain else "SUBDOMAIN"
                discovered.append({
                    "asset_type": asset_type,
                    "identifier": host,
                    "hostname": host,
                    "ip_address": records["A"][0] if records["A"] else (records["AAAA"][0] if records["AAAA"] else None),
                    "dns_records": records
                })

        return discovered

    def execution_summary(self, confirmed_assets: int) -> Dict[str, Any]:
        """Return bounded, sanitized DNS execution facts for the scan record."""
        query_states = [query["state"] for query in self.query_outcomes]
        attempted = sum(state in {"completed", "failed"} for state in query_states)
        completed = sum(state == "completed" for state in query_states)
        failed = sum(state == "failed" for state in query_states)
        not_attempted = sum(state == "not_attempted" for state in query_states)
        skipped = sum(state == "skipped" for state in query_states)
        if attempted == 0:
            state = "not_attempted"
        elif failed == attempted:
            state = "failed"
        elif failed or not_attempted or skipped:
            state = "incomplete"
        else:
            state = "completed"

        root = next((row for row in self.hostname_outcomes if row["hostname"] == self.target_domain), None)
        private_records_filtered = sum(
            query.get("private_records_filtered", 0) for query in self.query_outcomes
        )
        return {
            "state": state,
            "result": "records_found" if confirmed_assets else (
                "private_addresses_filtered" if private_records_filtered else "no_public_asset_records" if state == "completed" else "unknown"
            ),
            "target_domain": self.target_domain,
            "hostnames_considered": self.hostname_candidates,
            "hostnames_attempted": sum(row["state"] in {"completed", "failed", "incomplete"} for row in self.hostname_outcomes),
            "hostnames_with_records": sum(row["result"] == "records_found" for row in self.hostname_outcomes),
            "confirmed_assets": confirmed_assets,
            "root_domain": root,
            "query_counts": {
                "attempted": attempted,
                "completed": completed,
                "failed": failed,
                "skipped": skipped,
                "not_attempted": not_attempted,
            },
            "private_records_filtered": private_records_filtered,
            "hosts": self.hostname_outcomes,
            "queries": self.query_outcomes,
        }

    @staticmethod
    def inspect_tls(
        hostname: str,
        port: int = 443,
        timeout: float = 3.0,
        target_root_domain: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Connects via TLS to inspect certificate issuer, expiry, SANs, and protocol version safely.
        """
        if port not in (443, 8443):
            return None

        try:
            # Validate every DNS answer and connect to one of the returned IPs
            # directly so a second DNS lookup cannot rebind the connection.
            target_ips = resolve_and_verify_ip(hostname, target_root_domain)
        except SecurityValidationError:
            return None

        context = ssl.create_default_context()
        tls_deadline = time.monotonic() + max(0.0, timeout)
        for target_ip in target_ips[:4]:
            remaining = tls_deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                with socket.create_connection((target_ip, port), timeout=remaining) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()

                        san_list = [
                            value
                            for kind, value in cert.get("subjectAltName", [])
                            if kind == "DNS"
                        ]
                        return {
                            "subject": dict(x[0] for x in cert.get("subject", ())),
                            "issuer": dict(x[0] for x in cert.get("issuer", ())),
                            "notBefore": cert.get("notBefore"),
                            "notAfter": cert.get("notAfter"),
                            "subjectAltName": san_list,
                            "cipher": cipher,
                            "version": version,
                            "valid": True,
                        }
            except ssl.SSLCertVerificationError as exc:
                return {
                    "valid": False,
                    "error": f"Certificate verification failed: {type(exc).__name__}",
                }
            except (OSError, ssl.SSLError):
                continue
        # A failed connection or TLS negotiation does not prove a bad certificate.
        return None

