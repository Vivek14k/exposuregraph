import ipaddress
import re
import time
import dns.exception
import dns.resolver
from typing import List, Tuple, Optional
from urllib.parse import urlsplit

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class SecurityValidationError(Exception):
    """Raised when domain or network validation fails for security reasons."""
    pass


def normalize_domain(domain_str: str) -> str:
    """Return an ASCII, lowercase DNS name; accept only a bare host or a root URL."""
    if not isinstance(domain_str, str) or not domain_str.strip():
        raise SecurityValidationError("Domain cannot be empty.")

    candidate = domain_str.strip()
    if "://" in candidate:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise SecurityValidationError("Only a bare domain or an HTTP(S) root URL is accepted.")
        if parsed.username is not None or parsed.password is not None:
            raise SecurityValidationError("Credentials are not allowed in a target URL.")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise SecurityValidationError("Provide a domain or a URL to its root without a path, query, or fragment.")
        try:
            port = parsed.port
        except ValueError as exc:
            raise SecurityValidationError("Invalid port in target URL.") from exc
        expected_port = 443 if parsed.scheme.lower() == "https" else 80
        if port not in {None, expected_port}:
            raise SecurityValidationError("Custom ports are not accepted as scan targets.")
        candidate = parsed.hostname
    elif any(char in candidate for char in "/\\?#@:"):
        raise SecurityValidationError("Provide a domain name without a path, credentials, or port.")

    try:
        candidate = candidate.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise SecurityValidationError("Invalid internationalized domain name.") from exc

    if len(candidate) > 253 or not DOMAIN_REGEX.fullmatch(candidate):
        raise SecurityValidationError("Invalid domain format. Provide a valid fully qualified domain name.")
    return candidate


def is_ip_prohibited(ip_str: str) -> Tuple[bool, str]:
    """
    Checks if an IP address belongs to loopback, private, link-local,
    multicast, or reserved/unspecified ranges (SSRF protection).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    if not ip.is_global:
        if ip.is_loopback:
            reason = "Loopback IP address is prohibited."
        elif ip.is_link_local:
            reason = "Link-local IP address is prohibited."
        elif ip.is_multicast:
            reason = "Multicast IP address is prohibited."
        elif ip.is_unspecified:
            reason = "Unspecified IP address is prohibited."
        elif ip.is_private:
            reason = "Private/internal IP address is prohibited."
        elif ip.is_reserved:
            reason = "Reserved IP address is prohibited."
        else:
            reason = "Non-public IP address is prohibited."
        return True, reason

    return False, ""


def is_in_scope(hostname: str, target_root_domain: str) -> bool:
    """
    Verifies that the hostname strictly belongs to the target domain scope
    (either exact match or subdomain).
    """
    hostname = hostname.lower().strip().rstrip(".")
    target_root_domain = target_root_domain.lower().strip().rstrip(".")
    
    if hostname == target_root_domain:
        return True
    if hostname.endswith("." + target_root_domain):
        return True
    return False


def resolve_and_verify_ip(
    hostname: str,
    target_root_domain: Optional[str] = None,
    timeout: float = 2.0,
) -> List[str]:
    """
    Resolves hostname to IP addresses and checks each against SSRF/prohibited ranges.
    Also validates that hostname is within target domain scope if provided.
    """
    try:
        hostname = normalize_domain(hostname)
        if target_root_domain:
            target_root_domain = normalize_domain(target_root_domain)
    except SecurityValidationError:
        raise

    if target_root_domain and not is_in_scope(hostname, target_root_domain):
        raise SecurityValidationError(f"Hostname '{hostname}' is out of scope for '{target_root_domain}'.")

    resolver = dns.resolver.Resolver()
    deadline = time.monotonic() + max(0.1, timeout)
    valid_ips = []
    seen_ips = set()
    for record_type in ("A", "AAAA"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        resolver.timeout = min(1.0, remaining)
        try:
            answers = resolver.resolve(hostname, record_type, lifetime=remaining)
        except dns.exception.DNSException:
            # A host may legitimately have only one address family. Continue
            # through both bounded lookups, then reject if neither yielded IPs.
            continue

        for answer in answers:
            ip = str(answer.address)
            prohibited, reason = is_ip_prohibited(ip)
            if prohibited:
                raise SecurityValidationError(
                    f"SSRF Protection: Hostname '{hostname}' resolved to prohibited IP '{ip}' ({reason})"
                )
            if ip not in seen_ips:
                seen_ips.add(ip)
                valid_ips.append(ip)

    if not valid_ips:
        raise SecurityValidationError(f"No valid public IP addresses resolved for '{hostname}'.")

    return valid_ips

