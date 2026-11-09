import datetime
import logging
import time
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from backend.database.models import Scan, Asset, Finding, GraphEdge, SessionLocal
from backend.discovery.engine import DiscoveryService
from backend.scanner.engine import SecurityScanner, SAFE_PORTS_TO_CHECK
from backend.risk_engine.calculator import RiskEngine
from backend.core.config import settings

logger = logging.getLogger("exposuregraph.scanner")


def _check_row(subject: str, state: str, result: str, detail: str) -> Dict[str, Any]:
    return {"subject": subject, "state": state, "result": result, "detail": detail}


def _aggregate_check(name: str, outcomes: List[Dict[str, Any]], summary: str) -> Dict[str, Any]:
    counts = {
        state: sum(row.get("state") == state for row in outcomes)
        for state in ("completed", "failed", "skipped", "not_attempted", "incomplete")
    }
    attempted = counts["completed"] + counts["failed"]
    if not outcomes or counts["not_attempted"] == len(outcomes):
        state = "not_attempted"
    elif counts["skipped"] == len(outcomes):
        state = "skipped"
    elif attempted and counts["failed"] == attempted and not counts["completed"]:
        state = "failed"
    elif counts["failed"] or counts["skipped"] or counts["not_attempted"] or counts["incomplete"]:
        state = "incomplete"
    else:
        state = "completed"
    results: Dict[str, int] = {}
    for row in outcomes:
        result = str(row.get("result", "unknown"))
        results[result] = results.get(result, 0) + 1
    return {
        "name": name,
        "state": state,
        "attempted": attempted,
        **counts,
        "results": results,
        "summary": summary,
        "details": outcomes,
    }


def _safe_probe_detail(error: Any) -> str:
    known = {
        "No public IP resolved.": "No publicly validated address was available for the service probe.",
        "Scan time limit reached.": "The assessment time limit was reached before the probe completed.",
        "Unsupported service probe.": "The requested service probe is outside the bounded port list.",
    }
    if not error:
        return "No HTTP response was received from the bounded probe."
    return known.get(str(error), "No HTTP response was received from the bounded probe.")


def execute_scan_task(scan_id: int):
    """
    Orchestrates the entire non-invasive security scan workflow:
    1. Passive & DNS Asset Discovery (domains, subdomains, A, AAAA, CNAME, MX, NS)
    2. TLS & Certificate Inspection
    3. Safe service probing (80, 443, 8080, 8443)
    4. Security misconfiguration & header checks
    5. Exposure graph relationship synthesis
    6. Transparent risk scoring & persistence
    """
    db: Session = SessionLocal()
    scan = None
    metadata: Dict[str, Any] = {
        "schema_version": 1,
        "coverage": "in_progress",
        "discovery": None,
        "checks": [],
        "limitations": [],
        "recommendations": [],
    }
    tls_outcomes: List[Dict[str, Any]] = []
    service_outcomes: List[Dict[str, Any]] = []
    header_outcomes: List[Dict[str, Any]] = []
    finding_outcomes: List[Dict[str, Any]] = []
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = "RUNNING"
        scan.execution_metadata = metadata
        db.commit()

        target_domain = scan.target_domain
        deadline = time.monotonic() + max(1.0, settings.scan_timeout_seconds)
        discovery = DiscoveryService(target_domain, deadline=deadline)
        scanner = SecurityScanner(target_domain, deadline=deadline)

        # Step 1: Enumerate subdomains & DNS
        discovered_assets = discovery.enumerate_subdomains()
        discovery_summary = discovery.execution_summary(len(discovered_assets))
        metadata["discovery"] = discovery_summary
        dns_outcomes = [
            _check_row(
                f"{query['hostname']} · {query['record_type']}",
                query["state"],
                query["result"],
                query.get("detail") or (
                    f"{query['record_count']} record(s) returned."
                    if query["result"] == "records_found"
                    else "The DNS query completed without an address or canonical-name record."
                ),
            )
            for query in discovery.query_outcomes
        ]
        metadata["checks"] = [_aggregate_check(
            "DNS and hostname discovery",
            dns_outcomes,
            f"Considered {discovery.hostname_candidates} in-scope hostnames; {len(discovered_assets)} produced confirmed public asset records.",
        )]
        
        # Do not invent a root asset when DNS did not confirm one. Preserve the
        # assessment as partial so the UI can explain the missing evidence.
        if not discovered_assets:
            metadata["checks"].extend([
                _aggregate_check("TLS certificate inspection", [
                    _check_row("Confirmed public hosts", "not_attempted", "unknown", "No confirmed public hostname was available for TLS inspection.")
                ], "TLS inspection was not attempted because discovery confirmed no public assets."),
                _aggregate_check("Bounded web service probes", [
                    _check_row("Confirmed public hosts", "not_attempted", "unknown", "No confirmed public hostname was available for a service probe.")
                ], "Service probes were not attempted because discovery confirmed no public assets."),
                _aggregate_check("Security header review", [
                    _check_row("HTTPS response", "not_attempted", "unknown", "No HTTPS response was available; header conditions were not assessed.")
                ], "Security headers were not assessed because no HTTPS response was recorded."),
                _aggregate_check("Evidence-based finding analysis", [
                    _check_row("Confirmed public hosts", "not_attempted", "unknown", "Finding analysis had no confirmed asset evidence to evaluate.")
                ], "No host-level finding rules could run without confirmed assets."),
            ])
            metadata["coverage"] = "incomplete"
            metadata["limitations"] = [
                "No public DNS assets were confirmed, so TLS and web service checks were not attempted.",
                "Zero recorded findings do not establish that the target is secure.",
            ]
            metadata["recommendations"] = [
                "Verify the target spelling and its public DNS records, then retry the authorized assessment.",
                "If DNS is intentionally private or unavailable, use an assessment method appropriate to that environment.",
            ]
            scan.status = "PARTIAL"
            scan.error_message = "No public DNS assets were confirmed. TLS and web service checks were not attempted."
            scan.total_assets = 0
            scan.total_findings = 0
            scan.risk_score = 0.0
            scan.completed_at = datetime.datetime.utcnow()
            scan.execution_metadata = metadata
            db.commit()
            return

        all_findings_scores = []
        discovered_ip_set = set()
        timed_out = False
        dns_incomplete = discovery_summary["state"] in {"failed", "incomplete", "not_attempted"}

        for asset_data in discovered_assets:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            hostname = asset_data["hostname"]
            asset_type = asset_data["asset_type"]
            dns_records = asset_data.get("dns_records", {})
            ip_address = asset_data.get("ip_address")

            # Persist host/subdomain asset
            host_asset_record = Asset(
                scan_id=scan.id,
                asset_type=asset_type,
                identifier=hostname,
                hostname=hostname,
                ip_address=ip_address,
                dns_records=dns_records
            )
            db.add(host_asset_record)
            db.flush()

            # Create Graph Edge if subdomain
            if asset_type == "SUBDOMAIN":
                edge = GraphEdge(
                    scan_id=scan.id,
                    source=hostname,
                    target=target_domain,
                    relationship_type="SUBDOMAIN_OF"
                )
                db.add(edge)

            # Record IP Assets and Graph Edges
            for a_rec in dict.fromkeys(dns_records.get("A", []) + dns_records.get("AAAA", [])):
                if a_rec not in discovered_ip_set:
                    discovered_ip_set.add(a_rec)
                    ip_asset = Asset(
                        scan_id=scan.id,
                        asset_type="IP",
                        identifier=a_rec,
                        ip_address=a_rec
                    )
                    db.add(ip_asset)

                # Edge: Hostname -> IP
                edge = GraphEdge(
                    scan_id=scan.id,
                    source=hostname,
                    target=a_rec,
                    relationship_type="RESOLVES_TO"
                )
                db.add(edge)

            # Check TLS Certificate if accessible. A missing handshake is kept
            # separate from a validated certificate; it is never marked passed.
            remaining = max(0.0, deadline - time.monotonic())
            if remaining > 0:
                tls_info = discovery.inspect_tls(
                    hostname,
                    443,
                    timeout=min(3.0, remaining),
                    target_root_domain=target_domain,
                )
                if tls_info:
                    valid = bool(tls_info.get("valid"))
                    tls_outcomes.append(_check_row(
                        hostname,
                        "completed",
                        "no_finding" if valid else "finding",
                        "A certificate handshake completed and validation succeeded." if valid else "A certificate was observed, but validation failed.",
                    ))
                else:
                    tls_outcomes.append(_check_row(
                        hostname,
                        "failed",
                        "no_response",
                        "No verifiable TLS handshake was obtained; this does not establish that TLS is absent or insecure.",
                    ))
            else:
                tls_info = None
                timed_out = True
                tls_outcomes.append(_check_row(
                    hostname, "not_attempted", "unknown", "The assessment time limit was reached before TLS inspection."
                ))
            if tls_info:
                host_asset_record.tls_info = tls_info

            # Probe safe HTTP/HTTPS services
            http_results = []
            for port_index, port in enumerate(SAFE_PORTS_TO_CHECK):
                if time.monotonic() >= deadline:
                    timed_out = True
                    for remaining_port in SAFE_PORTS_TO_CHECK[port_index:]:
                        service_outcomes.append(_check_row(
                            f"{hostname}:{remaining_port}",
                            "not_attempted",
                            "unknown",
                            "The assessment time limit was reached before this bounded port probe.",
                        ))
                    break
                # Safe quick socket check if IP known
                use_tls = port in (443, 8443)
                if ip_address:
                    is_open = scanner.check_port_open(ip_address, port)
                    if not is_open:
                        http_results.append({
                            "url": f"{'https' if use_tls else 'http'}://{hostname}:{port}/",
                            "port": port,
                            "use_tls": use_tls,
                            "accessible": False,
                            "probe_state": "unreachable",
                            "error": "TCP connection attempt did not complete",
                        })
                        service_outcomes.append(_check_row(
                            f"{hostname}:{port}",
                            "completed",
                            "no_response",
                            "The bounded TCP probe received no connection. Filtering or a timeout can look the same as a closed service.",
                        ))
                        continue

                service_res = scanner.scan_http_service(hostname, port, use_tls=use_tls)
                http_results.append(service_res)

                if service_res.get("accessible"):
                    service_outcomes.append(_check_row(
                        f"{hostname}:{port}",
                        "completed",
                        "response_received",
                        f"Received an HTTP response with status {service_res.get('status_code')}.",
                    ))
                elif service_res.get("error") == "Scan time limit reached.":
                    timed_out = True
                    service_outcomes.append(_check_row(
                        f"{hostname}:{port}", "incomplete", "unknown", _safe_probe_detail(service_res.get("error"))
                    ))
                elif service_res.get("error") == "No public IP resolved.":
                    service_outcomes.append(_check_row(
                        f"{hostname}:{port}", "skipped", "unknown", _safe_probe_detail(service_res.get("error"))
                    ))
                else:
                    service_outcomes.append(_check_row(
                        f"{hostname}:{port}", "failed", "no_response", _safe_probe_detail(service_res.get("error"))
                    ))

                if service_res.get("accessible"):
                    service_ident = f"{hostname}:{port}"
                    service_asset = Asset(
                        scan_id=scan.id,
                        asset_type="SERVICE",
                        identifier=service_ident,
                        hostname=hostname,
                        port=port,
                        protocol="https" if use_tls else "http",
                        http_status=service_res.get("status_code"),
                        page_title=service_res.get("title")
                    )
                    db.add(service_asset)

                    # Edge: Hostname -> Service
                    edge = GraphEdge(
                        scan_id=scan.id,
                        source=hostname,
                        target=service_ident,
                        relationship_type="RUNS_SERVICE"
                    )
                    db.add(edge)

            accessible_https = [
                result for result in http_results
                if result.get("use_tls") and result.get("accessible")
            ]
            if accessible_https:
                for result in accessible_https:
                    missing_headers = result.get("missing_headers") or []
                    header_outcomes.append(_check_row(
                        f"{hostname}:{result.get('port')}",
                        "completed",
                        "findings" if missing_headers else "no_findings",
                        f"Observed {len(missing_headers)} missing defensive header(s)." if missing_headers else "The assessed response included the checked defensive headers.",
                    ))
            else:
                header_outcomes.append(_check_row(
                    hostname,
                    "skipped",
                    "not_assessed",
                    "No HTTPS response was available; security header conditions were not tested.",
                ))

            # Step 4: Evaluate findings
            findings_data = scanner.evaluate_findings(asset_data, http_results, tls_info)
            finding_outcomes.append(_check_row(
                hostname,
                "completed",
                "findings" if findings_data else "no_findings",
                f"Evidence rules recorded {len(findings_data)} finding(s) for this confirmed host." if findings_data else "Evidence rules completed without recording a finding for this confirmed host.",
            ))
            for f_data in findings_data:
                is_root = (hostname == target_domain)
                score = RiskEngine.calculate_finding_score(f_data["severity"], f_data["confidence"], is_root_domain=is_root)
                all_findings_scores.append(score)

                finding_rec = Finding(
                    scan_id=scan.id,
                    title=f_data["title"],
                    affected_asset=f_data["affected_asset"],
                    severity=f_data["severity"],
                    score=score,
                    confidence=f_data["confidence"],
                    evidence=f_data["evidence"],
                    explanation=f_data["explanation"],
                    remediation=f_data["remediation"]
                )
                db.add(finding_rec)

            if time.monotonic() >= deadline:
                timed_out = True
                break

        # Calculate scan-level aggregate metrics
        total_assets = db.query(Asset).filter(Asset.scan_id == scan.id).count()
        total_findings = db.query(Finding).filter(Finding.scan_id == scan.id).count()
        overall_risk = RiskEngine.calculate_overall_risk(all_findings_scores)

        metadata["checks"].extend([
            _aggregate_check("TLS certificate inspection", tls_outcomes, "TLS outcomes are reported per confirmed hostname; no response is not treated as a pass."),
            _aggregate_check("Bounded web service probes", service_outcomes, "Only the configured public web ports were probed. No response does not prove a service is absent."),
            _aggregate_check("Security header review", header_outcomes, "Header conditions are assessed only when an HTTPS response is recorded."),
            _aggregate_check("Evidence-based finding analysis", finding_outcomes, "Finding rules run against saved discovery, TLS, and HTTP evidence."),
        ])

        scan.status = "PARTIAL" if timed_out or dns_incomplete else "COMPLETED"
        if timed_out:
            scan.error_message = "The configured assessment time limit was reached. Some checks were not attempted or did not complete."
        elif dns_incomplete:
            scan.error_message = "Some DNS discovery checks failed or were not attempted. Review the recorded coverage before interpreting this assessment."

        metadata["coverage"] = "incomplete" if scan.status == "PARTIAL" else "bounded"
        metadata["limitations"] = [
            "This assessment uses bounded public DNS and web checks; it is not a penetration test.",
            "Zero findings do not prove that the target is secure.",
        ]
        if discovery_summary["state"] in {"failed", "incomplete", "not_attempted"}:
            metadata["limitations"].append("Some DNS lookups failed or were not attempted; see the per-host query outcomes.")
            metadata["recommendations"].append("Verify public DNS and retry the authorized assessment after resolver or network issues are resolved.")
        if timed_out:
            metadata["limitations"].append("The configured time limit stopped some checks before they were attempted or completed.")
            metadata["recommendations"].append("Retry when the target is responsive or adjust the bounded assessment time limit.")
        if not any(outcome["result"] == "response_received" for outcome in service_outcomes):
            metadata["limitations"].append("No HTTP response was recorded from the bounded service probes; filtering and timeouts can prevent confirmation.")
            metadata["recommendations"].append("Confirm which public web services should respond and whether network filtering permits these bounded checks.")
        if total_findings == 0:
            metadata["recommendations"].append("Review the assessed scope and supplement this bounded scan with other authorized security reviews as appropriate.")
        scan.total_assets = total_assets
        scan.total_findings = total_findings
        scan.risk_score = overall_risk
        scan.completed_at = datetime.datetime.utcnow()
        scan.execution_metadata = metadata
        db.commit()

    except Exception as e:
        logger.exception(f"Error executing scan {scan_id}: {str(e)}")
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "FAILED"
            scan.error_message = "The assessment stopped because a scan step failed. Check the backend log for details."
            scan.completed_at = datetime.datetime.utcnow()
            metadata["coverage"] = "incomplete"
            metadata["limitations"] = list(metadata.get("limitations", [])) + [
                "The scan stopped before every assessment step could complete."
            ]
            metadata["recommendations"] = list(metadata.get("recommendations", [])) + [
                "Review the backend log and retry only after the failure is understood."
            ]
            metadata["checks"] = list(metadata.get("checks", [])) + [
                _aggregate_check("Scan orchestration", [
                    _check_row("Assessment", "failed", "unknown", "A backend scan step stopped before completion.")
                ], "The assessment did not finish all configured steps.")
            ]
            scan.execution_metadata = metadata
            db.commit()
    finally:
        db.close()

