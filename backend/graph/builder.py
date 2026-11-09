from typing import List, Dict, Any


def get_field(obj: Any, key: str, default: Any = None) -> Any:
    """Helper to safely extract field whether obj is a SQLAlchemy model instance or dict."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class ExposureGraphBuilder:
    def __init__(self, target_domain: str):
        self.target_domain = target_domain

    def build_graph(self, assets: List[Any], edges_records: List[Any], findings: List[Any] | None = None) -> Dict[str, Any]:
        """
        Builds React Flow compatible nodes and edges based on discovered assets
        and validated relationships.
        Features modern light-theme styling with clean cards, distinct badges, and smooth layout.
        """
        nodes = []
        edges = []

        # Color and style schema for light Gnani-inspired theme
        type_styles = {
            "DOMAIN": {
                "background": "linear-gradient(135deg, #ffffff 0%, #fff7ee 100%)",
                "color": "#1e293b",
                "border": "2px solid #fb923c",
                "headerBg": "#ffedd5",
                "badgeBg": "#f97316",
                "badgeText": "#ffffff"
            },
            "SUBDOMAIN": {
                "background": "linear-gradient(135deg, #ffffff 0%, #fdf2f6 100%)",
                "color": "#1e293b",
                "border": "2px solid #ec4899",
                "headerBg": "#fce7f3",
                "badgeBg": "#ec4899",
                "badgeText": "#ffffff"
            },
            "IP": {
                "background": "linear-gradient(135deg, #ffffff 0%, #f5effe 100%)",
                "color": "#1e293b",
                "border": "2px solid #8b5cf6",
                "headerBg": "#ede9fe",
                "badgeBg": "#8b5cf6",
                "badgeText": "#ffffff"
            },
            "SERVICE": {
                "background": "linear-gradient(135deg, #ffffff 0%, #fffbeb 100%)",
                "color": "#1e293b",
                "border": "2px solid #f59e0b",
                "headerBg": "#fef3c7",
                "badgeBg": "#d97706",
                "badgeText": "#ffffff"
            }
        }

        node_ids = set()

        # Layout offset trackers with clean spacing
        y_offsets = {"DOMAIN": 40, "SUBDOMAIN": 190, "IP": 340, "SERVICE": 490}
        x_counters = {"DOMAIN": 300, "SUBDOMAIN": 80, "IP": 80, "SERVICE": 80}

        for asset in assets:
            atype = get_field(asset, "asset_type") or "DOMAIN"
            ident = get_field(asset, "identifier") or ""
            host = get_field(asset, "hostname")
            ip = get_field(asset, "ip_address")
            port = get_field(asset, "port")
            proto = get_field(asset, "protocol")
            status = get_field(asset, "http_status")
            title = get_field(asset, "page_title")
            dns_rec = get_field(asset, "dns_records") or {}
            tls_info = get_field(asset, "tls_info")

            if not ident:
                continue

            node_id = f"node-{ident}"
            if node_id not in node_ids:
                node_ids.add(node_id)
                x_pos = x_counters.get(atype, 80)
                y_pos = y_offsets.get(atype, 80)
                x_counters[atype] = x_pos + 250

                style_conf = type_styles.get(atype, type_styles["DOMAIN"])

                nodes.append({
                    "id": node_id,
                    "type": "default",
                    "data": {
                        "label": ident,
                        "asset_type": atype,
                        "hostname": host,
                        "ip": ip,
                        "port": port,
                        "protocol": proto,
                        "http_status": status,
                        "page_title": title,
                        "dns_records": dns_rec,
                        "tls_info": tls_info
                    },
                    "position": {"x": x_pos, "y": y_pos},
                    "style": {
                        "background": style_conf["background"],
                        "color": style_conf["color"],
                        "border": style_conf["border"],
                        "borderRadius": "12px",
                        "padding": "12px 14px",
                        "fontWeight": "600",
                        "fontSize": "12px",
                        "minWidth": "180px",
                        "boxShadow": "0 4px 12px -2px rgba(15, 23, 42, 0.08), 0 2px 4px -2px rgba(15, 23, 42, 0.04)"
                    }
                })

        # Process edges safely
        for idx, edge in enumerate(edges_records):
            src = get_field(edge, "source")
            tgt = get_field(edge, "target")
            rel = get_field(edge, "relationship_type") or "CONNECTS_TO"

            src_node = f"node-{src}"
            tgt_node = f"node-{tgt}"

            if src_node in node_ids and tgt_node in node_ids:
                is_animated = rel in ("RESOLVES_TO", "RUNS_SERVICE")
                edges.append({
                    "id": f"edge-{idx}-{src_node}-{tgt_node}",
                    "source": src_node,
                    "target": tgt_node,
                    "label": rel.replace("_", " ").lower(),
                    "animated": is_animated,
                    "style": {
                        "stroke": "#ec4899" if is_animated else "#a78bfa",
                        "strokeWidth": 2.5
                    }
                })

        # Finding nodes are included only when their affected asset is present in
        # this scan's actual inventory, and each edge points to that recorded host.
        finding_rows = []
        for index, finding in enumerate(findings or []):
            affected_asset = get_field(finding, "affected_asset") or ""
            source_node_id = f"node-{affected_asset}"
            if source_node_id not in node_ids:
                continue

            finding_id = get_field(finding, "id", index)
            finding_node_id = f"node-finding-{finding_id}"
            severity = get_field(finding, "severity") or "INFO"
            severity_color = {
                "CRITICAL": "#e11d48",
                "HIGH": "#ea580c",
                "MEDIUM": "#d97706",
                "LOW": "#8b5cf6",
                "INFO": "#ec4899",
            }.get(severity, "#a855f7")
            finding_rows.append({
                "id": finding_node_id,
                "type": "default",
                "data": {
                    "label": get_field(finding, "title") or "Recorded finding",
                    "asset_type": "FINDING",
                    "severity": severity,
                    "score": get_field(finding, "score"),
                    "confidence": get_field(finding, "confidence"),
                    "affected_asset": affected_asset,
                    "evidence": get_field(finding, "evidence"),
                    "explanation": get_field(finding, "explanation"),
                    "remediation": get_field(finding, "remediation"),
                },
                "position": {"x": 80 + (index % 4) * 250, "y": 650 + (index // 4) * 150},
                "style": {
                    "background": "#ffffff",
                    "color": "#253b64",
                    "border": f"2px solid {severity_color}",
                    "borderRadius": "12px",
                    "padding": "12px 14px",
                    "fontWeight": "600",
                    "fontSize": "12px",
                    "minWidth": "180px",
                    "boxShadow": "0 4px 12px -2px rgba(15, 23, 42, 0.08)",
                },
            })
            edges.append({
                "id": f"edge-finding-{finding_id}",
                "source": source_node_id,
                "target": finding_node_id,
                "label": "has finding",
                "animated": False,
                "style": {"stroke": severity_color, "strokeWidth": 2},
            })

        nodes.extend(finding_rows)

        return {
            "nodes": nodes,
            "edges": edges
        }
