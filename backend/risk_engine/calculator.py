from typing import Dict, Any

# Transparent weights
SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 4.5,
    "LOW": 2.0,
    "INFO": 0.5
}

CONFIDENCE_MULTIPLIER = {
    "HIGH": 1.0,
    "MEDIUM": 0.8,
    "LOW": 0.5
}


class RiskEngine:
    @staticmethod
    def calculate_finding_score(severity: str, confidence: str, is_root_domain: bool = False) -> float:
        """
        Calculates an individual finding risk score (0 to 10) based on severity,
        measurement confidence, and asset exposure/importance.
        Never presented as a fake CVSS score.
        """
        sev = severity.upper()
        conf = confidence.upper()

        base = SEVERITY_WEIGHTS.get(sev, 2.0)
        multiplier = CONFIDENCE_MULTIPLIER.get(conf, 0.8)

        # Assets on primary root domain or api often carry higher blast radius
        exposure_factor = 1.1 if is_root_domain else 1.0

        score = min(10.0, round(base * multiplier * exposure_factor, 1))
        return score

    @staticmethod
    def calculate_overall_risk(findings_scores: list[float]) -> float:
        """
        Calculates the aggregate exposure score for the entire scan (0 to 100).
        Uses a logarithmic diminishing returns formula so a high number of minor
        issues doesn't artificially outweigh severe issues.
        """
        if not findings_scores:
            return 0.0

        # Max single risk contribution
        max_score = max(findings_scores) * 7.0  # up to 70 pts from top risk
        
        # Cumulative contribution of remaining scores
        rest_sum = sum(findings_scores) - max(findings_scores)
        additional = min(30.0, rest_sum * 1.5)

        total = min(100.0, round(max_score + additional, 1))
        return total

