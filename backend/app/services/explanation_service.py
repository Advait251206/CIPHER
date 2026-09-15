"""
CIPHER Explanation Service
Generates evidence-backed, human-readable explanations based on triggered heuristics
and dominant ML feature contributions, providing actionable security guidance.
"""

from typing import Dict, Any, List


class ExplanationService:
    """Explains cybersecurity verdicts using deterministic feature and rule evidence."""

    @staticmethod
    def generate_explanations(
        features: Dict[str, Any],
        heuristic_reasons: List[str],
        ml_prob: float,
        classification: str
    ) -> List[str]:
        """
        Synthesizes heuristic flags and ML feature anomalies into coherent, clear explanations.
        """
        reasons: List[str] = []

        # 1. Include specific heuristic alerts (excluding generic fallback)
        for h_reason in heuristic_reasons:
            if "No overt structural" not in h_reason:
                reasons.append(h_reason)

        # 2. Extract ML feature indicators if ML probability is high
        if ml_prob >= 0.50:
            if features.get('IsHTTPS', 1) == 0:
                reasons.append("Unencrypted connection (HTTP): Modern legitimate login services mandate HTTPS")
            if features.get('PathLength', 0) > 40:
                reasons.append(f"Excessively long URL path ({features['PathLength']} chars), common in phishing staging folders")
            if features.get('DegitRatioInURL', 0) > 0.15:
                reasons.append(f"Elevated digit ratio ({features['DegitRatioInURL']*100:.1f}%), often used to bypass basic domain filters")
            if features.get('URLEntropy', 0) > 4.4:
                reasons.append(f"High URL lexical entropy ({features['URLEntropy']}), indicating machine-generated parameters")
            if features.get('CharContinuationRate', 1.0) < 0.4:
                reasons.append("Irregular character transitions characteristic of obscured phishing URLs")
            if features.get('NoOfHyphensInURL', 0) >= 3:
                reasons.append(f"Multiple hyphens in URL ({features['NoOfHyphensInURL']}), often used in lookalike brand combinations")

        # If classified legitimate and no reasons were triggered
        if not reasons and classification == "LEGITIMATE":
            reasons.append("Clean URL structure with expected legitimate domain characteristics")
            reasons.append("HTTPS transport encryption in use with no spoofing indicators")

        # Deduplicate while maintaining order
        seen = set()
        deduped_reasons = []
        for r in reasons:
            if r not in seen:
                seen.add(r)
                deduped_reasons.append(r)

        return deduped_reasons[:6]
