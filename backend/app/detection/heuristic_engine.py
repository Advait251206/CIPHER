"""
CIPHER Heuristic Detection Engine
Performs independent rule-based heuristic inspection of URLs to catch known attack vectors,
homoglyphs, brand spoofing, and credential harvest indicators without relying solely on ML.
"""

import re
import math
import urllib.parse
from typing import Dict, Any, List, Tuple

# Suspicious high-abuse TLDs
HIGH_RISK_TLDS = {
    'xyz', 'top', 'gq', 'cf', 'tk', 'ml', 'ga', 'work', 'date', 'wang',
    'racing', 'icu', 'buzz', 'club', 'surf', 'cam', 'rest', 'fit', 'cc', 'ru'
}

# Targeted high-profile brands and their official root domains
MAJOR_BRANDS: Dict[str, List[str]] = {
    'google': ['google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.fr', 'google.ca', 'gmail.com', 'youtube.com'],
    'paypal': ['paypal.com', 'paypal.me'],
    'apple': ['apple.com', 'icloud.com'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'office365.com', 'azure.com'],
    'amazon': ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com'],
    'netflix': ['netflix.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'instagram': ['instagram.com'],
    'whatsapp': ['whatsapp.com'],
    'chase': ['chase.com'],
    'wellsfargo': ['wellsfargo.com'],
    'bankofamerica': ['bankofamerica.com'],
    'binance': ['binance.com'],
    'coinbase': ['coinbase.com'],
    'metamask': ['metamask.io'],
    'dropbox': ['dropbox.com'],
    'adobe': ['adobe.com'],
    'yahoo': ['yahoo.com']
}

# Credential-related keywords
CREDENTIAL_KEYWORDS = [
    'login', 'signin', 'log-in', 'sign-in', 'verify', 'verification', 'update',
    'security-check', 'authenticate', 'password', 'credential', 'recovery',
    'restore-account', 'confirm-identity', 'wallet-connect', 'webscr'
]


class HeuristicEngine:
    """Independent cybersecurity heuristic inspection engine."""

    def __init__(self):
        pass

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq: Dict[str, int] = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Inspects URL and produces a heuristic risk score (0-100),
        triggered reasons, and individual indicator weights.
        """
        if not url or not isinstance(url, str):
            return {
                "heuristic_score": 0,
                "reasons": ["Empty or invalid URL provided"],
                "indicators": {}
            }

        url_str = url.strip()
        url_to_parse = url_str if "://" in url_str else f"http://{url_str}"
        parsed = urllib.parse.urlparse(url_to_parse)

        netloc = parsed.netloc or parsed.path.split('/')[0]
        domain = netloc.split(':')[0].lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url_lower = url_str.lower()

        reasons: List[str] = []
        indicators: Dict[str, Any] = {}
        score: float = 0.0

        # 1. IP address in hostname (High risk - standard phishing technique)
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, domain):
            score += 45.0
            reasons.append("Raw IPv4 address used in hostname instead of registered domain name")
            indicators["is_domain_ip"] = True
        else:
            indicators["is_domain_ip"] = False

        # 2. Presence of '@' symbol (Credential spoofing / redirect syntax)
        if '@' in url_str:
            score += 50.0
            reasons.append("URL contains '@' symbol used in credential spoofing and misleading redirect attacks")
            indicators["has_at_symbol"] = True
        else:
            indicators["has_at_symbol"] = False

        # 3. Punycode / IDN Homograph attack ('xn--')
        if 'xn--' in domain:
            score += 40.0
            reasons.append("Punycode / IDN homograph domain detected (potential character spoofing)")
            indicators["is_punycode"] = True
        else:
            indicators["is_punycode"] = False

        # 4. Brand Impersonation in Domain / Subdomain / Path
        brand_impersonated = None
        for brand, official_domains in MAJOR_BRANDS.items():
            if brand in full_url_lower:
                # Check if current domain is an official domain or subdomain of official
                is_official = any(
                    domain == off or domain.endswith(f".{off}")
                    for off in official_domains
                )
                if not is_official:
                    brand_impersonated = brand
                    break

        if brand_impersonated:
            score += 40.0
            reasons.append(f"Potential brand impersonation: '{brand_impersonated}' token found on unofficial domain '{domain}'")
            indicators["brand_impersonation"] = brand_impersonated
        else:
            indicators["brand_impersonation"] = None

        # 5. Excessive Subdomain Depth (> 2 subdomains)
        domain_parts = domain.split('.')
        subdomain_count = max(0, len(domain_parts) - 2) if len(domain_parts) > 2 else 0
        if subdomain_count >= 3:
            score += 20.0
            reasons.append(f"Excessive subdomain nesting detected ({subdomain_count} levels)")
            indicators["excessive_subdomains"] = subdomain_count
        else:
            indicators["excessive_subdomains"] = subdomain_count

        # 6. High-Risk / Suspicious TLD
        tld = domain_parts[-1] if len(domain_parts) > 1 else ""
        if tld in HIGH_RISK_TLDS:
            score += 25.0
            reasons.append(f"High-abuse top-level domain detected (.{tld})")
            indicators["high_risk_tld"] = tld
        else:
            indicators["high_risk_tld"] = None

        # 7. Credential / Login Keywords in unverified domain
        found_cred_kws = [kw for kw in CREDENTIAL_KEYWORDS if kw in full_url_lower]
        if found_cred_kws:
            weight = min(30.0, len(found_cred_kws) * 10.0)
            score += weight
            reasons.append(f"Sensitive authentication/credential tokens detected in URL: {', '.join(found_cred_kws[:4])}")
            indicators["credential_keywords"] = found_cred_kws
        else:
            indicators["credential_keywords"] = []

        # 8. Unencrypted HTTP with Sensitive Authentication Keywords
        is_http = parsed.scheme.lower() == 'http'
        if is_http and found_cred_kws:
            score += 25.0
            reasons.append("Unencrypted HTTP protocol combined with authentication/login keywords")
            indicators["insecure_http_auth"] = True
        else:
            indicators["insecure_http_auth"] = False

        # 9. Excessive URL / Path Length (> 100 chars or > 6 slashes in path)
        if len(url_str) > 120:
            score += 15.0
            reasons.append(f"Unusually long URL structure ({len(url_str)} characters)")
            indicators["excessive_length"] = True
        else:
            indicators["excessive_length"] = False

        # 10. Domain Shannon Entropy (Detect Algorithmic / DGA generation)
        domain_entropy = self._calculate_entropy(domain)
        if domain_entropy > 4.2 and not re.match(ipv4_pattern, domain):
            score += 20.0
            reasons.append(f"Elevated domain lexical randomness (entropy: {domain_entropy}) indicative of DGA generation")
            indicators["high_entropy"] = domain_entropy
        else:
            indicators["high_entropy"] = None

        # 11. Multiple embedded URL / redirect keywords in query string
        if any(param in query for param in ['redirect=', 'url=', 'goto=', 'link=', 'target=']):
            score += 15.0
            reasons.append("Open redirect query parameter structure detected")
            indicators["open_redirect_param"] = True
        else:
            indicators["open_redirect_param"] = False

        # Bound score between 0 and 100
        final_heuristic_score = min(100, int(round(score)))

        if final_heuristic_score == 0:
            reasons.append("No overt structural or lexical heuristic anomalies detected")

        return {
            "heuristic_score": final_heuristic_score,
            "reasons": reasons,
            "indicators": indicators
        }
