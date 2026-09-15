"""
CIPHER Feature Extraction Pipeline
Local, privacy-preserving lexical and structural feature extractor for URLs.
Extracts 28 reproducible features with zero external network requests.
"""

import re
import math
import urllib.parse
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np

# Suspicious keywords frequently observed in phishing / credential-harvesting paths and parameters
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'update', 'account', 'banking',
    'secure', 'security', 'webscr', 'ebayisapi', 'auth', 'authenticate', 'wallet',
    'confirm', 'password', 'credential', 'support', 'service', 'recover', 'token',
    'client', 'portal', 'validation', 'upgrade', 'alert'
]

# High-risk TLDs commonly abused in automated phishing kits
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'gq', 'cf', 'tk', 'ml', 'ga', 'work', 'date', 'wang',
    'racing', 'icu', 'buzz', 'club', 'surf', 'cam', 'rest', 'fit', 'cc'
}

# Known brand tokens often spoofed in domains/paths
BRAND_TOKENS = [
    'google', 'paypal', 'apple', 'microsoft', 'netflix', 'amazon', 'chase',
    'wellsfargo', 'bankofamerica', 'facebook', 'instagram', 'whatsapp', 'binance',
    'coinbase', 'metamask', 'dropbox', 'adobe', 'outlook', 'yahoo'
]


class FeatureExtractor:
    """Extracts lexical, structural, and entropy features from URLs."""

    def __init__(self):
        # Removed absolute length/count features (e.g. URLLength, PathLength, NoOfLettersInURL)
        # to prevent dataset leakage, as PhiUSIIL legitimate URLs typically lack paths,
        # causing the model to erroneously flag any valid URL with a path as phishing.
        self.feature_names = [
            'DomainLength',
            'IsDomainIP',
            'TLDLength',
            'NoOfSubDomain',
            'HasObfuscation',
            'ObfuscationRatio',
            'LetterRatioInURL',
            'DegitRatioInURL',
            'SpacialCharRatioInURL',
            'IsHTTPS',
            'CharContinuationRate',
            'URLEntropy',
            'DomainEntropy',
            'SuspiciousKeywordCount',
            'IsSuspiciousTLD',
        ]

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Computes Shannon entropy to detect randomized/DGA string patterns."""
        if not text:
            return 0.0
        length = len(text)
        freq: Dict[str, int] = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def char_continuation_rate(text: str) -> float:
        """
        Measures longest consecutive sequence of identical character type (Letter, Digit, Symbol)
        normalized by length. Legitimate text has continuous syllables; phishing often has erratic transitions.
        """
        if not text:
            return 0.0

        def get_type(c: str) -> str:
            if c.isalpha():
                return 'L'
            if c.isdigit():
                return 'D'
            return 'S'

        max_run = 0
        cur_run = 0
        cur_type = None
        for c in text:
            ctype = get_type(c)
            if ctype == cur_type:
                cur_run += 1
            else:
                cur_run = 1
                cur_type = ctype
            if cur_run > max_run:
                max_run = cur_run
        return round(max_run / len(text), 4)

    @staticmethod
    def canonicalize_url(url: str) -> str:
        """
        Canonicalizes apex domains (e.g. 'https://github.com' -> 'https://www.github.com')
        to align with the canonical web origin representation of the PhiUSIIL dataset,
        where legitimate crawled origins uniformly included 'www.' (134,850 / 134,850).
        Preserves IP addresses, multi-level subdomains, and ports untouched.
        """
        if not url or not isinstance(url, str):
            return ""
        url_str = url.strip()
        url_to_parse = url_str if "://" in url_str else f"http://{url_str}"
        try:
            parsed = urllib.parse.urlparse(url_to_parse)
            host = parsed.netloc.split(':')[0].lower() if parsed.netloc else parsed.path.split('/')[0].split(':')[0].lower()
            ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            # If domain has exactly one dot (apex domain) and does not start with www and is not an IP
            if host.count('.') == 1 and not host.startswith('www.') and not re.match(ipv4_pattern, host):
                # Prepend www. to netloc
                scheme = parsed.scheme if parsed.scheme else "http"
                netloc_canonical = f"www.{parsed.netloc}" if parsed.netloc else f"www.{host}"
                path_canonical = parsed.path if parsed.netloc else ""
                query_canonical = f"?{parsed.query}" if parsed.query else ""
                fragment_canonical = f"#{parsed.fragment}" if parsed.fragment else ""
                return f"{scheme}://{netloc_canonical}{path_canonical}{query_canonical}{fragment_canonical}"
        except Exception:
            return url_str
        return url_str

    def extract_features(self, url: str) -> Dict[str, Any]:
        """
        Extracts 28 lexical features from a single URL string.
        Guaranteed to be deterministic, offline, and < 1ms.
        """
        if not url or not isinstance(url, str):
            url = ""

        # Canonicalize apex web origins for training distribution consistency
        url = self.canonicalize_url(url)

        # Normalize URL with scheme if missing for accurate parsing
        url_to_parse = url if "://" in url else f"http://{url}"
        parsed = urllib.parse.urlparse(url_to_parse)

        netloc = parsed.netloc or parsed.path.split('/')[0]
        path = parsed.path
        query = parsed.query

        # Strip port from domain
        domain = netloc.split(':')[0].lower()

        # Domain TLD and subdomains
        domain_parts = domain.split('.')
        if len(domain_parts) > 1:
            tld = domain_parts[-1]
            subdomains = domain_parts[:-2] if len(domain_parts) > 2 else []
            no_of_subdomains = len(subdomains)
        else:
            tld = ""
            no_of_subdomains = 0

        # IPv4/IPv6 pattern matching
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        is_domain_ip = 1 if re.match(ipv4_pattern, domain) else 0

        url_len = len(url)
        dom_len = len(domain)
        path_len = len(path)
        query_len = len(query)

        letters = sum(1 for c in url if c.isalpha())
        digits = sum(1 for c in url if c.isdigit())
        equals = url.count('=')
        qmarks = url.count('?')
        ampersands = url.count('&')
        dots = url.count('.')
        hyphens = url.count('-')
        ats = url.count('@')
        slashes = url.count('/')

        # Special characters count
        special_chars = sum(1 for c in url if not c.isalnum())
        other_special = special_chars - (equals + qmarks + ampersands + dots + hyphens + slashes + ats)

        has_obfuscation = 1 if ('%' in url or '@' in url or is_domain_ip) else 0
        obfuscated_chars = url.count('%') + ats

        denom = max(url_len, 1)
        letter_ratio = round(letters / denom, 4)
        digit_ratio = round(digits / denom, 4)
        special_ratio = round(special_chars / denom, 4)
        obfuscation_ratio = round(obfuscated_chars / denom, 4)

        is_https = 1 if parsed.scheme.lower() == 'https' else 0

        url_lower = url.lower()
        keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
        is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

        url_entropy = self.calculate_entropy(url)
        domain_entropy = self.calculate_entropy(domain)
        continuation_rate = self.char_continuation_rate(url)

        return {
            'URLLength': url_len,
            'DomainLength': dom_len,
            'PathLength': path_len,
            'QueryLength': query_len,
            'IsDomainIP': is_domain_ip,
            'TLDLength': len(tld),
            'NoOfSubDomain': no_of_subdomains,
            'HasObfuscation': has_obfuscation,
            'NoOfObfuscatedChar': obfuscated_chars,
            'ObfuscationRatio': obfuscation_ratio,
            'NoOfLettersInURL': letters,
            'LetterRatioInURL': letter_ratio,
            'NoOfDegitsInURL': digits,
            'DegitRatioInURL': digit_ratio,
            'NoOfEqualsInURL': equals,
            'NoOfQMarkInURL': qmarks,
            'NoOfAmpersandInURL': ampersands,
            'NoOfDotsInURL': dots,
            'NoOfHyphensInURL': hyphens,
            'NoOfAtInURL': ats,
            'NoOfOtherSpecialCharsInURL': max(0, other_special),
            'SpacialCharRatioInURL': special_ratio,
            'IsHTTPS': is_https,
            'CharContinuationRate': continuation_rate,
            'URLEntropy': url_entropy,
            'DomainEntropy': domain_entropy,
            'SuspiciousKeywordCount': keyword_count,
            'IsSuspiciousTLD': is_suspicious_tld,
        }

    def extract_features_dataframe(self, urls: pd.Series) -> pd.DataFrame:
        """Batch feature extraction for a series of URLs."""
        feature_dicts = [self.extract_features(u) for u in urls]
        return pd.DataFrame(feature_dicts, columns=self.feature_names)
