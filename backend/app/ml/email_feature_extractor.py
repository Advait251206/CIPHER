"""
CIPHER Email Feature Extractor
Extracts 32 deterministic, leak-free lexical, behavioral, URL, HTML, and sender features
from email subjects, bodies, and header metadata.
Zero external dependencies, sub-millisecond execution.
"""

import re
import math
from typing import Dict, Any, List, Optional, Tuple

# Pre-compiled regex patterns for performance
URL_PATTERN = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'{}|\\^`\[\]]+',
    re.IGNORECASE
)
IP_URL_PATTERN = re.compile(
    r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>"\'{}|\\^`\[\]]*)?',
    re.IGNORECASE
)
HTML_TAG_PATTERN = re.compile(r'<[^>]+>')
HTML_LINK_PATTERN = re.compile(r'<a\s+[^>]*href=["\']?([^"\'>\s]+)', re.IGNORECASE)
HIDDEN_STYLE_PATTERN = re.compile(r'(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)', re.IGNORECASE)
EMAIL_ADDR_PATTERN = re.compile(r'[\w\.-]+@([\w\.-]+)')

# Lexicon sets
URGENCY_TERMS = [
    "urgent", "immediately", "act now", "action required", "expires", "expiring",
    "suspended", "suspension", "24 hours", "48 hours", "deadline", "immediate attention",
    "prompt response", "within 24", "time-sensitive", "final notice"
]
THREAT_TERMS = [
    "locked", "suspended", "termination", "terminated", "legal action", "unauthorized",
    "breach", "restricted", "security alert", "compromised", "account closure", "disabled",
    "investigation", "penalty", "consequences"
]
CREDENTIAL_TERMS = [
    "password", "passcode", "login", "log in", "sign in", "verify your account",
    "confirm identity", "confirm your account", "credentials", "security update",
    "reset password", "security question", "passphrase", "pin code", "auth code", "2fa"
]
FINANCIAL_TERMS = [
    "invoice", "wire transfer", "bank account", "refund", "bitcoin", "crypto",
    "fund", "funds", "claim prize", "lottery", "beneficiary", "payment overdue",
    "billing statement", "remittance", "inheritance", "western union", "moneygram", "usd $"
]
ACTION_VERBS = [
    "click", "download", "open", "update", "verify", "confirm", "submit", "validate",
    "reactivate", "restore", "claim", "authenticate"
]
SUSPICIOUS_CTAS = [
    "click here", "download attachment", "open the link", "log in below",
    "update now", "verify now", "click below", "claim now", "confirm now",
    "click the link", "follow the link", "reactivate now"
]
FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "zoho.com", "protonmail.com", "yandex.com", "gmx.com"
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "loan", "tk", "ml", "ga", "cf", "gq",
    "buzz", "fit", "surf", "date", "racing", "party", "review", "country", "kim"
}
PROTECTED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "chase", "bank of america", "wellsfargo", "facebook", "instagram"
]


class EmailFeatureExtractor:
    """Extracts 32 independent features from raw email components."""

    FEATURE_NAMES = [
        # 1. Content / Lexical (10)
        "subject_length",
        "body_length",
        "word_count",
        "char_count",
        "avg_word_length",
        "uppercase_ratio",
        "exclamation_count",
        "question_count",
        "currency_symbol_count",
        "pipe_count",
        # 2. Behavioral & Urgency Lexicons (6)
        "urgency_term_count",
        "threat_term_count",
        "credential_term_count",
        "financial_term_count",
        "action_verb_count",
        "suspicious_cta_count",
        # 3. URL & Redirection Features (6)
        "url_count",
        "has_urls",
        "ip_url_count",
        "at_symbol_url_count",
        "max_url_length",
        "suspicious_tld_url_count",
        # 4. HTML & Structure (4)
        "has_html_tags",
        "html_tag_count",
        "html_link_count",
        "hidden_text_indicators",
        # 5. Sender Characteristics (6)
        "has_sender",
        "sender_domain_length",
        "is_freemail_sender",
        "sender_display_name_mismatch",
        "subdomain_depth_sender",
        "has_ip_sender"
    ]

    def __init__(self):
        self.feature_names = list(self.FEATURE_NAMES)
        self.feature_count = len(self.feature_names)

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extracts all embedded HTTP/HTTPS and www URLs from plain text or HTML."""
        if not text:
            return []
        raw_matches = URL_PATTERN.findall(text)
        cleaned = []
        for m in raw_matches:
            # Strip trailing punctuation often caught in sentence context
            u = m.rstrip(".,;:!?)>\"'")
            if u:
                cleaned.append(u)
        return list(dict.fromkeys(cleaned))

    def extract_features(
        self,
        subject: Optional[str] = None,
        body: Optional[str] = None,
        sender: Optional[str] = None
    ) -> Dict[str, float]:
        """
        Extracts 32 numerical/boolean features from email parts.
        All values returned as float for direct ML consumption.
        """
        subj_str = str(subject or "").strip()
        body_str = str(body or "").strip()
        sender_str = str(sender or "").strip()
        full_text = f"{subj_str} {body_str}".strip()
        text_lower = full_text.lower()

        # -------------------------------------------------------------
        # 1. Content / Lexical Features (10)
        # -------------------------------------------------------------
        subject_len = float(len(subj_str))
        body_len = float(len(body_str))
        char_count = float(len(full_text))

        words = [w for w in re.split(r'\s+', full_text) if w]
        word_count = float(len(words))
        avg_word_length = float(sum(len(w) for w in words) / word_count) if word_count > 0 else 0.0

        letters = [c for c in full_text if c.isalpha()]
        uppercase_count = sum(1 for c in letters if c.isupper())
        uppercase_ratio = float(uppercase_count / len(letters)) if letters else 0.0

        exclamation_count = float(full_text.count('!'))
        question_count = float(full_text.count('?'))
        currency_count = float(sum(full_text.count(sym) for sym in ['$', '€', '£', '¥']))
        pipe_count = float(full_text.count('|'))

        # -------------------------------------------------------------
        # 2. Behavioral & Urgency Lexicons (6)
        # -------------------------------------------------------------
        urgency_term_count = float(sum(1 for term in URGENCY_TERMS if term in text_lower))
        threat_term_count = float(sum(1 for term in THREAT_TERMS if term in text_lower))
        credential_term_count = float(sum(1 for term in CREDENTIAL_TERMS if term in text_lower))
        financial_term_count = float(sum(1 for term in FINANCIAL_TERMS if term in text_lower))
        action_verb_count = float(sum(1 for term in ACTION_VERBS if re.search(r'\b' + re.escape(term) + r'\b', text_lower)))
        suspicious_cta_count = float(sum(1 for term in SUSPICIOUS_CTAS if term in text_lower))

        # -------------------------------------------------------------
        # 3. URL & Redirection Features (6)
        # -------------------------------------------------------------
        urls = self.extract_urls(full_text)
        url_count = float(len(urls))
        has_urls = 1.0 if url_count > 0 else 0.0

        ip_url_count = float(len(IP_URL_PATTERN.findall(full_text)))
        at_symbol_url_count = float(sum(1 for u in urls if '@' in u))
        max_url_length = float(max((len(u) for u in urls), default=0))

        suspicious_tld_count = 0
        for u in urls:
            m = re.search(r'https?://(?:www\.)?[^/:]+\.([a-z0-9-]+)', u, re.IGNORECASE)
            if m and m.group(1).lower() in SUSPICIOUS_TLDS:
                suspicious_tld_count += 1
        suspicious_tld_url_count = float(suspicious_tld_count)

        # -------------------------------------------------------------
        # 4. HTML & Structure Features (4)
        # -------------------------------------------------------------
        has_html_tags = 1.0 if ("<html" in text_lower or "<body" in text_lower or "<div" in text_lower or "<table" in text_lower or "<a href" in text_lower) else 0.0
        html_tag_count = float(len(HTML_TAG_PATTERN.findall(full_text)))
        html_link_count = float(len(HTML_LINK_PATTERN.findall(full_text)))
        hidden_text_indicators = float(len(HIDDEN_STYLE_PATTERN.findall(full_text)))

        # -------------------------------------------------------------
        # 5. Sender Characteristics (6)
        # -------------------------------------------------------------
        has_sender = 1.0 if sender_str else 0.0
        sender_domain = ""
        sender_match = EMAIL_ADDR_PATTERN.search(sender_str)
        if sender_match:
            sender_domain = sender_match.group(1).lower()

        sender_domain_length = float(len(sender_domain))
        is_freemail_sender = 1.0 if sender_domain in FREEMAIL_DOMAINS else 0.0

        # Sender Display Name vs Domain mismatch
        # E.g. Display name says "PayPal Security" but domain is "yahoo.com" or "evil.com"
        mismatch = 0.0
        if sender_str and sender_domain:
            sender_lower = sender_str.lower()
            for brand in PROTECTED_BRANDS:
                if brand in sender_lower and brand not in sender_domain:
                    mismatch = 1.0
                    break
        sender_display_name_mismatch = mismatch

        subdomain_depth_sender = float(sender_domain.count('.')) if sender_domain else 0.0
        has_ip_sender = 1.0 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', sender_str) else 0.0

        return {
            "subject_length": subject_len,
            "body_length": body_len,
            "word_count": word_count,
            "char_count": char_count,
            "avg_word_length": avg_word_length,
            "uppercase_ratio": uppercase_ratio,
            "exclamation_count": exclamation_count,
            "question_count": question_count,
            "currency_symbol_count": currency_count,
            "pipe_count": pipe_count,
            "urgency_term_count": urgency_term_count,
            "threat_term_count": threat_term_count,
            "credential_term_count": credential_term_count,
            "financial_term_count": financial_term_count,
            "action_verb_count": action_verb_count,
            "suspicious_cta_count": suspicious_cta_count,
            "url_count": url_count,
            "has_urls": has_urls,
            "ip_url_count": ip_url_count,
            "at_symbol_url_count": at_symbol_url_count,
            "max_url_length": max_url_length,
            "suspicious_tld_url_count": suspicious_tld_url_count,
            "has_html_tags": has_html_tags,
            "html_tag_count": html_tag_count,
            "html_link_count": html_link_count,
            "hidden_text_indicators": hidden_text_indicators,
            "has_sender": has_sender,
            "sender_domain_length": sender_domain_length,
            "is_freemail_sender": is_freemail_sender,
            "sender_display_name_mismatch": sender_display_name_mismatch,
            "subdomain_depth_sender": subdomain_depth_sender,
            "has_ip_sender": has_ip_sender
        }


class EmailFeaturePipeline:
    """Sanitizes inputs and guarantees feature ordering for email inference."""

    def __init__(self, feature_names: Optional[List[str]] = None):
        self.feature_names = list(feature_names) if feature_names else list(EmailFeatureExtractor.FEATURE_NAMES)
        self.feature_count = len(self.feature_names)
        self.medians: Dict[str, float] = {}

    def fit(self, X):
        import pandas as pd
        import numpy as np
        if isinstance(X, pd.DataFrame):
            for col in self.feature_names:
                if col in X.columns:
                    val = float(X[col].median())
                    self.medians[col] = 0.0 if np.isnan(val) else val
                else:
                    self.medians[col] = 0.0
        return self

    def transform(self, X):
        import pandas as pd
        import numpy as np
        if isinstance(X, dict):
            X = pd.DataFrame([X])
        if isinstance(X, pd.DataFrame):
            df_out = pd.DataFrame(index=X.index)
            for col in self.feature_names:
                if col in X.columns:
                    df_out[col] = X[col]
                else:
                    df_out[col] = self.medians.get(col, 0.0)
            arr = df_out.values.astype(np.float32)
            arr = np.nan_to_num(arr, nan=0.0, posinf=1e6, neginf=0.0)
            return arr
        elif isinstance(X, np.ndarray):
            return np.nan_to_num(X.astype(np.float32), nan=0.0, posinf=1e6, neginf=0.0)
        else:
            raise ValueError(f"Unsupported input type for transform: {type(X)}")

