"""
Domain analysis utility for typosquatting and suspicious domain detection.
Uses deterministic rules — no LLM dependency.
"""

import re
import tldextract
from typing import List, Tuple, Optional
from Levenshtein import distance as levenshtein_distance
import logging

logger = logging.getLogger(__name__)

# Known legitimate brands → canonical domain name (the part before the TLD)
KNOWN_BRANDS: dict[str, str] = {
    "paypal":        "paypal",
    "microsoft":     "microsoft",
    "google":        "google",
    "apple":         "apple",
    "amazon":        "amazon",
    "linkedin":      "linkedin",
    "instagram":     "instagram",
    "facebook":      "facebook",
    "netflix":       "netflix",
    "dropbox":       "dropbox",
    "docusign":      "docusign",
    "wellsfargo":    "wellsfargo",
    "bankofamerica": "bankofamerica",
    "chase":         "chase",
    "citibank":      "citibank",
    "irs":           "irs",
    "dhl":           "dhl",
    "fedex":         "fedex",
    "ups":           "ups",
    "usps":          "usps",
}

# Legitimate TLD+1 combos that must NEVER be flagged
LEGITIMATE_DOMAINS: set[str] = {
    "paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com",
    "linkedin.com", "instagram.com", "facebook.com", "netflix.com",
    "dropbox.com", "docusign.com", "wellsfargo.com", "bankofamerica.com",
    "chase.com", "citibank.com", "irs.gov", "dhl.com", "fedex.com",
    "ups.com", "usps.com",
    # Common safe domains that should never score high
    "github.com", "gitlab.com", "stackoverflow.com", "wikipedia.org",
    "youtube.com", "twitter.com", "x.com", "reddit.com", "medium.com",
    "cloudflare.com", "amazonaws.com", "azure.com", "office.com",
    "outlook.com", "live.com", "hotmail.com", "yahoo.com", "gmail.com",
    "mit.edu", "stanford.edu", "harvard.edu",
}

# Common character substitutions used in typosquatting
CHAR_SUBSTITUTIONS: dict[str, list[str]] = {
    'a': ['@', '4'],
    'e': ['3'],
    'i': ['1', 'l'],
    'l': ['1', 'i'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7'],
    'g': ['9'],
    'b': ['6'],
}

# Suspicious TLDs more commonly associated with phishing / free registrars
SUSPICIOUS_TLDS: set[str] = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'link',
    'pw', 'cc', 'bid', 'win', 'download', 'loan', 'review',
    'accountant', 'science', 'trade', 'date', 'faith', 'racing',
    'party', 'stream', 'men', 'webcam', 'icu',
}

SUSPICIOUS_DOMAIN_KEYWORDS: list[str] = [
    'secure', 'security', 'login', 'signin', 'account', 'verify',
    'update', 'confirm', 'support', 'helpdesk', 'service', 'alert',
    'urgent', 'suspended', 'limited', 'restore', 'recover',
    'billing', 'payment', 'invoice', 'wallet',
]


def extract_domain_parts(domain: str) -> Tuple[str, str, str]:
    """Extract (subdomain, domain_name, suffix) from a domain string."""
    extracted = tldextract.extract(domain)
    return extracted.subdomain, extracted.domain, extracted.suffix


def normalize_domain(domain: str) -> str:
    """Lowercase and strip leading www."""
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def extract_domain_from_email(email_addr: str) -> str:
    """Return the domain portion of an email address."""
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower().strip()
    return ""


def _normalize_with_char_sub(text: str) -> str:
    """Replace common phishing substitutions so we can compare against brand name."""
    out = text.lower()
    for real_char, subs in CHAR_SUBSTITUTIONS.items():
        for sub in subs:
            out = out.replace(sub, real_char)
    return out


def detect_char_substitution(domain_name: str, brand_canonical: str) -> bool:
    """
    Return True if domain_name is a character-substituted version of brand_canonical.
    Requires brand_canonical to be at least 3 characters to avoid false positives.
    """
    if not brand_canonical or len(brand_canonical) < 3:
        return False
    normalized = _normalize_with_char_sub(domain_name)
    # The brand name must appear fully in the normalised domain
    # AND the original domain must differ (so 'paypal' itself isn't flagged)
    return (
        brand_canonical in normalized
        and domain_name.lower() != brand_canonical
        # Make sure the brand covers a substantial portion (≥70%) of the domain length
        and len(brand_canonical) / max(len(domain_name), 1) >= 0.60
    )


def calculate_brand_similarity(a: str, b: str) -> float:
    """Levenshtein-based similarity in [0, 1]."""
    if not a or not b:
        return 0.0
    d = levenshtein_distance(a.lower(), b.lower())
    max_len = max(len(a), len(b))
    return 1.0 - (d / max_len)


def _effective_domain(domain: str) -> str:
    """Return 'name.suffix', e.g. 'github.com' from 'api.github.com'."""
    _, name, suffix = extract_domain_parts(domain)
    if name and suffix:
        return f"{name}.{suffix}"
    return domain


def analyze_domain(domain: str) -> dict:
    """
    Comprehensive deterministic domain-risk analysis.
    Returns a dict with risk_score, is_suspicious, is_typosquatting, reasons, etc.
    """
    if not domain:
        return {"risk_score": 0, "is_suspicious": False, "reasons": []}

    domain = normalize_domain(domain)

    # Hard-allow known-legitimate domains immediately
    effective = _effective_domain(domain)
    if effective in LEGITIMATE_DOMAINS:
        return {"risk_score": 0, "is_suspicious": False, "is_typosquatting": False,
                "reasons": [], "domain": domain}

    subdomain, domain_name, suffix = extract_domain_parts(domain)

    reasons: list[str] = []
    risk_score = 0
    matched_brand: Optional[str] = None
    is_typosquatting = False

    # ── 1. Suspicious TLD ────────────────────────────────────────────────────
    if suffix.lower() in SUSPICIOUS_TLDS:
        reasons.append(f"Uses suspicious TLD '.{suffix}'")
        risk_score += 20

    # ── 2. Excessive subdomains ───────────────────────────────────────────────
    if subdomain and subdomain.count('.') >= 2:
        reasons.append(f"Excessive subdomain depth: '{subdomain}'")
        risk_score += 15

    # ── 3. Suspicious keyword in domain label ─────────────────────────────────
    for keyword in SUSPICIOUS_DOMAIN_KEYWORDS:
        if keyword in domain_name.lower():
            reasons.append(f"Contains suspicious keyword '{keyword}' in domain")
            risk_score += 10
            break

    # ── 4. Brand similarity checks ────────────────────────────────────────────
    for brand_label, brand_canonical in KNOWN_BRANDS.items():
        if not brand_canonical or len(brand_canonical) < 3:
            continue

        # Skip if the domain IS the canonical brand (e.g. paypal.com → paypal)
        if domain_name.lower() == brand_canonical:
            return {"risk_score": 0, "is_suspicious": False, "is_typosquatting": False,
                    "reasons": [], "brand": brand_label}

        # 4a. Levenshtein similarity
        sim = calculate_brand_similarity(domain_name, brand_canonical)
        if 0.80 <= sim < 1.0:
            is_typosquatting = True
            matched_brand = brand_label
            reasons.append(
                f"'{domain_name}' is {sim:.0%} similar to '{brand_canonical}' "
                f"(brand: {brand_label})"
            )
            risk_score += 40

        # 4b. Character substitution (only if not already caught by sim)
        elif detect_char_substitution(domain_name, brand_canonical):
            is_typosquatting = True
            matched_brand = brand_label
            reasons.append(
                f"'{domain_name}' uses character substitution to mimic '{brand_canonical}' "
                f"(brand: {brand_label})"
            )
            risk_score += 50

        # 4c. Brand name hidden in subdomain
        if subdomain and brand_canonical in subdomain.lower():
            reasons.append(
                f"Brand '{brand_canonical}' appears in subdomain — possible impersonation"
            )
            risk_score += 35
            matched_brand = brand_label

        # 4d. Hyphen-separated brand name in domain label
        if (re.search(rf'(?<![a-z]){re.escape(brand_canonical)}[-_]', domain_name.lower()) or
                re.search(rf'[-_]{re.escape(brand_canonical)}(?![a-z])', domain_name.lower())):
            if not is_typosquatting:
                reasons.append(
                    f"Domain uses '{brand_canonical}' with hyphen/underscore — possible impersonation"
                )
                risk_score += 30
                matched_brand = brand_label

    # ── 5. Raw IP address ─────────────────────────────────────────────────────
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        reasons.append("Domain is a raw IP address — highly suspicious in email context")
        risk_score += 45

    # ── 6. Very long domain name ──────────────────────────────────────────────
    if len(domain_name) > 30:
        reasons.append(f"Unusually long domain name ({len(domain_name)} chars)")
        risk_score += 10

    # ── 7. Mixed letters+numbers (only meaningful when brand is also matched) ─
    if matched_brand and re.search(r'[a-z]\d|\d[a-z]', domain_name):
        reasons.append("Domain mixes letters and numbers alongside brand impersonation")
        risk_score += 15

    risk_score = min(risk_score, 100)

    return {
        "risk_score": risk_score,
        "is_suspicious": risk_score >= 25,
        "is_typosquatting": is_typosquatting,
        "matched_brand": matched_brand,
        "domain": domain,
        "domain_name": domain_name,
        "suffix": suffix,
        "subdomain": subdomain,
        "reasons": reasons,
    }


def compare_domains(domain1: str, domain2: str) -> dict:
    """
    Compare two domains (e.g. From vs Reply-To).
    Returns mismatch flag, risk score, and reasons.
    """
    if not domain1 or not domain2:
        return {"mismatch": False, "risk_score": 0, "reasons": []}

    n1 = normalize_domain(domain1)
    n2 = normalize_domain(domain2)
    _, name1, suffix1 = extract_domain_parts(n1)
    _, name2, suffix2 = extract_domain_parts(n2)

    # Same effective domain → no mismatch
    if name1 == name2 and suffix1 == suffix2:
        return {"mismatch": False, "risk_score": 0, "reasons": []}

    sim = calculate_brand_similarity(name1, name2)
    reasons = [f"From domain '{n1}' differs from Reply-To domain '{n2}'"]
    risk_score = 30

    if sim < 0.30:
        risk_score = 55
        reasons.append(
            "Completely unrelated domains — strong indicator of reply-to hijacking"
        )

    return {
        "mismatch": True,
        "risk_score": risk_score,
        "similarity": sim,
        "reasons": reasons,
    }
