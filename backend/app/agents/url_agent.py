"""
Agent 3: URL / Threat Intelligence Agent

Extracts and analyzes URLs from emails.
Integrates VirusTotal when available, falls back to deterministic analysis.
"""

import re
import hashlib
import logging
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse, unquote
import tldextract
import httpx

from app.schemas.analysis import URLAgentResult, URLInfo
from app.utils.domain_analyzer import analyze_domain
from app.config import settings

logger = logging.getLogger(__name__)

# Suspicious URL patterns
SUSPICIOUS_URL_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update',
    'confirm', 'validate', 'banking', 'password', 'credential',
    'wallet', 'paypal', 'microsoft', 'google', 'apple', 'amazon',
    'netflix', 'bank', 'support', 'helpdesk', 'suspended', 'billing',
]

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'link',
    'pw', 'cc', 'bid', 'win', 'download', 'loan', 'review', 'icu',
}

SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'shorte.st', 'tiny.cc', 'rb.gy',
}

VIRUSTOTAL_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_TIMEOUT = 15


class URLThreatAgent:
    """
    Analyzes URLs found in emails for malicious indicators.
    Uses VirusTotal when available, heuristics as fallback.
    """

    def __init__(self):
        self.agent_name = "url_threat"
        self._vt_cache: Dict[str, dict] = {}  # Simple in-memory cache

    def analyze(self, parsed_email: Dict) -> URLAgentResult:
        """Analyze all URLs found in the email."""
        logger.info("URL agent: starting analysis")

        urls = parsed_email.get("all_urls", [])
        # Deduplicate and normalize
        urls = list(set(self._normalize_url(u) for u in urls if u))

        if not urls:
            logger.info("URL agent: no URLs found")
            return URLAgentResult(
                agent=self.agent_name,
                risk_score=0,
                confidence=0.6,
                findings=["No URLs found in email"],
                urls_found=[],
                virustotal_available=settings.virustotal_available,
            )

        logger.info(f"URL agent: analyzing {len(urls)} URLs")

        malicious_urls = []
        suspicious_urls = []
        findings = []
        indicators = []
        evidence = []
        total_risk = 0

        for url in urls[:20]:  # Limit to 20 URLs per email
            url_analysis = self._analyze_single_url(url)

            if url_analysis.is_malicious:
                malicious_urls.append(url_analysis)
                findings.append(f"Malicious URL detected: {url}")
                indicators.append("malicious_url")
                evidence.append(f"URL: {url} | Reasons: {', '.join(url_analysis.reasons)}")
            elif url_analysis.is_suspicious:
                suspicious_urls.append(url_analysis)
                findings.append(f"Suspicious URL: {url}")
                indicators.append("suspicious_url")

            total_risk = max(total_risk, url_analysis.risk_score)

        # Run VirusTotal check on high-risk URLs
        vt_results = []
        vt_available = settings.virustotal_available

        if vt_available and (malicious_urls or suspicious_urls):
            check_urls = [u.url for u in malicious_urls[:3]] + [u.url for u in suspicious_urls[:2]]
            for url in check_urls:
                vt_result = self._check_virustotal_sync(url)
                if vt_result:
                    vt_results.append(vt_result)
                    if vt_result.get("malicious", 0) > 2:
                        total_risk = min(total_risk + 20, 100)
                        findings.append(
                            f"VirusTotal: {vt_result.get('malicious', 0)} engines flagged {url}"
                        )

        # Recommendations
        recommendations = []
        if malicious_urls:
            recommendations.append(f"DO NOT click {len(malicious_urls)} flagged URL(s)")
        if suspicious_urls:
            recommendations.append("Verify suspicious URLs through official channels before clicking")
        if any(u.url in SHORTENER_DOMAINS or any(s in u.url for s in SHORTENER_DOMAINS) for u in suspicious_urls + malicious_urls):
            recommendations.append("URL shorteners were detected — destination cannot be verified without clicking")

        confidence = 0.90 if vt_available else 0.75
        total_risk = min(total_risk, 100)

        logger.info(f"URL agent: score={total_risk}, {len(malicious_urls)} malicious, {len(suspicious_urls)} suspicious")

        return URLAgentResult(
            agent=self.agent_name,
            risk_score=total_risk,
            confidence=confidence,
            findings=findings,
            indicators=list(set(indicators)),
            evidence=evidence,
            recommendations=recommendations,
            urls_found=urls,
            malicious_urls=malicious_urls,
            suspicious_urls=suspicious_urls,
            virustotal_available=vt_available,
            virustotal_results=vt_results,
            metadata={
                "url_count": len(urls),
                "malicious_count": len(malicious_urls),
                "suspicious_count": len(suspicious_urls),
                "vt_checked": len(vt_results),
            }
        )

    def _normalize_url(self, url: str) -> str:
        """Normalize a URL for consistent analysis."""
        url = url.strip()
        if not url.startswith(('http://', 'https://', 'ftp://')):
            url = 'http://' + url
        return url

    def _analyze_single_url(self, url: str) -> URLInfo:
        """Perform deterministic analysis on a single URL."""
        reasons = []
        risk_score = 0
        is_malicious = False
        is_suspicious = False

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            path = parsed.path or ""
            scheme = parsed.scheme or ""

            # Check 1: HTTP (not HTTPS)
            if scheme == "http":
                reasons.append("Uses insecure HTTP protocol")
                risk_score += 15
                is_suspicious = True

            # Check 2: IP-based URL
            ip_pattern = re.compile(
                r'^(\d{1,3}\.){3}\d{1,3}$'
            )
            if ip_pattern.match(hostname):
                reasons.append("URL uses raw IP address instead of domain name")
                risk_score += 40
                is_malicious = True

            # Check 3: Suspicious TLD
            extracted = tldextract.extract(hostname)
            if extracted.suffix.lower() in SUSPICIOUS_TLDS:
                reasons.append(f"Suspicious TLD: .{extracted.suffix}")
                risk_score += 20
                is_suspicious = True

            # Check 4: URL length
            if len(url) > 100:
                reasons.append(f"Unusually long URL ({len(url)} chars) — may be obfuscating destination")
                risk_score += 10
                is_suspicious = True

            # Check 5: Encoded characters
            if '%' in url and re.search(r'%[0-9a-fA-F]{2}', url):
                decoded = unquote(url)
                if decoded != url:
                    reasons.append("URL contains encoded characters that obscure the actual destination")
                    risk_score += 15
                    is_suspicious = True

            # Check 6: Excessive subdomains
            if hostname.count('.') >= 4:
                reasons.append(f"Excessive subdomain depth — possible domain confusion attack")
                risk_score += 20
                is_suspicious = True

            # Check 7: URL shorteners
            for shortener in SHORTENER_DOMAINS:
                if shortener in hostname:
                    reasons.append(f"URL shortener used — real destination is hidden")
                    risk_score += 25
                    is_suspicious = True
                    break

            # Check 8: Suspicious keywords in URL path
            full_url_lower = url.lower()
            for keyword in SUSPICIOUS_URL_KEYWORDS:
                if keyword in full_url_lower:
                    reasons.append(f"Suspicious keyword in URL: '{keyword}'")
                    risk_score += 10
                    is_suspicious = True
                    break

            # Check 9: Domain typosquatting
            domain_result = analyze_domain(hostname)
            if domain_result.get("is_typosquatting"):
                reasons.extend(domain_result.get("reasons", []))
                risk_score += 40
                is_malicious = True
            elif domain_result.get("is_suspicious"):
                reasons.extend(domain_result.get("reasons", []))
                risk_score += 20
                is_suspicious = True

            # Check 10: Double slashes in path (redirect pattern)
            if '//' in path:
                reasons.append("Double slashes in URL path — possible open redirect")
                risk_score += 15
                is_suspicious = True

            # Check 11: @-sign in URL (before hostname — redirect trick)
            if '@' in url and url.index('@') < url.index(hostname) + len(hostname):
                reasons.append("@ symbol in URL — classic phishing redirect trick")
                risk_score += 35
                is_malicious = True

        except Exception as e:
            logger.warning(f"URL parse error for {url}: {e}")
            reasons.append("URL could not be fully parsed")
            risk_score = 10

        risk_score = min(risk_score, 100)
        if risk_score >= 60:
            is_malicious = True
        elif risk_score >= 25:
            is_suspicious = True

        return URLInfo(
            url=url,
            risk_score=risk_score,
            is_malicious=is_malicious,
            is_suspicious=is_suspicious,
            reasons=reasons,
        )

    def _check_virustotal_sync(self, url: str) -> Optional[dict]:
        """
        Check URL against VirusTotal API (synchronous wrapper).
        Results are cached to minimize API usage.
        """
        if not settings.virustotal_api_key:
            return None

        # Check cache first
        url_hash = hashlib.md5(url.encode()).hexdigest()
        if url_hash in self._vt_cache:
            return self._vt_cache[url_hash]

        try:
            headers = {"x-apikey": settings.virustotal_api_key}

            # Submit URL for analysis
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            with httpx.Client(timeout=VIRUSTOTAL_TIMEOUT) as client:
                response = client.get(
                    f"{VIRUSTOTAL_URL_ENDPOINT}/{url_id}",
                    headers=headers,
                )

                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    result = {
                        "url": url,
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "source": "virustotal",
                    }
                    self._vt_cache[url_hash] = result
                    return result

                elif response.status_code == 404:
                    # URL not in VT database — submit for analysis
                    submit_response = client.post(
                        VIRUSTOTAL_URL_ENDPOINT,
                        headers=headers,
                        data={"url": url},
                    )
                    if submit_response.status_code == 200:
                        return {"url": url, "malicious": 0, "source": "virustotal_pending"}

        except httpx.TimeoutException:
            logger.warning(f"VirusTotal timeout for URL: {url}")
        except Exception as e:
            logger.warning(f"VirusTotal error: {e}")

        return None
