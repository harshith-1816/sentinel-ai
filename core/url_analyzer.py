"""
Sentinel AI - URL & Web App Threat Analyzer
Detects typosquatting, deceptive login portals, dangerous TLDs, IP literals, and phishing heuristics.
"""
import re
from typing import List, Optional
from urllib.parse import urlparse
import requests

from core.threat_scorer import ThreatReport, Finding, RiskLevel, calculate_risk

HIGH_VALUE_BRANDS = [
    "paypal", "google", "microsoft", "apple", "netflix", "amazon", "facebook",
    "instagram", "twitter", "chase", "wellsfargo", "bankofamerica", "citibank",
    "binance", "coinbase", "whatsapp", "telegram", "dropbox", "adobe", "github",
    "outlook", "linkedin", "steam", "walmart", "fedex", "dhl", "usps"
]

HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "cf", "gq", "buzz", "work", "click", "monster",
    "cam", "sbs", "rest", "fit", "surf", "cfd", "country", "stream"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "tiny.cc", "cutt.ly", "rb.gy"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "banking", "wallet",
    "suspended", "confirm", "billing", "recover", "authenticate", "credential",
    "password", "security", "support-team", "helpdesk"
]


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def normalize_homoglyphs(domain: str) -> str:
    substitutions = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
        '7': 't', '8': 'b', '@': 'a', 'vv': 'w',
    }
    normalized = domain.lower()
    for k, v in substitutions.items():
        normalized = normalized.replace(k, v)
    return normalized


class URLAnalyzer:
    def __init__(self, check_live_status: bool = False, timeout: float = 3.0):
        self.check_live = check_live_status
        self.timeout = timeout

    def analyze(self, raw_url: str) -> ThreatReport:
        findings: List[Finding] = []
        score = 0

        # Basic sanitation and scheme check
        url = raw_url.strip()
        if not re.match(r'^[a-zA-Z]+://', url):
            url = "http://" + url

        try:
            parsed = urlparse(url)
        except Exception as e:
            return ThreatReport(
                target=raw_url,
                target_type="url",
                overall_risk=RiskLevel.HIGH,
                risk_score=75,
                summary="Invalid or malformed URL syntax, often used to bypass filters.",
                findings=[Finding(
                    category="Malformed URL",
                    severity=RiskLevel.HIGH,
                    title="URL Parsing Error",
                    description=str(e),
                    remediation="Do not open this URL in any browser."
                )],
                recommended_actions=["Block URL completely."]
            )

        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        scheme = parsed.scheme.lower()

        # 1. Scheme Check
        if scheme not in ("http", "https"):
            score += 60
            findings.append(Finding(
                category="Protocol",
                severity=RiskLevel.HIGH,
                title=f"Non-standard web scheme: {scheme}",
                description="The URL uses an unusual or dangerous protocol (e.g. data:, javascript:, file:).",
                indicator=scheme,
                remediation="Never execute non-http/https links from unknown senders."
            ))

        # 2. IP Address Literal Host Check
        ip_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_regex, hostname):
            score += 50
            findings.append(Finding(
                category="IP Host",
                severity=RiskLevel.HIGH,
                title="Direct IP Address Host",
                description="Legitimate web applications use verified domain names. Raw IP addresses are strongly correlated with malicious hosting.",
                indicator=hostname,
                remediation="Avoid browsing directly to numeric IP addresses without trusted DNS."
            ))

        # 3. Embedded Credentials / Obfuscated '@'
        if "@" in parsed.netloc:
            score += 55
            findings.append(Finding(
                category="Obfuscation",
                severity=RiskLevel.CRITICAL,
                title="Deceptive Credential Syntax (@ symbol)",
                description="The URL contains an '@' symbol, tricking users into seeing a fake trusted domain while redirecting to the host after the '@'.",
                indicator=parsed.netloc,
                remediation="Do not click. This is a classic URL deception technique."
            ))

        # 4. URL Shortener Detection
        if hostname in URL_SHORTENERS:
            score += 20
            findings.append(Finding(
                category="Obfuscation",
                severity=RiskLevel.MEDIUM,
                title="URL Shortener Detected",
                description=f"Domain {hostname} hides the actual final destination URL.",
                indicator=hostname,
                remediation="Use a link unshortener or expansion tool before visiting."
            ))

        # 5. Extract domain components & High Risk TLDs
        parts = hostname.split('.')
        tld = parts[-1] if len(parts) > 1 else ""
        if tld in HIGH_RISK_TLDS:
            score += 25
            findings.append(Finding(
                category="Domain Reputation",
                severity=RiskLevel.MEDIUM,
                title=f"High-Risk TLD (.{tld})",
                description=f"Top-level domain '.{tld}' is disproportionately abused for disposable phishing campaigns.",
                indicator=tld,
                remediation="Verify sender authenticity carefully."
            ))

        # 6. Deep Subdomain Nesting / Deceptive Brand Subdomains
        if len(parts) >= 4 and not re.match(ip_regex, hostname):
            score += 25
            findings.append(Finding(
                category="Subdomain Structure",
                severity=RiskLevel.MEDIUM,
                title="Excessive Subdomain Nesting",
                description=f"Host '{hostname}' has {len(parts)} domain labels, common when hiding attacker domains behind familiar names.",
                indicator=hostname,
                remediation="Examine the true root domain at the very end of the hostname."
            ))

        # 7. Brand Impersonation & Typosquatting
        cleaned_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        domain_name = parts[-2] if len(parts) >= 2 else parts[0]
        norm_hostname = normalize_homoglyphs(hostname)
        norm_domain = normalize_homoglyphs(domain_name)

        for brand in HIGH_VALUE_BRANDS:
            is_official = (cleaned_domain == f"{brand}.com") or (cleaned_domain == f"{brand}.org") or (cleaned_domain == f"{brand}.net")

            if not is_official:
                # 1. Check if normalized brand is in the hostname or domain slug (e.g. paypa1-security.xyz or paypal.fake.com)
                if brand in norm_hostname:
                    score += 55
                    findings.append(Finding(
                        category="Typosquatting & Brand Spoofing",
                        severity=RiskLevel.CRITICAL,
                        title=f"Deceptive Brand Spoofing ({brand.capitalize()})",
                        description=f"The domain name or host mimics '{brand}', but the actual registered domain is '{cleaned_domain}'.",
                        indicator=hostname,
                        remediation=f"Go directly to official {brand.capitalize()} website rather than clicking this link."
                    ))
                    break

                # 2. Typosquatting distance check on the actual domain name (e.g. paypai, netfllx)
                dist = levenshtein_distance(norm_domain, brand)
                if dist == 1 or (dist == 2 and len(brand) > 5):
                    score += 50
                    findings.append(Finding(
                        category="Typosquatting",
                        severity=RiskLevel.CRITICAL,
                        title=f"Typosquatting Detected (Target: {brand.capitalize()})",
                        description=f"The domain '{domain_name}' closely mimics trusted brand '{brand}' with minor character alterations.",
                        indicator=domain_name,
                        remediation="This is a look-alike fake domain. Do not submit credentials."
                    ))
                    break

        # 8. Phishing Keywords in Path or Query with Insecure Protocol
        path_query = f"{path} {query}"
        found_keywords = [
            kw for kw in SUSPICIOUS_KEYWORDS
            if re.search(r'(?:^|[/_=?&.\-])' + re.escape(kw) + r'(?:$|[/_=?&.\-])', path_query)
        ]
        if found_keywords:
            if scheme == "http":
                score += 35
                findings.append(Finding(
                    category="Insecure Protocol",
                    severity=RiskLevel.HIGH,
                    title="Insecure HTTP Authentication Endpoint",
                    description=f"The URL handles sensitive actions ({', '.join(found_keywords)}) over unencrypted HTTP.",
                    indicator=url,
                    remediation="Never input credentials or personal data over unencrypted HTTP."
                ))
            else:
                score += 15
                findings.append(Finding(
                    category="Heuristic",
                    severity=RiskLevel.LOW,
                    title="Sensitive Action Keywords Detected",
                    description=f"URL path or parameters contain keywords commonly targeted by phishers: {', '.join(found_keywords)}.",
                    indicator=", ".join(found_keywords),
                    remediation="Confirm the domain matches your expected organization before logging in."
                ))

        # 9. Optional Live Status & Redirection Inspection
        if self.check_live:
            try:
                resp = requests.get(
                    url,
                    timeout=self.timeout,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelSecurity/1.0"},
                    allow_redirects=True
                )
                if len(resp.history) > 2:
                    score += 20
                    findings.append(Finding(
                        category="Redirect Chain",
                        severity=RiskLevel.MEDIUM,
                        title=f"Multiple Redirect Hops ({len(resp.history)} redirects)",
                        description=f"URL redirects through {len(resp.history)} intermediate locations ending at {resp.url}.",
                        indicator=resp.url,
                        remediation="Be cautious of cloaking techniques that route users through multiple servers."
                    ))
            except requests.exceptions.SSLError:
                score += 45
                findings.append(Finding(
                    category="SSL/TLS",
                    severity=RiskLevel.HIGH,
                    title="Invalid or Self-Signed SSL Certificate",
                    description="The server SSL certificate failed validation, indicating possible interception or fake site.",
                    indicator=url,
                    remediation="Never proceed past SSL certificate warnings."
                ))
            except Exception:
                pass  # Live check network issues shouldn't fail offline scan

        score = min(score, 100)
        overall_risk = calculate_risk(score)

        summary_map = {
            RiskLevel.SAFE: "The URL appears legitimate and displays no common phishing or deception markers.",
            RiskLevel.LOW: "Low risk indicators detected. The URL appears mostly benign, but exercise basic caution.",
            RiskLevel.MEDIUM: "Moderate risk. Contains indicators such as high-risk TLD, URL shortening, or sensitive keywords.",
            RiskLevel.HIGH: "High threat detected! Significant risk of phishing, spoofing, or credential theft.",
            RiskLevel.CRITICAL: "CRITICAL THREAT: Clear evidence of brand impersonation, deceptive homoglyphs, or malicious obfuscation."
        }

        recommended_actions = []
        if overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            recommended_actions.extend([
                "Block this URL in firewall and DNS filters.",
                "Do NOT enter any passwords, 2FA tokens, or personal identifiers.",
                "If credentials were submitted, immediately reset passwords on official platforms."
            ])
        elif overall_risk == RiskLevel.MEDIUM:
            recommended_actions.append("Inspect target domain WHOIS and verify sender before entering credentials.")
        else:
            recommended_actions.append("No immediate action required. Maintain general browsing safety.")

        return ThreatReport(
            target=raw_url,
            target_type="url",
            overall_risk=overall_risk,
            risk_score=score,
            summary=summary_map[overall_risk],
            findings=findings,
            metadata={"hostname": hostname, "scheme": scheme, "path": path, "tld": tld},
            recommended_actions=recommended_actions
        )
