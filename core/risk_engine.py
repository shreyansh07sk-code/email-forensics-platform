"""
risk_engine.py
Fuses header-auth signals, origin/geolocation signals, and content signals
into a single 0-100 fraud confidence score + verdict + human-readable
explanation. This is "Identity Correlation and Attribution Support" +
"Alerting" from the problem statement, condensed into one function.

The weighting below is a starting point for the prototype/demo - in a
real deployment these weights should be tuned against a labeled dataset
(e.g. Nazario phishing corpus + Enron ham corpus) rather than hand-picked.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RiskFactor:
    category: str
    detail: str
    weight: int


@dataclass
class RiskAssessment:
    score: int = 0                      # 0-100, higher = more fraudulent
    verdict: str = "Unknown"            # Legitimate | Suspicious | Likely Phishing | High-Risk Fraud
    factors: List[RiskFactor] = field(default_factory=list)
    origin_country: Optional[str] = None
    origin_ip: Optional[str] = None
    origin_flagged_infra: bool = False


def _verdict_from_score(score: int) -> str:
    if score >= 70:
        return "High-Risk Fraud"
    if score >= 45:
        return "Likely Phishing"
    if score >= 20:
        return "Suspicious"
    return "Legitimate"


def assess_risk(auth_verdict, content_analysis, geo_result, parsed_email,
                 num_attachments: int = 0, ml_result=None, domain_intel=None) -> RiskAssessment:
    factors: List[RiskFactor] = []

    # --- Authentication signals ---
    if auth_verdict.spf in ("fail", "softfail"):
        factors.append(RiskFactor("Authentication", f"SPF check: {auth_verdict.spf}", 20))
    if auth_verdict.dkim == "fail":
        factors.append(RiskFactor("Authentication", "DKIM signature failed validation", 20))
    if auth_verdict.dmarc == "fail":
        factors.append(RiskFactor("Authentication", "DMARC alignment failed", 25))
    if auth_verdict.alignment_ok is False:
        factors.append(RiskFactor(
            "Authentication",
            "SPF/DKIM passed for a different domain than the visible From: address "
            "(possible spoofing via a secondary authorized domain)",
            15,
        ))
    if auth_verdict.spf == "none" and auth_verdict.dkim == "none" and auth_verdict.dmarc == "none":
        factors.append(RiskFactor(
            "Authentication",
            "No SPF/DKIM/DMARC results present in this message's headers - this means "
            "authentication status could not be verified, not that it failed. Weighted "
            "low accordingly; if this were a live mail-server delivery, the receiving "
            "server would normally have stamped Authentication-Results",
            10,
        ))

    # --- Origin / infrastructure signals ---
    # Proxy and hosting are scored separately (not as one blanket flag) so a
    # trusted major provider's own hosting infrastructure - e.g. Google's
    # mail-sending IPs, which ARE classified as "hosting" by IP-intelligence
    # APIs since Google Cloud is a hosting provider - doesn't get penalized
    # the same way an actual anonymous VPN/proxy relay would.
    if geo_result and geo_result.status == "ok":
        if geo_result.proxy and not geo_result.trusted_provider:
            factors.append(RiskFactor(
                "Origin infrastructure",
                f"Originating IP {geo_result.ip} is flagged as proxy/anonymization "
                f"infrastructure ({geo_result.isp or geo_result.org})",
                22,
            ))
        elif geo_result.proxy and geo_result.trusted_provider:
            # Same rationale as the hosting exception below: major mail
            # providers' own sending IPs are sometimes flagged "proxy" by
            # IP-intelligence APIs even though they aren't an actual
            # anonymizer/VPN relay. Don't penalize known providers for it.
            factors.append(RiskFactor(
                "Infrastructure reputation",
                f"Originating IP {geo_result.ip} is flagged as proxy/anonymization "
                f"infrastructure by the GeoIP provider, but belongs to a recognized "
                f"trusted mail provider ({geo_result.isp or geo_result.org}) - "
                f"not treated as a risk signal",
                0,
            ))
        elif geo_result.hosting and not geo_result.trusted_provider:
            factors.append(RiskFactor(
                "Origin infrastructure",
                f"Originating IP {geo_result.ip} resolves to generic hosting/datacenter "
                f"infrastructure ({geo_result.isp or geo_result.org}), not a recognized "
                f"major mail provider",
                18,
            ))
        elif geo_result.hosting and geo_result.trusted_provider:
            # Informational only (weight 0) - shown in the report for
            # transparency ("here's why we did NOT penalize this") without
            # contributing to the fraud score.
            factors.append(RiskFactor(
                "Infrastructure reputation",
                f"Originating IP {geo_result.ip} belongs to a recognized trusted mail "
                f"provider ({geo_result.isp or geo_result.org}) - hosting classification "
                f"not treated as a risk signal",
                0,
            ))

        header_domain_hint = parsed_email.from_domain
        if geo_result.country_code and header_domain_hint.endswith(
            (".gov", ".edu")
        ) and geo_result.country_code != "US":
            factors.append(RiskFactor(
                "Origin mismatch",
                f".gov/.edu sender domain but message originated from {geo_result.country}",
                12,
            ))

    # --- Content signals ---
    # Each heuristic finding becomes its own risk factor rather than being
    # collapsed into one lump-sum factor. A prior version capped the
    # combined contribution at 40 regardless of how much evidence was
    # found, which meant a message with several independent strong
    # indicators (impersonation + urgency + reply-to mismatch + ...)
    # could never score higher than one with a single weak indicator.
    # The overall fraud score is still globally capped at 100 below, so
    # this doesn't risk runaway scores - it just stops discarding evidence.
    for f in content_analysis.findings:
        factors.append(RiskFactor(
            f"Content analysis — {f.category}",
            f.detail,
            f.weight,
        ))

    # --- ML/NLP classifier signal (the actual "AI" component) ---
    if ml_result and ml_result.available and ml_result.score_contribution > 0:
        factors.append(RiskFactor(
            "Content analysis (ML classifier)",
            ml_result.note,
            ml_result.score_contribution,
        ))

    # --- Domain registration intelligence ---
    if domain_intel and domain_intel.status == "ok" and domain_intel.is_newly_registered:
        factors.append(RiskFactor(
            "Domain intelligence",
            f"Sending domain '{domain_intel.domain}' was registered {domain_intel.age_days} "
            f"day(s) ago ({domain_intel.created_date}) - newly-registered domains are "
            f"disproportionately used for phishing infrastructure",
            15,
        ))

    # --- Structural signals ---
    if not parsed_email.hops:
        factors.append(RiskFactor(
            "Header structure",
            "No Received header chain present - message may be malformed, "
            "locally injected, or headers stripped",
            10,
        ))

    if num_attachments > 0:
        suspicious_exts = (".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".lnk", ".iso", ".hta")
        risky = [a for a in parsed_email.attachments if a.lower().endswith(suspicious_exts)]
        if risky:
            factors.append(RiskFactor(
                "Attachments",
                f"Executable/script-type attachment(s): {', '.join(risky)}",
                25,
            ))

    score = min(sum(f.weight for f in factors), 100)

    assessment = RiskAssessment(
        score=score,
        verdict=_verdict_from_score(score),
        factors=factors,
        origin_country=geo_result.country if geo_result and geo_result.status == "ok" else None,
        origin_ip=geo_result.ip if geo_result else None,
        origin_flagged_infra=geo_result.likely_hosting_or_proxy if geo_result else False,
    )
    return assessment
