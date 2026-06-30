def make_verdict(abuseipdb_response):
    """
    Convert raw AbuseIPDB response into a clean verdict dict.
    """

    # Handle errors first
    if "error" in abuseipdb_response:
        return {
            "verdict": "error",
            "reason": abuseipdb_response["error"],
            "source": "AbuseIPDB"
        }

    data = abuseipdb_response.get("data", {})
    score = data.get("abuseConfidenceScore", 0)
    total_reports = data.get("totalReports", 0)
    country = data.get("countryCode", "unknown")
    isp = data.get("isp", "unknown")
    domain = data.get("domain", "unknown")
    is_tor = data.get("isTor", False)
    usage_type = data.get("usageType", "unknown")

    # Verdict decision logic
    # AbuseIPDB score is 0-100. 0 = clean, 100 = definitely malicious
    if score >= 50:
        verdict = "malicious"
    elif score >= 15:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "score": score,            # 0-100 confidence score
        "total_reports": total_reports,
        "country": country,
        "isp": isp,
        "domain": domain,
        "is_tor": is_tor,
        "usage_type": usage_type,
        "source": "AbuseIPDB"
    }

