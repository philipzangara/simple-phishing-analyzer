from analyzer.headers import HeaderAnalysis

def calculate_verdict(score: int) -> str:
    if score <= 20:
        return "LOW"
    elif score <= 50:
        return "MEDIUM"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"


def calculate_score(
    header_results: HeaderAnalysis,
    vt_results: list,
    mb_results: list
) -> dict:

    score = 0
    reasons = []

    # Authentication score
    if header_results.spf == "fail":
        score += 10
        reasons.append("SPF fail")
    elif header_results.spf == "softfail":
        score += 5
        reasons.append("SPF softfail")

    if header_results.dkim == "fail":
        score += 15
        reasons.append("DKIM fail")

    if header_results.dmarc == "fail":
        score += 20
        reasons.append("DMARC fail")

    # Header score
    if (
        header_results.display_name_spoof is not None
        and header_results.display_name_spoof.spoofed is True
    ):
        score += 20
        reasons.append("Display Name Spoof")

    if header_results.reply_to_mismatch is True:
        score += 25
        reasons.append("Reply-To Mismatch")

    if header_results.received_mismatch is True:
        score += 20
        reasons.append("Received Chain Mismatch")

    # URL score
    for vt_result in vt_results:
        if vt_result.get("malicious", 0) >= 1:
            score += 60
            reasons.append(f"Malicious URL: {vt_result['url']}")

    # Attachment score
    for mb_result in mb_results:
        if mb_result.get("found") is True:
            score += 70
            reasons.append(
                f"Malicious attachment: {mb_result['filename']}"
            )

    return {
        "score": score,
        "verdict": calculate_verdict(score),
        "reasons": reasons
    }