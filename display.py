from typing import Optional, Any
from pathlib import Path
from analyzer.iocs import IOCCollection
from analyzer.headers import HeaderAnalysis
from config import DEBUG

def defang(value: str) -> str:
    return (
        value
        .replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace(".", "[.]")
    )

def display_results(
    results: HeaderAnalysis,
    filename: str,
    iocs: IOCCollection,
    vt_results: list,
    mb_results: list,
    score: dict,
    enrichment_enabled: bool ) -> None:

    print("=== Simple Phishing Analyzer v1.1.1 ===")
    print("\n=== File Info ===")
    print_field("Email: ", filename)
    print_field("Size: ", f"{Path(filename).stat().st_size} bytes")
    print("\n=== Header Analysis ===")
    print_field("Subject: ", results.subject or "N/A")
    print_field(
    "From: ",
    results.display_name_spoof.display_name
    if results.display_name_spoof else "N/A"
    )
    print_field(
    "From Domain: ",
    defang(results.display_name_spoof.from_domain or "N/A")
    if results.display_name_spoof else "N/A"
    )
    print_field(
    "Reply-To Domain: ",
    defang(results.reply_to_domain or "N/A")
    )
    print_field(
    "Origin Domain: ",
    defang(results.received_origin_domain or "N/A")
    )
    print_field("Hops: ", results.received_hops or "N/A")

    print_field("   SPF: ", results.spf)
    print_field("   DKIM: ", results.dkim)
    print_field("   DMARC: ", results.dmarc)

    print_field(
        "Display Name Spoof: ",
        verdict(
            results.display_name_spoof.spoofed
            if results.display_name_spoof else None
        )
    )

    print_field(
        "Reply-To Mismatch: ",
        verdict(results.reply_to_mismatch)
    )

    print_field(
        "Received Chain Mismatch: ",
        verdict(results.received_mismatch)
    )

    # Display extracted artifacts independently of threat intelligence.
    print("\n=== Observables ===")
    print(f"\nURLs ({len(iocs.urls)})")
    if iocs.urls:
        for i, url in enumerate(iocs.urls, start=1):
            print(f"  [{i}] {defang(url)}")
    else:
        print("  None")

    print(f"\nDomains ({len(iocs.domains)})")
    if iocs.domains:
        for i, domain in enumerate(iocs.domains, start=1):
            print(f"  [{i}] {defang(domain)}")
    else:
        print("  None")

    print(f"\nIP Addresses ({len(iocs.ips)})")
    if iocs.ips:
        for i, ip in enumerate(iocs.ips, start=1):
            print(f"  [{i}] {defang(ip)}")
    else:
        print("  None")

    print(f"\nAttachments ({len(iocs.attachments)})")
    if iocs.attachments:
        for i, attachment in enumerate(iocs.attachments, start=1):
            print(f"  [{i}] {attachment['filename']}")
            print(f"      SHA256: {attachment['sha256']}")
    else:
        print("  None")

    # Show enrichment results only when explicitly enabled.
    print("\n=== Threat Intelligence ===")
    if not enrichment_enabled:
        print("Enrichment: DISABLED")
        print("Run with --enrich to enable external threat intelligence lookups.")

    else:
        print("Enrichment: ENABLED")

        print("\nVirusTotal")
        if vt_results:
            for vt_result in vt_results:
                if vt_result.get("error") and not vt_result.get("url"):
                    print(f"  {vt_result['error']}")
                elif vt_result.get("error"):
                    print_field("   URL: ", vt_result["url"])
                    print_field("   Error: ", vt_result["error"])
                else:
                    print_field("   URL: ", vt_result["url"])
                    print_field(
                        "   Verdict: ",
                        url_verdict(
                            vt_result["malicious"],
                            vt_result["suspicious"]
                        )
                    )
                    print_field("   Malicious: ", vt_result["malicious"])
                    print_field("   Suspicious: ", vt_result["suspicious"])
        else:
            print("  No URLs to check.")

        print("\nMalwareBazaar")
        if mb_results:
            for result in mb_results:
                if result.get("error") and not result.get("filename"):
                    print(f"  {result['error']}")
                elif result.get("error"):
                    print_field("   Filename: ", result["filename"])
                    print_field("   Error: ", result["error"])
                elif result["found"]:
                    print_field("   Filename: ", result["filename"])
                    print_field("   SHA256: ", result["sha256"])
                    print_field("   Verdict: ", "FOUND - MALICIOUS")
                    print_field("   Malware Name: ", result["malware_name"])
                else:
                    print_field("   Filename: ", result["filename"])
                    print_field("   SHA256: ", result["sha256"])
                    print_field("   Verdict: ", "Not found in MalwareBazaar")
        else:
            print("  No attachments to check.")

    print("\n=== Score ===")
    print_field("Verdict: ", score["verdict"])
    print_field("Score: ", score["score"])    
    print_field("Reasons:", ", ".join(score["reasons"]) or "None")

    
def print_field(label: str, value: Any) -> None:
    print(f"{label:<30} {value}")

# Translate Spoofed and Mismatch from True/False/None to FLAGGED/CLEAN/N/A
def verdict(value: Optional[bool]) -> str:
    if value is True:
        return "FLAGGED"
    elif value is False:
        return "CLEAN"
    return "N/A"

def url_verdict(malicious: int, suspicious: int) -> str:
    if malicious >= 1:
        return "MALICIOUS"
    elif suspicious >= 1:
        return "SUSPICIOUS"
    return "CLEAN"