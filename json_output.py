from analyzer.headers import HeaderAnalysis
from analyzer.iocs import IOCCollection

SCHEMA_VERSION = "1.0"


def build_json_output(
    file_name: str,
    file_size: int,
    headers: HeaderAnalysis,
    observables: IOCCollection,
    score: dict,
) -> dict:
    """Build the standardized JSON output structure."""

    return {
        "schema_version": SCHEMA_VERSION,

        "file": {
            "name": file_name,
            "size": file_size,
        },

        "headers": {
            "subject": headers.subject,

            "from": {
                "display_name": (
                    headers.display_name_spoof.display_name
                    if headers.display_name_spoof
                    else None
                ),
                "domain": (
                    headers.display_name_spoof.from_domain
                    if headers.display_name_spoof
                    else None
                ),
            },

            "reply_to_domain": headers.reply_to_domain,
            "origin_domain": headers.received_origin_domain,
            "hops": headers.received_hops,

            "authentication": {
                "spf": headers.spf,
                "dkim": headers.dkim,
                "dmarc": headers.dmarc,
            },

            "flags": {
                "display_name_spoof": (
                    headers.display_name_spoof.spoofed
                    if headers.display_name_spoof
                    else None
                ),
                "reply_to_mismatch": headers.reply_to_mismatch,
                "received_chain_mismatch": headers.received_mismatch,
            },
        },

        "observables": {
            "urls": observables.urls,
            "domains": observables.domains,
            "ip_addresses": observables.ips,
            "attachments": observables.attachments,
        },

        "score": {
            "score": score.get("score", 0),
            "verdict": score.get("verdict"),
            "reasons": score.get("reasons", []),
        },
    }