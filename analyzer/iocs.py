from dataclasses import dataclass, field
from ipaddress import ip_address
from urllib.parse import urlsplit
from typing import Optional

# Stores observables collected across the email analysis.
@dataclass
class IOCCollection:
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)


def classify_hostname(
    hostname: Optional[str],
    domains: set[str],
    ips: set[str] ) -> None:
    if not hostname:
        return

    hostname = hostname.lower().strip().rstrip(".")

    # Keep IP addresses separate from domain names.
    try:
        ip_address(hostname)
        ips.add(hostname)
    except ValueError:
        domains.add(hostname)


def build_ioc_collection(
    urls: list[str],
    hashes: list[dict],
    header_results: dict ) -> IOCCollection:    
    domains: set[str] = set()
    ips: set[str] = set()

    # Collect hostnames from URLs.
    for url in urls:
        classify_hostname(
            urlsplit(url).hostname,
            domains,
            ips
        )

    # Collect domains identified during header analysis.
    header_domains = [
        header_results
        .get("display_name_spoof", {})
        .get("from_domain"),

        header_results
        .get("reply_to", {})
        .get("replyto_domain"),

        header_results
        .get("received_chain", {})
        .get("origin_domain")
    ]

    for hostname in header_domains:
        classify_hostname(hostname, domains, ips)

    return IOCCollection(
            urls=sorted(set(urls)),
            domains=sorted(domains),
            ips=sorted(ips),
            attachments=hashes
        )