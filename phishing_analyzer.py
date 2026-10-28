# CLI entry point for phishing email analysis.

import argparse 
import sys
from pathlib import Path
from email import message_from_binary_file
from email import policy
from email.message import Message

from headers import analyze_headers
from body import parse_body, extract_urls
from attachments import parse_attachments, hash_attachments
from vt import check_urls_vt
from display import display_results
from malwarebazaar import check_hashes_malwarebazaar
from scoring import calculate_score
from analyzer.iocs import build_ioc_collection
from config import DEBUG

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Analyze an .eml file for phishing indicators."
    )

    parser.add_argument(
        "filename",
        help="Path to the .eml file to analyze"
    )

    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Enable external threat intelligence enrichment"
    )

    return parser.parse_args(argv)

def parse_headers(msg: Message) -> None:
    if DEBUG:
        print("Headers")
        print(msg['From'])
        print(msg['Subject'])
        print(msg.get_all('Received'))
        
def main(argv=None) -> None:
    args = parse_args(argv)
    filename = args.filename
    file_ext = Path(args.filename)
    if file_ext.suffix.lower() not in [".eml"]:
        print("Error: Email must have .eml extension", file=sys.stderr)
        raise SystemExit(2)

    with open(filename, 'rb') as f:
        msg = message_from_binary_file(f, policy=policy.default)

    # Parse the email locally before any optional external enrichment.
    parse_headers(msg)
    body = parse_body(msg)
    urls = extract_urls(body)
    attachments = parse_attachments(msg)
    hashes = hash_attachments(attachments)
    header_results = analyze_headers(msg)

    # Consolidate artifacts from the body, headers, and attachments.
    iocs = build_ioc_collection(
        urls,
        hashes,
        header_results
    )

    # External threat intelligence is opt-in with --enrich.
    vt_results = []
    mb_results = []

    if args.enrich:
        vt_results = check_urls_vt(urls)
        mb_results = check_hashes_malwarebazaar(hashes)

    score = calculate_score(
        header_results,
        vt_results,
        mb_results
    )

    display_results(
        header_results,
        filename,
        iocs,
        vt_results,
        mb_results,
        score,
        args.enrich
    )

if __name__ == "__main__":
    main()