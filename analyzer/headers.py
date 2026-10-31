from email.utils import parseaddr
from email.message import Message
import tldextract
from dataclasses import dataclass
from config import DEBUG

@dataclass
class DisplaySpoofAnalysis:
    display_name: str | None = None
    from_domain: str | None = None
    spoofed: bool | None = None
    reason: str = "N/A"


@dataclass
class HeaderAnalysis:
    subject: str | None = None

    spf: str = "N/A"
    dkim: str = "N/A"
    dmarc: str = "N/A"

    display_name_spoof: DisplaySpoofAnalysis | None = None

    reply_to_domain: str | None = None
    reply_to_from_domain: str | None = None
    reply_to_mismatch: bool | None = None
    reply_to_reason: str = "N/A"

    received_origin_domain: str | None = None
    received_from_domain: str | None = None
    received_mismatch: bool | None = None
    received_hops: int | None = None
    received_reason: str = "N/A"


def analyze_headers(msg: Message) -> HeaderAnalysis:
    results = HeaderAnalysis()

    auth_fields = ["spf", "dkim", "dmarc"]

    headers = msg.get_all("Authentication-Results", [])
    parts = [
        p.strip()
        for p in headers[0].split(";")
        if p.strip()
    ] if headers else []

    for part in parts:
        for af in auth_fields:
            if part.startswith(af + "="):
                result = part.split(" ", 1)[0]
                field, value = result.split("=", 1)

                if field == "spf":
                    results.spf = value
                elif field == "dkim":
                    results.dkim = value
                elif field == "dmarc":
                    results.dmarc = value

    results.subject = msg["Subject"]
    results.display_name_spoof = check_display_name_spoof(msg)

    reply_to = check_reply_to(msg)
    results.reply_to_domain = reply_to.get("replyto_domain")
    results.reply_to_from_domain = reply_to.get("from_domain")
    results.reply_to_mismatch = reply_to.get("mismatch")
    results.reply_to_reason = reply_to.get("reason", "N/A")

    received = received_chain_analysis(msg)

    results.received_origin_domain = received.received_origin_domain
    results.received_from_domain = received.received_from_domain
    results.received_mismatch = received.received_mismatch
    results.received_hops = received.received_hops
    results.received_reason = received.received_reason

    if DEBUG:
        print(results)

    return results

# Check is the display name is similar to the domain name, ex. "Microsoft Support" and info@microsoft.com
# Matches on the first word found in domain - TLD not evaluated here.
def check_display_name_spoof(msg: Message) -> DisplaySpoofAnalysis:
    name, addr = parseaddr(msg['From'])

    # If display_name is not empty
    if name:
        extract = tldextract.extract(addr)
        name_split = name.split(' ')

        # check if display name is the same as the extracted domain name
        for n in name_split:
            if n.lower() in extract.domain:
                return DisplaySpoofAnalysis(
                    display_name = name,
                    from_domain = extract.domain+"."+extract.suffix,
                    spoofed = False
                )
        return DisplaySpoofAnalysis(
                display_name = name,
                from_domain = extract.domain+"."+extract.suffix,
                spoofed = True
        )
    
    return DisplaySpoofAnalysis(
            spoofed = None, 
            reason = "No display name present"
            )

# Check if the Reply-To address matches the From address
def check_reply_to(msg: Message) -> dict:
    if msg['Reply-To']:
        _, reply_addr = parseaddr(msg['Reply-To'])
        _, from_addr = parseaddr(msg['From'])
        reply_extract = tldextract.extract(reply_addr)
        from_extract = tldextract.extract(from_addr)
        if reply_extract.domain == from_extract.domain:
            return {
                "mismatch": False, 
                "from_domain":from_extract.domain+"."+from_extract.suffix, 
                "replyto_domain": reply_extract.domain+"."+reply_extract.suffix
                }
        else:
            return {
                "mismatch": True, 
                "from_domain":from_extract.domain+"."+from_extract.suffix, 
                "replyto_domain": reply_extract.domain+"."+reply_extract.suffix
                }
        
    return {
        "mismatch": None,
        "reason": "No Reply-To header"
        }

# received gets a header similar to "from 2435sdf.co.uk (X.X.X.X) by DM6NAFSDTM11FT012.mail.protection.outlook.com ...."
# The last item of the array is the first hop
# Split the array, the "from" is the [0] item of the array, then the domain is the [1] item
def received_chain_analysis(msg: Message) -> HeaderAnalysis:
    received = msg.get_all('Received')

    if not received:
        return HeaderAnalysis(
            received_origin_domain=None,
            received_from_domain=None,
            received_mismatch=None,
            received_hops=0,
            received_reason="No Received headers"
        )
    
    received_split = received[-1].split()
    received_extract = tldextract.extract(received_split[1])

    _, from_addr = parseaddr(msg['From'])
    from_extract = tldextract.extract(from_addr)

    mismatch = None
    if (from_extract.domain+"."+from_extract.suffix == received_extract.domain+"."+received_extract.suffix):   
        mismatch = False     
    else:
        mismatch = True


    return HeaderAnalysis(
                        received_origin_domain=received_extract.domain + "." + received_extract.suffix,
                        received_from_domain=from_extract.domain + "." + from_extract.suffix,
                        received_mismatch=mismatch,
                        received_hops=len(received)
            )
    
