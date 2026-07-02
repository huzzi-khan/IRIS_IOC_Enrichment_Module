from abuseipdb import lookup_ip
from verdict import make_verdict
from iris_client import get_iocs, post_enrichment

# IOC types in IRIS that represent IP addresses
IP_TYPES = ["ip-dst", "ip-src", "ip-any", "ip-dst|port", "ip-src|port"]

def enrich_case(case_id):
    """
    Fetch all IOCs from a case and enrich
    IP addresses via AbuseIPDB.
    """
    print(f"\nEnriching case {case_id}...")
    iocs = get_iocs(case_id)

    if not iocs:
        print("No IOCs found in this case.")
        return

    print(f"Found {len(iocs)} IOC(s). Checking for IP types...")

    for ioc in iocs:
        # Your IRIS returns ioc_type as a flat string
        ioc_type  = ioc.get("ioc_type", "")
        ioc_value = ioc.get("ioc_value", "")
        ioc_id    = ioc.get("ioc_id")

        # Only enrich IP type IOCs
        if ioc_type not in IP_TYPES:
            print(f"  Skipping {ioc_value} — type '{ioc_type}' not supported")
            continue

        print(f"  Enriching IP: {ioc_value}")

        # Lookup → verdict → post back
        raw     = lookup_ip(ioc_value)
        verdict = make_verdict(raw)
        post_enrichment(case_id, ioc_id, verdict)

        print(f"  Result: {verdict['verdict'].upper()} "
              f"(score: {verdict['score']}/100)")
        
def enrich_observable(case_id, ioc):
    """
    Enrich a single IOC. Called by webhook server.
    """
    ioc_type  = ioc.get("ioc_type", "")
    ioc_value = ioc.get("ioc_value", "")
    ioc_id    = ioc.get("ioc_id")

    print(f"Processing IOC: {ioc_value} (type: {ioc_type})")

    if ioc_type not in IP_TYPES:
        print(f"Skipping {ioc_value} — type '{ioc_type}' not supported")
        return

    raw     = lookup_ip(ioc_value)
    verdict = make_verdict(raw)
    post_enrichment(case_id, ioc_id, verdict)

    print(f"Done: {verdict['verdict'].upper()} (score: {verdict['score']}/100)")

if __name__ == "__main__":
    enrich_case(3)