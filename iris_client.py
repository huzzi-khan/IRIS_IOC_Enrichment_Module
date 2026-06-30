import requests
import os
from dotenv import load_dotenv

load_dotenv()

IRIS_URL = os.getenv("IRIS_URL")
IRIS_KEY = os.getenv("IRIS_API_KEY")

HEADERS = {
    "Authorization": f"Bearer {IRIS_KEY}",
    "Content-Type": "application/json"
}

# Disable SSL warnings for local dev
requests.packages.urllib3.disable_warnings()

def get_iocs(case_id):
    """Fetch all IOCs for a given case."""
    url = f"{IRIS_URL}/case/ioc/list"
    response = requests.get(
        url,
        headers=HEADERS,
        params={"cid": case_id},
        verify=False
    )
    if response.status_code == 200:
        return response.json().get("data", {}).get("ioc", [])
    print(f"Failed to get IOCs: {response.status_code} {response.text}")
    return []

def post_enrichment(case_id, ioc_id, verdict):
    """Write AbuseIPDB verdict back to an IOC."""
    url = f"{IRIS_URL}/case/ioc/update/{ioc_id}"

    # Format verdict as a readable note
    note = (
        f"[AbuseIPDB Enrichment]\n"
        f"Verdict      : {verdict['verdict'].upper()}\n"
        f"Abuse Score  : {verdict['score']} / 100\n"
        f"Total Reports: {verdict['total_reports']}\n"
        f"Country      : {verdict['country']}\n"
        f"ISP          : {verdict['isp']}\n"
        f"Is Tor Node  : {verdict['is_tor']}\n"
        f"Source       : {verdict['source']}"
    )

    payload = {
        "ioc_description": note,
        "cid": case_id
    }

    response = requests.post(
        url,
        json=payload,
        headers=HEADERS,
        params={"cid": case_id},
        verify=False
    )

    if response.status_code == 200:
        print(f"✓ Verdict posted to IOC {ioc_id}")
        return True
    else:
        print(f"✗ Failed: {response.status_code} {response.text}")
        return False