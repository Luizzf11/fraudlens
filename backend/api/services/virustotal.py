import httpx
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": VT_API_KEY,
    "Accept": "application/json",
}


def _detect_ioc_type(ioc: str) -> str:
    import re
    if re.match(r"^[a-fA-F0-9]{32}$", ioc) or re.match(r"^[a-fA-F0-9]{40}$", ioc) or re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "file"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip_address"
    if re.match(r"^https?://", ioc):
        return "url"
    return "domain"


def _parse_result(ioc_type: str, data: dict) -> dict:
    attrs = data.get("data", {}).get("attributes", {})

    if ioc_type == "file":
        stats = attrs.get("last_analysis_stats", {})
        return {
            "type": "file",
            "name": attrs.get("meaningful_name") or attrs.get("name", "unknown"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
            "file_type": attrs.get("type_description"),
            "size": attrs.get("size"),
            "first_seen": attrs.get("first_submission_date"),
            "last_seen": attrs.get("last_analysis_date"),
        }

    if ioc_type == "ip_address":
        stats = attrs.get("last_analysis_stats", {})
        return {
            "type": "ip",
            "ip": data.get("data", {}).get("id"),
            "country": attrs.get("country"),
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "reputation": attrs.get("reputation"),
        }

    if ioc_type in ("domain", "url"):
        stats = attrs.get("last_analysis_stats", {})
        return {
            "type": ioc_type,
            "ioc": data.get("data", {}).get("id"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "categories": attrs.get("categories", {}),
            "reputation": attrs.get("reputation"),
            "last_analysis_date": attrs.get("last_analysis_date"),
        }

    return {}


async def enrich_ioc(ioc: str) -> dict:
    ioc_type = _detect_ioc_type(ioc)

    endpoint_map = {
        "file": f"/files/{ioc}",
        "ip_address": f"/ip_addresses/{ioc}",
        "domain": f"/domains/{ioc}",
        "url": f"/urls/{_url_id(ioc)}",
    }

    url = VT_BASE_URL + endpoint_map[ioc_type]

    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(url, headers=HEADERS)
        response.raise_for_status()
        data = response.json()

    return _parse_result(ioc_type, data)


def _url_id(url: str) -> str:
    import base64
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
