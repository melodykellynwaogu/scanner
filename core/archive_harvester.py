from typing import Any, Dict, List
from urllib.parse import urlparse

import requests


MAX_ARCHIVED_URLS = 100
ARCHIVE_TIMEOUT = 12


def _get_hostname(target_input: str) -> str:
    value = target_input.strip()
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return (urlparse(value).hostname or "").lower().rstrip(".")


def harvest_archived_urls(target_input: str) -> Dict[str, Any]:
    domain = _get_hostname(target_input)
    if not domain:
        return {"status": "error", "message": "A valid domain is required."}

    endpoint = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": str(MAX_ARCHIVED_URLS),
    }

    try:
        response = requests.get(
            endpoint,
            params=params,
            timeout=ARCHIVE_TIMEOUT,
            headers={"User-Agent": "Signal-Recon/1.0"},
        )
        response.raise_for_status()
        rows = response.json()
        archived_urls: List[Dict[str, Any]] = []

        for row in rows[1:] if rows and isinstance(rows[0], list) else rows:
            if not isinstance(row, list) or len(row) < 4:
                continue
            archived_urls.append(
                {
                    "timestamp": row[0],
                    "url": row[1],
                    "status_code": row[2],
                    "mime_type": row[3],
                    "replay_url": f"https://web.archive.org/web/{row[0]}/{row[1]}",
                }
            )

        return {
            "status": "success",
            "domain": domain,
            "source": "Internet Archive CDX API",
            "count": len(archived_urls),
            "urls": archived_urls,
        }
    except (requests.RequestException, ValueError) as error:
        return {"status": "error", "domain": domain, "message": str(error)}
