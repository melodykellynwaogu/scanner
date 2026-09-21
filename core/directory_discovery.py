from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

COMMON_PATHS = [
    "/admin",
    "/login",
    "/dashboard",
    "/api",
    "/api/v1",
    "/graphql",
    "/.git",
    "/.env",
    "/backup",
    "/backup.zip",
    "/config",
    "/wp-admin",
    "/phpmyadmin",
    "/robots.txt",
    "/sitemap.xml",
    "/console",
    "/manage",
    "/debug",
    "/admin/login",
    "/uploads",
]
MAX_PATHS = 20
REQUEST_TIMEOUT = 5



def _normalize_target(target_input: str) -> str:
    value = target_input.strip()
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    parsed = urlparse(value)
    return f"{parsed.scheme}://{parsed.netloc}"

def _probe_path(session: requests.Session, base_url: str, path: str, baseline: Optional[tuple]) -> Optional[Dict[str, Any]]:
    full_url = base_url.rstrip("/") + "/" + path.lstrip("/")
    try:
        response = session.get(full_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
    except requests.RequestException:
        return None

    if response.status_code not in (200, 301, 302, 401, 403, 405):
        return None        

    response_signature = (response.status_code, len(response.content))
    if baseline and response_signature == baseline:
        return None

    category = "possible exposure" if response.status_code in (200, 401, 403, 405) else "redirect"
    return {
        "path": path,
        "url": full_url,
        "status_code": response.status_code,
        "category": category,
        "location": response.headers.get("Location"),
    }


def discover_directory_paths(target_input: str) -> Dict[str, Any]:
    base_url = _normalize_target(target_input)

    session = requests.Session()
    session.headers.update({"User-Agent": "Signal-Recon/1.0"})
    baseline = None
    try:
        baseline_url = base_url.rstrip("/") + "/__signal_recon_missing__"
        baseline_response = session.get(baseline_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        baseline = (baseline_response.status_code, len(baseline_response.content))
    except requests.RequestException:
        pass

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(lambda path: _probe_path(session, base_url, path, baseline), COMMON_PATHS[:MAX_PATHS])
        found_paths: List[Dict[str, Any]] = [result for result in results if result]

    return {
        "status": "success",
        "base_url": base_url,
        "count": len(found_paths),
        "paths": found_paths,
    }
