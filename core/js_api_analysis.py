import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

import requests


MAX_JS_FILES = 10                     
MAX_ENDPOINTS = 50
MAX_SECRET_FINDINGS = 20
SECRET_PATTERNS = [
    ("named credential", r"(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("private key marker", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]


def _extract_js_links(html: str) -> List[str]:
    pattern = r"(?:src|href)=['\"]([^'\"]+\.(?:js|mjs|js\?[^'\"]*))['\"]"
    matches = re.findall(pattern, html, flags=re.IGNORECASE)
    return sorted(set(match for match in matches if not match.startswith("data:")))


def _extract_endpoints(html: str) -> List[str]:
    patterns = [
        r"https?://[A-Za-z0-9._:/?=&%\-]+",
        r"/(?:api|graphql|v[0-9]+|auth|oauth|login|users|admin)[A-Za-z0-9_/?=&%\-.]*",
    ]
    endpoints = set()
    for pattern in patterns:
        for match in re.findall(pattern, html, flags=re.IGNORECASE):
            if "http" in match or match.startswith("/"):
                endpoints.add(match)
    return sorted(endpoints)[:MAX_ENDPOINTS]


def _extract_possible_secrets(text: str) -> List[str]:
    findings = []
    for label, pattern in SECRET_PATTERNS:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            value = match.group(1) if match.lastindex else match.group(0)
            if len(value) > 8:
                findings.append(f"{label}: {value[:4]}...{value[-4:]}")
    return sorted(set(findings))[:MAX_SECRET_FINDINGS]


def analyze_js_and_api(target_input: str) -> Dict[str, Any]:
    value = target_input.strip()
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"

    parsed = urlparse(value)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    discovered_js = []
    endpoints = []
    secrets = []

    try:
        page = requests.get(value, timeout=10, allow_redirects=True)
        page.raise_for_status()
        page_text = page.text
        discovered_js = _extract_js_links(page_text)

        for js_url in discovered_js[:MAX_JS_FILES]:
            full_js_url = urljoin(value, js_url)
            if urlparse(full_js_url).netloc != parsed.netloc:
                continue
            try:
                js_response = requests.get(full_js_url, timeout=10, headers={"User-Agent": "Signal-Recon/1.0"})
                js_response.raise_for_status()
                if "javascript" not in js_response.headers.get("Content-Type", "").lower() and not full_js_url.lower().split("?")[0].endswith((".js", ".mjs")):
                    continue
                endpoints.extend(_extract_endpoints(js_response.text))
                secrets.extend(_extract_possible_secrets(js_response.text))
            except requests.RequestException:
                continue

        endpoints.extend(_extract_endpoints(page_text))
        secrets.extend(_extract_possible_secrets(page_text))

        return {
            "status": "success",
            "base_url": base_url,
            "javascript_files": discovered_js,
            "endpoints": sorted(set(endpoints))[:50],
            "possible_secrets": sorted(set(secrets))[:20],
        }
    except requests.RequestException as exc:
        return {"status": "error", "base_url": base_url, "message": str(exc)}
