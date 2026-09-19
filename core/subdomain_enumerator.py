import socket
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests


MAX_SUBDOMAINS = 100


def _get_hostname(target_input: str) -> str:
    value = target_input.strip()
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return (urlparse(value).hostname or "").lower().rstrip(".")


def _certificate_names(domain: str) -> List[str]:
    response = requests.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        timeout=10,
    )
    response.raise_for_status()

    names = set()
    for certificate in response.json():
        for raw_name in certificate.get("name_value", "").splitlines():
            name = raw_name.strip().lower().lstrip("*.").rstrip(".")
            if name and name != domain and name.endswith(f".{domain}"):
                names.add(name)

    return sorted(names)[:MAX_SUBDOMAINS]


def _resolve_name(name: str) -> Dict[str, Any]:
    try:
        addresses = sorted({result[4][0] for result in socket.getaddrinfo(name, None)})
        return {"hostname": name, "addresses": addresses, "status": "resolved"}
    except socket.gaierror:
        return {"hostname": name, "addresses": [], "status": "no_dns"}


def enumerate_subdomains(target_input: str) -> Dict[str, Any]:
    domain = _get_hostname(target_input)
    if not domain:
        return {"status": "error", "message": "A valid domain is required."}

    try:
        names = _certificate_names(domain)
        discovered = [_resolve_name(name) for name in names]
        return {
            "status": "success",
            "domain": domain,
            "source": "Certificate Transparency logs + DNS resolution",
            "count": len(discovered),
            "subdomains": discovered,
        }
    except (requests.RequestException, ValueError) as error:
        return {"status": "error", "domain": domain, "message": str(error)}
