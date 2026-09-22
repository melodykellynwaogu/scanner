import requests
from typing import Dict, Any
import re

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "HSTS enforces HTTPS connections.",
        "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
        "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
        "vercel_key": "Strict-Transport-Security",
        "vercel_val": "max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "desc": "CSP prevents XSS and data injection attacks.",
        "nginx": "add_header Content-Security-Policy \"default-src 'self';\" always;",
        "apache": "Header set Content-Security-Policy \"default-src 'self';\"",
        "vercel_key": "Content-Security-Policy",
        "vercel_val": "default-src 'self';"
    },
    "X-Frame-Options": {
        "desc": "Protects against clickjacking attacks.",
        "nginx": "add_header X-Frame-Options \"SAMEORIGIN\" always;",
        "apache": "Header always set X-Frame-Options \"SAMEORIGIN\"",
        "vercel_key": "X-Frame-Options",
        "vercel_val": "SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME-type sniffing.",
        "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
        "apache": "Header always set X-Content-Type-Options \"nosniff\"",
        "vercel_key": "X-Content-Type-Options",
        "vercel_val": "nosniff"
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information sent in requests.",
        "nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
        "apache": "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
        "vercel_key": "Referrer-Policy",
        "vercel_val": "strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "desc": "Restricts browser feature usage.",
        "nginx": "add_header Permissions-Policy \"geolocation=(), microphone=()\" always;",
        "apache": "Header always set Permissions-Policy \"geolocation=(), microphone=()\"",
        "vercel_key": "Permissions-Policy",
        "vercel_val": "geolocation=(), microphone=()"
    }
}

USER_AGENT = "Mozilla/5.0 (compatible; Signal-Recon/1.0)"


def _header_quality(header: str, value: str) -> str | None:
    normalized_value = value.strip().lower()

    if header == "Strict-Transport-Security":
        match = re.search(r"max-age\s*=\s*(\d+)", normalized_value)
        if not match or int(match.group(1)) < 15_552_000:
            return "HSTS is present but max-age is shorter than six months."
    elif header == "Content-Security-Policy":
        if "default-src" not in normalized_value and "script-src" not in normalized_value:
            return "CSP is present but does not define default-src or script-src."
    elif header == "X-Frame-Options":
        if normalized_value not in {"deny", "sameorigin"}:
            return "X-Frame-Options should be DENY or SAMEORIGIN."
    elif header == "X-Content-Type-Options":
        if normalized_value != "nosniff":
            return "X-Content-Type-Options should be nosniff."
    elif header == "Referrer-Policy":
        valid_policies = {
            "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
            "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url",
        }
        if normalized_value not in valid_policies:
            return "Referrer-Policy contains an unrecognized policy value."
    elif header == "Permissions-Policy" and not normalized_value:
        return "Permissions-Policy is present but empty."

    return None


def _fallback_result(target_url: str, error: Exception) -> Dict[str, Any]:
    fallback_missing = {
        header: {
            "description": info["desc"],
            "remediation_nginx": info["nginx"],
            "remediation_apache": info["apache"],
            "verification": "Not verified because the target could not be reached.",
        }       
        for header, info in RECOMMENDED_HEADERS.items()
    }
    return {
        "status": "fallback",
        "message": f"Live connection failed ({error}). Displaying unverified remediation guidance.",
        "target": target_url,
        "detected_platform": "Unknown (Connection Failed)",
        "present_headers": {},
        "missing_headers": fallback_missing,
        "weak_headers": {},
        "header_summary": {
            "status": "unable_to_verify",
            "message": "Unable to verify required headers because the target could not be reached.",
            "required_count": len(RECOMMENDED_HEADERS),
            "present_count": 0,
            "missing_count": len(RECOMMENDED_HEADERS),
            "weak_count": 0,
            "missing": list(RECOMMENDED_HEADERS),    
            "weak": [],               
        },
        "banner_disclosures": {},               
    }

def analyze_headers(target_url: str) -> Dict[str, Any]:
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    try:
        response = requests.get(
            target_url,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        normalized_headers = {key.lower(): value for key, value in response.headers.items()}

        present_headers = {}
        missing_headers = {}
        weak_headers = {}
        banners = {}

        # Detect Web Stack / Host Provider
        server_header = normalized_headers.get("server", "").lower()
        is_vercel = "vercel" in server_header or "x-vercel-id" in normalized_headers

        # Audit Security Headers
        for header, info in RECOMMENDED_HEADERS.items():
            header_value = normalized_headers.get(header.lower())
            if header_value is not None:
                present_headers[header] = header_value
                quality_issue = _header_quality(header, header_value)
                if quality_issue:
                    weak_headers[header] = {
                        "value": header_value,
                        "description": quality_issue,
                    }
            else:
                remediation_data = {
                    "description": info["desc"],
                    "remediation_nginx": info["nginx"],
                    "remediation_apache": info["apache"]
                }
                
                # Add Vercel JSON snippet if Vercel is detected
                if is_vercel:
                    remediation_data["remediation_vercel_json"] = {
                        "key": info["vercel_key"],
                        "value": info["vercel_val"]
                    }

                missing_headers[header] = remediation_data

        # Banner Disclosure Check
        for banner_header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
            if banner_header.lower() in normalized_headers:
                banners[banner_header] = normalized_headers[banner_header.lower()]

        missing_names = list(missing_headers)
        weak_names = list(weak_headers)
        if missing_names:
            summary_status = "missing_headers"
            summary_message = f"Missing required headers: {', '.join(missing_names)}."
        elif weak_names:
            summary_status = "weak_headers"
            summary_message = f"All required headers are present, but values need attention: {', '.join(weak_names)}."
        else:
            summary_status = "complete"
            summary_message = "All required security headers are present and passed basic value checks."

        return {
            "status": "success",
            "target": target_url,
            "status_code": response.status_code,
            "detected_platform": "Vercel" if is_vercel else "Standard Web Server",
            "present_headers": present_headers,
            "missing_headers": missing_headers,
            "weak_headers": weak_headers,
            "header_summary": {
                "status": summary_status,
                "message": summary_message,
                "required_count": len(RECOMMENDED_HEADERS),
                "present_count": len(present_headers),
                "missing_count": len(missing_headers),
                "weak_count": len(weak_headers),
                "missing": missing_names,
                "weak": weak_names,
            },
            "banner_disclosures": banners
        }

    except requests.RequestException as e:
        return _fallback_result(target_url, e)