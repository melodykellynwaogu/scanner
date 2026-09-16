# import requests
# from typing import Dict, Any

# RECOMMENDED_HEADERS = {
#     "Strict-Transport-Security": {
#         "desc": "HSTS enforces HTTPS connections.",
#         "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
#         "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
#     },
#     "Content-Security-Policy": {
#         "desc": "CSP prevents XSS and data injection attacks.",
#         "nginx": "add_header Content-Security-Policy \"default-src 'self';\" always;",
#         "apache": "Header set Content-Security-Policy \"default-src 'self';\""
#     },
#     "X-Frame-Options": {
#         "desc": "Protects against clickjacking attacks.",
#         "nginx": "add_header X-Frame-Options \"SAMEORIGIN\" always;",
#         "apache": "Header always set X-Frame-Options \"SAMEORIGIN\""
#     },
#     "X-Content-Type-Options": {
#         "desc": "Prevents MIME-type sniffing.",
#         "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
#         "apache": "Header always set X-Content-Type-Options \"nosniff\""
#     },
#     "Referrer-Policy": {
#         "desc": "Controls referrer information sent in requests.",
#         "nginx": "add_header Referrer-Policy \"no-referrer-when-downgrade\" always;",
#         "apache": "Header always set Referrer-Policy \"no-referrer-when-downgrade\""
#     },
#     "Permissions-Policy": {
#         "desc": "Restricts browser feature usage.",
#         "nginx": "add_header Permissions-Policy \"geolocation=(), microphone=()\" always;",
#         "apache": "Header always set Permissions-Policy \"geolocation=(), microphone=()\""
#     }
# }

# def analyze_headers(target_url: str) -> Dict[str, Any]:
#     if not target_url.startswith(("http://", "https://")):
#         target_url = f"https://{target_url}"

#     try:
#         response = requests.get(target_url, timeout=5, allow_redirects=True)
#         headers = response.headers

#         present_headers = {}
#         missing_headers = {}
#         banners = {}

#         # Audit Security Headers
#         for header, info in RECOMMENDED_HEADERS.items():
#             if header in headers:
#                 present_headers[header] = headers[header]
#             else:
#                 missing_headers[header] = {
#                     "description": info["desc"],
#                     "remediation_nginx": info["nginx"],
#                     "remediation_apache": info["apache"]
#                 }

#         # Banner Disclosure Check
#         for banner_header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
#             if banner_header in headers:
#                 banners[banner_header] = headers[banner_header]

#         return {
#             "status": "success",
#             "target": target_url,
#             "status_code": response.status_code,
#             "present_headers": present_headers,
#             "missing_headers": missing_headers,
#             "banner_disclosures": banners
#         }

#     except requests.RequestException as e:
#         return {"status": "error", "message": str(e)}






import requests
from typing import Dict, Any

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

def analyze_headers(target_url: str) -> Dict[str, Any]:
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    try:
        response = requests.get(target_url, timeout=5, allow_redirects=True)
        headers = response.headers

        present_headers = {}
        missing_headers = {}
        banners = {}

        # Detect Web Stack / Host Provider
        server_header = headers.get("Server", "").lower()
        is_vercel = "vercel" in server_header or "x-vercel-id" in headers

        # Audit Security Headers
        for header, info in RECOMMENDED_HEADERS.items():
            if header in headers:
                present_headers[header] = headers[header]
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
            if banner_header in headers:
                banners[banner_header] = headers[banner_header]

        return {
            "status": "success",
            "target": target_url,
            "status_code": response.status_code,
            "detected_platform": "Vercel" if is_vercel else "Standard Web Server",
            "present_headers": present_headers,
            "missing_headers": missing_headers,
            "banner_disclosures": banners
        }

    except requests.RequestException as e:
        return {"status": "error", "message": str(e)}