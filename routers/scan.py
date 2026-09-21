from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter
from pydantic import BaseModel
from core.archive_harvester import harvest_archived_urls
from core.directory_discovery import discover_directory_paths
from core.header_checker import analyze_headers
from core.js_api_analysis import analyze_js_and_api
from core.port_scanner import scan_ports
from core.subdomain_enumerator import enumerate_subdomains
from core.technology_fingerprint import fingerprint_technology

router = APIRouter(prefix="/api", tags=["Scanner"])

class ScanRequest(BaseModel):
    url: str

@router.post("/scan")
def run_scan(request: ScanRequest):
    with ThreadPoolExecutor(max_workers=7) as executor:
        header_task = executor.submit(analyze_headers, request.url)
        port_task = executor.submit(scan_ports, request.url)
        subdomain_task = executor.submit(enumerate_subdomains, request.url)
        directory_task = executor.submit(discover_directory_paths, request.url)
        js_api_task = executor.submit(analyze_js_and_api, request.url)
        archive_task = executor.submit(harvest_archived_urls, request.url)
        technology_task = executor.submit(fingerprint_technology, request.url)

        header_results = header_task.result()
        port_results = port_task.result()
        subdomain_results = subdomain_task.result()
        directory_results = directory_task.result()
        js_api_results = js_api_task.result()
        archive_results = archive_task.result()
        technology_results = technology_task.result()

    return {
        "headers": header_results,
        "ports": port_results,
        "subdomains": subdomain_results,
        "directories": directory_results,
        "js_api": js_api_results,
        "archives": archive_results,
        "technology": technology_results,
    }                 