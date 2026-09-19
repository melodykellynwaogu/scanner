from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter
from pydantic import BaseModel
from core.header_checker import analyze_headers
from core.port_scanner import scan_ports
from core.subdomain_enumerator import enumerate_subdomains

router = APIRouter(prefix="/api", tags=["Scanner"])

class ScanRequest(BaseModel):
    url: str

@router.post("/scan")
def run_scan(request: ScanRequest):
    with ThreadPoolExecutor(max_workers=3) as executor:
        header_task = executor.submit(analyze_headers, request.url)
        port_task = executor.submit(scan_ports, request.url)
        subdomain_task = executor.submit(enumerate_subdomains, request.url)

        header_results = header_task.result()
        port_results = port_task.result()
        subdomain_results = subdomain_task.result()

    return {
        "headers": header_results,
        "ports": port_results,
        "subdomains": subdomain_results
    }                 