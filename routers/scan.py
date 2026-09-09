from fastapi import APIRouter
from pydantic import BaseModel
from core.header_checker import analyze_headers
from core.port_scanner import scan_ports

router = APIRouter(prefix="/api", tags=["Scanner"])

class ScanRequest(BaseModel):
    url: str

@router.post("/scan")
def run_scan(request: ScanRequest):
    header_results = analyze_headers(request.url)
    port_results = scan_ports(request.url)

    return {
        "headers": header_results,
        "ports": port_results
    }