import nmap
from typing import Dict, Any
from urllib.parse import urlparse

def scan_ports(target_input: str) -> Dict[str, Any]:
    # Extract host/domain from URL if full URL is passed
    if "://" in target_input:
        domain = urlparse(target_input).netloc
    else:
        domain = target_input.split('/')[0]

    nm = nmap.PortScanner()
    
    try:
        # Scan common web/infra ports with service version detection
        nm.scan(hosts=domain, ports='21,22,80,443,8080', arguments='-sV --open')
        
        open_ports = []
        host_ip = "Unknown"

        for host in nm.all_hosts():
            host_ip = host
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    port_info = nm[host][proto][port]
                    open_ports.append({
                        "port": port,
                        "protocol": proto,
                        "state": port_info.get("state", "open"),
                        "service": port_info.get("name", "unknown"),
                        "version": f"{port_info.get('product', '')} {port_info.get('version', '')}".strip() or "N/A"
                    })

        return {
            "status": "success",
            "host_ip": host_ip,
            "open_ports": open_ports
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}