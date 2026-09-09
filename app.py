from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from routers import scan

app = FastAPI(title="SOC Recon & Security Hardening Dashboard")

# Include API routes
app.include_router(scan.router)

# Serve static frontend files
app.mount("/", StaticFiles(directory="static", html=True), name="static")