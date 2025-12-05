# main.py
import os
import tempfile
import json
import csv
from fastapi import FastAPI, Response, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from analyzer import analyze_pcap
from typing import Optional
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from dotenv import load_dotenv
import logging
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

# Config from env with defaults
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
BACKEND_HOST = os.getenv("BACKEND_HOST", "0.0.0.0")
BACKEND_PORT = int(os.getenv("BACKEND_PORT", "8000"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", "104857600"))  # 100MB default

os.makedirs(UPLOAD_DIR, exist_ok=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for startup/shutdown tasks"""
    logger.info("Starting PCAP Analyzer API")
    yield
    logger.info("Shutting down PCAP Analyzer API")

app = FastAPI(
    title="PCAP Exfiltration Analyzer (Enhanced)",
    version="2.0.0",
    description="Advanced network traffic analyzer for detecting data exfiltration",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for last analysis (thread-safe for single worker)
class AnalysisStore:
    def __init__(self):
        self.data = None
        self.filename = None
    
    def set(self, data, filename):
        self.data = data
        self.filename = filename
    
    def get(self):
        return self.data, self.filename
    
    def clear(self):
        self.data = None
        self.filename = None

ANALYSIS_STORE = AnalysisStore()


@app.get("/", tags=["Status"])
def root():
    """Health check endpoint"""
    return {
        "message": "PCAP Analyzer API Running",
        "version": "2.0.0",
        "status": "healthy"
    }


@app.get("/health", tags=["Status"])
def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "upload_dir": UPLOAD_DIR,
        "upload_dir_exists": os.path.exists(UPLOAD_DIR),
        "has_analysis": ANALYSIS_STORE.data is not None
    }


@app.post("/analyze", tags=["Analysis"])
async def analyze_endpoint(file: UploadFile = File(...)):
    """
    Analyze a PCAP file for suspicious network activity.
    
    - **file**: PCAP file to analyze (must have .pcap extension)
    
    Returns summary with suspicious flows, DNS anomalies, and traffic patterns.
    """
    # Validation
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    
    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400, 
            detail="Only .pcap and .pcapng files are accepted"
        )

    # Check file size
    content = await file.read()
    file_size = len(content)
    
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {MAX_FILE_SIZE / 1024 / 1024:.1f}MB"
        )
    
    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    logger.info(f"Received file: {file.filename} ({file_size} bytes)")

    # Save to temp file with automatic cleanup
    tmp_path = None
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pcap", dir=UPLOAD_DIR)
        with os.fdopen(tmp_fd, "wb") as out:
            out.write(content)
        
        logger.info(f"Saved to temporary file: {tmp_path}")
    except Exception as e:
        logger.error(f"Failed to save upload: {e}")
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(status_code=500, detail=f"Failed to save upload: {str(e)}")

    # Analyze
    try:
        logger.info(f"Starting analysis of {file.filename}")
        result = analyze_pcap(tmp_path)
        logger.info(f"Analysis complete: {result['flow_count']} flows, {result['suspicious_count']} suspicious items")
        
        # Store result
        ANALYSIS_STORE.set(result, file.filename)
        
        # Enhanced response with additional metrics
        return JSONResponse({
            "success": True,
            "file": file.filename,
            "file_size": file_size,
            "summary": result.get("summary", {}),
            "metrics": {
                "flow_count": result.get("flow_count", 0),
                "suspicious_count": result.get("suspicious_count", 0),
                "total_bytes": result.get("total_bytes", 0),
                "suspicious_flows": len([s for s in result.get("suspicious", []) if s.get("type") == "flow"]),
                "dns_anomalies": len([s for s in result.get("suspicious", []) if s.get("type") in ("dns", "dns_txt")]),
                "burst_events": len([s for s in result.get("suspicious", []) if s.get("type") == "burst"])
            },
            "suspicious": result.get("suspicious", []),
            "flow_sample_ids": list(result.get("flows", {}).keys())[:20]
        })
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    
    finally:
        # Cleanup temp file
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
                logger.debug(f"Cleaned up temporary file: {tmp_path}")
            except Exception as e:
                logger.warning(f"Failed to cleanup temp file: {e}")


@app.get("/flows", tags=["Analysis"])
def list_flows(limit: int = 100, offset: int = 0):
    """
    List all flows from the last analysis with pagination.
    
    - **limit**: Maximum number of flows to return (default: 100)
    - **offset**: Number of flows to skip (default: 0)
    """
    data, filename = ANALYSIS_STORE.get()
    if not data:
        raise HTTPException(
            status_code=404, 
            detail="No analysis available. Upload a PCAP file first."
        )
    
    flows = data.get("flows", {})
    flow_ids = list(flows.keys())
    
    paginated_ids = flow_ids[offset:offset + limit]
    paginated_flows = {fid: flows[fid] for fid in paginated_ids}
    
    return JSONResponse({
        "filename": filename,
        "total": len(flow_ids),
        "limit": limit,
        "offset": offset,
        "flows": paginated_flows
    })


@app.get("/flows/{flow_id}", tags=["Analysis"])
def flow_detail(flow_id: str):
    """
    Get detailed information about a specific flow.
    
    - **flow_id**: The unique identifier of the flow
    """
    data, filename = ANALYSIS_STORE.get()
    if not data:
        raise HTTPException(
            status_code=404, 
            detail="No analysis available. Upload a PCAP file first."
        )
    
    flows = data.get("flows", {})
    if flow_id not in flows:
        raise HTTPException(status_code=404, detail=f"Flow ID '{flow_id}' not found")
    
    return JSONResponse({
        "filename": filename,
        "flow": flows[flow_id]
    })


@app.get("/suspicious", tags=["Analysis"])
def get_suspicious(type_filter: Optional[str] = None):
    """
    Get all suspicious items from the last analysis.
    
    - **type_filter**: Filter by type (flow, dns, dns_txt, burst)
    """
    data, filename = ANALYSIS_STORE.get()
    if not data:
        raise HTTPException(
            status_code=404,
            detail="No analysis available. Upload a PCAP file first."
        )
    
    suspicious = data.get("suspicious", [])
    
    if type_filter:
        suspicious = [s for s in suspicious if s.get("type") == type_filter]
    
    return JSONResponse({
        "filename": filename,
        "count": len(suspicious),
        "items": suspicious
    })


@app.get("/export/{fmt}", tags=["Export"])
def export(fmt: str):
    """
    Export the last analysis in different formats.
    
    - **fmt**: Export format (csv, json)
    """
    data, filename = ANALYSIS_STORE.get()
    if not data:
        raise HTTPException(
            status_code=404, 
            detail="No analysis available to export."
        )

    if fmt not in ("csv", "json"):
        raise HTTPException(
            status_code=400, 
            detail="Format must be 'csv' or 'json'"
        )

    base_name = filename.rsplit('.', 1)[0] if filename else "analysis"

    if fmt == "json":
        content = json.dumps(data, indent=2, default=str)
        return StreamingResponse(
            iter([content.encode()]), 
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={base_name}_analysis.json"}
        )

    # CSV export with improved structure
    def iter_csv():
        header = [
            "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", 
            "protocol", "bytes", "packets", "start_time", "end_time", 
            "duration_sec", "is_suspicious"
        ]
        out = io.StringIO()
        csvw = csv.writer(out)
        
        # Write header
        csvw.writerow(header)
        yield out.getvalue().encode()
        out.truncate(0)
        out.seek(0)
        
        # Get suspicious flow IDs for marking
        suspicious_ids = {
            s.get("id") for s in data.get("suspicious", []) 
            if s.get("type") == "flow"
        }
        
        # Write data rows
        for fid, f in data.get("flows", {}).items():
            ft = f.get("five_tuple", {})
            row = [
                fid,
                ft.get("src", ""),
                ft.get("dst", ""),
                ft.get("sport", 0),
                ft.get("dport", 0),
                ft.get("protocol", ""),
                f.get("bytes", 0),
                f.get("packets", 0),
                f.get("start", ""),
                f.get("end", ""),
                f.get("duration", ""),
                "Yes" if fid in suspicious_ids else "No"
            ]
            csvw.writerow(row)
            yield out.getvalue().encode()
            out.truncate(0)
            out.seek(0)

    return StreamingResponse(
        iter_csv(), 
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={base_name}_analysis.csv"}
    )


@app.get("/export-pdf", tags=["Export"])
def export_pdf():
    """
    Export the last analysis as a PDF report.
    """
    data, filename = ANALYSIS_STORE.get()
    if not data:
        raise HTTPException(
            status_code=400, 
            detail="No analysis available"
        )

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter
    
    def new_page():
        """Helper to start a new page"""
        text = c.beginText(40, height - 40)
        text.setFont("Helvetica", 11)
        return text
    
    text = new_page()
    
    # Title
    text.setFont("Helvetica-Bold", 16)
    text.textLine("PCAP Analysis Report")
    text.setFont("Helvetica", 11)
    text.textLine("")
    
    # File info
    text.textLine(f"File: {filename or 'Unknown'}")
    text.textLine("")
    
    # Summary section
    text.setFont("Helvetica-Bold", 12)
    text.textLine("Summary")
    text.setFont("Helvetica", 11)
    
    summary = data.get("summary", {})
    text.textLine(f"  Total Flows: {summary.get('flow_count', 0)}")
    text.textLine(f"  Suspicious Items: {summary.get('suspicious_count', 0)}")
    text.textLine(f"  Total Bytes: {summary.get('total_bytes', 0):,}")
    text.textLine("")
    
    # Suspicious items section
    text.setFont("Helvetica-Bold", 12)
    text.textLine("Suspicious Activity")
    text.setFont("Helvetica", 11)
    text.textLine("")
    
    sus = data.get("suspicious", []) or []
    
    if not sus:
        text.textLine("  No suspicious activity detected.")
    else:
        # Group by type
        by_type = {}
        for s in sus:
            stype = s.get("type", "unknown")
            by_type.setdefault(stype, []).append(s)
        
        for stype, items in by_type.items():
            text.setFont("Helvetica-Bold", 11)
            text.textLine(f"  {stype.upper()} ({len(items)} items)")
            text.setFont("Helvetica", 10)
            
            for idx, s in enumerate(items[:20], 1):  # Limit per type
                # Format title based on type
                if stype == "flow":
                    title = f"{s.get('src', 'N/A')} -> {s.get('dst', 'N/A')}"
                elif stype in ("dns", "dns_txt"):
                    title = s.get("domain", "N/A")
                elif stype == "burst":
                    title = f"{s.get('src', 'N/A')} at {s.get('bucket', 'N/A')}"
                else:
                    title = s.get("id", "N/A")
                
                text.textLine(f"    {idx}. {title}")
                
                # Reasons
                for r in s.get("reasons", [])[:3]:  # Limit reasons
                    text.textLine(f"       - {r}")
                
                # Check if we need a new page
                if text.getY() < 80:
                    c.drawText(text)
                    c.showPage()
                    text = new_page()
            
            text.textLine("")
            
            if text.getY() < 80:
                c.drawText(text)
                c.showPage()
                text = new_page()
    
    # Footer
    if text.getY() > 60:
        text.setFont("Helvetica-Oblique", 9)
        text.textLine("")
        text.textLine("Generated by PCAP Exfiltration Analyzer")
    
    c.drawText(text)
    c.showPage()
    c.save()
    buf.seek(0)
    
    base_name = filename.rsplit('.', 1)[0] if filename else "analysis"
    
    return StreamingResponse(
        buf, 
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={base_name}_report.pdf"}
    )


@app.delete("/analysis", tags=["Analysis"])
def clear_analysis():
    """Clear the stored analysis data."""
    ANALYSIS_STORE.clear()
    return {"message": "Analysis data cleared successfully"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app, 
        host=BACKEND_HOST, 
        port=BACKEND_PORT,
        log_level="info"
    )