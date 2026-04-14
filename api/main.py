"""
VURA REST API — FastAPI Backend
═══════════════════════════════════════════════════
Provides REST endpoints for clients, scans, reports, and scheduling.

Dependencies (add to requirements.txt):
    fastapi>=0.110.0
    uvicorn>=0.27.0

Run:
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

Production:
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --workers 4
"""

import os
import sys
import datetime

# ── إضافة مسار المشروع لـ sys.path ──
_API_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_API_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
from typing import Optional

# ═══════════════════════════════════════════════════════════════════════════════
# APP CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="VURA Security API",
    description="Vulnerability Reporting AI",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS — يسمح للـ Dashboard بالوصول ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # في الإنتاج: حدد الدومينات المسموحة
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══════════════════════════════════════════════════════════════════════════════
# REQUEST / RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class ClientCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    domain: Optional[str] = None
    contact_email: Optional[str] = None
    plan: str = Field(default="free")
    notes: Optional[str] = None

class ClientUpdate(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    contact_email: Optional[str] = None
    plan: Optional[str] = None
    active: Optional[int] = None
    notes: Optional[str] = None

class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1)
    scan_type: str = Field(default="terminal")
    approach: str = Field(default="defense")
    language: str = Field(default="English")
    include_script: bool = Field(default=True)
    raw_data: Optional[str] = None  # للتحليل المباشر — إذا None يشغّل recon

class ScheduleRequest(BaseModel):
    domain: str = Field(..., min_length=1)
    job_type: str = Field(default="recon")
    interval_hours: int = Field(default=24, ge=1, le=720)
    scan_type: str = Field(default="default")
    language: str = Field(default="English")
    shodan_key: Optional[str] = None



# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION — Token-based
# ═══════════════════════════════════════════════════════════════════════════════

def _get_client_from_token(authorization: Optional[str] = Header(None)):
    """
    استخراج العميل من Bearer token.
    كل عميل يملك api_token فريد يُولَّد عند الإنشاء.

    Header: Authorization: Bearer vura_xxxx...
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header. Use: Bearer <api_token>")

    token = authorization.replace("Bearer ", "").strip()
    if not token.startswith("vura_"):
        raise HTTPException(status_code=401, detail="Invalid token format. Expected: Bearer vura_xxx...")

    from app.core.database import VuraDB
    db = VuraDB()
    client = db.get_client_by_token(token)
    db.close()

    if not client:
        raise HTTPException(status_code=401, detail="Invalid API token")

    client_dict = dict(client)
    if not client_dict.get("active"):
        raise HTTPException(status_code=403, detail="Account is inactive. Contact support.")

    return client_dict


# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", tags=["System"])
async def root():
    return {
        "service": "VURA Security API",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/health", tags=["System"])
async def health_check():
    """فحص صحة الـ API والمكونات."""
    from app.core.database import VuraDB
    from app.utils.config import load_api_config

    checks = {"api": "ok", "database": "error", "ai_engine": "error"}

    try:
        db = VuraDB()
        stats = db.get_global_stats()
        db.close()
        checks["database"] = "ok"
        checks["total_clients"] = stats.get("total_clients", 0)
        checks["total_scans"] = stats.get("total_scans", 0)
    except Exception as e:
        checks["database_error"] = str(e)

    config = load_api_config()
    if config and config.get("api_key"):
        checks["ai_engine"] = "configured"
        checks["ai_provider"] = config.get("provider", "unknown")
    else:
        checks["ai_engine"] = "not_configured"

    return checks


# ═══════════════════════════════════════════════════════════════════════════════
# CLIENT ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/clients", tags=["Clients"])
async def create_client(data: ClientCreate):
    """إنشاء عميل جديد."""
    from app.core.database import VuraDB

    db = VuraDB()
    try:
        client = db.add_client(
            name=data.name,
            domain=data.domain,
            contact_email=data.contact_email,
            plan=data.plan,
            notes=data.notes,
        )
        return {"success": True, "client": client}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        db.close()


@app.get("/api/clients", tags=["Clients"])
async def list_clients(active_only: bool = False, plan: Optional[str] = None):
    """قائمة العملاء."""
    from app.core.database import VuraDB

    db = VuraDB()
    clients = db.list_clients(active_only=active_only, plan=plan)
    db.close()
    return {"clients": clients, "total": len(clients)}


@app.get("/api/clients/{client_id}", tags=["Clients"])
async def get_client(client_id: int):
    """جلب بيانات عميل."""
    from app.core.database import VuraDB

    db = VuraDB()
    client = db._row_to_dict(db.get_client(client_id))
    stats = db.get_client_stats(client_id)
    db.close()

    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    return {"client": client, "stats": stats}


@app.put("/api/clients/{client_id}", tags=["Clients"])
async def update_client(client_id: int, data: ClientUpdate):
    """تحديث بيانات عميل."""
    from app.core.database import VuraDB

    db = VuraDB()
    updates = {k: v for k, v in data.dict().items() if v is not None}

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    try:
        success = db.update_client(client_id, **updates)
        db.close()
        if success:
            return {"success": True, "message": "Client updated"}
        raise HTTPException(status_code=404, detail="Client not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/clients/{client_id}/regenerate-token", tags=["Clients"])
async def regenerate_client_token(client_id: int):
    """توليد API token جديد."""
    from app.core.database import VuraDB

    db = VuraDB()
    client = db.get_client(client_id)
    if not client:
        db.close()
        raise HTTPException(status_code=404, detail="Client not found")

    new_token = db.regenerate_token(client_id)
    db.close()
    return {"success": True, "api_token": new_token}


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/scans", tags=["Scans"])
async def create_scan(data: ScanRequest, client: dict = Depends(_get_client_from_token)):
    """
    تشغيل فحص جديد — يحتاج Bearer token.

    إذا raw_data موجود: يحلل البيانات مباشرة.
    إذا raw_data فارغ: يشغّل recon على الـ target.
    """
    from app.core.database import VuraDB

    # ── تسجيل الفحص ──
    db = VuraDB()
    scan_id = db.add_scan(
        target=data.target,
        scan_type=data.scan_type,
        approach=data.approach,
        language=data.language,
        client_id=client["id"],
    )

    try:
        # ── جلب البيانات ──
        if data.raw_data:
            raw = data.raw_data
        else:
            from app.core.recon import run_full_recon
            raw = run_full_recon(data.target)

        if not raw or len(raw.strip()) < 10:
            db.fail_scan(scan_id, "No data to analyze")
            db.close()
            raise HTTPException(status_code=422, detail="No scannable data for this target")

        # ── توليد التقرير ──
        from app.core.ai_engine import generate_report
        report = generate_report(
            raw,
            language=data.language,
            output_format="md",
            approach=data.approach,
            include_script=data.include_script,
            scan_type=data.scan_type,
        )

        if not report or report.startswith("# Connection Error") or report.startswith("# Error"):
            db.fail_scan(scan_id, report or "Report generation failed")
            db.close()
            return JSONResponse(
                status_code=502,
                content={"error": "AI engine error", "details": report, "scan_id": scan_id},
            )

        # ── حفظ ──
        from app.utils.formatter import save_markdown_report, export_to_pdf, add_compliance_section

        report_with_compliance = add_compliance_section(report)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        session_id = f"VURA_API_{data.scan_type}_{timestamp}"

        md_path, script_path, enriched = save_markdown_report(report_with_compliance, session_id, data.approach)
        pdf_path = export_to_pdf(enriched, session_id)

        db.complete_scan(
            scan_id,
            report_md=md_path,
            report_pdf=pdf_path,
            script_path=script_path,
        )
        db.close()

        return {
            "success": True,
            "scan_id": scan_id,
            "session_id": session_id,
            "report_md": md_path,
            "report_pdf": pdf_path,
            "script_path": script_path,
            "report_content": enriched[:5000] if enriched else None,  # أول 5000 حرف
        }

    except HTTPException:
        raise
    except Exception as e:
        db.fail_scan(scan_id, str(e))
        db.close()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/api/scans", tags=["Scans"])
async def list_scans(
    client: dict = Depends(_get_client_from_token),
    status: Optional[str] = None,
    scan_type: Optional[str] = None,
    limit: int = 50,
):
    """قائمة فحوصات العميل."""
    from app.core.database import VuraDB

    db = VuraDB()
    scans = db.list_scans(client_id=client["id"], status=status, scan_type=scan_type, limit=limit)
    db.close()
    return {"scans": scans, "total": len(scans)}


@app.get("/api/scans/{scan_id}", tags=["Scans"])
async def get_scan(scan_id: int, client: dict = Depends(_get_client_from_token)):
    """جلب تفاصيل فحص."""
    from app.core.database import VuraDB

    db = VuraDB()
    scan = db.get_scan(scan_id)
    db.close()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.get("client_id") != client["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    return {"scan": scan}


@app.get("/api/scans/{scan_id}/report", tags=["Scans"])
async def get_scan_report(scan_id: int, format: str = "md"):
    """تحميل تقرير فحص (md أو pdf)."""
    from app.core.database import VuraDB

    db = VuraDB()
    scan = db.get_scan(scan_id)
    db.close()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if format == "pdf" and scan.get("report_pdf"):
        path = scan["report_pdf"]
        if os.path.exists(path):
            return FileResponse(path, media_type="application/pdf", filename=os.path.basename(path))

    elif format == "md" and scan.get("report_md"):
        path = scan["report_md"]
        if os.path.exists(path):
            return FileResponse(path, media_type="text/markdown", filename=os.path.basename(path))

    raise HTTPException(status_code=404, detail=f"Report ({format}) not available for this scan")


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEDULING ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

# ── Scheduler instance (singleton) ──
_scheduler_instance = None

def _get_scheduler():
    global _scheduler_instance
    if _scheduler_instance is None:
        from app.core.scheduler import VuraScheduler
        _scheduler_instance = VuraScheduler()
        _scheduler_instance.start(background=True)
    return _scheduler_instance


@app.post("/api/schedule", tags=["Scheduling"])
async def create_scheduled_job(data: ScheduleRequest, client: dict = Depends(_get_client_from_token)):
    """إضافة فحص مجدول."""
    scheduler = _get_scheduler()

    if not scheduler.scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not available. Install apscheduler.")

    job_id = None
    if data.job_type == "recon":
        job_id = scheduler.add_recon_job(
            client_id=client["id"],
            domain=data.domain,
            interval_hours=data.interval_hours,
            language=data.language,
        )
    elif data.job_type == "nmap":
        job_id = scheduler.add_nmap_job(
            client_id=client["id"],
            target=data.domain,
            scan_type=data.scan_type,
            interval_hours=data.interval_hours,
            language=data.language,
        )
    elif data.job_type == "full_recon":
        job_id = scheduler.add_full_recon_job(
            client_id=client["id"],
            domain=data.domain,
            interval_hours=data.interval_hours,
            shodan_key=data.shodan_key,
            language=data.language,
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown job_type: {data.job_type}")

    return {"success": True, "job_id": job_id}


@app.get("/api/schedule", tags=["Scheduling"])
async def list_scheduled_jobs():
    """قائمة الـ jobs المجدولة."""
    scheduler = _get_scheduler()
    jobs = scheduler.get_jobs_summary()
    return {"jobs": jobs, "total": len(jobs)}


@app.delete("/api/schedule/{job_id}", tags=["Scheduling"])
async def delete_scheduled_job(job_id: str):
    """حذف job مجدولة."""
    scheduler = _get_scheduler()
    success = scheduler.remove_job(job_id)
    if success:
        return {"success": True, "message": f"Job {job_id} removed"}
    raise HTTPException(status_code=404, detail="Job not found")




# ═══════════════════════════════════════════════════════════════════════════════
# STATS & DASHBOARD DATA
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/stats", tags=["Dashboard"])
async def global_stats():
    """إحصائيات عامة — للـ Dashboard."""
    from app.core.database import VuraDB

    db = VuraDB()
    stats = db.get_global_stats()
    db.close()
    return {"stats": stats}


@app.get("/api/stats/{client_id}", tags=["Dashboard"])
async def client_stats(client_id: int):
    """إحصائيات عميل محدد."""
    from app.core.database import VuraDB

    db = VuraDB()
    client = db._row_to_dict(db.get_client(client_id))
    if not client:
        db.close()
        raise HTTPException(status_code=404, detail="Client not found")

    stats = db.get_client_stats(client_id)
    recent_scans = db.list_scans(client_id=client_id, limit=10)
    db.close()

    return {"client": client, "stats": stats, "recent_scans": recent_scans}


# ═══════════════════════════════════════════════════════════════════════════════
# STARTUP / SHUTDOWN
# ═══════════════════════════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup_event():
    """تهيئة قاعدة البيانات عند تشغيل الـ API."""
    from app.core.database import init_db, migrate_json_to_sqlite
    init_db()
    migrate_json_to_sqlite()


@app.on_event("shutdown")
async def shutdown_event():
    """إيقاف الـ Scheduler عند إغلاق الـ API."""
    global _scheduler_instance
    if _scheduler_instance:
        _scheduler_instance.stop()
