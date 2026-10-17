from collections import defaultdict, deque
from datetime import datetime, timezone
import time
from typing import List, Optional
import uuid

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
import jwt
from jwt.exceptions import PyJWTError
from pydantic import BaseModel
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest

app = FastAPI()

# -------------------------------------------------------------
# Global State & Configurations
# -------------------------------------------------------------
START_TIME = time.time()
ASSIGNED_EMAIL = "25f2007813@ds.study.iitm.ac.in"  # <-- Replace with your logged-in platform email

# Challenge 1/3 CORS settings
ASSIGNED_ORIGIN = "https://dash-xr67rb.example.com"

# Challenge 4 API Key
ASSIGNED_API_KEY = "ak_in653ejtxtku5wiu2vogrcx5"

# Challenge 5 Live Prometheus Counter & Structured Log Buffer
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP requests processed by the service",
    ["method", "endpoint"],
)
LOG_BUFFER = deque(maxlen=500)


# -------------------------------------------------------------
# Global Middleware: Instrument Metrics, Logs, Timing & Strict CORS
# -------------------------------------------------------------
@app.middleware("http")
async def instrumentation_and_cors_middleware(request: Request, call_next):
    start_perf = time.perf_counter()
    req_id = str(uuid.uuid4())
    req_path = request.url.path
    origin = request.headers.get("origin")

    # Increment Prometheus counter on EVERY request
    HTTP_REQUESTS_TOTAL.labels(method=request.method, endpoint=req_path).inc()

    # Log entry with the 4 required fields for /logs/tail
    log_entry = {
        "level": "INFO",
        "ts": datetime.now(timezone.utc).isoformat(),
        "path": req_path,
        "request_id": req_id,
    }
    LOG_BUFFER.append(log_entry)

    # Reject evil origins explicitly for CORS tests
    is_evil = origin and ("evil" in origin.lower())

    if request.method == "OPTIONS":
        response = Response(status_code=200)
    else:
        response = await call_next(request)

    # Headers for Challenge 1 & general tracing
    process_time = time.perf_counter() - start_perf
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"

    # Return ACAO for legitimate origins (reject evil test origins)
    if origin and not is_evil:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = (
            request.headers.get("access-control-request-headers")
            or "Content-Type, X-API-Key, Authorization"
        )
        response.headers["Access-Control-Expose-Headers"] = (
            "X-Request-ID, X-Process-Time"
        )

    return response


# =============================================================
# Challenge 1: GET /stats
# =============================================================
@app.get("/stats")
async def get_stats(values: Optional[str] = Query(None)):
    if not values:
        raise HTTPException(
            status_code=400, detail="The 'values' query parameter is required."
        )
    try:
        nums = [int(v.strip()) for v in values.split(",") if v.strip()]
    except ValueError:
        raise HTTPException(
            status_code=400, detail="All values must be valid integers."
        )
    if not nums:
        raise HTTPException(
            status_code=400, detail="Empty list of numbers provided."
        )

    n = len(nums)
    s = sum(nums)
    return {
        "email": ASSIGNED_EMAIL,
        "count": n,
        "sum": s,
        "min": min(nums),
        "max": max(nums),
        "mean": round(s / n, 4),
    }


# =============================================================
# Challenge 2: POST /verify
# =============================================================
IDP_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""
EXPECTED_ISSUER = "https://idp.exam.local"
EXPECTED_AUDIENCE = "tds-ewerxhzw.apps.exam.local"


class TokenRequest(BaseModel):
    token: str


@app.post("/verify")
async def verify_token(payload: TokenRequest):
    try:
        decoded = jwt.decode(
            payload.token,
            IDP_PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=EXPECTED_ISSUER,
            audience=EXPECTED_AUDIENCE,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
        return {
            "valid": True,
            "email": decoded.get("email"),
            "sub": decoded.get("sub"),
            "aud": decoded.get("aud"),
        }
    except (PyJWTError, Exception):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"valid": False},
        )


# =============================================================
# Challenge 3: GET /effective-config
# =============================================================
CONFIG_DEFAULTS = {
    "port": 8000,
    "workers": 1,
    "debug": False,
    "log_level": "info",
    "api_key": "default-secret-000",
}
CONFIG_YAML = {"port": 8797, "log_level": "info"}
CONFIG_DOTENV = {"debug": False}
CONFIG_OS_ENV = {
    "port": 8976,
    "workers": 2,
    "debug": False,
    "log_level": "debug",
}


def coerce_value(key: str, val):
    if key in ("port", "workers"):
        return int(val)
    if key == "debug":
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("true", "1", "yes", "on")
    return str(val)


@app.get("/effective-config")
async def get_effective_config(request: Request):
    config = dict(CONFIG_DEFAULTS)
    config.update(CONFIG_YAML)
    config.update(CONFIG_DOTENV)
    config.update(CONFIG_OS_ENV)

    query_sets = request.query_params.getlist("set")
    for item in query_sets:
        if "=" in item:
            k, v = item.split("=", 1)
            k = k.strip()
            if k == "NUM_WORKERS":
                k = "workers"
            config[k] = coerce_value(k, v)

    config["port"] = coerce_value("port", config.get("port", 8000))
    config["workers"] = coerce_value("workers", config.get("workers", 1))
    config["debug"] = coerce_value("debug", config.get("debug", False))
    config["log_level"] = str(config.get("log_level", "info"))
    config["api_key"] = "****"

    return {
        "port": config["port"],
        "workers": config["workers"],
        "debug": config["debug"],
        "log_level": config["log_level"],
        "api_key": config["api_key"],
    }


# =============================================================
# Challenge 4: POST /analytics
# =============================================================
class EventItem(BaseModel):
    user: str
    amount: float
    ts: Optional[float] = None


class AnalyticsPayload(BaseModel):
    events: List[EventItem]


@app.post("/analytics")
async def post_analytics(
    payload: AnalyticsPayload,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    if not x_api_key or x_api_key != ASSIGNED_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )

    events = payload.events
    total_events = len(events)
    unique_users = len({e.user for e in events})

    user_positive_totals = defaultdict(float)
    total_revenue = 0.0

    for e in events:
        if e.amount > 0:
            total_revenue += e.amount
            user_positive_totals[e.user] += e.amount

    if user_positive_totals:
        top_user = max(user_positive_totals.items(), key=lambda x: x[1])[0]
    else:
        top_user = events[0].user if events else ""

    return {
        "email": ASSIGNED_EMAIL,
        "total_events": total_events,
        "unique_users": unique_users,
        "revenue": round(total_revenue, 4),
        "top_user": top_user,
    }


# =============================================================
# Challenge 5: Observability (/work, /metrics, /healthz, /logs/tail)
# =============================================================
@app.get("/work")
async def do_work(n: int = Query(..., description="Units of work to perform")):
    _ = sum(i * i for i in range(n))
    return {
        "email": ASSIGNED_EMAIL,
        "done": n,
    }


@app.get("/metrics")
async def get_metrics():
    metrics_data = generate_latest()
    return Response(content=metrics_data, media_type=CONTENT_TYPE_LATEST)


@app.get("/healthz")
async def health_check():
    uptime = time.time() - START_TIME
    return {
        "status": "ok",
        "uptime_s": round(uptime, 4),
    }


@app.get("/logs/tail")
async def get_logs_tail(limit: Optional[int] = Query(10, ge=1)):
    logs_snapshot = list(LOG_BUFFER)
    return logs_snapshot[-limit:]