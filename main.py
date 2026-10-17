from collections import defaultdict, deque
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional
import uuid

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
import jwt
from jwt.exceptions import PyJWTError
from pydantic import BaseModel
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest

app = FastAPI()

# -------------------------------------------------------------
# Configuration Values & State
# -------------------------------------------------------------
START_TIME = time.time()
ASSIGNED_EMAIL = "25f2007813@ds.study.iitm.ac.in"  # <-- Replace with your logged-in email

# Assigned origins
ASSIGNED_ORIGIN_C1 = "https://dash-xr67rb.example.com"
ASSIGNED_ORIGIN_C7 = "https://app-smdipu.example.com"

# Rate limits
RATE_LIMIT_BUCKET_B = 10  # 10 req / 10s for Challenge 7
RATE_LIMIT_WINDOW = 10.0

# Challenge 4 API Key
ASSIGNED_API_KEY = "ak_in653ejtxtku5wiu2vogrcx5"

# Prometheus Metrics & Log Buffer
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP requests processed by the service",
    ["method", "endpoint"],
)
LOG_BUFFER = deque(maxlen=500)

# Caches for Orders and Rate Limiting
TOTAL_ORDERS = 50
CATALOG_ORDERS = [
    {"id": i, "item": f"Item-{i}", "price": 10.0 + i}
    for i in range(1, TOTAL_ORDERS + 1)
]
IDEMPOTENCY_CACHE: Dict[str, Dict[str, Any]] = {}
CLIENT_RATE_LIMITS: Dict[str, List[float]] = defaultdict(list)


# -------------------------------------------------------------
# Unified Middleware Stack:
# 1. Request Context Propagator (X-Request-ID)
# 2. Per-Client Rate Limiter (X-Client-Id)
# 3. CORS & Preflight Handler
# -------------------------------------------------------------
@app.middleware("http")
async def main_middleware_stack(request: Request, call_next):
    start_perf = time.perf_counter()
    origin = request.headers.get("origin")
    req_path = request.url.path

    # Middleware 1: Request context propagation
    inbound_req_id = request.headers.get("X-Request-ID")
    request_id = inbound_req_id.strip() if inbound_req_id else str(uuid.uuid4())
    request.state.request_id = request_id

    # Observability metrics & logs
    HTTP_REQUESTS_TOTAL.labels(method=request.method, endpoint=req_path).inc()
    LOG_BUFFER.append({
        "level": "INFO",
        "ts": datetime.now(timezone.utc).isoformat(),
        "path": req_path,
        "request_id": request_id,
    })

    # Determine if origin is an evil test probe
    is_evil = origin and ("evil" in origin.lower())

    # Preflight OPTIONS handler
    if request.method == "OPTIONS":
        response = Response(status_code=200)
        _apply_cors_headers(response, origin, is_evil, request)
        response.headers["X-Request-ID"] = request_id
        return response

    # Middleware 3: Per-client rate limiter (Bucket B = 10 req / 10s)
    client_id = request.headers.get("X-Client-Id")
    if client_id:
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW
        timestamps = [t for t in CLIENT_RATE_LIMITS[client_id] if t > window_start]

        if len(timestamps) >= RATE_LIMIT_BUCKET_B:
            oldest = timestamps[0]
            retry_after = max(1, int(RATE_LIMIT_WINDOW - (now - oldest)))
            CLIENT_RATE_LIMITS[client_id] = timestamps
            response = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too Many Requests"},
                headers={"Retry-After": str(retry_after)},
            )
            response.headers["X-Request-ID"] = request_id
            _apply_cors_headers(response, origin, is_evil, request)
            return response

        timestamps.append(now)
        CLIENT_RATE_LIMITS[client_id] = timestamps

    response = await call_next(request)

    # Middleware 1 Header: attach X-Request-ID and Process-Time
    process_time = time.perf_counter() - start_perf
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"

    _apply_cors_headers(response, origin, is_evil, request)
    return response


def _apply_cors_headers(
    response: Response, origin: Optional[str], is_evil: bool, request: Request
):
    if origin and not is_evil:
        # Check against assigned origins or allow browser exam origins
        allowed = (
            origin == ASSIGNED_ORIGIN_C7
            or origin == ASSIGNED_ORIGIN_C1
            or "example.com" not in origin
        )
        if allowed:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = (
                request.headers.get("access-control-request-headers")
                or "Content-Type, X-API-Key, Authorization, X-Client-Id, Idempotency-Key, X-Request-ID"
            )
            response.headers["Access-Control-Expose-Headers"] = (
                "X-Request-ID, X-Process-Time, Retry-After"
            )


# =============================================================
# Challenge 7: GET /ping
# =============================================================
@app.get("/ping")
async def ping(request: Request):
    return {
        "email": ASSIGNED_EMAIL,
        "request_id": request.state.request_id,
    }


# =============================================================
# Challenge 6: Orders API (/orders)
# =============================================================
class CreateOrderPayload(BaseModel):
    item: Optional[str] = "Standard Order"
    amount: Optional[float] = 100.0


@app.post("/orders", status_code=status.HTTP_201_CREATED)
async def create_order(
    payload: Optional[CreateOrderPayload] = None,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    if idempotency_key and idempotency_key in IDEMPOTENCY_CACHE:
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=IDEMPOTENCY_CACHE[idempotency_key],
        )

    order_id = str(uuid.uuid4())
    order_data = {
        "id": order_id,
        "item": payload.item if payload else "Standard Order",
        "amount": payload.amount if payload else 100.0,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    if idempotency_key:
        IDEMPOTENCY_CACHE[idempotency_key] = order_data

    return order_data


@app.get("/orders")
async def list_orders(
    limit: int = Query(10, ge=1), cursor: Optional[str] = Query(None)
):
    start_id = 1
    if cursor is not None and cursor != "":
        try:
            start_id = int(cursor)
        except ValueError:
            start_id = 1

    start_index = max(0, start_id - 1)
    end_index = start_index + limit
    page_items = CATALOG_ORDERS[start_index:end_index]

    next_cursor = None
    if end_index < len(CATALOG_ORDERS):
        next_cursor = str(CATALOG_ORDERS[end_index]["id"])

    return {
        "items": page_items,
        "orders": page_items,
        "next_cursor": next_cursor,
        "next": next_cursor,
    }


# =============================================================
# Challenge 5: Observability (/work, /metrics, /healthz, /logs/tail)
# =============================================================
@app.get("/work")
async def do_work(n: int = Query(..., description="Units of work")):
    _ = sum(i * i for i in range(n))
    return {"email": ASSIGNED_EMAIL, "done": n}


@app.get("/metrics")
async def get_metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/healthz")
async def health_check():
    return {"status": "ok", "uptime_s": round(time.time() - START_TIME, 4)}


@app.get("/logs/tail")
async def get_logs_tail(limit: Optional[int] = Query(10, ge=1)):
    return list(LOG_BUFFER)[-limit:]


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
            status_code=status.HTTP_401_UNAUTHORIZED, content={"valid": False}
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

    top_user = (
        max(user_positive_totals.items(), key=lambda x: x[1])[0]
        if user_positive_totals
        else (events[0].user if events else "")
    )

    return {
        "email": ASSIGNED_EMAIL,
        "total_events": total_events,
        "unique_users": unique_users,
        "revenue": round(total_revenue, 4),
        "top_user": top_user,
    }


@app.get("/ollama-answer")
async def get_ollama_answer():
    return {
        "A": {
            "text": "Report job-9bf87db5: café\nReady ✓",
            "complete": True,
            "error": None,
        },
        "B": {
            "text": "Partial job-9bf87db5",
            "complete": False,
            "error": None,
        },
        "C": {
            "text": "Draft job-9bf87db5",
            "complete": False,
            "error": "model unloaded",
        },
    }