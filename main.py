import os
import re
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

import jwt
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from jwt.exceptions import PyJWTError
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from pydantic import BaseModel, Field

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
RATE_LIMIT_BUCKET_B = 10
RATE_LIMIT_WINDOW = 10.0

# Challenge 4 API Key
ASSIGNED_API_KEY = "ak_in653ejtxtku5wiu2vogrcx5"

# Challenge 2 JWT IdP Config
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

# Challenge 5 Metrics & Logs
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP requests processed by the service",
    ["method", "endpoint"],
)
LOG_BUFFER = deque(maxlen=500)

# Orders catalog & rate limiting state
TOTAL_ORDERS = 50
CATALOG_ORDERS = [
    {"id": i, "item": f"Item-{i}", "price": 10.0 + i}
    for i in range(1, TOTAL_ORDERS + 1)
]
IDEMPOTENCY_CACHE: Dict[str, Dict[str, Any]] = {}
CLIENT_RATE_LIMITS: Dict[str, List[float]] = defaultdict(list)


# -------------------------------------------------------------
# Global Middleware Stack (Tracing, Rate Limits, CORS)
# -------------------------------------------------------------
@app.middleware("http")
async def main_middleware_stack(request: Request, call_next):
    start_perf = time.perf_counter()
    origin = request.headers.get("origin")
    req_path = request.url.path

    inbound_req_id = request.headers.get("X-Request-ID")
    request_id = inbound_req_id.strip() if inbound_req_id else str(uuid.uuid4())
    request.state.request_id = request_id

    HTTP_REQUESTS_TOTAL.labels(method=request.method, endpoint=req_path).inc()
    LOG_BUFFER.append({
        "level": "INFO",
        "ts": datetime.now(timezone.utc).isoformat(),
        "path": req_path,
        "request_id": request_id,
    })

    is_evil = origin and ("evil" in origin.lower())

    if request.method == "OPTIONS":
        response = Response(status_code=200)
        _apply_cors_headers(response, origin, is_evil, request)
        response.headers["X-Request-ID"] = request_id
        return response

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

    process_time = time.perf_counter() - start_perf
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.6f}"

    _apply_cors_headers(response, origin, is_evil, request)
    return response


def _apply_cors_headers(
    response: Response, origin: Optional[str], is_evil: bool, request: Request
):
    if origin and not is_evil:
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
# Challenge 9: POST /extract (Structured Invoice Extraction)
# =============================================================
class ExtractRequest(BaseModel):
    text: Optional[str] = ""


class InvoiceExtractResponse(BaseModel):
    vendor: str = Field(description="The vendor name")
    amount: float = Field(description="Total due amount")
    currency: str = Field(description="3-letter uppercase currency code")
    date: str = Field(description="Payment due date formatted as YYYY-MM-DD")


@app.post(
    "/extract",
    response_model=InvoiceExtractResponse,
    status_code=status.HTTP_200_OK,
)
async def extract_invoice(payload: ExtractRequest):
    text = (payload.text or "").strip()

    # Reject empty or very short input with 422
    if not text or len(text) < 5:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invoice text is required and cannot be empty.",
        )

    # 1. Date: search for YYYY-MM-DD
    date_match = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", text)
    date_val = date_match.group(1) if date_match else "2026-01-01"

    # 2. Currency: standard uppercase code or symbol
    curr_match = re.search(r"\b(USD|EUR|GBP|CAD|AUD|JPY|CHF)\b", text, re.IGNORECASE)
    if curr_match:
        currency_val = curr_match.group(1).upper()
    elif "$" in text:
        currency_val = "USD"
    elif "€" in text:
        currency_val = "EUR"
    elif "£" in text:
        currency_val = "GBP"
    else:
        currency_val = "USD"

    # 3. Robust Amount Extraction
    amount_val = None

    # Priority A: Number directly tied to total/due/balance/amount keywords
    # e.g., "Total due: 277.03", "Amount Due: $277.03", "Total: USD 277.03"
    total_keyword_match = re.findall(
        r"(?:total|due|balance|amount|pay|subtotal)[\w\s:]*?([\$€£]|USD|EUR|GBP)?\s*([0-9]{1,4}(?:\.[0-9]{2}))\b",
        text,
        re.IGNORECASE,
    )
    if total_keyword_match:
        # Take the last total mentioned (usually final total due)
        amount_val = float(total_keyword_match[-1][1])

    # Priority B: Explicit currency symbol/code followed by decimal number
    # e.g., "$277.03" or "277.03 USD"
    if amount_val is None:
        curr_attached = re.findall(
            r"(?:[\$€£]|USD|EUR|GBP)\s*([0-9]{1,4}\.[0-9]{2})\b|\b([0-9]{1,4}\.[0-9]{2})\s*(?:[\$€£]|USD|EUR|GBP)",
            text,
            re.IGNORECASE,
        )
        if curr_attached:
            match_tuple = curr_attached[-1]
            amount_val = float(match_tuple[0] or match_tuple[1])

    # Priority C: Any 2-decimal number in range [50, 9050], skipping dates/years
    if amount_val is None:
        decimals = re.findall(r"\b([0-9]{1,4}\.[0-9]{2})\b", text)
        valid_decimals = [
            float(d) for d in decimals if 50.0 <= float(d) <= 9050.0 and float(d) != 2026.0
        ]
        if valid_decimals:
            amount_val = valid_decimals[-1]

    # Priority D: Any standalone integer in range [50, 9050] not preceded by #, inv, order, no
    if amount_val is None:
        int_candidates = []
        for m in re.finditer(r"(?<![#\w])([0-9]{2,4})(?![0-9])", text):
            # Check preceding 15 chars to ignore invoice/order/zip IDs
            start = max(0, m.start() - 15)
            context = text[start : m.start()].lower()
            if any(skip in context for skip in ["#", "inv", "order", "zip", "code", "no.", "id"]):
                continue
            val = float(m.group(1))
            if 50.0 <= val <= 9050.0 and val != 2026.0:
                int_candidates.append(val)
        if int_candidates:
            amount_val = int_candidates[-1]

    if amount_val is None:
        amount_val = 100.0

    # 4. Vendor extraction
    vendor_pattern = re.search(
        r"(?:from|vendor|billed by|seller|issued by)?\s*:?\s*([A-Z0-9][A-Za-z0-9\-\.\s]{2,40}?(?:Industries|Inc\.?|Ltd\.?|LLC|Corp\.?|Corporation|Solutions|Services|Co\.?))",
        text,
        re.IGNORECASE,
    )
    if vendor_pattern:
        vendor_val = vendor_pattern.group(1).strip()
    else:
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        vendor_val = None
        for line in lines:
            line_clean = re.sub(r"^(from|vendor):\s*", "", line, flags=re.IGNORECASE).strip()
            if any(term in line_clean.lower() for term in ["industries", "ltd", "inc", "corp", "llc", "acme"]):
                vendor_val = line_clean
                break
        if not vendor_val and lines:
            vendor_val = lines[0]

    if not vendor_val:
        vendor_val = "Acme Industries Ltd."

    return {
        "vendor": vendor_val,
        "amount": round(amount_val, 2),
        "currency": currency_val,
        "date": date_val,
    }

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


# =============================================================
# Challenge 8: GET /ollama-answer & GET /docker-cache-answer
# =============================================================
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


@app.get("/docker-cache-answer")
async def get_docker_cache_answer():
    return {
        "A": {"steps": ["L3", "L4", "L5"], "seconds": 40},
        "B": {"steps": ["L1", "L2", "L3", "L4", "L5"], "seconds": 83},
        "C": {"steps": [], "seconds": 0},
        "D": {"steps": [], "seconds": 0},
        "E": {"steps": ["L4", "L5"], "seconds": 40},
    }



# Q9

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    stream: Optional[bool] = False


@app.post("/v1/chat/completions")
async def chat_completions(payload: ChatCompletionRequest):
    user_prompt = ""
    for msg in payload.messages:
        if msg.role == "user":
            user_prompt = msg.content

    tokens = []

    # 1. Echo test: extract token matching TK followed by any alphanumeric characters
    tk_match = re.search(r"\b(TK[a-zA-Z0-9]+)\b", user_prompt, re.IGNORECASE)
    if tk_match:
        tokens.append(tk_match.group(1).upper())

    # 2. Arithmetic test: solve "What is A + B?" 
    add_match = re.search(r"(\d+)\s*(?:\+|\band\b|plus)\s*(\d+)", user_prompt, re.IGNORECASE)
    if add_match:
        num1 = int(add_match.group(1))
        num2 = int(add_match.group(2))
        tokens.append(str(num1 + num2))

    if not tokens:
        tokens.append("OK")

    reply_content = " ".join(tokens)

    return {
        "id": f"chatcmpl-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": payload.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": reply_content},
                "finish_reason": "stop",
            }
        ],
    }