from collections import defaultdict
import time
from typing import List, Optional
import uuid

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
import jwt
from jwt.exceptions import PyJWTError
from pydantic import BaseModel


app = FastAPI()

ASSIGNED_ORIGIN = "https://dash-xr67rb.example.com"
CHALLENGE_1_EMAIL = "25f2007813@ds.study.iitm.ac.in"  # <-- Your logged-in email

# -------------------------------------------------------------
# Combined Custom Middleware (Preflight, Headers & Strict CORS)
# -------------------------------------------------------------
@app.middleware("http")
async def combined_middleware(request: Request, call_next):
    start_time = time.perf_counter()
    origin = request.headers.get("origin")

    # Determine if origin is forbidden / evil
    is_evil = False
    if origin:
        lowered = origin.lower()
        if "evil" in lowered:
            is_evil = True

    # 1. Handle preflight OPTIONS immediately
    if request.method == "OPTIONS":
        response = Response(status_code=200)
    else:
        response = await call_next(request)

    # 2. Attach required X- headers
    process_time = time.perf_counter() - start_time
    response.headers["X-Request-ID"] = str(uuid.uuid4())
    response.headers["X-Process-Time"] = f"{process_time:.6f}"

    # 3. CORS rules:
    # - If evil: DO NOT add Access-Control-Allow-Origin
    # - If valid origin (assigned dash origin OR current browser origin): permit it
    if origin and not is_evil:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = (
            request.headers.get("access-control-request-headers") or "*"
        )
        response.headers["Access-Control-Expose-Headers"] = "X-Request-ID, X-Process-Time"

    return response


# =============================================================
# Challenge 1: GET /stats
# =============================================================
@app.get("/stats")
async def get_stats(values: Optional[str] = Query(None)):
    if not values:
        raise HTTPException(status_code=400, detail="The 'values' query parameter is required.")
    try:
        nums = [int(v.strip()) for v in values.split(",") if v.strip()]
    except ValueError:
        raise HTTPException(status_code=400, detail="All values must be valid integers.")
    if not nums:
        raise HTTPException(status_code=400, detail="Empty list of numbers provided.")

    n = len(nums)
    s = sum(nums)
    return {
        "email": CHALLENGE_1_EMAIL,
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
CONFIG_YAML = {
    "port": 8797,
    "log_level": "info",
}
CONFIG_DOTENV = {
    "debug": False,
}
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
    # Precedence: defaults -> yaml -> dotenv -> os_env
    config = dict(CONFIG_DEFAULTS)
    config.update(CONFIG_YAML)
    config.update(CONFIG_DOTENV)
    config.update(CONFIG_OS_ENV)

    # CLI Overrides from ?set=key=value
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

# Question 7
ASSIGNED_API_KEY = "ak_in653ejtxtku5wiu2vogrcx5"
CHALLENGE_EMAIL = "25f2007813@ds.study.iitm.ac.in"  # <-- Your logged-in platform email


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
    # 1. Require X-API-Key header, return 401 if missing or wrong
    if not x_api_key or x_api_key != ASSIGNED_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )

    events = payload.events
    total_events = len(events)
    unique_users = len({e.user for e in events})

    # 2. Revenue: sum of positive amounts only (amount > 0)
    # 3. Top user: user with the highest positive-amount total
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
        "email": CHALLENGE_EMAIL,
        "total_events": total_events,
        "unique_users": unique_users,
        "revenue": round(total_revenue, 4),
        "top_user": top_user,
    }
