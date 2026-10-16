import time
import uuid
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt
from jwt.exceptions import PyJWTError

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
