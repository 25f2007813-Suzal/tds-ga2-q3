import time
import uuid
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt
from jwt.exceptions import PyJWTError

app = FastAPI()

# -------------------------------------------------------------
# Configuration from Challenges
# -------------------------------------------------------------
# Challenge 1 (Stats):
STATS_ALLOWED_ORIGIN = "https://dash-xr67rb.example.com"
YOUR_EMAIL = "25f2007813@ds.study.iitm.ac.in"  # <-- Your logged-in email

# Challenge 2 (JWT IdP):
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

# -------------------------------------------------------------
# CORS Middleware (Restricted to Challenge 1 origin)
# -------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[STATS_ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Process-Time"],
)


# -------------------------------------------------------------
# Process Time & Request ID Middleware
# -------------------------------------------------------------
@app.middleware("http")
async def add_custom_headers(request: Request, call_next):
    start_time = time.perf_counter()
    response: Response = await call_next(request)
    process_time = time.perf_counter() - start_time

    response.headers["X-Request-ID"] = str(uuid.uuid4())
    response.headers["X-Process-Time"] = f"{process_time:.6f}"
    return response


# -------------------------------------------------------------
# Challenge 1: GET /stats
# -------------------------------------------------------------
@app.get("/stats")
async def get_stats(values: Optional[str] = Query(None)):
    if not values:
        raise HTTPException(
            status_code=400,
            detail="The 'values' query parameter is required."
        )

    try:
        nums = [int(v.strip()) for v in values.split(",") if v.strip()]
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="All values must be valid integers."
        )

    if not nums:
        raise HTTPException(
            status_code=400,
            detail="Empty list of numbers provided."
        )

    n = len(nums)
    s = sum(nums)
    m = min(nums)
    x = max(nums)
    mean_val = round(s / n, 4)

    return {
        "email": YOUR_EMAIL,
        "count": n,
        "sum": s,
        "min": m,
        "max": x,
        "mean": mean_val,
    }


# -------------------------------------------------------------
# Challenge 2: POST /verify
# -------------------------------------------------------------
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