import time
import uuid
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# 1. Assigned CORS configuration
ASSIGNED_ORIGIN = "https://dash-xr67rb.example.com"
YOUR_EMAIL = "25f2007813@ds.study.iitm.ac.in"  # <-- REPLACE WITH YOUR LOGGED-IN EMAIL

# Notice: ONLY the assigned origin is allowed. Do NOT use ["*"].
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ASSIGNED_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Process-Time"],
)


# 2. Required Middleware: X-Request-ID and X-Process-Time
@app.middleware("http")
async def add_custom_headers(request: Request, call_next):
    start_time = time.perf_counter()
    response: Response = await call_next(request)
    process_time = time.perf_counter() - start_time

    # X-Request-ID: unique UUID per request
    response.headers["X-Request-ID"] = str(uuid.uuid4())
    # X-Process-Time: non-negative decimal string in seconds
    response.headers["X-Process-Time"] = f"{process_time:.6f}"

    return response


# 3. Endpoint: GET /stats?values=1,2,3,...
@app.get("/stats")
async def get_stats(values: Optional[str] = Query(None)):
    if not values:
        raise HTTPException(
            status_code=400,
            detail="The 'values' query parameter is required."
        )

    try:
        # Parse comma-separated integers
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
