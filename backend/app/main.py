from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import ioc

app = FastAPI(title="FraudLens API v2", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ioc.router)


@app.get("/health")
def health():
    return {"status": "ok"}
