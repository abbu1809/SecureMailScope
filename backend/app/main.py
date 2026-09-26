"""
SecureMailScope — AI-Assisted Cryptographic Security Posture Assessment (SIH PS 26159)
FastAPI Backend Application Entrypoint.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import APP_NAME, APP_VERSION, APP_DESCRIPTION
from app.api.routes_captures import router as captures_router, initialize_demo_captures, CAPTURES_STORE
from app.api.routes_sessions import router as sessions_router
from app.api.routes_analytics import router as analytics_router
from app.api.routes_reports import router as reports_router
from app.api.routes_rules import router as rules_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure captures are initialized
    if not CAPTURES_STORE:
        initialize_demo_captures()
    yield

# Auto-initialize on module load
initialize_demo_captures()

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=APP_DESCRIPTION,
    lifespan=lifespan
)

# Enable CORS for local Vite development & production web SPA
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://SecureMailScope.techemist.dev",
        "https://securemailscope.techemist.dev",
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
        "*",
    ],
    allow_origin_regex=r"https://.*techemist\.dev|https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Feature Routers
app.include_router(captures_router)
app.include_router(sessions_router)
app.include_router(analytics_router)
app.include_router(reports_router)
app.include_router(rules_router)

@app.get("/")
@app.get("/health")
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "system": APP_NAME,
        "version": APP_VERSION,
        "mode": "offline-passive-assessment",
        "ps_number": "SIH-26159"
    }

if __name__ == "__main__":
    import os
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=True)
