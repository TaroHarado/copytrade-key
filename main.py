"""
Privy Signing Microservice
===========================

ISOLATED service for signing Polymarket orders, allowances, and transfers.
ONLY 3 endpoints, strict validation, full audit logging.

⚠️  SECURITY CRITICAL - DO NOT MODIFY WITHOUT REVIEW
"""
from fastapi import FastAPI
from dishka.integrations.fastapi import setup_dishka
from contextlib import asynccontextmanager
import uvicorn

from core.container import container
from core.environment.config import Settings
from core.logger import logger
from api.router import router
from middleware.security import SecurityMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    settings = Settings()
    
    logger.info("🔐 Starting Privy Signing Service...")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Privy App ID: {settings.privy_app_id}")
    logger.info(f"Platform commission: {settings.platform_commission_percentage}%")
    
    logger.info("✅ Privy Signing Service started successfully")
    
    yield
    
    # Shutdown
    logger.info("🔒 Shutting down Privy Signing Service...")
    await container.close()


app = FastAPI(
    title="Privy Signing Service",
    description="Isolated microservice for signing Polymarket orders and allowances",
    version="1.0.0",
    docs_url="/docs" if Settings().environment == "development" else None,
    redoc_url=None,
    lifespan=lifespan
)

# Setup DI container
setup_dishka(container, app)

# Security middleware (includes IP whitelisting)
app.add_middleware(SecurityMiddleware)

# Mount router
app.include_router(router, prefix="/api")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "privy-signing",
        "version": "1.0.0"
    }


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Privy Signing Service",
        "endpoints": [
            "POST /api/sign/order - Sign Polymarket order",
            "POST /api/sign/allowance - Sign ERC20 allowance",
            "POST /api/sign/transfer - Sign USDC transfer (platform fees)"
        ],
        "security": "All requests are validated, rate-limited, IP-whitelisted, and audited"
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8010,
        reload=Settings().environment == "development"
    )
