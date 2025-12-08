"""
API Router
==========

ONLY 3 endpoints:
1. POST /sign/order - Sign Polymarket order
2. POST /sign/allowance - Sign ERC20 allowance
3. POST /sign/transfer - Sign USDC transfer (platform fees)

⚠️  DO NOT ADD MORE ENDPOINTS WITHOUT SECURITY REVIEW
"""
from fastapi import APIRouter, HTTPException, Request
from dishka.integrations.fastapi import inject
from dishka import FromComponent
from typing import Annotated
from datetime import datetime

from api.validators import SignOrderRequest, SignAllowanceRequest, SignTransferRequest, SignatureResponse
from signing.usecases import SignOrderUseCase, SignAllowanceUseCase, SignTransferUseCase


router = APIRouter()


def get_client_ip(request: Request) -> str:
    """Extract client IP from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host if request.client else "unknown"


def get_service_name(request: Request) -> str:
    """Extract service name from headers"""
    return request.headers.get("X-Service-Name", "unknown")


@router.post("/sign/order", response_model=SignatureResponse)
@inject
async def sign_order(
    request: SignOrderRequest,
    http_request: Request,
    usecase: Annotated[SignOrderUseCase, FromComponent("signing")]
):
    """
    Sign Polymarket order
    
    Security:
    - Validates request against whitelist
    - Validates activity via copytrading DB
    - Checks rate limits
    - Logs to audit trail
    - Returns signature from Privy
    
    Args:
        request: Order signing request (validated)
        
    Returns:
        SignatureResponse with signature or error
    """
    ip_address = get_client_ip(http_request)
    service_name = get_service_name(http_request)
    
    success, result, audit_id = await usecase.execute(
        request=request,
        ip_address=ip_address,
        service_name=service_name
    )
    
    if not success:
        # Determine error code
        if "validation failed" in result.lower():
            status_code = 403
        elif "rate limit" in result.lower() or "volume limit" in result.lower():
            status_code = 429
        else:
            status_code = 500
        
        raise HTTPException(
            status_code=status_code,
            detail=result
        )
    
    return SignatureResponse(
        success=True,
        signature=result,
        audit_id=audit_id,
        timestamp=datetime.utcnow().isoformat()
    )


@router.post("/sign/allowance", response_model=SignatureResponse)
@inject
async def sign_allowance(
    request: SignAllowanceRequest,
    http_request: Request,
    usecase: Annotated[SignAllowanceUseCase, FromComponent("signing")]
):
    """
    Sign ERC20 allowance (permit)
    
    Security:
    - Validates request against whitelist
    - Checks rate limits
    - Logs to audit trail
    - Returns signature from Privy
    
    Args:
        request: Allowance signing request (validated)
        
    Returns:
        SignatureResponse with signature or error
    """
    ip_address = get_client_ip(http_request)
    service_name = get_service_name(http_request)
    
    success, result, audit_id = await usecase.execute(
        request=request,
        ip_address=ip_address,
        service_name=service_name
    )
    
    if not success:
        # Determine error code
        if "rate limit" in result.lower():
            status_code = 429
        else:
            status_code = 500
        
        raise HTTPException(
            status_code=status_code,
            detail=result
        )
    
    return SignatureResponse(
        success=True,
        signature=result,
        audit_id=audit_id,
        timestamp=datetime.utcnow().isoformat()
    )


@router.post("/sign/transfer", response_model=SignatureResponse)
@inject
async def sign_transfer(
    request: SignTransferRequest,
    http_request: Request,
    usecase: Annotated[SignTransferUseCase, FromComponent("signing")]
):
    """
    Sign USDC transfer (platform fees ONLY)
    
    Security:
    - Validates request against whitelist
    - Validates commission via copytrading DB
    - Checks rate limits
    - ONLY allows transfers to team wallets
    - Logs to audit trail
    - Returns signature from Privy
    
    Args:
        request: Transfer signing request (validated)
        
    Returns:
        SignatureResponse with signature or error
    """
    ip_address = get_client_ip(http_request)
    service_name = get_service_name(http_request)
    
    success, result, audit_id = await usecase.execute(
        request=request,
        ip_address=ip_address,
        service_name=service_name
    )
    
    if not success:
        # Determine error code
        if "validation failed" in result.lower():
            status_code = 403
        elif "rate limit" in result.lower() or "volume limit" in result.lower():
            status_code = 429
        else:
            status_code = 500
        
        raise HTTPException(
            status_code=status_code,
            detail=result
        )
    
    return SignatureResponse(
        success=True,
        signature=result,
        audit_id=audit_id,
        timestamp=datetime.utcnow().isoformat()
    )
