"""
Security Middleware
===================

Service token authentication and IP whitelist for internal requests.
"""
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from typing import List

from core.environment.config import settings
from core.logger import logger


def get_client_ip(request: Request) -> str:
    """Extract real client IP from request (handles proxies)"""
    # Check X-Forwarded-For header (from proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take first IP (original client)
        return forwarded.split(",")[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fallback to direct connection IP
    return request.client.host if request.client else "unknown"


def check_ip_whitelist(client_ip: str, allowed_ips: List[str]) -> bool:
    """
    Check if client IP is in whitelist
    
    Args:
        client_ip: Client IP address
        allowed_ips: List of allowed IPs (empty = allow all)
        
    Returns:
        True if allowed, False otherwise
    """
    # Empty whitelist = allow all
    if not allowed_ips:
        return True
    
    # Check if IP is in whitelist
    return client_ip in allowed_ips


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Middleware for service authentication and IP whitelisting
    
    Requires:
    - X-Service-Token header for all API requests
    - IP address in whitelist (per endpoint)
    """
    
    async def dispatch(self, request: Request, call_next):
        # Skip auth for health check and root
        if request.url.path in ["/health", "/"]:
            return await call_next(request)
        
        # Check service token for API endpoints
        if request.url.path.startswith("/api/"):
            # 1. Check service token
            token = request.headers.get("X-Service-Token")
            
            if not token:
                logger.warning(f"⚠️  Missing service token from {request.client.host}")
                raise HTTPException(
                    status_code=401,
                    detail="Service token required"
                )
            
            if token != settings.service_token:
                logger.error(f"🚨 Invalid service token from {request.client.host}")
                raise HTTPException(
                    status_code=403,
                    detail="Invalid service token"
                )
            
            # 2. Check IP whitelist (per endpoint)
            client_ip = get_client_ip(request)
            
            # Determine endpoint type
            endpoint_type = None
            if "/sign/order" in request.url.path:
                endpoint_type = "order"
            elif "/sign/allowance" in request.url.path:
                endpoint_type = "allowance"
            elif "/sign/transfer" in request.url.path:
                endpoint_type = "transfer"
            
            if endpoint_type:
                allowed_ips = settings.get_allowed_ips_list(endpoint_type)
                
                if not check_ip_whitelist(client_ip, allowed_ips):
                    logger.error(
                        f"🚨 IP NOT WHITELISTED!\n"
                        f"Endpoint: {endpoint_type}\n"
                        f"Client IP: {client_ip}\n"
                        f"Allowed IPs: {allowed_ips}"
                    )
                    raise HTTPException(
                        status_code=403,
                        detail=f"IP address {client_ip} not whitelisted for {endpoint_type} endpoint"
                    )
                
                logger.info(f"✅ IP check passed: {client_ip} for {endpoint_type}")
        
        response = await call_next(request)
        return response

