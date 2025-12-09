"""
Entity models for Privy Signing Service
"""
from pydantic import BaseModel, ConfigDict
from datetime import datetime


class SignatureAuditLogEntity(BaseModel):
    """Entity for signature audit log"""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    signature_type: str
    user_id: int
    wallet_address: str
    target_activity_id: int | None
    signature: str | None
    success: bool
    error: str | None
    is_order_signed: bool
    is_commission_signed: bool
    ip_address: str | None
    service_name: str | None
    rate_limited: bool
    volume_limited: bool
    validation_failed: bool
    token_id: str | None
    token_address: str | None
    amount_usdc: float | None
    created_at: datetime






