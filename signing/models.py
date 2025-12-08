"""
SQLAlchemy Models for Privy Signing Service
"""
from sqlalchemy import Integer, String, DateTime, Boolean, Float, func, Index
from sqlalchemy.orm import Mapped, mapped_column
from core.database.config import Base
from datetime import datetime


class SignatureAuditLog(Base):
    """
    Audit log for all signature requests
    
    Tracks every signature request with full context for security auditing.
    """
    __tablename__ = "signature_audit_log"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    
    # Request info
    signature_type: Mapped[str] = mapped_column(
        String(20), 
        nullable=False, 
        index=True,
        comment="Type: order, allowance, transfer"
    )
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    wallet_address: Mapped[str] = mapped_column(String(42), nullable=False, index=True)
    
    # Target activity (для валидации)
    target_activity_id: Mapped[int | None] = mapped_column(
        Integer, 
        nullable=True, 
        index=True,
        comment="Target activity ID from copytrading DB"
    )
    
    # Signature result
    signature: Mapped[str | None] = mapped_column(String(255), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    
    # Security flags
    is_order_signed: Mapped[bool] = mapped_column(
        Boolean, 
        default=False,
        comment="Order signature completed (replay protection)"
    )
    is_commission_signed: Mapped[bool] = mapped_column(
        Boolean, 
        default=False,
        comment="Commission transfer signed (replay protection)"
    )
    
    # Security tracking
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    service_name: Mapped[str | None] = mapped_column(String(50), nullable=True)
    rate_limited: Mapped[bool] = mapped_column(Boolean, default=False)
    volume_limited: Mapped[bool] = mapped_column(Boolean, default=False)
    validation_failed: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Transaction details (JSON-like fields)
    token_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    token_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    amount_usdc: Mapped[float | None] = mapped_column(Float, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        server_default=func.now(),
        nullable=False
    )
    
    __table_args__ = (
        Index('idx_user_created', 'user_id', 'created_at'),
        Index('idx_wallet_created', 'wallet_address', 'created_at'),
        Index('idx_type_created', 'signature_type', 'created_at'),
        Index('idx_target_activity', 'target_activity_id'),
    )


