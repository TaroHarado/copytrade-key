"""
Repositories for Privy Signing Service
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.sql.elements import ColumnElement
from signing.models import SignatureAuditLog
from signing.entities import SignatureAuditLogEntity
from typing import List


class SignatureAuditRepository:
    """Repository for signature audit logs"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create_audit_log(
        self,
        signature_type: str,
        user_id: int,
        wallet_address: str,
        target_activity_id: int | None = None,
        signature: str | None = None,
        success: bool = True,
        error: str | None = None,
        is_order_signed: bool = False,
        is_commission_signed: bool = False,
        ip_address: str | None = None,
        service_name: str | None = None,
        rate_limited: bool = False,
        volume_limited: bool = False,
        validation_failed: bool = False,
        token_id: str | None = None,
        token_address: str | None = None,
        amount_usdc: float | None = None
    ) -> SignatureAuditLogEntity:
        """
        Create audit log entry
        
        Returns:
            Created entity
        """
        audit_log = SignatureAuditLog(
            signature_type=signature_type,
            user_id=user_id,
            wallet_address=wallet_address,
            target_activity_id=target_activity_id,
            signature=signature,
            success=success,
            error=error,
            is_order_signed=is_order_signed,
            is_commission_signed=is_commission_signed,
            ip_address=ip_address,
            service_name=service_name,
            rate_limited=rate_limited,
            volume_limited=volume_limited,
            validation_failed=validation_failed,
            token_id=token_id,
            token_address=token_address,
            amount_usdc=amount_usdc
        )
        
        self.session.add(audit_log)
        await self.session.flush()
        await self.session.refresh(audit_log)
        
        return SignatureAuditLogEntity.model_validate(audit_log)
    
    async def get_audit_logs(
        self,
        where_clause: ColumnElement[bool] | None = None,
        limit: int = 100
    ) -> List[SignatureAuditLogEntity]:
        """
        Get audit logs with optional filtering
        
        Args:
            where_clause: SQLAlchemy filter condition
            limit: Maximum number of records
            
        Returns:
            List of entities
        """
        query = select(SignatureAuditLog).order_by(SignatureAuditLog.created_at.desc()).limit(limit)
        
        if where_clause is not None:
            query = query.where(where_clause)
        
        result = await self.session.execute(query)
        logs = result.scalars().all()
        
        return [SignatureAuditLogEntity.model_validate(log) for log in logs]
    
    async def get_audit_log_by_id(self, audit_id: int) -> SignatureAuditLogEntity | None:
        """Get single audit log by ID"""
        result = await self.session.execute(
            select(SignatureAuditLog).where(SignatureAuditLog.id == audit_id)
        )
        
        if log := result.scalar_one_or_none():
            return SignatureAuditLogEntity.model_validate(log)
        
        return None




