"""
Copytrading Repositories (READ-ONLY + replay protection updates)

⚠️ Используется ТОЛЬКО для валидации activities
⚠️ UPDATE только для is_order_signed и is_commission_signed
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from copytrading.models import TargetActivity, MonitoringSession, UserActivity
from typing import Tuple


class CopytradingValidationRepository:
    """Repository for validating activities from copytrading DB"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def get_target_activity(
        self,
        target_activity_id: int
    ) -> TargetActivity | None:
        """Get target activity by ID"""
        result = await self.session.execute(
            select(TargetActivity).where(TargetActivity.id == target_activity_id)
        )
        return result.scalar_one_or_none()
    
    async def get_monitoring_session(
        self,
        user_id: int,
        target_address: str
    ) -> MonitoringSession | None:
        """Get active monitoring session for user and target"""
        result = await self.session.execute(
            select(MonitoringSession).where(
                MonitoringSession.user_id == user_id,
                MonitoringSession.target_address == target_address.lower(),
                MonitoringSession.is_active == True
            )
        )
        return result.scalar_one_or_none()
    
    async def get_user_activity(
        self,
        user_id: int,
        target_activity_id: int
    ) -> UserActivity | None:
        """Get user activity by user_id and target_activity_id"""
        result = await self.session.execute(
            select(UserActivity).where(
                UserActivity.user_id == user_id,
                UserActivity.target_activity_id == target_activity_id
            )
        )
        return result.scalar_one_or_none()
    
    async def mark_order_signed(
        self,
        user_id: int,
        target_activity_id: int
    ) -> bool:
        """
        Mark order as signed (replay protection)
        
        Returns:
            True if updated successfully
        """
        result = await self.session.execute(
            update(UserActivity)
            .where(
                UserActivity.user_id == user_id,
                UserActivity.target_activity_id == target_activity_id
            )
            .values(is_order_signed=True)
        )
        await self.session.commit()
        return result.rowcount > 0
    
    async def mark_commission_signed(
        self,
        user_id: int,
        target_activity_id: int
    ) -> bool:
        """
        Mark commission as signed (replay protection)
        
        Returns:
            True if updated successfully
        """
        result = await self.session.execute(
            update(UserActivity)
            .where(
                UserActivity.user_id == user_id,
                UserActivity.target_activity_id == target_activity_id
            )
            .values(is_commission_signed=True)
        )
        await self.session.commit()
        return result.rowcount > 0
    
    async def validate_order_activity(
        self,
        user_id: int,
        target_activity_id: int,
        wallet_address: str,
        token_id: str,
        side: int  # 0=BUY, 1=SELL
    ) -> Tuple[bool, str]:
        """
        Validate order activity
        
        Returns:
            (is_valid, error_message)
        """
        # Get target activity
        target_activity = await self.get_target_activity(target_activity_id)
        if not target_activity:
            return False, f"Target activity {target_activity_id} not found"
        
        # Check token_id match
        if target_activity.token_id != token_id:
            return False, f"Token ID mismatch: expected {target_activity.token_id}, got {token_id}"
        
        # Check side match
        side_str = "BUY" if side == 0 else "SELL"
        if target_activity.side != side_str:
            return False, f"Side mismatch: expected {target_activity.side}, got {side_str}"
        
        # Check monitoring session exists
        monitoring_session = await self.get_monitoring_session(user_id, target_activity.wallet_address)
        if not monitoring_session:
            return False, f"No active monitoring session for user {user_id} and target {target_activity.wallet_address}"
        
        # Check wallet address match
        if monitoring_session.internal_wallet_address and monitoring_session.internal_wallet_address.lower() != wallet_address.lower():
            return False, f"Wallet address mismatch"
        
        # Check if order already signed
        user_activity = await self.get_user_activity(user_id, target_activity_id)
        if user_activity and user_activity.is_order_signed:
            return False, f"Order for target_activity_id {target_activity_id} already signed"
        
        return True, ""
    
    async def validate_transfer_activity(
        self,
        user_id: int,
        target_activity_id: int,
        wallet_address: str,
        token_address: str,
        amount: int  # amount in wei
    ) -> Tuple[bool, str]:
        """
        Validate transfer activity (commission)
        
        Returns:
            (is_valid, error_message)
        """
        # Get user activity
        user_activity = await self.get_user_activity(user_id, target_activity_id)
        if not user_activity:
            return False, f"User activity {target_activity_id} not found for user {user_id}"
        
        # Check if commission already signed
        if user_activity.is_commission_signed:
            return False, f"Commission for target_activity_id {target_activity_id} already signed"
        
        # Check if order was signed
        if not user_activity.is_order_signed:
            return False, f"Order must be signed before commission transfer"
        
        # Validate commission amount (~1% of trade)
        if user_activity.usdc_amount is None:
            return False, "Trade amount not available"
        
        expected_commission_usdc = user_activity.usdc_amount * 0.01  # 1%
        actual_commission_usdc = amount / 10**6  # wei to USDC
        
        # Allow ±5% tolerance
        tolerance = 0.05
        if not ((1 - tolerance) * expected_commission_usdc <= actual_commission_usdc <= (1 + tolerance) * expected_commission_usdc):
            return False, f"Commission amount {actual_commission_usdc:.2f} USDC does not match expected 1% of trade ({expected_commission_usdc:.2f} USDC)"
        
        return True, ""




