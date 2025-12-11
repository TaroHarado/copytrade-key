"""
Use cases for signing operations
"""
from typing import Tuple
from datetime import datetime

from api.validators import SignOrderRequest, SignAllowanceRequest, SignTransferRequest
from signing.repositories import SignatureAuditRepository
from signing.services import PrivyClient
from copytrading.repositories import CopytradingValidationRepository
from core.security import SecurityManager
from core.logger import logger


class SignOrderUseCase:
    """
    Use case для подписи ордеров Polymarket
    
    Включает:
    - Валидацию activity через copytrading DB
    - Security проверки (rate limit, volume)
    - Подпись через Privy API
    - Audit logging
    - Replay protection
    """
    
    def __init__(
        self,
        audit_repository: SignatureAuditRepository,
        privy_client: PrivyClient,
        validation_repository: CopytradingValidationRepository,
        security_manager: SecurityManager
    ):
        self.audit_repository = audit_repository
        self.privy_client = privy_client
        self.validation_repository = validation_repository
        self.security_manager = security_manager
    
    async def execute(
        self,
        request: SignOrderRequest,
        ip_address: str,
        service_name: str
    ) -> Tuple[bool, str | None, int | None]:
        """
        Execute order signing
        
        Returns:
            (success, signature_or_error, audit_id)
        """
        logger.info(
            f"📥 Order signature request: "
            f"user={request.user_id}, "
            f"token={request.token_id[:16]}..., "
            f"side={'BUY' if request.side == 0 else 'SELL'}, "
            f"amount=${request.get_usdc_amount():,.2f}, "
            f"from={service_name}"
        )
        
        try:
            # 1. Activity validation (защита от внутренних атак)
            is_valid, error_msg = await self.validation_repository.validate_order_activity(
                user_id=request.user_id,
                target_activity_id=request.target_activity_id,
                wallet_address=request.wallet_address,
                token_id=request.token_id,
                side=request.side
            )
            
            if not is_valid:
                # Log failed attempt
                audit_log = await self.audit_repository.create_audit_log(
                    signature_type="order",
                    user_id=request.user_id,
                    wallet_address=request.wallet_address,
                    target_activity_id=request.target_activity_id,
                    success=False,
                    error=f"Activity validation failed: {error_msg}",
                    ip_address=ip_address,
                    service_name=service_name,
                    validation_failed=True,
                    token_id=request.token_id,
                    amount_usdc=request.get_usdc_amount()
                )
                
                logger.error(
                    f"🚨 SECURITY: Activity validation failed!\n"
                    f"User: {request.user_id}\n"
                    f"Activity: {request.target_activity_id}\n"
                    f"Token: {request.token_id}\n"
                    f"Error: {error_msg}\n"
                    f"IP: {ip_address}\n"
                    f"Service: {service_name}"
                )
                
                return False, f"Activity validation failed: {error_msg}", audit_log.id
            
            # 2. Security validation (rate limit, volume)
            amount_usdc = request.get_usdc_amount()
            
            if not await self.security_manager.validate_request(request.user_id, amount_usdc):
                # Log failed attempt
                audit_log = await self.audit_repository.create_audit_log(
                    signature_type="order",
                    user_id=request.user_id,
                    wallet_address=request.wallet_address,
                    target_activity_id=request.target_activity_id,
                    success=False,
                    error="Security validation failed (rate limit or volume limit)",
                    ip_address=ip_address,
                    service_name=service_name,
                    rate_limited=True,
                    volume_limited=True,
                    token_id=request.token_id,
                    amount_usdc=amount_usdc
                )
                
                return False, "Rate limit or volume limit exceeded", audit_log.id
            
            # 3. Build EIP-712 typed data
            typed_data = self.privy_client.build_order_typed_data(
                maker_address=request.wallet_address,
                token_id=request.token_id,
                maker_amount=request.maker_amount,
                taker_amount=request.taker_amount,
                side=request.side,
                verifying_contract=request.verifying_contract,
                fee_rate_bps=request.fee_rate_bps,
                nonce=request.nonce,
                expiration=request.expiration
            )
            
            # 4. Sign via Privy
            logger.info(f"📝 Signing order with privy_wallet_id={request.privy_wallet_id}")
            signature = await self.privy_client.sign_typed_data(
                privy_wallet_id=request.privy_wallet_id,
                typed_data=typed_data
            )
            
            # 5. Mark order as signed (replay protection)
            await self.validation_repository.mark_order_signed(
                user_id=request.user_id,
                target_activity_id=request.target_activity_id
            )
            
            # 6. Log successful signature
            audit_log = await self.audit_repository.create_audit_log(
                signature_type="order",
                user_id=request.user_id,
                wallet_address=request.wallet_address,
                target_activity_id=request.target_activity_id,
                signature=signature,
                success=True,
                is_order_signed=True,
                ip_address=ip_address,
                service_name=service_name,
                token_id=request.token_id,
                amount_usdc=amount_usdc
            )
            
            logger.info(
                f"✅ Order signed successfully: "
                f"user={request.user_id}, audit_id={audit_log.id}"
            )
            
            return True, signature, audit_log.id
        
        except Exception as e:
            logger.error(f"❌ Error signing order: {e}", exc_info=True)
            
            # Log failed attempt
            audit_log = await self.audit_repository.create_audit_log(
                signature_type="order",
                user_id=request.user_id,
                wallet_address=request.wallet_address,
                target_activity_id=request.target_activity_id,
                success=False,
                error=str(e),
                ip_address=ip_address,
                service_name=service_name,
                token_id=request.token_id,
                amount_usdc=request.get_usdc_amount()
            )
            
            return False, str(e), audit_log.id


class SignAllowanceUseCase:
    """
    Use case для подписи ERC20 allowances
    
    Включает:
    - Security проверки (rate limit)
    - Подпись через Privy API
    - Audit logging
    """
    
    def __init__(
        self,
        audit_repository: SignatureAuditRepository,
        privy_client: PrivyClient,
        security_manager: SecurityManager
    ):
        self.audit_repository = audit_repository
        self.privy_client = privy_client
        self.security_manager = security_manager
    
    async def execute(
        self,
        request: SignAllowanceRequest,
        ip_address: str,
        service_name: str
    ) -> Tuple[bool, str | None, int | None]:
        """
        Execute allowance signing
        
        Returns:
            (success, signature_or_error, audit_id)
        """
        logger.info(
            f"📥 Allowance signature request: "
            f"user={request.user_id}, "
            f"token={request.token_address[:10]}..., "
            f"spender={request.spender_address[:10]}..., "
            f"amount={request.amount / 10**6:,.2f} USDC, "
            f"from={service_name}"
        )
        
        try:
            # 1. Security validation (rate limit only)
            if not await self.security_manager.check_rate_limit(request.user_id):
                # Log failed attempt
                audit_log = await self.audit_repository.create_audit_log(
                    signature_type="allowance",
                    user_id=request.user_id,
                    wallet_address=request.wallet_address,
                    success=False,
                    error="Rate limit exceeded",
                    ip_address=ip_address,
                    service_name=service_name,
                    rate_limited=True,
                    token_address=request.token_address,
                    amount_usdc=request.amount / 10**6
                )
                
                return False, "Rate limit exceeded", audit_log.id
            
            # 2. Build EIP-712 typed data
            typed_data = self.privy_client.build_allowance_typed_data(
                owner_address=request.wallet_address,
                spender_address=request.spender_address,
                token_address=request.token_address,
                amount=request.amount
            )
            
            # 3. Sign via Privy
            signature = await self.privy_client.sign_typed_data(
                privy_wallet_id=request.privy_wallet_id,
                typed_data=typed_data
            )
            
            # 4. Log successful signature
            audit_log = await self.audit_repository.create_audit_log(
                signature_type="allowance",
                user_id=request.user_id,
                wallet_address=request.wallet_address,
                signature=signature,
                success=True,
                ip_address=ip_address,
                service_name=service_name,
                token_address=request.token_address,
                amount_usdc=request.amount / 10**6
            )
            
            logger.info(
                f"✅ Allowance signed successfully: "
                f"user={request.user_id}, audit_id={audit_log.id}"
            )
            
            return True, signature, audit_log.id
        
        except Exception as e:
            logger.error(f"❌ Error signing allowance: {e}", exc_info=True)
            
            # Log failed attempt
            audit_log = await self.audit_repository.create_audit_log(
                signature_type="allowance",
                user_id=request.user_id,
                wallet_address=request.wallet_address,
                success=False,
                error=str(e),
                ip_address=ip_address,
                service_name=service_name,
                token_address=request.token_address,
                amount_usdc=request.amount / 10**6
            )
            
            return False, str(e), audit_log.id


class SignTransferUseCase:
    """
    Use case для подписи трансферов (комиссия платформе)
    
    Включает:
    - Валидацию комиссии через copytrading DB
    - Security проверки (rate limit, volume)
    - Подпись через Privy API
    - Audit logging
    - Replay protection
    """
    
    def __init__(
        self,
        audit_repository: SignatureAuditRepository,
        privy_client: PrivyClient,
        validation_repository: CopytradingValidationRepository,
        security_manager: SecurityManager
    ):
        self.audit_repository = audit_repository
        self.privy_client = privy_client
        self.validation_repository = validation_repository
        self.security_manager = security_manager
    
    async def execute(
        self,
        request: SignTransferRequest,
        ip_address: str,
        service_name: str
    ) -> Tuple[bool, str | None, int | None]:
        """
        Execute transfer signing
        
        Returns:
            (success, signature_or_error, audit_id)
        """
        amount_usdc = request.get_usdc_amount()
        
        logger.info(
            f"📥 Transfer signature request: "
            f"user={request.user_id}, "
            f"token={request.token_address[:10]}..., "
            f"recipient={request.recipient_address[:10]}..., "
            f"amount=${amount_usdc:,.2f}, "
            f"from={service_name}"
        )
        
        try:
            # 1. Commission validation (защита от несанкционированных трансферов)
            is_valid, error_msg = await self.validation_repository.validate_transfer_activity(
                user_id=request.user_id,
                target_activity_id=request.target_activity_id,
                wallet_address=request.wallet_address,
                token_address=request.token_address,
                amount=request.amount
            )
            
            if not is_valid:
                # Log failed attempt
                audit_log = await self.audit_repository.create_audit_log(
                    signature_type="transfer",
                    user_id=request.user_id,
                    wallet_address=request.wallet_address,
                    target_activity_id=request.target_activity_id,
                    success=False,
                    error=f"Commission validation failed: {error_msg}",
                    ip_address=ip_address,
                    service_name=service_name,
                    validation_failed=True,
                    token_address=request.token_address,
                    amount_usdc=amount_usdc
                )
                
                logger.error(
                    f"🚨 SECURITY: Commission validation failed!\n"
                    f"User: {request.user_id}\n"
                    f"Activity: {request.target_activity_id}\n"
                    f"Amount: ${amount_usdc:.2f}\n"
                    f"Recipient: {request.recipient_address}\n"
                    f"Error: {error_msg}\n"
                    f"IP: {ip_address}\n"
                    f"Service: {service_name}"
                )
                
                return False, f"Commission validation failed: {error_msg}", audit_log.id
            
            # 2. Security validation (rate limit, volume)
            if not await self.security_manager.validate_request(request.user_id, amount_usdc):
                # Log failed attempt
                audit_log = await self.audit_repository.create_audit_log(
                    signature_type="transfer",
                    user_id=request.user_id,
                    wallet_address=request.wallet_address,
                    target_activity_id=request.target_activity_id,
                    success=False,
                    error="Security validation failed (rate limit or volume limit)",
                    ip_address=ip_address,
                    service_name=service_name,
                    rate_limited=True,
                    volume_limited=True,
                    token_address=request.token_address,
                    amount_usdc=amount_usdc
                )
                
                return False, "Rate limit or volume limit exceeded", audit_log.id
            
            # 3. Build transaction data for transfer
            tx_data = self.privy_client.build_transfer_typed_data(
                from_address=request.wallet_address,
                to_address=request.recipient_address,
                token_address=request.token_address,
                amount=request.amount
            )
            
            # 4. Sign via Privy
            signature = await self.privy_client.sign_typed_data(
                privy_wallet_id=request.privy_wallet_id,
                typed_data=tx_data
            )
            
            # 5. Mark commission as signed (replay protection)
            await self.validation_repository.mark_commission_signed(
                user_id=request.user_id,
                target_activity_id=request.target_activity_id
            )
            
            # 6. Log successful signature
            audit_log = await self.audit_repository.create_audit_log(
                signature_type="transfer",
                user_id=request.user_id,
                wallet_address=request.wallet_address,
                target_activity_id=request.target_activity_id,
                signature=signature,
                success=True,
                is_commission_signed=True,
                ip_address=ip_address,
                service_name=service_name,
                token_address=request.token_address,
                amount_usdc=amount_usdc
            )
            
            logger.info(
                f"✅ Transfer signed successfully: "
                f"user={request.user_id}, audit_id={audit_log.id}"
            )
            
            return True, signature, audit_log.id
        
        except Exception as e:
            logger.error(f"❌ Error signing transfer: {e}", exc_info=True)
            
            # Log failed attempt
            audit_log = await self.audit_repository.create_audit_log(
                signature_type="transfer",
                user_id=request.user_id,
                wallet_address=request.wallet_address,
                target_activity_id=request.target_activity_id,
                success=False,
                error=str(e),
                ip_address=ip_address,
                service_name=service_name,
                token_address=request.token_address,
                amount_usdc=amount_usdc
            )
            
            return False, str(e), audit_log.id





