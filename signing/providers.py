from dishka import Provider, Scope, provide, FromComponent
from typing import Annotated
from sqlalchemy.ext.asyncio import AsyncSession

from signing.repositories import SignatureAuditRepository
from signing.services import PrivyClient
from signing.usecases import SignOrderUseCase, SignAllowanceUseCase, SignTransferUseCase
from copytrading.repositories import CopytradingValidationRepository
from core.security import SecurityManager


class SigningProvider(Provider):
    scope = Scope.REQUEST
    component = "signing"
    
    @provide
    def get_audit_repository(
        self,
        session: Annotated[AsyncSession, FromComponent("database")]
    ) -> SignatureAuditRepository:
        """Get audit repository"""
        return SignatureAuditRepository(session)
    
    @provide(scope=Scope.APP)
    def get_privy_client(self) -> PrivyClient:
        """Get Privy client (singleton)"""
        return PrivyClient()
    
    @provide(scope=Scope.APP)
    def get_security_manager(self) -> SecurityManager:
        """Get security manager (singleton)"""
        return SecurityManager()
    
    @provide
    def get_validation_repository(
        self,
        session: Annotated[AsyncSession, FromComponent("copytrading_database")]
    ) -> CopytradingValidationRepository:
        """Get copytrading validation repository"""
        return CopytradingValidationRepository(session)
    
    @provide
    def get_sign_order_usecase(
        self,
        audit_repository: Annotated[SignatureAuditRepository, FromComponent("signing")],
        privy_client: Annotated[PrivyClient, FromComponent("signing")],
        validation_repository: Annotated[CopytradingValidationRepository, FromComponent("signing")],
        security_manager: Annotated[SecurityManager, FromComponent("signing")]
    ) -> SignOrderUseCase:
        """Get sign order use case"""
        return SignOrderUseCase(
            audit_repository=audit_repository,
            privy_client=privy_client,
            validation_repository=validation_repository,
            security_manager=security_manager
        )
    
    @provide
    def get_sign_allowance_usecase(
        self,
        audit_repository: Annotated[SignatureAuditRepository, FromComponent("signing")],
        privy_client: Annotated[PrivyClient, FromComponent("signing")],
        security_manager: Annotated[SecurityManager, FromComponent("signing")]
    ) -> SignAllowanceUseCase:
        """Get sign allowance use case"""
        return SignAllowanceUseCase(
            audit_repository=audit_repository,
            privy_client=privy_client,
            security_manager=security_manager
        )
    
    @provide
    def get_sign_transfer_usecase(
        self,
        audit_repository: Annotated[SignatureAuditRepository, FromComponent("signing")],
        privy_client: Annotated[PrivyClient, FromComponent("signing")],
        validation_repository: Annotated[CopytradingValidationRepository, FromComponent("signing")],
        security_manager: Annotated[SecurityManager, FromComponent("signing")]
    ) -> SignTransferUseCase:
        """Get sign transfer use case"""
        return SignTransferUseCase(
            audit_repository=audit_repository,
            privy_client=privy_client,
            validation_repository=validation_repository,
            security_manager=security_manager
        )
