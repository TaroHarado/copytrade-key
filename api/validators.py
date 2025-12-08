"""
Request Validators with STRICT whitelisting
============================================

⚠️  SECURITY CRITICAL
Only whitelisted contracts, tokens, and operations are allowed.
"""
from pydantic import BaseModel, Field, field_validator
from typing import Literal
from core.environment.config import settings
from core.logger import logger


class SignOrderRequest(BaseModel):
    """
    Request to sign Polymarket order
    
    STRICT validation:
    - Only Polymarket CTF Exchange contracts
    - Only Polygon (chain_id=137)
    - Amount limits enforced
    """
    
    # User identification
    user_id: int = Field(gt=0, description="User ID from main database")
    privy_wallet_id: str = Field(min_length=10, description="Privy wallet ID")
    wallet_address: str = Field(min_length=42, max_length=42, description="Wallet address (0x...)")
    
    # Order details
    token_id: str = Field(description="Polymarket token ID")
    side: Literal[0, 1] = Field(description="0=BUY, 1=SELL")
    maker_amount: int = Field(gt=0, description="Maker amount in wei")
    taker_amount: int = Field(gt=0, description="Taker amount in wei")
    
    # Activity validation (защита от внутренних атак) - ОБЯЗАТЕЛЬНО!
    target_activity_id: int = Field(gt=0, description="Target activity ID для валидации (REQUIRED)")
    
    # Optional fields
    fee_rate_bps: int = Field(default=0, ge=0, le=1000, description="Fee rate in basis points")
    nonce: int | None = Field(default=None, description="Nonce (auto-generated if None)")
    expiration: int | None = Field(default=None, description="Expiration timestamp (auto-generated if None)")
    
    # Security (MUST match whitelist)
    verifying_contract: str = Field(description="Polymarket CTF Exchange address")
    chain_id: Literal[137] = Field(default=137, description="ONLY Polygon mainnet")
    
    @field_validator('verifying_contract')
    @classmethod
    def validate_contract(cls, v: str) -> str:
        """
        ⚠️  WHITELIST: Only Polymarket contracts allowed
        """
        ALLOWED_CONTRACTS = [
            settings.polymarket_ctf_exchange.lower(),
            settings.polymarket_neg_risk_ctf_exchange.lower(),
        ]
        
        if v.lower() not in ALLOWED_CONTRACTS:
            logger.error(f"🚨 BLOCKED: Unauthorized contract {v}")
            raise ValueError(
                f"Contract {v} not whitelisted. "
                f"Only Polymarket CTF Exchange contracts allowed."
            )
        
        return v.lower()
    
    @field_validator('wallet_address')
    @classmethod
    def validate_address(cls, v: str) -> str:
        """Validate Ethereum address format"""
        if not v.startswith('0x') or len(v) != 42:
            raise ValueError(f"Invalid Ethereum address: {v}")
        return v.lower()
    
    def get_usdc_amount(self) -> float:
        """Calculate USDC amount for audit logging"""
        # For BUY: maker pays USDC
        # For SELL: taker receives USDC
        usdc_wei = self.maker_amount if self.side == 0 else self.taker_amount
        return usdc_wei / 10**6


class SignAllowanceRequest(BaseModel):
    """
    Request to sign ERC20 allowance (approve)
    
    STRICT validation:
    - Only USDC/USDC.e tokens
    - Only Polymarket contracts as spenders
    - Amount limits enforced
    """
    
    # User identification
    user_id: int = Field(gt=0, description="User ID from main database")
    privy_wallet_id: str = Field(min_length=10, description="Privy wallet ID")
    wallet_address: str = Field(min_length=42, max_length=42, description="Wallet address (0x...)")
    
    # Allowance details
    token_address: str = Field(description="Token address (USDC/USDC.e only)")
    spender_address: str = Field(description="Spender address (Polymarket contracts only)")
    amount: int = Field(gt=0, description="Allowance amount in wei")
    
    # Security
    chain_id: Literal[137] = Field(default=137, description="ONLY Polygon mainnet")
    
    @field_validator('token_address')
    @classmethod
    def validate_token(cls, v: str) -> str:
        """
        ⚠️  WHITELIST: Only USDC/USDC.e allowed
        """
        ALLOWED_TOKENS = [
            settings.usdc_address.lower(),
            settings.usdce_address.lower(),
        ]
        
        if v.lower() not in ALLOWED_TOKENS:
            logger.error(f"🚨 BLOCKED: Unauthorized token {v}")
            raise ValueError(
                f"Token {v} not whitelisted. "
                f"Only USDC/USDC.e allowed."
            )
        
        return v.lower()
    
    @field_validator('spender_address')
    @classmethod
    def validate_spender(cls, v: str) -> str:
        """
        ⚠️  WHITELIST: Only Polymarket contracts as spenders
        """
        ALLOWED_SPENDERS = [
            settings.polymarket_ctf_exchange.lower(),
            settings.polymarket_neg_risk_ctf_exchange.lower(),
        ]
        
        if v.lower() not in ALLOWED_SPENDERS:
            logger.error(f"🚨 BLOCKED: Unauthorized spender {v}")
            raise ValueError(
                f"Spender {v} not whitelisted. "
                f"Only Polymarket contracts allowed."
            )
        
        return v.lower()
    

    @field_validator('wallet_address')
    @classmethod
    def validate_address(cls, v: str) -> str:
        """Validate Ethereum address format"""
        if not v.startswith('0x') or len(v) != 42:
            raise ValueError(f"Invalid Ethereum address: {v}")
        return v.lower()


class SignTransferRequest(BaseModel):
    """
    Request to sign USDC transfer (platform fees)
    
    STRICT validation:
    - Only USDC/USDC.e tokens
    - Only team wallets as recipients
    - Amount validated via user_activity (~1% commission)
    """
    
    # User identification
    user_id: int = Field(gt=0, description="User ID from main database")
    privy_wallet_id: str = Field(min_length=10, description="Privy wallet ID")
    wallet_address: str = Field(min_length=42, max_length=42, description="Wallet address (0x...)")
    
    # Transfer details
    token_address: str = Field(description="Token address (USDC/USDC.e only)")
    recipient_address: str = Field(description="Recipient address (team wallets only)")
    amount: int = Field(gt=0, description="Transfer amount in wei")
    
    # Activity validation (защита от внутренних атак) - ОБЯЗАТЕЛЬНО!
    target_activity_id: int = Field(gt=0, description="Target activity ID для валидации (REQUIRED)")
    
    # Security
    chain_id: Literal[137] = Field(default=137, description="ONLY Polygon mainnet")
    
    @field_validator('token_address')
    @classmethod
    def validate_token(cls, v: str) -> str:
        """
        ⚠️  WHITELIST: Only USDC/USDC.e allowed
        """
        ALLOWED_TOKENS = [
            settings.usdc_address.lower(),
            settings.usdce_address.lower(),
        ]
        
        if v.lower() not in ALLOWED_TOKENS:
            logger.error(f"🚨 BLOCKED: Unauthorized token {v}")
            raise ValueError(
                f"Token {v} not whitelisted. "
                f"Only USDC/USDC.e allowed."
            )
        
        return v.lower()
    
    @field_validator('recipient_address')
    @classmethod
    def validate_recipient(cls, v: str) -> str:
        """
        ⚠️  CRITICAL: Only team wallets as recipients
        
        This prevents malicious transfers to attacker wallets!
        """
        team_wallets = settings.get_team_wallets_list()
        
        if not team_wallets:
            logger.error("🚨 CRITICAL: team_wallets not configured in settings!")
            raise ValueError(
                "Team wallets not configured. Cannot process transfers."
            )
        
        if v.lower() not in team_wallets:
            logger.error(
                f"🚨 BLOCKED: Unauthorized recipient {v}\n"
                f"Allowed team wallets: {team_wallets}"
            )
            raise ValueError(
                f"Recipient {v} not in team wallets. "
                f"Only platform team wallets can receive transfers."
            )
        
        return v.lower()
    

    @field_validator('wallet_address')
    @classmethod
    def validate_address(cls, v: str) -> str:
        """Validate Ethereum address format"""
        if not v.startswith('0x') or len(v) != 42:
            raise ValueError(f"Invalid Ethereum address: {v}")
        return v.lower()
    
    def get_usdc_amount(self) -> float:
        """Calculate USDC amount for audit logging"""
        return self.amount / 10**6


class SignatureResponse(BaseModel):
    """Response with signature"""
    success: bool
    signature: str | None = None
    error: str | None = None
    
    # Audit info
    audit_id: int
    timestamp: str

