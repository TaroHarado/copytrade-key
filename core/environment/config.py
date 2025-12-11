"""
Configuration for Privy Signing Service
"""
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """Settings for signing service"""
    
    # Environment
    environment: str = "production"
    
    # Privy credentials
    privy_app_id: str
    privy_app_secret: str
    
    # Privy authorization key (для delegated actions / session signers)
    # Это private key из private.pem (base64 encoded, без PEM обертки)
    privy_authorization_private_key: str
    
    # Database (audit logs)
    database_dialect: str = "postgresql"
    postgres_user: str
    postgres_password: str
    postgres_hostname: str
    postgres_port: int = 5432
    postgres_db: str
    
    # Copytrading database (READ-ONLY + replay protection)
    copytrading_database_url: str
    
    # Security
    service_token: str  # Token for internal service authentication
    
    # Activity validation (защита от внутренних атак)
    # Всегда используется прямой доступ к БД
    enable_activity_validation: bool = True  # Включить валидацию
    
    # Комиссия платформы (для валидации трансферов)
    platform_commission_percentage: float = 1.0  # 1% комиссия
    commission_tolerance: float = 0.1  # ±0.1% допустимое отклонение
    
    # IP Whitelists for each endpoint (comma-separated)
    # ONLY backend server IP should be allowed
    allowed_ips_order: str = "91.99.224.254"  # Backend server IP
    allowed_ips_allowance: str = "91.99.224.254"  # Backend server IP
    allowed_ips_transfer: str = "91.99.224.254"  # Backend server IP
    
    # Rate limiting (disabled for production with thousands of users)
    max_signatures_per_minute: int = 0  # 0 = unlimited
    max_daily_volume_usdc: float = 0.0  # 0 = unlimited
    
    # Polymarket contracts (Polygon mainnet)
    polymarket_ctf_exchange: str = "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
    polymarket_neg_risk_ctf_exchange: str = "0xC5d563A36AE78145C45a50134d48A1215220f80a"
    
    # Token addresses (Polygon mainnet)
    usdc_address: str = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"
    usdce_address: str = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
    
    # Team wallets (comma-separated, lowercase) - ONLY these can receive transfers
    team_wallets: str = ""  # e.g. "0xabc...,0xdef..."
    
    # Alerts
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    
    class Config:
        env_file = ".env"
        case_sensitive = False
    
    def get_allowed_ips_list(self, endpoint: str) -> List[str]:
        """
        Get allowed IPs for specific endpoint
        
        Args:
            endpoint: "order", "allowance", or "transfer"
            
        Returns:
            List of allowed IP addresses (empty list = allow all)
        """
        if endpoint == "order":
            ips_str = self.allowed_ips_order
        elif endpoint == "allowance":
            ips_str = self.allowed_ips_allowance
        elif endpoint == "transfer":
            ips_str = self.allowed_ips_transfer
        else:
            return []
        
        if not ips_str or ips_str.strip() == "":
            return []  # Empty = allow all
        
        return [ip.strip() for ip in ips_str.split(",") if ip.strip()]
    
    def get_team_wallets_list(self) -> List[str]:
        """
        Get list of team wallet addresses (lowercase)
        
        Returns:
            List of team wallet addresses
        """
        if not self.team_wallets or self.team_wallets.strip() == "":
            return []
        
        return [addr.strip().lower() for addr in self.team_wallets.split(",") if addr.strip()]


settings = Settings()

