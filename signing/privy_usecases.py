"""
Use cases для Privy операций (авторизация)
==========================================

Эти use cases используются backend для валидации Privy токенов
БЕЗ хранения PRIVY_APP_SECRET на backend.

ВАЖНО: Используется ТОЛЬКО Privy embedded wallet (один кошелек на пользователя).
External wallets (MetaMask/Phantom) НЕ используются.
"""
from typing import Tuple, Dict
from signing.services import PrivyClient
from core.logger import logger


class VerifyPrivyTokenUseCase:
    """
    Use case для валидации Privy токена
    
    Используется backend для проверки privy_token от фронтенда.
    Возвращает информацию о пользователе из Privy.
    
    ВАЖНО: Возвращает ТОЛЬКО Privy embedded wallet (создается автоматически на фронте).
    """
    
    def __init__(self, privy_client: PrivyClient):
        self.privy_client = privy_client
    
    async def execute(self, privy_token: str) -> Tuple[bool, Dict | str]:
        """
        Валидировать Privy токен
        
        Args:
            privy_token: Access token от Privy (из фронтенда)
            
        Returns:
            (success, user_data_or_error)
            
        user_data format:
        {
            "privy_user_id": "did:privy:...",
            "wallet_address": "0x...",  # Privy embedded wallet (единственный)
            "wallet_id": "..."  # ID для подписи через API
        }
        """
        try:
            logger.info("[VerifyPrivyToken] Валидация токена через Privy API...")
            
            # Валидируем токен через Privy API
            user_data = await self.privy_client.verify_token(privy_token)
            
            if not user_data:
                logger.error("[VerifyPrivyToken] Токен невалиден")
                return False, "Invalid Privy token"
            
            privy_user_id = user_data.get("id")
            if not privy_user_id:
                logger.error("[VerifyPrivyToken] Privy user ID отсутствует в ответе")
                return False, "Privy user ID missing in response"
            
            logger.info(f"[VerifyPrivyToken] Privy user ID: {privy_user_id}")
            
            # Извлекаем ТОЛЬКО Privy embedded wallet из linked_accounts
            linked_accounts = user_data.get("linked_accounts", [])
            
            wallet_address = None
            wallet_id = None
            
            for account in linked_accounts:
                if (account.get("type") == "wallet" and 
                    account.get("wallet_client") == "privy" and
                    account.get("chain_type") == "ethereum"):
                    wallet_address = account.get("address")
                    wallet_id = f"{privy_user_id}:wallet:{account.get('wallet_index', 0)}"
                    break
            
            if not wallet_address:
                logger.error("[VerifyPrivyToken] Privy embedded wallet не найден")
                return False, "No Privy embedded wallet found. Please create wallet on frontend."
            
            logger.info(f"[VerifyPrivyToken] ✅ Токен валиден, wallet: {wallet_address}")
            
            return True, {
                "privy_user_id": privy_user_id,
                "internal_wallet_address": wallet_address.lower(),
                "wallet_id": wallet_id
            }
        
        except Exception as e:
            logger.error(f"[VerifyPrivyToken] Ошибка: {e}")
            return False, f"Failed to verify token: {str(e)}"

