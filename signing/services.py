"""
Privy API Client
================

Wrapper for Privy API calls.
"""
import aiohttp
import time
import random
from typing import Dict

from core.environment.config import settings
from core.logger import logger


class PrivyClient:
    """
    Client for Privy API
    
    Handles signing requests to Privy's secure enclave.
    """
    
    def __init__(self):
        self.base_url = "https://auth.privy.io"
        self.app_id = settings.privy_app_id
        self.app_secret = settings.privy_app_secret
        self._session: aiohttp.ClientSession | None = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def close(self):
        """Close HTTP session"""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def verify_token(self, privy_token: str) -> Dict:
        """
        Verify Privy access token and get user data
        
        Args:
            privy_token: Privy access token from frontend
            
        Returns:
            Dict with user data including:
            - user_id: Privy user ID
            - wallet_address: Embedded wallet address
            - wallet_id: Privy wallet ID
            
        Raises:
            Exception: If token is invalid or Privy API returns error
        """
        session = await self._get_session()
        
        try:
            logger.info(f"🔐 Verifying Privy token: {privy_token[:16]}...")
            
            async with session.get(
                f"{self.base_url}/api/v1/users/me",
                headers={
                    "Authorization": f"Bearer {privy_token}",
                    "privy-app-id": self.app_id,
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"❌ Privy token verification failed (status {response.status}): {error_text}")
                    raise Exception(f"Invalid Privy token ({response.status}): {error_text}")
                
                user_data = await response.json()
                
                # Extract user ID
                user_id = user_data.get("id")
                if not user_id:
                    raise Exception("Privy API did not return user ID")
                
                # Extract embedded wallet (created by Privy SDK on frontend)
                linked_accounts = user_data.get("linked_accounts", [])
                embedded_wallet = None
                
                for account in linked_accounts:
                    if account.get("type") == "wallet" and account.get("wallet_client") == "privy":
                        embedded_wallet = account
                        break
                
                if not embedded_wallet:
                    raise Exception("No Privy embedded wallet found for user")
                
                wallet_address = embedded_wallet.get("address")
                wallet_id = embedded_wallet.get("wallet_id")
                
                if not wallet_address or not wallet_id:
                    raise Exception("Invalid embedded wallet data from Privy")
                
                logger.info(f"✅ Token verified for user {user_id}, wallet {wallet_address}")
                
                return {
                    "user_id": user_id,
                    "wallet_address": wallet_address,
                    "wallet_id": wallet_id
                }
        
        except aiohttp.ClientError as e:
            logger.error(f"❌ Privy API connection error: {e}")
            raise Exception(f"Failed to connect to Privy API: {e}")
    
    async def sign_typed_data(
        self,
        privy_wallet_id: str,
        typed_data: Dict
    ) -> str:
        """
        Sign EIP-712 typed data via Privy API
        
        Args:
            privy_wallet_id: Privy wallet ID
            typed_data: EIP-712 structured data
            
        Returns:
            Hex-encoded signature (0x...)
            
        Raises:
            Exception: If Privy API returns error
        """
        session = await self._get_session()
        
        try:
            logger.info(f"🔐 Requesting signature from Privy for wallet {privy_wallet_id[:16]}...")
            
            async with session.post(
                f"{self.base_url}/api/v1/wallets/{privy_wallet_id}/sign_typed_data",
                headers={
                    "Authorization": f"Bearer {self.app_secret}",
                    "privy-app-id": self.app_id,
                    "Content-Type": "application/json"
                },
                json={"typed_data": typed_data},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"❌ Privy API error (status {response.status}): {error_text}")
                    raise Exception(f"Privy API error ({response.status}): {error_text}")
                
                result = await response.json()
                signature = result.get("signature")
                
                if not signature:
                    raise Exception("Privy API did not return signature")
                
                logger.info(f"✅ Signature received from Privy: {signature[:16]}...")
                return signature
        
        except aiohttp.ClientError as e:
            logger.error(f"❌ Privy API connection error: {e}")
            raise Exception(f"Failed to connect to Privy API: {e}")
    
    def build_order_typed_data(
        self,
        maker_address: str,
        token_id: str,
        maker_amount: int,
        taker_amount: int,
        side: int,
        verifying_contract: str,
        fee_rate_bps: int = 0,
        nonce: int | None = None,
        expiration: int | None = None
    ) -> Dict:
        """
        Build EIP-712 typed data for Polymarket order
        
        Args:
            maker_address: Maker wallet address
            token_id: Token ID
            maker_amount: Maker amount in wei
            taker_amount: Taker amount in wei
            side: 0=BUY, 1=SELL
            verifying_contract: CTF Exchange contract address
            fee_rate_bps: Fee rate in basis points
            nonce: Nonce (auto-generated if None)
            expiration: Expiration timestamp (auto-generated if None)
            
        Returns:
            EIP-712 typed data dict
        """
        if nonce is None:
            nonce = int(time.time() * 1000)
        
        if expiration is None:
            expiration = int(time.time()) + 3600  # +1 hour
        
        salt = random.randint(0, 2**256 - 1)
        
        return {
            "domain": {
                "name": "Polymarket CTF Exchange",
                "version": "1",
                "chainId": 137,
                "verifyingContract": verifying_contract
            },
            "types": {
                "Order": [
                    {"name": "salt", "type": "uint256"},
                    {"name": "maker", "type": "address"},
                    {"name": "signer", "type": "address"},
                    {"name": "taker", "type": "address"},
                    {"name": "tokenId", "type": "uint256"},
                    {"name": "makerAmount", "type": "uint256"},
                    {"name": "takerAmount", "type": "uint256"},
                    {"name": "expiration", "type": "uint256"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "feeRateBps", "type": "uint256"},
                    {"name": "side", "type": "uint8"},
                    {"name": "signatureType", "type": "uint8"}
                ]
            },
            "primaryType": "Order",
            "message": {
                "salt": salt,
                "maker": maker_address,
                "signer": maker_address,
                "taker": "0x0000000000000000000000000000000000000000",
                "tokenId": token_id,
                "makerAmount": str(maker_amount),
                "takerAmount": str(taker_amount),
                "expiration": str(expiration),
                "nonce": str(nonce),
                "feeRateBps": str(fee_rate_bps),
                "side": side,
                "signatureType": 0  # EOA signature
            }
        }
    
    def build_allowance_typed_data(
        self,
        owner_address: str,
        spender_address: str,
        token_address: str,
        amount: int
    ) -> Dict:
        """
        Build EIP-712 typed data for ERC20 allowance (permit)
        
        Note: This is for EIP-2612 permit function.
        For standard approve(), we need to sign a transaction instead.
        
        Args:
            owner_address: Token owner address
            spender_address: Spender address
            token_address: Token contract address
            amount: Allowance amount in wei
            
        Returns:
            EIP-712 typed data dict
        """
        nonce = int(time.time() * 1000)
        deadline = int(time.time()) + 3600  # +1 hour
        
        return {
            "domain": {
                "name": "USD Coin",  # Token name
                "version": "2",
                "chainId": 137,
                "verifyingContract": token_address
            },
            "types": {
                "Permit": [
                    {"name": "owner", "type": "address"},
                    {"name": "spender", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"}
                ]
            },
            "primaryType": "Permit",
            "message": {
                "owner": owner_address,
                "spender": spender_address,
                "value": str(amount),
                "nonce": str(nonce),
                "deadline": str(deadline)
            }
        }
    
    def build_transfer_typed_data(
        self,
        from_address: str,
        to_address: str,
        token_address: str,
        amount: int,
        nonce: int | None = None,
        gas_limit: int = 100000
    ) -> Dict:
        """
        Build transaction data for ERC20 transfer
        
        Note: For transfers, we need to sign a transaction, not EIP-712 typed data.
        This returns transaction parameters that Privy can sign.
        
        Args:
            from_address: Sender address
            to_address: Recipient address
            token_address: Token contract address
            amount: Transfer amount in wei
            nonce: Transaction nonce (auto-fetched if None)
            gas_limit: Gas limit for transaction
            
        Returns:
            Transaction data dict for Privy signing
        """
        # ERC20 transfer function signature: transfer(address,uint256)
        # Function selector: 0xa9059cbb
        
        # Encode transfer call data
        # transfer(to, amount)
        transfer_data = (
            "0xa9059cbb"  # transfer function selector
            + to_address[2:].zfill(64)  # to address (32 bytes)
            + hex(amount)[2:].zfill(64)  # amount (32 bytes)
        )
        
        return {
            "from": from_address,
            "to": token_address,  # Token contract
            "data": transfer_data,
            "value": "0x0",  # No ETH transfer
            "chainId": 137,  # Polygon
            "gasLimit": hex(gas_limit),
            "nonce": hex(nonce) if nonce else None
        }


# Global Privy client instance
privy_client = PrivyClient()

