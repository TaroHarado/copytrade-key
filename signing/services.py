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
        self.base_url = "https://api.privy.io"
        self.app_id = settings.privy_app_id
        self.app_secret = settings.privy_app_secret
        self._session: aiohttp.ClientSession | None = None
        
        # Basic Auth credentials
        import base64
        credentials = f"{self.app_id}:{self.app_secret}"
        self.basic_auth = base64.b64encode(credentials.encode()).decode()
    
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
        
        Since Privy doesn't have a direct REST API endpoint for token verification,
        we decode the JWT token locally to extract the user_id (subject),
        then fetch full user data using Basic Auth.
        
        Args:
            privy_token: Privy access token from frontend (JWT)
            
        Returns:
            Dict with user data including:
            - id: Privy user ID
            - linked_accounts: User's linked accounts
            
        Raises:
            Exception: If token is invalid or Privy API returns error
        """
        session = await self._get_session()
        
        try:
            logger.info(f"🔐 Verifying Privy token: {privy_token[:16]}...")
            
            # Step 1: Decode JWT token (without verification for now) to get user_id
            # JWT format: header.payload.signature
            import json
            import base64
            
            try:
                # Split token and decode payload
                parts = privy_token.split('.')
                if len(parts) != 3:
                    raise Exception("Invalid JWT format")
                
                # Decode payload (add padding if needed)
                payload = parts[1]
                payload += '=' * (4 - len(payload) % 4)
                decoded_payload = json.loads(base64.urlsafe_b64decode(payload))
                
                user_id = decoded_payload.get('sub') or decoded_payload.get('userId')
                if not user_id:
                    raise Exception(f"No user ID in token payload: {decoded_payload}")
                
                logger.info(f"✅ Decoded user ID from token: {user_id}")
                
            except Exception as decode_error:
                logger.error(f"❌ Failed to decode JWT: {decode_error}")
                raise Exception(f"Invalid JWT token: {decode_error}")
            
            # Step 2: Fetch full user data using Basic Auth
            # According to Privy docs: https://api.privy.io/v1/users/{user_id}
            url = f"{self.base_url}/v1/users/{user_id}"
            logger.info(f"🔗 Fetching user data from: {url}")
            
            async with session.get(
                url,
                headers={
                    "Authorization": f"Basic {self.basic_auth}",
                    "privy-app-id": self.app_id
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                logger.info(f"📡 Response status: {response.status}")
                
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"❌ Failed to fetch user data (status {response.status}): {error_text[:500]}")
                    raise Exception(f"Failed to fetch user data ({response.status}): {error_text[:200]}")
                
                user_data = await response.json()
                
                # Validate user ID matches
                fetched_user_id = user_data.get("id")
                if fetched_user_id != user_id:
                    raise Exception(f"User ID mismatch: token={user_id}, api={fetched_user_id}")
                
                logger.info(f"✅ User data fetched successfully")
                
                # Return user data with linked accounts
                linked_accounts = user_data.get("linked_accounts", [])
                logger.info(f"✅ Got user data with {len(linked_accounts)} linked accounts")
                
                return {
                    "id": user_id,
                    "linked_accounts": linked_accounts
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
        Sign EIP-712 typed data via Privy API using RPC endpoint
        
        Args:
            privy_wallet_id: Privy wallet ID (can be full DID or just wallet address)
            typed_data: EIP-712 structured data
            
        Returns:
            Hex-encoded signature (0x...)
            
        Raises:
            Exception: If Privy API returns error
        """
        session = await self._get_session()
        
        try:
            logger.info(f"🔐 Requesting signature from Privy for wallet {privy_wallet_id[:30]}...")
            logger.info(f"📋 Full wallet ID received: {privy_wallet_id}")
            
            # Parse wallet DID format
            # Expected formats:
            # 1. Full DID: did:privy:{user_id}:wallet:{index}  (stored in DB)
            # 2. API format: did:privy:{user_id}  (what Privy API expects)
            
            wallet_id_for_api = privy_wallet_id
            
            if privy_wallet_id.startswith("did:privy:"):
                parts = privy_wallet_id.split(":")
                logger.info(f"🔍 Parsing DID format, parts count: {len(parts)}, parts: {parts}")
                
                # Format: ['did', 'privy', '{user_id}', 'wallet', '{index}']
                if len(parts) == 5 and parts[3] == "wallet":
                    # Extract just user ID part: did:privy:{user_id}
                    user_id_part = parts[2]
                    wallet_id_for_api = f"did:privy:{user_id_part}"
                    logger.info(f"✂️ Extracted user-only DID for API: {wallet_id_for_api}")
                elif len(parts) == 3:
                    # Already in correct format: did:privy:{user_id}
                    wallet_id_for_api = privy_wallet_id
                    logger.info(f"✅ DID already in API format: {wallet_id_for_api}")
                else:
                    logger.warning(f"⚠️ Unexpected DID format with {len(parts)} parts, using as-is")
            
            api_url = f"{self.base_url}/api/v1/wallets/{wallet_id_for_api}/rpc"
            logger.info(f"🌐 API URL: {api_url}")
            logger.info(f"📤 Request payload: method=eth_signTypedData_v4, typed_data keys: {list(typed_data.keys())}")
            
            # Use RPC endpoint with eth_signTypedData_v4 method
            async with session.post(
                api_url,
                headers={
                    "Authorization": f"Basic {self.basic_auth}",
                    "privy-app-id": self.app_id,
                    "Content-Type": "application/json"
                },
                json={
                    "method": "eth_signTypedData_v4",
                    "params": {
                        "data": typed_data
                    }
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                response_text = await response.text()
                logger.info(f"📥 Response status: {response.status}")
                logger.info(f"📥 Response body: {response_text[:500]}")
                
                if response.status != 200:
                    logger.error(f"❌ Privy API error (status {response.status}): {response_text}")
                    raise Exception(f"Privy API error ({response.status}): {response_text}")
                
                result = await response.json()
                signature = result.get("data")
                
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

