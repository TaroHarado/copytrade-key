"""
Security Manager
================

Rate limiting, anomaly detection, and alerting.
"""
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List
import aiohttp

from core.environment.config import settings
from core.logger import logger


class SecurityManager:
    """
    Security manager for signature requests
    
    Features:
    - Rate limiting per user
    - Daily volume tracking
    - Anomaly detection
    - Alert system
    """
    
    def __init__(self):
        # Rate limiting: user_id -> [timestamps]
        self.user_requests: Dict[int, List[datetime]] = defaultdict(list)
        
        # Volume tracking: user_id -> daily USDC volume
        self.daily_volumes: Dict[int, float] = defaultdict(float)
        self.last_volume_reset = datetime.now()
        
        # Blocked users (temporary)
        self.blocked_users: Dict[int, datetime] = {}
    
    async def check_rate_limit(self, user_id: int) -> bool:
        """
        Check rate limit for user
        
        Limit: max_signatures_per_minute per user (0 = unlimited)
        
        Returns:
            True if allowed, False if rate limit exceeded
        """
        # If limit is 0, unlimited
        if settings.max_signatures_per_minute == 0:
            return True
        
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        
        # Remove old requests
        self.user_requests[user_id] = [
            ts for ts in self.user_requests[user_id]
            if ts > minute_ago
        ]
        
        # Check limit
        current_count = len(self.user_requests[user_id])
        
        if current_count >= settings.max_signatures_per_minute:
            logger.warning(
                f"⚠️  RATE LIMIT: User {user_id} exceeded limit "
                f"({current_count}/{settings.max_signatures_per_minute} per minute)"
            )
            await self.send_alert(
                f"🚨 Rate limit exceeded\n"
                f"User: {user_id}\n"
                f"Requests: {current_count} in last minute"
            )
            return False
        
        # Add new request
        self.user_requests[user_id].append(now)
        
        return True
    
    async def check_daily_volume(self, user_id: int, amount_usdc: float) -> bool:
        """
        Check daily volume limit for user
        
        Limit: max_daily_volume_usdc per user per day (0 = unlimited)
        
        Returns:
            True if allowed, False if limit exceeded
        """
        # If limit is 0, unlimited
        if settings.max_daily_volume_usdc == 0:
            return True
        
        # Reset daily volumes at midnight
        now = datetime.now()
        if (now - self.last_volume_reset).days >= 1:
            logger.info("🔄 Resetting daily volume counters")
            self.daily_volumes.clear()
            self.last_volume_reset = now
        
        # Get current volume
        current_volume = self.daily_volumes[user_id]
        new_volume = current_volume + amount_usdc
        
        # Check limit
        if new_volume > settings.max_daily_volume_usdc:
            logger.error(
                f"🚨 VOLUME LIMIT EXCEEDED!\n"
                f"User: {user_id}\n"
                f"Current daily volume: ${current_volume:,.2f}\n"
                f"Attempted to add: ${amount_usdc:,.2f}\n"
                f"Total would be: ${new_volume:,.2f}\n"
                f"Limit: ${settings.max_daily_volume_usdc:,.2f}"
            )
            
            await self.send_alert(
                f"🚨🚨🚨 CRITICAL: Daily volume limit exceeded!\n\n"
                f"User ID: {user_id}\n"
                f"Current volume: ${current_volume:,.2f}\n"
                f"Attempted: ${amount_usdc:,.2f}\n"
                f"Limit: ${settings.max_daily_volume_usdc:,.2f}\n\n"
                f"⚠️  SIGNATURE BLOCKED"
            )
            
            # Temporarily block user
            self.blocked_users[user_id] = now
            
            return False
        
        # Update volume
        self.daily_volumes[user_id] = new_volume
        
        return True
    
    async def check_blocked(self, user_id: int) -> bool:
        """
        Check if user is temporarily blocked
        
        Returns:
            True if allowed, False if blocked
        """
        if user_id not in self.blocked_users:
            return True
        
        # Unblock after 1 hour
        blocked_at = self.blocked_users[user_id]
        if (datetime.now() - blocked_at).seconds > 3600:
            logger.info(f"🔓 Unblocking user {user_id}")
            del self.blocked_users[user_id]
            return True
        
        logger.warning(f"🚫 User {user_id} is temporarily blocked")
        return False
    
    async def validate_request(self, user_id: int, amount_usdc: float) -> bool:
        """
        Full validation: rate limit + volume + blocked status
        
        Returns:
            True if all checks pass, False otherwise
        """
        # Check if blocked
        if not await self.check_blocked(user_id):
            return False
        
        # Check rate limit
        if not await self.check_rate_limit(user_id):
            return False
        
        # Check daily volume
        if not await self.check_daily_volume(user_id, amount_usdc):
            return False
        
        return True
    
    async def send_alert(self, message: str):
        """
        Send alert to Telegram
        
        Args:
            message: Alert message
        """
        if not settings.telegram_bot_token or not settings.telegram_chat_id:
            logger.warning("⚠️  Telegram not configured, alert not sent")
            logger.critical(f"ALERT: {message}")
            return
        
        try:
            url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json={
                        "chat_id": settings.telegram_chat_id,
                        "text": message,
                        "parse_mode": "HTML"
                    }
                ) as response:
                    if response.status == 200:
                        logger.info("✅ Alert sent to Telegram")
                    else:
                        logger.error(f"❌ Failed to send Telegram alert: {response.status}")
        
        except Exception as e:
            logger.error(f"❌ Error sending Telegram alert: {e}")


# Global security manager instance
security_manager = SecurityManager()

