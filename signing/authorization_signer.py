"""
Authorization Signature для Privy API
======================================

Реализация подписи запросов для delegated actions (session signers).
Следует спецификации: https://docs.privy.io/controls/authorization-keys/using-owners/sign/direct-implementation
"""
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Dict, Any
from core.logger import logger


def canonicalize_json(obj: Dict[str, Any]) -> str:
    """
    Канонизирует JSON согласно RFC 8785
    
    Простая реализация: сортировка ключей + минимальные разделители
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_privy_request(
    private_key_base64: str,
    method: str,
    url: str,
    body: Dict[str, Any],
    app_id: str,
    idempotency_key: str | None = None
) -> str:
    """
    Подписывает запрос к Privy API используя authorization private key
    
    Args:
        private_key_base64: Base64-encoded private key (без PEM обертки) или с ней
        method: HTTP метод ('POST', 'PUT', 'PATCH', 'DELETE')
        url: Полный URL запроса (без trailing slash)
        body: JSON body запроса
        app_id: Privy App ID
        idempotency_key: Опциональный ключ идемпотентности
        
    Returns:
        Base64-encoded подпись для заголовка privy-authorization-signature
        
    Raises:
        Exception: Если подпись не удалась
    """
    try:
        # 1. Строим payload для подписи
        headers = {"privy-app-id": app_id}
        if idempotency_key:
            headers["privy-idempotency-key"] = idempotency_key
        
        payload = {
            "version": 1,
            "method": method,
            "url": url,
            "body": body,
            "headers": headers
        }
        
        # 2. Канонизируем JSON
        serialized_payload = canonicalize_json(payload)
        logger.debug(f"Canonicalized payload: {serialized_payload[:200]}...")
        
        # 3. Парсим private key
        # Убираем префикс wallet-auth: если есть
        private_key_string = private_key_base64.replace("wallet-auth:", "")
        
        # Конвертируем в PEM формат если нужно
        if not private_key_string.startswith("-----BEGIN"):
            private_key_pem = (
                f"-----BEGIN PRIVATE KEY-----\n{private_key_string}\n-----END PRIVATE KEY-----"
            )
        else:
            private_key_pem = private_key_string
        
        # 4. Загружаем private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None
        )
        
        # 5. Подписываем payload используя ECDSA P-256 + SHA-256
        signature = private_key.sign(
            serialized_payload.encode("utf-8"),
            ec.ECDSA(hashes.SHA256())
        )
        
        # 6. Кодируем в base64
        signature_b64 = base64.b64encode(signature).decode("utf-8")
        
        logger.info("✅ Authorization signature generated successfully")
        return signature_b64
        
    except Exception as e:
        logger.error(f"❌ Failed to generate authorization signature: {e}")
        raise Exception(f"Failed to sign request: {e}")


def get_authorization_headers(
    private_key_base64: str,
    method: str,
    url: str,
    body: Dict[str, Any],
    app_id: str,
    idempotency_key: str | None = None
) -> Dict[str, str]:
    """
    Генерирует все необходимые заголовки для запроса к Privy API
    
    Включает:
    - privy-app-id
    - privy-authorization-signature
    - privy-idempotency-key (если передан)
    
    Args:
        Те же что и в sign_privy_request
        
    Returns:
        Dict с заголовками для запроса
    """
    signature = sign_privy_request(
        private_key_base64=private_key_base64,
        method=method,
        url=url,
        body=body,
        app_id=app_id,
        idempotency_key=idempotency_key
    )
    
    headers = {
        "privy-app-id": app_id,
        "privy-authorization-signature": signature,
        "Content-Type": "application/json"
    }
    
    if idempotency_key:
        headers["privy-idempotency-key"] = idempotency_key
    
    return headers
