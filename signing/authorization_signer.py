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
        private_key_base64: Base64-encoded private key.
                           По умолчанию ожидается без PEM заголовков (чистый base64).
                           Поддерживаются форматы: EC PRIVATE KEY (SEC1) и PRIVATE KEY (PKCS#8).
                           Также можно передать с PEM заголовками.
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
        private_key_string = private_key_base64.replace("wallet-auth:", "").strip()
        
        # 4. Загружаем private key
        # По умолчанию предполагаем, что ключ без PEM заголовков (просто base64)
        if not private_key_string.startswith("-----BEGIN"):
            # Пробуем оба формата: сначала EC PRIVATE KEY (SEC1), потом PRIVATE KEY (PKCS#8)
            try:
                # Формат EC PRIVATE KEY (SEC1) - стандартный для EC ключей
                private_key_pem = (
                    f"-----BEGIN EC PRIVATE KEY-----\n{private_key_string}\n-----END EC PRIVATE KEY-----"
                )
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode("utf-8"),
                    password=None
                )
                logger.debug("✅ Loaded EC PRIVATE KEY (SEC1 format)")
            except Exception as e1:
                logger.debug(f"Failed to load as EC PRIVATE KEY: {e1}")
                try:
                    # Формат PRIVATE KEY (PKCS#8)
                    private_key_pem = (
                        f"-----BEGIN PRIVATE KEY-----\n{private_key_string}\n-----END PRIVATE KEY-----"
                    )
                    private_key = serialization.load_pem_private_key(
                        private_key_pem.encode("utf-8"),
                        password=None
                    )
                    logger.debug("✅ Loaded PRIVATE KEY (PKCS#8 format)")
                except Exception as e2:
                    logger.error(f"Failed to load as PRIVATE KEY: {e2}")
                    raise ValueError(f"Could not load private key in any supported format. Tried EC PRIVATE KEY and PRIVATE KEY formats.")
        else:
            # Ключ уже в PEM формате
            private_key = serialization.load_pem_private_key(
                private_key_string.encode("utf-8"),
                password=None
            )
            logger.debug("✅ Loaded key from PEM format")
        
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
    public_key_base64: str,
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
    - privy-authorization-public-key
    - privy-authorization-signature
    - privy-idempotency-key (если передан)
    
    Args:
        private_key_base64: Base64-encoded private key (без PEM заголовков)
        public_key_base64: Base64-encoded public key (без PEM заголовков)
        method: HTTP метод
        url: Полный URL запроса
        body: JSON body запроса
        app_id: Privy App ID
        idempotency_key: Опциональный ключ идемпотентности
        
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
        "privy-authorization-public-key": public_key_base64,
        "privy-authorization-signature": signature,
        "Content-Type": "application/json"
    }
    
    if idempotency_key:
        headers["privy-idempotency-key"] = idempotency_key
    
    return headers
