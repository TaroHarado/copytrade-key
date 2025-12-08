# Privy Signing Service

🔐 **Изолированный микросервис для подписи Polymarket ордеров, allowances и transfers**

## 🎯 Назначение

Критически важный микросервис, который изолирует логику Privy.io для безопасной подписи транзакций без хранения приватных ключей.

### Ключевые особенности

- ✅ **3 эндпоинта**: order signing, allowance signing, transfer signing
- ✅ **Строгая валидация**: проверка через copytrading DB
- ✅ **IP Whitelisting**: только с `91.99.224.254`
- ✅ **Replay Protection**: `is_order_signed`, `is_commission_signed`
- ✅ **Audit Logging**: полное логирование всех операций
- ✅ **Rate Limiting**: защита от перегрузки (опционально)
- ✅ **Docker Hardened**: read-only, no-new-privileges, resource limits

## 🏗️ Архитектура

Следует Clean Architecture паттернам как в `backend` и `copytrading`:

```
privy-signing/
├── signing/                  # Основной модуль
│   ├── models.py            # SQLAlchemy models
│   ├── entities.py          # Pydantic entities
│   ├── repositories.py      # Data access
│   ├── services.py          # Privy client
│   ├── usecases.py          # Business logic
│   └── providers.py         # Dishka DI
├── copytrading/             # Валидация
│   ├── models.py            # UserActivity, TargetActivity
│   └── repositories.py      # Validation queries
├── api/
│   ├── router.py            # FastAPI endpoints
│   └── validators.py        # Request validation
├── core/
│   ├── container.py         # Dishka container
│   ├── database/            # Audit DB providers
│   ├── environment/         # Settings providers
│   └── copytrading_providers.py  # Copytrading DB providers
└── middleware/
    └── security.py          # IP whitelisting, auth
```

## 🚀 Быстрый старт

### 1. Установка зависимостей

```bash
poetry install
```

### 2. Настройка окружения

```bash
cp env.example .env
# Заполните все переменные окружения
```

### 3. Миграции

```bash
poetry run alembic upgrade head
```

### 4. Запуск

```bash
# Development
poetry run python main.py

# Production (Docker)
docker-compose up -d
```

## 🔐 Безопасность

### SSH Доступ

Доступ к серверу **ТОЛЬКО** через SSH ключи основателей проекта.

### IP Whitelisting

Все эндпоинты доступны только с `91.99.224.254` (backend сервер).

### Service Token

Все запросы требуют `X-Service-Token` header.

### Activity Validation

- **Order Signing**: проверка существования `target_activity` в copytrading DB
- **Transfer Signing**: проверка ~1% комиссии от суммы сделки
- **Replay Protection**: `is_order_signed`, `is_commission_signed` флаги

### Audit Logging

Все операции логируются в `signature_audit_log` таблицу.

## 📡 API Endpoints

### POST /api/sign/order

Подпись Polymarket ордера.

**Request:**
```json
{
  "user_id": 123,
  "privy_wallet_id": "did:privy:...",
  "wallet_address": "0x...",
  "target_activity_id": 456,
  "token_id": "123456",
  "side": "BUY",
  "maker_amount": "1000000",
  "taker_amount": "500000",
  "chain_id": 137
}
```

**Response:**
```json
{
  "success": true,
  "signature": "0x...",
  "audit_id": 789,
  "timestamp": "2024-12-08T12:00:00"
}
```

### POST /api/sign/allowance

Подпись ERC20 allowance.

**Request:**
```json
{
  "user_id": 123,
  "privy_wallet_id": "did:privy:...",
  "wallet_address": "0x...",
  "token_address": "0x...",
  "spender_address": "0x...",
  "amount": "1000000000000",
  "chain_id": 137
}
```

### POST /api/sign/transfer

Подпись USDC трансфера (комиссия платформы).

**Request:**
```json
{
  "user_id": 123,
  "privy_wallet_id": "did:privy:...",
  "wallet_address": "0x...",
  "target_activity_id": 456,
  "token_address": "0x...",
  "recipient_address": "0x...",
  "amount": "10000",
  "chain_id": 137
}
```

## 🔧 Конфигурация

### Основные настройки

```env
# Privy
PRIVY_APP_ID=your_app_id
PRIVY_APP_SECRET=your_secret

# Databases
DATABASE_URL=postgresql://...  # Audit logs
COPYTRADING_DATABASE_URL=postgresql://...  # Validation

# Security
SERVICE_TOKEN=your_secure_token
ALLOWED_IPS_ORDER=91.99.224.254
ALLOWED_IPS_ALLOWANCE=91.99.224.254
ALLOWED_IPS_TRANSFER=91.99.224.254

# Platform
PLATFORM_COMMISSION_PERCENTAGE=1.0
COMMISSION_TOLERANCE=0.1
```

### Rate Limiting (опционально)

```env
MAX_SIGNATURES_PER_MINUTE=0  # 0 = unlimited
MAX_DAILY_VOLUME_USDC=0.0    # 0 = unlimited
```

## 🐳 Docker Deployment

```bash
# Build
docker-compose build

# Run
docker-compose up -d

# Logs
docker-compose logs -f privy-signing

# Stop
docker-compose down
```

## 📊 Мониторинг

### Health Check

```bash
curl http://localhost:8010/health
```

### Audit Logs

```sql
SELECT * FROM signature_audit_log 
ORDER BY timestamp DESC 
LIMIT 100;
```

## 🛠️ Разработка

### Структура Dishka DI

```python
# Providers
EnvironmentProvider          # Settings
DatabaseConnectionProvider   # Audit DB engine
DatabaseSessionProvider      # Audit DB sessions
CopytradingDatabaseConnectionProvider  # Copytrading DB engine
CopytradingDatabaseSessionProvider     # Copytrading DB sessions
SigningProvider             # Repositories, services, usecases

# Container
container = make_async_container(
    FastapiProvider(),
    EnvironmentProvider(),
    DatabaseConnectionProvider(),
    DatabaseSessionProvider(),
    CopytradingDatabaseConnectionProvider(),
    CopytradingDatabaseSessionProvider(),
    SigningProvider()
)
```

### Добавление нового эндпоинта

⚠️ **НЕ ДОБАВЛЯЙТЕ НОВЫЕ ЭНДПОИНТЫ БЕЗ SECURITY REVIEW!**

Если необходимо:

1. Создайте use case в `signing/usecases.py`
2. Добавьте provider в `signing/providers.py`
3. Добавьте endpoint в `api/router.py` с `@inject`
4. Обновите валидацию в `api/validators.py`
5. Обновите IP whitelist в `middleware/security.py`

## 📝 Миграции

```bash
# Создать миграцию
poetry run alembic revision --autogenerate -m "description"

# Применить миграции
poetry run alembic upgrade head

# Откатить
poetry run alembic downgrade -1
```

## 🔍 Troubleshooting

### "Validation failed: activity not found"

Проверьте:
1. Существует ли `target_activity` в copytrading DB
2. Правильно ли указан `target_activity_id`
3. Доступна ли copytrading DB

### "Replay attack detected"

Проверьте:
1. Не был ли уже подписан этот order/commission
2. Флаги `is_order_signed`, `is_commission_signed` в `user_activities`

### "IP not whitelisted"

Проверьте:
1. Запрос идет с `91.99.224.254`
2. Настройки `ALLOWED_IPS_*` в `.env`

## 📚 Документация

- [DEPLOYMENT.md](DEPLOYMENT.md) - Инструкции по деплою
- [ACTIVITY_VALIDATION.md](ACTIVITY_VALIDATION.md) - Логика валидации
- [ARCHITECTURE.md](ARCHITECTURE.md) - Детали архитектуры

## 🤝 Интеграция

### Из copytrading сервиса

```python
from wallets.signing_client import SigningServiceClient

client = SigningServiceClient(
    base_url=settings.signing_service_url,
    service_token=settings.signing_service_token
)

# Sign order
signature = await client.sign_order(
    user_id=user.id,
    privy_wallet_id=user.privy_wallet_id,
    wallet_address=user.wallet_address,
    target_activity_id=target_activity.id,
    token_id=order.token_id,
    side=order.side,
    maker_amount=order.maker_amount,
    taker_amount=order.taker_amount,
    chain_id=137
)
```

## ⚠️ Важные замечания

1. **НЕ ВЫСТАВЛЯЙТЕ ПОРТ НАРУЖУ** - только internal network
2. **НЕ ХРАНИТЕ ПРИВАТНЫЕ КЛЮЧИ** - только Privy credentials
3. **НЕ ДОБАВЛЯЙТЕ ЭНДПОИНТЫ** без security review
4. **ВСЕГДА ЛОГИРУЙТЕ** все операции в audit log
5. **ПРОВЕРЯЙТЕ IP** на каждом запросе

## 📄 Лицензия

Proprietary - All Rights Reserved
