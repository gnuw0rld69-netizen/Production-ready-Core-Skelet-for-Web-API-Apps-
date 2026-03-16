# Auth Service с FastAPI

Готовый сервис аутентификации и авторизации на FastAPI, JWT, MariaDB и Redis.

## Возможности

- JWT access и refresh токены
- Вход по email (без учета регистра)
- Подтверждение email и повторная отправка
- TOTP 2FA (настройка, включение, отключение)
- Роли (admin и superuser политики)
- Кеш пользователей в Redis
- Очередь аудита действий в Redis
- Security headers и CORS
- IP/CIDR allowlist на пользователя
- Health check
- Docker и Alembic миграции

## Стек

- FastAPI
- SQLAlchemy + MariaDB
- Alembic
- Redis
- PyOTP, bcrypt, python-jose
- Docker

## Структура проекта

```
app/
  app.py
  core/
  routers/
  services/
  models/
  schemas/
modules/
  cms_module/
alembic/
  env.py
  versions/
Dockerfile
docker-compose.yml
requirements.txt
```

## Настройка

Скопируйте `.env.example` в `.env` и заполните значения.

### База данных

- `DB_ROOT_PASSWORD` (для MariaDB в Docker Compose)
- `DB_USER`
- `DB_PASSWORD`
- `DB_HOST`
- `DB_PORT`
- `DB_NAME`

### JWT

- `SECRET_KEY`
- `ALGORITHM`
- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `REFRESH_TOKEN_EXPIRE_DAYS`

### Redis

- `REDIS_HOST`
- `REDIS_PORT`
- `REDIS_DB`
- `REDIS_PASSWORD`
- `REDIS_USE_SSL`

### Приложение

- `PROJECT_NAME`
- `VERSION`
- `BACKEND_BASE_URL`
- `DEBUG`
- `AUTO_CREATE_TABLES`
- `CORS_ORIGINS`

### Доступ

- `TRUSTED_PROXY_IPS`

### Кеш

- `CACHE_TTL_SECONDS`

### Turnstile

- `TURNSTILE_SITE_KEY`
- `TURNSTILE_SECRET_KEY`

### Email

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `SMTP_FROM_EMAIL`
- `SMTP_FROM_NAME`
- `SMTP_USE_TLS`
- `SMTP_USE_SSL`
- `SMTP_TIMEOUT_SECONDS`

## Быстрый старт

### Локально

1. `python -m venv venv && source venv/bin/activate`
2. `pip install -r requirements.txt`
3. `cp .env.example .env` и заполните значения
4. Запустите MariaDB и Redis (или используйте Docker Compose)
5. `uvicorn app.app:app --reload`

### Docker

`docker-compose up --build`

## API документация

- Swagger UI: `http://localhost:8000/api/v1/docs`
- ReDoc: `http://localhost:8000/api/v1/redoc`

## Веб интерфейс

- Пользователи (RU): `http://localhost:8000/ru/users/`
- Пользователи (EN): `http://localhost:8000/en/users/`
- Вход: `/{lang}/users/auth`
- Регистрация: `/{lang}/users/register`
- Подтверждение почты: `/{lang}/users/verify`
- Сброс пароля: `/{lang}/users/reset`
- Профиль: `/{lang}/users/profile`
- Админ-панель: `/{lang}/admin_panel/`

## Модули

Модули автоматически загружаются из `/modules`. Каждый модуль имеет свои роуты,
шаблоны и таблицы (с префиксом имени модуля). Манифесты модулей добавляют пункты
в админ-панель и определяют ресурсы модуля.

Каждый модуль содержит собственные переводы в `modules/<module>/i18n/`.

### Инициализация БД для модулей

Таблицы модулей управляются через Alembic. Контекст миграций автоматически загружает метаданные
модулей, поэтому `alembic revision --autogenerate` включает модульные таблицы.

```bash
alembic revision --autogenerate -m "add cms module"
alembic upgrade head
```

### CMS модуль

- Админ интерфейс: `/{lang}/admin_panel/module_cms_module`
- Страницы: `/{lang}/pages/{slug}`
- Главная страница: если опубликованная CMS‑страница отмечена как главная, она может заменить `/`.

Уровни доступа:

- `public`: доступна всем
- `auth`: только авторизованные и подтвержденные пользователи
- `role`: доступ по ролям moderator/admin/superuser

## Аутентификация

- Вход требует email, адреса нормализуются в lowercase.
- В Swagger можно передать OTP в `client_secret` (или `secret_code`), если 2FA включена.
- Сброс пароля генерирует временный пароль и отправляет по email.
- Неподтвержденные пользователи могут входить, но ограничены блоком подтверждения в профиле.

## IP Allowlist

Если у пользователя есть записи allowlist, все авторизованные запросы должны идти с разрешенных IP/CIDR.

Пользовательские эндпоинты:

- `GET /api/v1/users/me/allowed-ips`
- `POST /api/v1/users/me/allowed-ips`
- `PUT /api/v1/users/me/allowed-ips/{entry_id}`
- `DELETE /api/v1/users/me/allowed-ips/{entry_id}`

Админ эндпоинты:

- `GET /api/v1/users/{user_id}/allowed-ips`
- `POST /api/v1/users/{user_id}/allowed-ips`
- `PUT /api/v1/users/{user_id}/allowed-ips/{entry_id}`
- `DELETE /api/v1/users/{user_id}/allowed-ips/{entry_id}`

## Действия администратора

- `POST /api/v1/users/{user_id}/verify-email`
- `POST /api/v1/users/{user_id}/2fa/disable`

## Redis

- Кеш: `cache:user:<id>` с TTL из `CACHE_TTL_SECONDS`
- Аудит событий записывается в Redis и сохраняется воркером

## Alembic миграции

Проверьте, что в `.env` есть настройки БД и `SECRET_KEY`.

Создать миграцию:

```bash
alembic revision --autogenerate -m "add user tables"
```

Применить миграции:

```bash
alembic upgrade head
```

## Health Check

`GET /health` возвращает статус сервиса и базы данных.
