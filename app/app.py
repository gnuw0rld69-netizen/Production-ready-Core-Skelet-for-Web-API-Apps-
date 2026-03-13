import re
import threading
import time
from contextlib import asynccontextmanager
from collections.abc import Awaitable, Callable
from typing import cast

from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.database import Base, engine
from app.core.redis import close_redis_client
from app.core.security import InvalidTokenError, decode_token
from app.routers import auth_router, users_router, web_admin_router, web_users_router
from app.services.audit_service import AuditService

USER_ACTION_PATH_PREFIXES = ("/api/v1/auth", "/api/v1/users")
USER_ID_PATH_REGEX = re.compile(r"^/api/v1/users/(?P<user_id>\d+)(?:/|$)")
WEB_UI_PATH_PREFIXES = ("/ru/users", "/en/users", "/ru/admin_panel", "/en/admin_panel")

audit_worker_stop_event = threading.Event()
audit_worker_thread: threading.Thread | None = None


def _extract_actor_user_id(request: Request) -> int | None:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None

    try:
        payload = decode_token(token)
    except InvalidTokenError:
        return None

    user_id_raw = payload.get("sub")
    if user_id_raw is None:
        return None

    try:
        return int(cast(str, user_id_raw))
    except (TypeError, ValueError):
        return None


def _extract_target_user_id(path: str) -> int | None:
    match = USER_ID_PATH_REGEX.match(path)
    if not match:
        return None

    try:
        return int(match.group("user_id"))
    except (TypeError, ValueError):
        return None



@asynccontextmanager
async def lifespan(_: FastAPI):
    global audit_worker_thread
    if settings.AUTO_CREATE_TABLES:
        Base.metadata.create_all(bind=engine)

    audit_worker_stop_event.clear()
    audit_worker_thread = threading.Thread(
        target=AuditService.run_queue_worker,
        args=(audit_worker_stop_event,),
        daemon=True,
    )
    audit_worker_thread.start()
    try:
        yield
    finally:
        audit_worker_stop_event.set()
        if audit_worker_thread:
            audit_worker_thread.join(timeout=5)
        close_redis_client()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url="/api/v1/openapi.json",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

@app.middleware("http")
async def add_security_headers(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com;"
    return response


@app.middleware("http")
async def audit_user_actions(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    if not request.url.path.startswith(USER_ACTION_PATH_PREFIXES):
        return await call_next(request)

    actor_user_id = _extract_actor_user_id(request)
    target_user_id = _extract_target_user_id(request.url.path)
    response: Response | None = None
    error_detail: str | None = None

    try:
        response = await call_next(request)
        return response
    except Exception as exc:
        error_detail = str(exc)
        raise
    finally:
        status_code = response.status_code if response else 500
        success = 200 <= status_code < 400
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        AuditService.enqueue_user_action(
            action=f"{request.method} {request.url.path}",
            method=request.method,
            path=request.url.path,
            status_code=status_code,
            success=success,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=error_detail,
        )


@app.middleware("http")
async def add_process_time_header(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


@app.middleware("http")
async def refresh_web_session_tokens(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    response = await call_next(request)
    if not request.url.path.startswith(WEB_UI_PATH_PREFIXES):
        return response

    new_access_token = getattr(request.state, "new_access_token", None)
    if new_access_token:
        max_age = settings.WEB_SESSION_HOURS * 60 * 60
        response.set_cookie(
            "access_token",
            new_access_token,
            httponly=True,
            samesite="lax",
            max_age=max_age,
        )
    return response


@app.get("/api/v1/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url="/api/v1/openapi.json",
        title=f"{settings.PROJECT_NAME} - Swagger UI",
        oauth2_redirect_url="/api/v1/docs/oauth2-redirect",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
    )

@app.get("/api/v1/docs/oauth2-redirect", include_in_schema=False)
async def swagger_ui_redirect():
    return get_swagger_ui_oauth2_redirect_html()


@app.get("/api/v1/redoc", include_in_schema=False)
async def redoc_html():
    return get_redoc_html(
        openapi_url="/api/v1/openapi.json",
        title=f"{settings.PROJECT_NAME} - ReDoc",
        redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js",
    )


app.include_router(auth_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
app.include_router(web_users_router)
app.include_router(web_admin_router)


@app.get("/")
async def root():
    return RedirectResponse(url="/ru/users/", status_code=307)


@app.get("/users")
@app.get("/users/")
async def users_root():
    return RedirectResponse(url="/ru/users/", status_code=307)


@app.get("/admin_panel")
@app.get("/admin_panel/")
async def admin_root():
    return RedirectResponse(url="/ru/admin_panel/", status_code=307)


@app.get("/health")
def health_check(response: Response):
    service_status = "healthy"
    database_status = "connected"

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        service_status = "degraded"
        database_status = "disconnected"
        response.status_code = 503

    return {
        "status": service_status,
        "timestamp": time.time(),
        "database": database_status,
    }
