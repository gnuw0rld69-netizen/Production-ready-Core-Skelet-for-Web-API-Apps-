from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.web.i18n import get_translations, normalize_lang
from app.core.database import get_db
from app.models.user import User, UserRole
from app.schemas.user import UserUpdate
from app.services.user_ip_allowlist_service import UserIpAllowlistService
from app.services.user_service import UserService
from app.routers.web_users import _get_current_user_from_cookie

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(prefix="/{lang}/admin_panel", tags=["Web Admin"])


def _redirect_with_message(lang: str, path: str, message: str) -> RedirectResponse:
    return RedirectResponse(f"/{lang}{path}?message={message}", status_code=status.HTTP_303_SEE_OTHER)


def _msg(lang: str, key: str, fallback: str) -> str:
    return get_translations(lang).get(key, fallback)


def _require_admin(request: Request, db: Session) -> User | None:
    user = _get_current_user_from_cookie(request, db)
    if not user:
        return None
    if user.role not in {UserRole.ADMIN, UserRole.SUPERUSER}:
        return None
    return user


@router.get("/", response_class=HTMLResponse)
def admin_home(request: Request, lang: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang)
        admin_user = _require_admin(request, db)
        message = request.query_params.get("message")
        return templates.TemplateResponse(
            "admin_panel/home.html",
            {
                "request": request,
                "admin_user": admin_user,
                "nav_user": admin_user,
                "message": message,
                "lang": lang,
                "t": t,
            },
        )
    finally:
        db.close()


@router.get("/users", response_class=HTMLResponse)
def admin_users_page(request: Request, lang: str, role: str | None = None, user_id: int | None = None):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang)
        admin_user = _require_admin(request, db)
        message = request.query_params.get("message")
        users = []
        target_user = None
        if admin_user:
            role_enum = None
            if role:
                try:
                    role_enum = UserRole(role.strip().lower())
                except ValueError:
                    message = _msg(lang, "web.msg.invalid_role_filter", "Invalid role filter")
            users = UserService.get_users(db, skip=0, limit=50, role=role_enum)
            if user_id:
                target_user = UserService.get_by_id(db, user_id)
        return templates.TemplateResponse(
            "admin_panel/users.html",
            {
                "request": request,
                "admin_user": admin_user,
                "nav_user": admin_user,
                "users": users,
                "target_user": target_user,
                "message": message,
                "lang": lang,
                "t": t,
            },
        )
    finally:
        db.close()


@router.get("/allowlist", response_class=HTMLResponse)
def admin_allowlist_page(request: Request, lang: str, user_id: int | None = None):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang)
        admin_user = _require_admin(request, db)
        message = request.query_params.get("message")
        target_user = None
        allowlist_entries = []
        if admin_user and user_id:
            target_user = UserService.get_by_id(db, user_id)
            if target_user:
                allowlist_entries = UserIpAllowlistService.list_for_user(db, target_user.id)
        return templates.TemplateResponse(
            "admin_panel/allowlist.html",
            {
                "request": request,
                "admin_user": admin_user,
                "nav_user": admin_user,
                "target_user": target_user,
                "allowlist_entries": allowlist_entries,
                "message": message,
                "lang": lang,
                "t": t,
            },
        )
    finally:
        db.close()


@router.post("/users/update")
def admin_update_user(
    request: Request,
    lang: str,
    user_id: int = Form(...),
    email: str | None = Form(default=None),
    full_name: str | None = Form(default=None),
    password: str | None = Form(default=None),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        if not _require_admin(request, db):
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        try:
            payload = UserUpdate(email=email or None, full_name=full_name or None, password=password or None)
        except Exception as exc:
            return _redirect_with_message(lang, "/admin_panel/users", str(exc))
        try:
            user = UserService.update_user(db, user_id, payload)
        except ValueError as exc:
            return _redirect_with_message(lang, "/admin_panel/users", str(exc))
        if not user:
            return _redirect_with_message(
                lang,
                "/admin_panel/users",
                _msg(lang, "web.msg.user_not_found", "User not found"),
            )
        return _redirect_with_message(
            lang,
            "/admin_panel/users",
            _msg(lang, "web.msg.user_updated", "User updated"),
        )
    finally:
        db.close()


@router.post("/users/role")
def admin_change_role(
    request: Request,
    lang: str,
    user_id: int = Form(...),
    role: str = Form(...),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        if not _require_admin(request, db):
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        try:
            role_enum = UserRole(role.strip().lower())
        except ValueError:
            return _redirect_with_message(
                lang,
                "/admin_panel/users",
                _msg(lang, "web.msg.invalid_role", "Invalid role"),
            )
        user = UserService.change_user_role(db, user_id, role_enum)
        if not user:
            return _redirect_with_message(
                lang,
                "/admin_panel/users",
                _msg(lang, "web.msg.user_not_found", "User not found"),
            )
        return _redirect_with_message(
            lang,
            "/admin_panel/users",
            _msg(lang, "web.msg.role_updated", "Role updated"),
        )
    finally:
        db.close()


@router.post("/users/activate")
def admin_activate_user(request: Request, lang: str, user_id: int = Form(...)):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        if not _require_admin(request, db):
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        user = UserService.activate_user(db, user_id)
        if not user:
            return _redirect_with_message(
                lang,
                "/admin_panel/users",
                _msg(lang, "web.msg.user_not_found", "User not found"),
            )
        return _redirect_with_message(
            lang,
            "/admin_panel/users",
            _msg(lang, "web.msg.user_activated", "User activated"),
        )
    finally:
        db.close()


@router.post("/users/deactivate")
def admin_deactivate_user(request: Request, lang: str, user_id: int = Form(...)):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        if not _require_admin(request, db):
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        user = UserService.deactivate_user(db, user_id)
        if not user:
            return _redirect_with_message(
                lang,
                "/admin_panel/users",
                _msg(lang, "web.msg.user_not_found", "User not found"),
            )
        return _redirect_with_message(
            lang,
            "/admin_panel/users",
            _msg(lang, "web.msg.user_deactivated", "User deactivated"),
        )
    finally:
        db.close()


@router.post("/users/verify-email")
def admin_verify_email(request: Request, lang: str, user_id: int = Form(...)):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        if not _require_admin(request, db):
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        user = UserService.verify_email_manually(db, user_id)
        if not user:
            return _redirect_with_message(
                lang,
                "/admin_panel/users",
                _msg(lang, "web.msg.user_not_found", "User not found"),
            )
        return _redirect_with_message(
            lang,
            "/admin_panel/users",
            _msg(lang, "web.msg.email_verified", "Email verified"),
        )
    finally:
        db.close()


@router.post("/users/2fa/disable")
def admin_disable_two_factor(request: Request, lang: str, user_id: int = Form(...)):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        if not _require_admin(request, db):
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        user = UserService.disable_two_factor(db, user_id)
        if not user:
            return _redirect_with_message(
                lang,
                "/admin_panel/users",
                _msg(lang, "web.msg.user_not_found", "User not found"),
            )
        return _redirect_with_message(
            lang,
            "/admin_panel/users",
            _msg(lang, "web.msg.twofa_disabled", "2FA disabled"),
        )
    finally:
        db.close()


@router.post("/users/allowlist/add")
def admin_allowlist_add(
    request: Request,
    lang: str,
    user_id: int = Form(...),
    ip_or_network: str = Form(...),
    description: str | None = Form(default=None),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        if not _require_admin(request, db):
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        try:
            UserIpAllowlistService.create_entry(
                db,
                user_id=user_id,
                ip_or_network=ip_or_network,
                description=description,
                is_active=True,
            )
        except ValueError as exc:
            return _redirect_with_message(lang, "/admin_panel/allowlist", str(exc))
        return _redirect_with_message(
            lang,
            "/admin_panel/allowlist",
            _msg(lang, "web.msg.allowlist_added", "Allowed IP added"),
        )
    finally:
        db.close()


@router.post("/users/allowlist/update")
def admin_allowlist_update(
    request: Request,
    lang: str,
    user_id: int = Form(...),
    entry_id: int = Form(...),
    ip_or_network: str | None = Form(default=None),
    description: str | None = Form(default=None),
    is_active: bool | None = Form(default=None),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        if not _require_admin(request, db):
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        try:
            entry = UserIpAllowlistService.update_entry(
                db,
                user_id=user_id,
                entry_id=entry_id,
                ip_or_network=ip_or_network or None,
                description=description or None,
                is_active=is_active,
            )
        except ValueError as exc:
            return _redirect_with_message(lang, "/admin_panel/allowlist", str(exc))
        if not entry:
            return _redirect_with_message(
                lang,
                "/admin_panel/allowlist",
                _msg(lang, "web.msg.allowlist_entry_not_found", "Allowed IP entry not found"),
            )
        return _redirect_with_message(
            lang,
            "/admin_panel/allowlist",
            _msg(lang, "web.msg.allowlist_updated", "Allowed IP updated"),
        )
    finally:
        db.close()


@router.post("/users/allowlist/delete")
def admin_allowlist_delete(
    request: Request,
    lang: str,
    user_id: int = Form(...),
    entry_id: int = Form(...),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        if not _require_admin(request, db):
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "web.msg.unauthorized", "Unauthorized"),
            )
        deleted = UserIpAllowlistService.delete_entry(db, user_id, entry_id)
        if not deleted:
            return _redirect_with_message(
                lang,
                "/admin_panel/allowlist",
                _msg(lang, "web.msg.allowlist_entry_not_found", "Allowed IP entry not found"),
            )
        return _redirect_with_message(
            lang,
            "/admin_panel/allowlist",
            _msg(lang, "web.msg.allowlist_deleted", "Allowed IP deleted"),
        )
    finally:
        db.close()
